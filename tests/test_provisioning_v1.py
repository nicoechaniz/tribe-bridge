import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from tribe_directory_admin_v1 import build_next_epoch
from tribe_directory_v1 import b64url_decode, directory_preimage
from tribe_provisioning_v1 import (
    CLIENT_ENVIRONMENT_KEYS,
    ProvisioningError,
    _manifest_preimage,
    apply_package,
    build_package,
    create_provisioning_authority,
    doctor,
    verify_package,
)
from v1_fixtures import NOW, b64url, make_material, signing_key


BUILD = "187c61d881e6de830a029027144193645f2c7f62"


def load_launcher_module():
    path = ROOT / "scripts" / "tribe_launcher.py"
    spec = importlib.util.spec_from_file_location("tribe_launcher", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Tribe launcher")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tree_snapshot(root):
    result = {}
    for path in sorted((root, *root.rglob("*"))):
        info = path.lstat()
        relative = str(path.relative_to(root)) if path != root else "."
        if stat.S_ISLNK(info.st_mode):
            payload = ("symlink", os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            payload = ("file", path.read_bytes())
        else:
            payload = ("directory", None)
        result[relative] = (stat.S_IMODE(info.st_mode), payload)
    return result


def signed_successor(snapshot, now_ms, *, previous_sha256=None):
    value = build_next_epoch(snapshot, now_ms=now_ms, validity_days=30)
    if previous_sha256 is not None:
        value["previous_sha256"] = previous_sha256
    value["governance"]["signatures"] = [
        {
            "kid": "governance/root/1",
            "alg": "Ed25519",
            "value": b64url(signing_key(1).sign(directory_preimage(value))),
        }
    ]
    return value


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tribe-provisioning-test-"))
        self.material = make_material(self.tmp / "material")
        private, public = create_provisioning_authority(
            kid="synthetic/provisioner/1"
        )
        self.private_authority = self.tmp / "provisioner-private.json"
        self.public_authority = self.tmp / "provisioner-public.json"
        self.private_authority.write_text(json.dumps(private))
        self.public_authority.write_text(json.dumps(public))
        os.chmod(self.private_authority, 0o600)
        os.chmod(self.public_authority, 0o644)

    def build(
        self,
        package: Path,
        *,
        directory_path=None,
        agent_id="alice",
        routes=None,
        endpoints=None,
        local_ids=None,
        now_ms=NOW,
        provisioning_id=None,
    ):
        required = [
            {
                "type": "direct",
                "id": agent_id,
                "epoch": 1,
            }
        ]
        return build_package(
            package,
            directory_path or self.material["directory_path"],
            self.material["roots_path"],
            self.private_authority,
            provisioning_id=provisioning_id
            or f"synthetic-{agent_id.replace('@', '-')}",
            agent_id=agent_id,
            required_audiences=required,
            routes=routes or {"worker@localhost": {"hub": "http://10.0.0.1:8685"}},
            inbox_endpoints=endpoints or ["http://10.0.0.1:8685"],
            local_agent_ids=[agent_id] if local_ids is None else local_ids,
            build_commit=BUILD,
            now_ms=now_ms,
            expires_at_ms=now_ms + 60 * 60 * 1000,
        )

    def test_fresh_apply_is_idempotent_public_only_and_local_doctor(self):
        package = self.tmp / "package"
        self.build(package)
        destination = self.tmp / "client"
        receipt = apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        self.assertFalse(receipt["network_access"])
        self.assertFalse(receipt["ssh_access"])
        self.assertFalse(receipt["contains_private_material"])
        high_water = destination / "provision-high-water.json"
        self.assertEqual(stat.S_IMODE(high_water.stat().st_mode), 0o600)
        high_water_value = json.loads(high_water.read_text())
        self.assertEqual(high_water_value["target_agent_id"], "alice")
        self.assertEqual(
            high_water_value["package_sha256"], receipt["package_sha256"]
        )
        env = destination / receipt["environment"]
        self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o600)
        self.assertNotIn("ssh", env.read_text().lower())
        self.assertNotIn("/proc/self/fd", env.read_text())
        self.assertIn(str(destination.resolve()), env.read_text())
        private_bundle = json.loads(
            self.material["bundles"]["alice"].read_text()
        )
        package_bytes = b"".join(
            path.read_bytes() for path in package.iterdir()
        )
        self.assertNotIn(
            private_bundle["signing"]["private_key"].encode(), package_bytes
        )
        again = apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        self.assertEqual(receipt, again)
        report = doctor(
            destination,
            self.material["bundles"]["alice"],
            agent_id="alice",
            now_ms=NOW,
        )
        self.assertTrue(report["ok"])
        self.assertFalse(report["network_checked"])
        self.assertFalse(report["matrix_receipt"])

    def test_crash_after_directory_install_resumes_one_state(self):
        package = self.tmp / "package"
        self.build(package)
        destination = self.tmp / "client"

        def crash(phase):
            if phase == "directory-installed":
                raise RuntimeError("synthetic crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic crash"):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
                fault_hook=crash,
            )
        self.assertTrue((destination / "provision-journal.json").exists())
        receipt = apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        self.assertEqual(receipt["directory_epoch"], 1)
        self.assertFalse((destination / "provision-journal.json").exists())

    def test_exact_crash_resume_crosses_expiry_but_expired_start_is_rejected(self):
        package = self.tmp / "package"
        self.build(package)
        destination = self.tmp / "client"

        def crash(phase):
            if phase == "directory-installed":
                raise RuntimeError("synthetic crash before expiry")

        with self.assertRaisesRegex(RuntimeError, "before expiry"):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
                fault_hook=crash,
            )
        journal = json.loads(
            (destination / "provision-journal.json").read_text()
        )
        self.assertEqual(journal["authorized_at_ms"], NOW)

        conflicting = self.tmp / "conflicting-package"
        self.build(
            conflicting,
            provisioning_id="synthetic-alice-not-the-started-package",
        )
        with self.assertRaisesRegex(
            ProvisioningError, "another provisioning transaction"
        ):
            apply_package(
                conflicting,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW + 60 * 60 * 1000,
            )

        receipt = apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW + 60 * 60 * 1000,
        )
        self.assertEqual(receipt["directory_epoch"], 1)
        self.assertFalse((destination / "provision-journal.json").exists())
        self.assertTrue((destination / "provision-high-water.json").exists())

        expired_destination = self.tmp / "expired-start"
        with self.assertRaisesRegex(
            ProvisioningError, "not currently valid"
        ):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                expired_destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW + 60 * 60 * 1000,
            )
        self.assertFalse(expired_destination.exists())

    def test_high_water_commit_crash_resumes_exact_and_rejects_conflict(self):
        package = self.tmp / "package"
        self.build(package)
        destination = self.tmp / "client"

        def crash(phase):
            if phase == "high-water-installed":
                raise RuntimeError("synthetic high-water crash")

        with self.assertRaisesRegex(RuntimeError, "high-water crash"):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
                fault_hook=crash,
            )
        self.assertTrue((destination / "provision-high-water.json").exists())
        self.assertTrue((destination / "provision-journal.json").exists())
        first = apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        second = apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        self.assertEqual(first, second)

        conflict = self.tmp / "conflicting-package"
        self.build(
            conflict,
            provisioning_id="synthetic-alice-conflict",
        )
        with self.assertRaisesRegex(
            ProvisioningError, "conflicts at the high-water epoch"
        ):
            apply_package(
                conflict,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )

    def test_signed_manifest_requires_created_before_expiry(self):
        package = self.tmp / "package"
        self.build(package)
        manifest_path = package / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["created_at_ms"] = manifest["expires_at_ms"]
        private = json.loads(self.private_authority.read_text())
        signer = Ed25519PrivateKey.from_private_bytes(
            b64url_decode(private["private_key"], 32)
        )
        manifest["signature"] = b64url(
            signer.sign(_manifest_preimage(manifest))
        )
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(
            ProvisioningError, "not currently valid"
        ):
            verify_package(package, self.public_authority, now_ms=NOW)

    def test_extra_package_file_is_rejected_before_target_creation(self):
        package = self.tmp / "package"
        self.build(package)
        (package / "unlisted.txt").write_text("not in the signed inventory")
        destination = self.tmp / "must-not-exist"
        with self.assertRaisesRegex(
            ProvisioningError, "invalid provisioning package inventory"
        ):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )
        self.assertFalse(destination.exists())

    def test_next_epoch_advances_and_old_package_is_rejected(self):
        package1 = self.tmp / "package-1"
        self.build(package1)
        destination = self.tmp / "client"
        apply_package(
            package1,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        successor = signed_successor(self.material["snapshot"], NOW + 1)
        directory2 = self.tmp / "directory-2.json"
        directory2.write_text(json.dumps(successor))
        package2 = self.tmp / "package-2"
        self.build(
            package2,
            directory_path=directory2,
            now_ms=NOW + 1,
        )
        receipt = apply_package(
            package2,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW + 1,
        )
        self.assertEqual(receipt["directory_epoch"], 2)
        with self.assertRaises(ProvisioningError):
            apply_package(
                package1,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW + 2,
            )
        self.assertFalse((destination / "provision-journal.json").exists())

    def test_rendered_environment_rejects_control_destination_without_effects(self):
        package = self.tmp / "package"
        self.build(package)
        destination = self.tmp / "client\x1fcontrol"
        before = tree_snapshot(self.tmp)

        with self.assertRaisesRegex(
            ProvisioningError, "invalid provisioning destination path"
        ):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )

        self.assertFalse(os.path.lexists(destination))
        self.assertEqual(tree_snapshot(self.tmp), before)

    def test_invalid_rendered_environment_preflight_creates_no_artifacts(self):
        package = self.tmp / "package"
        self.build(
            package,
            routes={
                "worker@localhost": {
                    "hub": "http://10.0.0.1/$(not-shell)"
                }
            },
        )
        missing = self.tmp / "missing-client"
        before_missing = tree_snapshot(self.tmp)

        with self.assertRaisesRegex(
            ProvisioningError, "invalid client environment value"
        ):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                missing,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )
        self.assertFalse(missing.exists())
        self.assertEqual(tree_snapshot(self.tmp), before_missing)

        existing = self.tmp / "existing-client"
        existing.mkdir(mode=0o700)
        before_existing = tree_snapshot(existing)
        with self.assertRaisesRegex(
            ProvisioningError, "invalid client environment value"
        ):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                existing,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )
        self.assertEqual(tree_snapshot(existing), before_existing)

    def test_writable_parent_cannot_swap_epoch_two_for_epoch_one(self):
        package1 = self.tmp / "package-1"
        self.build(package1)
        safe_destination = self.tmp / "safe-client"
        apply_package(
            package1,
            self.public_authority,
            self.material["bundles"]["alice"],
            safe_destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        epoch1 = self.tmp / "epoch-1-copy"
        shutil.copytree(safe_destination, epoch1)

        successor = signed_successor(self.material["snapshot"], NOW + 1)
        directory2 = self.tmp / "directory-2.json"
        directory2.write_text(json.dumps(successor))
        package2 = self.tmp / "package-2"
        self.build(package2, directory_path=directory2, now_ms=NOW + 1)
        apply_package(
            package2,
            self.public_authority,
            self.material["bundles"]["alice"],
            safe_destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW + 1,
        )

        writable_parent = self.tmp / "writable-parent"
        writable_parent.mkdir(mode=0o700)
        current = writable_parent / "client"
        shutil.copytree(safe_destination, current)
        renamed_epoch2 = writable_parent / "renamed-epoch-2"
        current.rename(renamed_epoch2)
        shutil.copytree(epoch1, current)
        writable_parent.chmod(0o777)
        before = tree_snapshot(writable_parent)

        with self.assertRaisesRegex(
            ProvisioningError, "untrusted provisioning destination parent"
        ):
            apply_package(
                package1,
                self.public_authority,
                self.material["bundles"]["alice"],
                current,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW + 2,
            )

        self.assertEqual(tree_snapshot(writable_parent), before)
        self.assertEqual(
            json.loads(
                (renamed_epoch2 / "provision-high-water.json").read_text()
            )["directory_epoch"],
            2,
        )
        self.assertEqual(
            json.loads(
                (current / "provision-high-water.json").read_text()
            )["directory_epoch"],
            1,
        )

    def test_destination_symlink_is_rejected_without_target_effects(self):
        package = self.tmp / "package"
        self.build(package)
        target = self.tmp / "client-target"
        apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["alice"],
            target,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        before = tree_snapshot(target)
        destination = self.tmp / "client-link"
        destination.symlink_to(target, target_is_directory=True)

        with self.assertRaises(ProvisioningError):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )

        self.assertTrue(destination.is_symlink())
        self.assertEqual(tree_snapshot(target), before)

        real_parent = self.tmp / "real-client-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.tmp / "linked-client-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        nested_destination = linked_parent / "nested-client"
        parent_before = tree_snapshot(real_parent)
        with self.assertRaises(ProvisioningError):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                nested_destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )
        self.assertEqual(tree_snapshot(real_parent), parent_before)

    def test_destination_swap_during_advance_never_mutates_replacement(self):
        package1 = self.tmp / "package-1"
        self.build(package1)
        destination = self.tmp / "client"
        apply_package(
            package1,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        epoch1 = self.tmp / "epoch-1-copy"
        shutil.copytree(destination, epoch1)
        replacement_before = tree_snapshot(epoch1)

        successor = signed_successor(self.material["snapshot"], NOW + 1)
        directory2 = self.tmp / "directory-2.json"
        directory2.write_text(json.dumps(successor))
        package2 = self.tmp / "package-2"
        self.build(package2, directory_path=directory2, now_ms=NOW + 1)
        renamed = self.tmp / "client-renamed-during-apply"

        def swap(phase):
            if phase == "directory-installed":
                destination.rename(renamed)
                shutil.copytree(epoch1, destination)

        with self.assertRaisesRegex(
            ProvisioningError, "destination changed during apply"
        ):
            apply_package(
                package2,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW + 1,
                fault_hook=swap,
            )

        self.assertEqual(tree_snapshot(destination), replacement_before)
        self.assertFalse((destination / "provision-journal.json").exists())
        self.assertTrue((renamed / "provision-journal.json").exists())

    def test_next_epoch_must_descend_from_high_water_without_installed_directory(self):
        package1 = self.tmp / "package-1"
        self.build(package1)
        destination = self.tmp / "client"
        apply_package(
            package1,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        high_water_path = destination / "provision-high-water.json"
        high_water_before = high_water_path.read_bytes()
        (destination / "directory.json").unlink()

        fork = signed_successor(
            self.material["snapshot"],
            NOW + 1,
            previous_sha256="f" * 64,
        )
        fork_path = self.tmp / "directory-fork.json"
        fork_path.write_text(json.dumps(fork))
        package2 = self.tmp / "package-2-fork"
        self.build(package2, directory_path=fork_path, now_ms=NOW + 1)

        with self.assertRaisesRegex(
            ProvisioningError, "does not descend from the high-water"
        ):
            apply_package(
                package2,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW + 1,
            )
        self.assertEqual(high_water_path.read_bytes(), high_water_before)
        self.assertFalse((destination / "directory.json").exists())
        self.assertFalse((destination / "provision-journal.json").exists())

    def test_authority_anchor_rejects_links_writable_file_and_untrusted_parent(self):
        package = self.tmp / "package"
        self.build(package)
        authority_bytes = self.public_authority.read_bytes()

        symlink = self.tmp / "authority-symlink.json"
        symlink.symlink_to(self.public_authority)

        hardlink_target = self.tmp / "authority-hardlink-target.json"
        hardlink_target.write_bytes(authority_bytes)
        hardlink_target.chmod(0o644)
        hardlink = self.tmp / "authority-hardlink.json"
        os.link(hardlink_target, hardlink)

        writable = self.tmp / "authority-writable.json"
        writable.write_bytes(authority_bytes)
        writable.chmod(0o666)

        fifo = self.tmp / "authority-fifo.json"
        os.mkfifo(fifo, mode=0o600)

        shared = self.tmp / "shared"
        shared.mkdir(mode=0o700)
        shared_authority = shared / "authority.json"
        shared_authority.write_bytes(authority_bytes)
        shared_authority.chmod(0o644)
        shared.chmod(0o777)

        real_parent = self.tmp / "real-parent"
        real_parent.mkdir(mode=0o700)
        parent_authority = real_parent / "authority.json"
        parent_authority.write_bytes(authority_bytes)
        parent_authority.chmod(0o644)
        parent_symlink = self.tmp / "parent-symlink"
        parent_symlink.symlink_to(real_parent, target_is_directory=True)

        attacks = (
            symlink,
            hardlink,
            writable,
            fifo,
            shared_authority,
            parent_symlink / "authority.json",
        )
        for index, authority in enumerate(attacks):
            with self.subTest(authority=authority):
                destination = self.tmp / f"authority-attack-{index}"
                with self.assertRaises(ProvisioningError):
                    apply_package(
                        package,
                        authority,
                        self.material["bundles"]["alice"],
                        destination,
                        authorized_local_agent_ids=frozenset({"alice"}),
                        now_ms=NOW,
                    )
                self.assertFalse(destination.exists())

    def test_exact_reapply_revalidates_launcher_environment_contract(self):
        package = self.tmp / "package"
        self.build(package)
        launcher = load_launcher_module()
        self.assertEqual(CLIENT_ENVIRONMENT_KEYS, launcher.IDENTITY_KEYS)

        def installed(index):
            destination = self.tmp / f"environment-attack-{index}"
            receipt = apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )
            self.assertEqual(
                set(
                    launcher.load_client_environment(
                        destination / receipt["environment"]
                    )
                ),
                CLIENT_ENVIRONMENT_KEYS,
            )
            return destination, destination / receipt["environment"]

        attacks = []

        destination, environment = installed(0)
        environment.chmod(0o644)
        attacks.append((destination, environment))

        destination, environment = installed(1)
        original = environment.read_bytes()
        environment.unlink()
        target = destination / "linked-environment-target"
        target.write_bytes(original)
        target.chmod(0o600)
        environment.symlink_to(target)
        attacks.append((destination, environment))

        destination, environment = installed(2)
        os.link(environment, destination / "environment-hardlink")
        attacks.append((destination, environment))

        destination, environment = installed(3)
        environment.write_bytes(
            environment.read_bytes() + b'TRIBE_V1_REPO="/tmp/attacker"\n'
        )
        attacks.append((destination, environment))

        destination, environment = installed(4)
        environment.write_text(
            environment.read_text().replace(
                'TRIBE_CLIENT_ID="alice"',
                'TRIBE_CLIENT_ID="mallory"',
            )
        )
        attacks.append((destination, environment))

        for destination, environment in attacks:
            with self.subTest(environment=environment):
                before = environment.lstat()
                with self.assertRaises(ProvisioningError):
                    apply_package(
                        package,
                        self.public_authority,
                        self.material["bundles"]["alice"],
                        destination,
                        authorized_local_agent_ids=frozenset({"alice"}),
                        now_ms=NOW,
                    )
                after = environment.lstat()
                self.assertEqual(
                    (before.st_dev, before.st_ino, before.st_mode),
                    (after.st_dev, after.st_ino, after.st_mode),
                )
                self.assertFalse((destination / "provision-journal.json").exists())

    def test_tamper_wrong_keys_insecure_keys_and_root_change_fail_closed(self):
        package = self.tmp / "package"
        self.build(package)
        tampered = self.tmp / "tampered"
        shutil.copytree(package, tampered)
        directory = json.loads((tampered / "directory.json").read_text())
        directory["directory_epoch"] = 9
        (tampered / "directory.json").write_text(json.dumps(directory))
        with self.assertRaises(ProvisioningError):
            apply_package(
                tampered,
                self.public_authority,
                self.material["bundles"]["alice"],
                self.tmp / "tampered-client",
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )
        with self.assertRaises(Exception):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["worker@localhost"],
                self.tmp / "wrong-client",
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )
        bad_permissions = self.tmp / "bad-keys.json"
        bad_permissions.write_bytes(
            self.material["bundles"]["alice"].read_bytes()
        )
        os.chmod(bad_permissions, 0o644)
        with self.assertRaises(PermissionError):
            apply_package(
                package,
                self.public_authority,
                bad_permissions,
                self.tmp / "bad-mode-client",
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )

        destination = self.tmp / "root-client"
        apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["alice"],
            destination,
            authorized_local_agent_ids=frozenset({"alice"}),
            now_ms=NOW,
        )
        roots = json.loads((destination / "governance-roots.json").read_text())
        roots["keys"]["governance/root/1"] = "A" * 43
        (destination / "governance-roots.json").write_text(json.dumps(roots))
        with self.assertRaises(ProvisioningError):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["alice"],
                destination,
                authorized_local_agent_ids=frozenset({"alice"}),
                now_ms=NOW,
            )

    def test_localhost_requires_exact_harness_boundary_and_loopback(self):
        with self.assertRaises(ProvisioningError):
            self.build(
                self.tmp / "bad-package",
                agent_id="worker@localhost",
                routes={"alice": {"hub": "http://10.0.0.1:8685"}},
                endpoints=["http://127.0.0.1:8685"],
                local_ids=["worker@localhost"],
            )
        package = self.tmp / "local-package"
        self.build(
            package,
            agent_id="worker@localhost",
            routes={"worker@localhost": {"direct": "http://127.0.0.1:8685"}},
            endpoints=["http://localhost:8685"],
            local_ids=["worker@localhost"],
        )
        with self.assertRaises(ProvisioningError):
            apply_package(
                package,
                self.public_authority,
                self.material["bundles"]["worker@localhost"],
                self.tmp / "local-client",
                authorized_local_agent_ids=frozenset(),
                now_ms=NOW,
            )
        receipt = apply_package(
            package,
            self.public_authority,
            self.material["bundles"]["worker@localhost"],
            self.tmp / "local-client-ok",
            authorized_local_agent_ids=frozenset({"worker@localhost"}),
            now_ms=NOW,
        )
        self.assertEqual(receipt["agent_id"], "worker@localhost")


if __name__ == "__main__":
    unittest.main()
