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


def signed_successor(snapshot, now_ms):
    value = build_next_epoch(snapshot, now_ms=now_ms, validity_days=30)
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
