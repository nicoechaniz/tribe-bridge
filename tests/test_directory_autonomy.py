import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import tribe_directory_admin_v1 as admin  # noqa: E402
from tribe_directory_v1 import Directory, directory_sha256  # noqa: E402
from v1_fixtures import NOW, b64url, make_material, signing_key  # noqa: E402


def governance_private_file(root: Path, mode=0o600) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "governance-root.json"
    path.write_text(
        json.dumps(
            {
                "schema": "tribe-governance-private/v1",
                "kid": "governance/root/1",
                "private_key": b64url(signing_key(1).private_bytes_raw()),
            }
        )
    )
    os.chmod(path, mode)
    return path


class DirectoryAdminTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dir-admin-test-"))
        material = make_material(self.tmp)
        self.material = material
        # admin module expects the canonical filenames inside a v1 dir
        self.v1 = self.tmp / "v1"
        self.v1.mkdir(exist_ok=True)
        (self.v1 / "directory.json").write_bytes(
            (self.tmp / "directory.json").read_bytes()
        )
        (self.v1 / "governance-roots.json").write_bytes(
            (self.tmp / "roots.json").read_bytes()
        )
        self.state = self.v1 / "agent-directory-state.json"
        # seed the state by loading the epoch-1 directory inside its validity
        Directory.load(
            self.v1 / "directory.json",
            self.v1 / "governance-roots.json",
            self.state,
            now_ms=NOW,
        )
        self.key_path = governance_private_file(self.tmp)


class BuildNextEpochTests(DirectoryAdminTestBase):
    def test_pure_validity_renewal(self):
        current = json.loads((self.v1 / "directory.json").read_text())
        nxt = admin.build_next_epoch(current, now_ms=NOW, validity_days=30)
        self.assertEqual(nxt["directory_epoch"], 2)
        self.assertEqual(nxt["previous_sha256"], directory_sha256(current))
        self.assertEqual(nxt["issued_at_ms"], NOW)
        self.assertEqual(nxt["expires_at_ms"], NOW + 30 * admin.MS_PER_DAY)
        self.assertEqual(nxt["agents"], current["agents"])
        self.assertEqual(nxt["audiences"], current["audiences"])
        self.assertEqual(nxt["governance"]["signatures"], [])


class RenewalTests(DirectoryAdminTestBase):
    def test_within_window_is_noop(self):
        summary = admin.renew_synthetic_single_holder_directory(
            self.v1, self.key_path, now_ms=NOW, window_days=1
        )
        self.assertFalse(summary["renewed"])
        self.assertEqual(summary["reason"], "within-validity-window")

    def test_renewal_installs_and_advances(self):
        summary = admin.renew_synthetic_single_holder_directory(
            self.v1, self.key_path, now_ms=NOW, window_days=10
        )
        self.assertTrue(summary["renewed"])
        self.assertEqual(summary["next_epoch"], 2)
        installed = json.loads((self.v1 / "directory.json").read_text())
        self.assertEqual(installed["directory_epoch"], 2)
        self.assertTrue((self.v1 / "directory.json.bak-epoch1").exists())
        # the real client state now advances 1 -> 2 on load
        directory = Directory.load(
            self.v1 / "directory.json",
            self.v1 / "governance-roots.json",
            self.state,
            now_ms=NOW,
        )
        self.assertEqual(directory.epoch, 2)

    def test_dry_run_installs_nothing(self):
        before = (self.v1 / "directory.json").read_bytes()
        summary = admin.renew_synthetic_single_holder_directory(
            self.v1, self.key_path, now_ms=NOW, window_days=10, dry_run=True
        )
        self.assertFalse(summary["renewed"])
        self.assertEqual((self.v1 / "directory.json").read_bytes(), before)

    def test_governance_key_must_be_0600(self):
        lax = governance_private_file(self.tmp / "lax", mode=0o644)
        with self.assertRaises(admin.RenewalError):
            admin.renew_synthetic_single_holder_directory(
                self.v1, lax, now_ms=NOW, window_days=10
            )


class ClientUpdateTests(DirectoryAdminTestBase):
    def _publish_epoch2(self) -> Path:
        current = json.loads((self.v1 / "directory.json").read_text())
        nxt = admin.build_next_epoch(current, now_ms=NOW, validity_days=30)
        key = admin.load_governance_private_key(self.key_path)
        admin.sign_snapshot(nxt, key)
        published = self.tmp / "published.json"
        published.write_bytes(admin.serialize_signed(nxt))
        return published

    def test_update_installs_newer_epoch_then_noop(self):
        published = self._publish_epoch2()
        url = published.as_uri()
        result = admin.update_client_directory(
            url,
            directory_path=self.v1 / "directory.json",
            roots_path=self.v1 / "governance-roots.json",
            state_path=self.state,
            now_ms=NOW,
        )
        self.assertTrue(result["updated"])
        self.assertEqual(result["epoch"], 2)
        again = admin.update_client_directory(
            url,
            directory_path=self.v1 / "directory.json",
            roots_path=self.v1 / "governance-roots.json",
            state_path=self.state,
            now_ms=NOW,
        )
        self.assertFalse(again["updated"])
        self.assertEqual(again["reason"], "already-current")

    def test_update_rejects_bad_signature(self):
        published = self._publish_epoch2()
        tampered = json.loads(published.read_text())
        tampered["expires_at_ms"] = NOW + 31 * admin.MS_PER_DAY  # invalidates the sig
        published.write_text(json.dumps(tampered))
        before = (self.v1 / "directory.json").read_bytes()
        with self.assertRaises(Exception):
            admin.update_client_directory(
                published.as_uri(),
                directory_path=self.v1 / "directory.json",
                roots_path=self.v1 / "governance-roots.json",
                state_path=self.state,
                now_ms=NOW,
            )
        self.assertEqual((self.v1 / "directory.json").read_bytes(), before)

    def test_update_rejects_expired_directory(self):
        current = json.loads((self.v1 / "directory.json").read_text())
        nxt = admin.build_next_epoch(current, now_ms=NOW, validity_days=30)
        nxt["expires_at_ms"] = NOW - 1  # already expired
        key = admin.load_governance_private_key(self.key_path)
        nxt["governance"]["signatures"] = []
        admin.sign_snapshot(nxt, key)
        published = self.tmp / "expired.json"
        published.write_bytes(admin.serialize_signed(nxt))
        with self.assertRaises(Exception):
            admin.update_client_directory(
                published.as_uri(),
                directory_path=self.v1 / "directory.json",
                roots_path=self.v1 / "governance-roots.json",
                state_path=self.state,
                now_ms=NOW,
            )


if __name__ == "__main__":
    unittest.main()
