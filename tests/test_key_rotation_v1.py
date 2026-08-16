import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from tribe_crypto_v1 import (
    KeyBundle,
    decrypt_envelope,
    encrypt_envelope,
    message_payload,
)
from tribe_directory_v1 import Directory, directory_preimage
from tribe_rotation_v1 import (
    RotationError,
    activate_staged_bundle,
    build_forward_recovery,
    compose_rotation,
    prepare_rotation,
    verify_announcement,
)
from v1_fixtures import NOW, b64url, make_material, signing_key


HOUR = 60 * 60 * 1000


def sign_directory(snapshot):
    value = copy.deepcopy(snapshot)
    value["governance"]["signatures"] = []
    value["governance"]["signatures"] = [
        {
            "kid": "governance/root/1",
            "alg": "Ed25519",
            "value": b64url(signing_key(1).sign(directory_preimage(value))),
        }
    ]
    return value


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tribe-rotation-test-"))
        self.material = make_material(self.tmp / "base")
        self.directory = Directory.load(
            self.material["directory_path"],
            self.material["roots_path"],
            self.material["state_path"],
            now_ms=NOW,
        )
        self.activation = NOW + HOUR
        self.expiry = NOW + HOUR // 2
        self.announcements = []
        self.staged = {}
        for agent_id, path in self.material["bundles"].items():
            staged = self.tmp / "holders" / agent_id.replace("@", "_") / "next.json"
            announcement = prepare_rotation(
                self.directory,
                self.material["roots"],
                path,
                staged,
                ceremony_id="synthetic-rotation-1",
                activation_at_ms=self.activation,
                expires_at_ms=self.expiry,
                now_ms=NOW,
            )
            self.announcements.append(announcement)
            self.staged[agent_id] = staged

    def compose(self):
        return compose_rotation(
            self.material["snapshot"],
            self.material["roots"],
            self.announcements,
            now_ms=NOW,
            ceremony_id="synthetic-rotation-1",
            activation_at_ms=self.activation,
        )

    def test_independent_prepare_and_keyless_deterministic_compose(self):
        private_blobs = [path.read_bytes() for path in self.staged.values()]
        self.assertEqual(len(private_blobs), len(set(private_blobs)))
        public = json.dumps(self.announcements, sort_keys=True)
        for private in private_blobs:
            staged = json.loads(private)
            self.assertNotIn(staged["signing"]["private_key"], public)
            for key in staged["encryption"]:
                self.assertNotIn(key["private_key"], public)

        candidate, receipt = self.compose()
        second, second_receipt = self.compose()
        self.assertEqual(candidate, second)
        self.assertEqual(receipt, second_receipt)
        self.assertEqual(candidate["directory_epoch"], 2)
        self.assertEqual(receipt["agent_ids"], sorted(self.material["agents"]))
        self.assertFalse(receipt["contains_private_material"])
        self.assertEqual(
            len([a for a in candidate["audiences"] if a["status"] == "active"]),
            len(self.material["snapshot"]["audiences"]),
        )
        self.assertTrue(
            all(
                key["not_before_ms"] == self.activation
                for agent in candidate["agents"]
                for purpose in ("signing_keys", "encryption_keys")
                for key in agent[purpose]
                if key["epoch"] == 2
            )
        )

    def test_forged_stale_wrong_base_partial_and_replay_fail_closed(self):
        forged = copy.deepcopy(self.announcements[0])
        forged["next_signing"]["public_key"] = b64url(
            ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        )
        with self.assertRaises(RotationError):
            verify_announcement(
                self.material["snapshot"],
                self.material["roots"],
                forged,
                now_ms=NOW,
                ceremony_id="synthetic-rotation-1",
                activation_at_ms=self.activation,
            )
        with self.assertRaises(RotationError):
            compose_rotation(
                self.material["snapshot"],
                self.material["roots"],
                self.announcements[:-1],
                now_ms=NOW,
                ceremony_id="synthetic-rotation-1",
                activation_at_ms=self.activation,
            )
        with self.assertRaises(RotationError):
            compose_rotation(
                self.material["snapshot"],
                self.material["roots"],
                self.announcements + [self.announcements[0]],
                now_ms=NOW,
                ceremony_id="synthetic-rotation-1",
                activation_at_ms=self.activation,
            )
        with self.assertRaises(RotationError):
            verify_announcement(
                self.material["snapshot"],
                self.material["roots"],
                self.announcements[0],
                now_ms=self.expiry,
                ceremony_id="synthetic-rotation-1",
                activation_at_ms=self.activation,
            )
        wrong_base = copy.deepcopy(self.material["snapshot"])
        wrong_base["directory_epoch"] = 2
        with self.assertRaises(RotationError):
            verify_announcement(
                wrong_base,
                self.material["roots"],
                self.announcements[0],
                now_ms=NOW,
                ceremony_id="synthetic-rotation-1",
                activation_at_ms=self.activation,
            )

    def test_activation_retains_old_ciphertext_and_is_idempotent(self):
        old_sender = KeyBundle.load(self.material["bundles"]["alice"])
        queued = encrypt_envelope(
            message_payload(
                sender="alice", to="worker@localhost", text="queued"
            ),
            directory=self.directory,
            keys=old_sender,
            audience_type="direct",
            audience_id="worker@localhost",
            local_agent_ids=frozenset(),
            now_ms=NOW,
            ttl_ms=2 * HOUR,
        )
        candidate, _ = self.compose()
        signed = sign_directory(candidate)
        candidate_path = self.tmp / "directory-2.json"
        candidate_path.write_text(json.dumps(signed))
        directory2 = Directory.load(
            candidate_path,
            self.material["roots_path"],
            self.material["state_path"],
            now_ms=self.activation + 1,
        )
        current = self.material["bundles"]["worker@localhost"]
        result = activate_staged_bundle(
            current,
            self.staged["worker@localhost"],
            directory2,
            now_ms=self.activation + 1,
        )
        self.assertTrue(result["activated"])
        activated = KeyBundle.load(current)
        self.assertEqual(activated.signing_kid, "worker@localhost/sig/2")
        self.assertIn("worker@localhost/enc/1", activated.encryption_private)
        self.assertIn("worker@localhost/enc/2", activated.encryption_private)
        self.assertEqual(
            decrypt_envelope(
                queued,
                directory=directory2,
                keys=activated,
                now_ms=self.activation + 1,
            )["text"],
            "queued",
        )
        retry = activate_staged_bundle(
            current,
            self.staged["worker@localhost"],
            directory2,
            now_ms=self.activation + 1,
        )
        self.assertFalse(retry["activated"])
        self.assertEqual(retry["reason"], "already-current")

    def test_activation_rejects_dropped_old_encryption_key(self):
        candidate, _ = self.compose()
        signed = sign_directory(candidate)
        candidate_path = self.tmp / "directory-2.json"
        candidate_path.write_text(json.dumps(signed))
        directory2 = Directory.load(
            candidate_path,
            self.material["roots_path"],
            self.material["state_path"],
            now_ms=self.activation + 1,
        )
        staged = self.staged["alice"]
        value = json.loads(staged.read_text())
        value["encryption"] = [value["encryption"][-1]]
        bad = self.tmp / "bad-stage.json"
        bad.write_text(json.dumps(value))
        os.chmod(bad, 0o600)
        with self.assertRaises(RotationError):
            activate_staged_bundle(
                self.material["bundles"]["alice"],
                bad,
                directory2,
                now_ms=self.activation + 1,
            )

    def test_forward_recovery_advances_and_refuses_to_strand_agent(self):
        candidate, _ = self.compose()
        signed = sign_directory(candidate)
        recovered = build_forward_recovery(
            signed,
            self.material["roots"],
            {"alice/sig/2", "alice/enc/2"},
            now_ms=self.activation + 1,
        )
        self.assertEqual(recovered["directory_epoch"], 3)
        self.assertEqual(recovered["previous_sha256"], Directory(signed).hash)
        alice = next(a for a in recovered["agents"] if a["id"] == "alice")
        self.assertEqual(alice["signing_keys"][-1]["status"], "revoked")
        with self.assertRaises(RotationError):
            build_forward_recovery(
                signed,
                self.material["roots"],
                {"alice/sig/1", "alice/sig/2"},
                now_ms=self.activation + 1,
            )


if __name__ == "__main__":
    unittest.main()
