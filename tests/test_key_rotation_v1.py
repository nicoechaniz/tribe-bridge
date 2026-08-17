import copy
import json
import os
import subprocess
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
    uuid7,
)
from tribe_directory_v1 import (
    Directory,
    DirectoryError,
    directory_preimage,
    validate_directory,
    validate_unsigned_directory_candidate,
)
import tribe_protocol_v1 as protocol
from tribe_broker_v1 import ClockRollback, SQLiteBroker
from tribe_rotation_v1 import (
    RotationError,
    activate_staged_bundle,
    announcement_preimage,
    build_forward_recovery,
    compose_rotation,
    prepare_rotation,
    verify_announcement,
)
from tribe_transport_v1 import auth_preimage, validate_request, wrap_request
from tribe_service_v1 import TribeV1Service
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
        later, later_receipt = compose_rotation(
            self.material["snapshot"],
            self.material["roots"],
            list(reversed(self.announcements)),
            now_ms=NOW + 1,
            ceremony_id="synthetic-rotation-1",
            activation_at_ms=self.activation,
        )
        self.assertEqual(candidate, later)
        self.assertEqual(receipt, later_receipt)
        self.assertEqual(len(receipt["ceremony_sha256"]), 64)

        snapshot_path = self.tmp / "restart-snapshot.json"
        roots_path = self.tmp / "restart-roots.json"
        announcements_path = self.tmp / "restart-announcements.json"
        snapshot_path.write_text(json.dumps(self.material["snapshot"]))
        roots_path.write_text(json.dumps(self.material["roots"]))
        announcements_path.write_text(json.dumps(self.announcements))
        restart = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import json,sys;"
                    f"sys.path.insert(0,{str(ROOT / 'src')!r});"
                    "from tribe_rotation_v1 import compose_rotation;"
                    "snapshot=json.load(open(sys.argv[1]));"
                    "roots=json.load(open(sys.argv[2]));"
                    "announcements=json.load(open(sys.argv[3]));"
                    "result=compose_rotation(snapshot,roots,announcements,"
                    "now_ms=int(sys.argv[4]),ceremony_id=sys.argv[5],"
                    "activation_at_ms=int(sys.argv[6]));"
                    "print(json.dumps(result,sort_keys=True,separators=(',',':')))"
                ),
                str(snapshot_path),
                str(roots_path),
                str(announcements_path),
                str(NOW + 1),
                "synthetic-rotation-1",
                str(self.activation),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(json.loads(restart.stdout), [candidate, receipt])

        validate_unsigned_directory_candidate(
            candidate, self.material["roots"], now_ms=NOW + 1
        )
        validate_directory(
            sign_directory(candidate),
            self.material["roots"],
            now_ms=NOW + 1,
        )
        self.assertEqual(candidate["directory_epoch"], 2)
        self.assertEqual(receipt["agent_ids"], sorted(self.material["agents"]))
        self.assertFalse(receipt["contains_private_material"])
        self.assertEqual(
            candidate["audiences"], self.material["snapshot"]["audiences"]
        )
        self.assertEqual(receipt["audience_successors"], 0)
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
        for agent in candidate["agents"]:
            for purpose in ("signing_keys", "encryption_keys"):
                previous = next(
                    key for key in agent[purpose] if key["epoch"] == 1
                )
                self.assertEqual(
                    previous["not_after_ms"], self.activation
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
        invalid_window = copy.deepcopy(self.announcements[0])
        invalid_window["issued_at_ms"] = invalid_window["expires_at_ms"]
        with self.assertRaises(RotationError):
            verify_announcement(
                self.material["snapshot"],
                self.material["roots"],
                invalid_window,
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

    def test_successor_kid_collision_is_global_across_key_purposes(self):
        colliding = copy.deepcopy(self.material["snapshot"])
        alice = next(
            agent for agent in colliding["agents"] if agent["id"] == "alice"
        )
        alice["encryption_keys"][0]["kid"] = "alice/sig/2"
        colliding = sign_directory(colliding)
        validate_directory(
            colliding, self.material["roots"], now_ms=NOW
        )
        directory = Directory(colliding)

        announcements = copy.deepcopy(self.announcements)
        for announcement in announcements:
            announcement["base_directory_sha256"] = directory.hash
            if announcement["agent_id"] == "alice":
                announcement["previous_encryption_kid"] = "alice/sig/2"
            bundle = KeyBundle.load(
                self.material["bundles"][announcement["agent_id"]]
            )
            announcement["signature"] = b64url(
                bundle.signing_private.sign(
                    announcement_preimage(announcement)
                )
            )

        with self.assertRaisesRegex(
            RotationError, "colliding successor key"
        ):
            compose_rotation(
                colliding,
                self.material["roots"],
                announcements,
                now_ms=NOW,
                ceremony_id="synthetic-rotation-1",
                activation_at_ms=self.activation,
            )

    def test_activation_never_extends_a_previous_key_expiry(self):
        late_activation = NOW + 11 * 86_400_000
        announcements = []
        for agent_id, path in self.material["bundles"].items():
            announcements.append(
                prepare_rotation(
                    self.directory,
                    self.material["roots"],
                    path,
                    self.tmp / f"late-{agent_id.replace('@', '_')}.json",
                    ceremony_id="synthetic-late-rotation",
                    activation_at_ms=late_activation,
                    expires_at_ms=NOW + HOUR,
                    now_ms=NOW,
                )
            )
        with self.assertRaisesRegex(
            RotationError, "activation exceeds a previous key expiry"
        ):
            compose_rotation(
                self.material["snapshot"],
                self.material["roots"],
                announcements,
                now_ms=NOW,
                ceremony_id="synthetic-late-rotation",
                activation_at_ms=late_activation,
            )

        exact_expiry = NOW + 10 * 86_400_000
        exact_announcements = []
        for agent_id, path in self.material["bundles"].items():
            exact_announcements.append(
                prepare_rotation(
                    self.directory,
                    self.material["roots"],
                    path,
                    self.tmp / f"exact-{agent_id.replace('@', '_')}.json",
                    ceremony_id="synthetic-exact-expiry-rotation",
                    activation_at_ms=exact_expiry,
                    expires_at_ms=NOW + HOUR,
                    now_ms=NOW,
                )
            )
        candidate, _ = compose_rotation(
            self.material["snapshot"],
            self.material["roots"],
            exact_announcements,
            now_ms=NOW,
            ceremony_id="synthetic-exact-expiry-rotation",
            activation_at_ms=exact_expiry,
        )
        for agent in candidate["agents"]:
            for purpose in ("signing_keys", "encryption_keys"):
                previous = next(
                    key for key in agent[purpose] if key["epoch"] == 1
                )
                self.assertEqual(previous["not_after_ms"], exact_expiry)

    def test_preloaded_rotation_preserves_current_audience_epoch(self):
        candidate, receipt = self.compose()
        directory2 = Directory(sign_directory(candidate))
        original_audiences = copy.deepcopy(
            self.material["snapshot"]["audiences"]
        )

        self.assertEqual(candidate["audiences"], original_audiences)
        self.assertEqual(receipt["audience_successors"], 0)
        pre_cut = encrypt_envelope(
            message_payload(
                sender="alice", to="worker@localhost", text="pre-cut"
            ),
            directory=directory2,
            keys=KeyBundle.load(self.material["bundles"]["alice"]),
            audience_type="direct",
            audience_id="worker@localhost",
            local_agent_ids=frozenset(),
            now_ms=self.activation - 1,
            ttl_ms=HOUR,
        )
        expected = next(
            audience
            for audience in original_audiences
            if audience["type"] == "direct"
            and audience["id"] == "worker@localhost"
        )
        self.assertEqual(pre_cut["audience"]["epoch"], expected["epoch"])
        self.assertEqual(expected["status"], "active")

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
        post_cut = copy.deepcopy(queued)
        post_cut["issued_at_ms"] = self.activation + 1
        post_cut["expires_at_ms"] = self.activation + HOUR
        post_cut["message_id"] = uuid7(self.activation + 1)
        post_cut["signature"]["value"] = b64url(
            old_sender.signing_private.sign(
                protocol.signature_preimage(post_cut)
            )
        )
        with self.assertRaisesRegex(
            protocol.ProtocolError, "key_not_valid"
        ):
            decrypt_envelope(
                post_cut,
                directory=directory2,
                keys=activated,
                now_ms=self.activation + 1,
            )
        retry = activate_staged_bundle(
            current,
            self.staged["worker@localhost"],
            directory2,
            now_ms=self.activation + 1,
        )
        self.assertFalse(retry["activated"])
        self.assertEqual(retry["reason"], "already-current")
        with self.assertRaises(DirectoryError):
            activate_staged_bundle(
                current,
                self.staged["worker@localhost"],
                directory2,
                now_ms=NOW,
            )

    def test_broker_and_http_reject_backdated_old_keys_after_cut(self):
        candidate, _ = self.compose()
        directory2 = Directory(sign_directory(candidate))
        old_sender = KeyBundle.load(self.material["bundles"]["alice"])
        forged_after_cut = encrypt_envelope(
            message_payload(
                sender="alice",
                to="worker@localhost",
                text="post-cut but backdated",
            ),
            directory=directory2,
            keys=old_sender,
            audience_type="direct",
            audience_id="worker@localhost",
            local_agent_ids=frozenset(),
            now_ms=self.activation - 1,
            ttl_ms=HOUR,
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "key_not_valid"):
            protocol.validate_broker_admission(
                forged_after_cut,
                directory2.context(
                    sender_id="alice", now_ms=self.activation + 1
                ),
            )

        wrapped = wrap_request(
            forged_after_cut,
            keys=old_sender,
            method="POST",
            path="/v1/messages",
            now_ms=self.activation - 1,
        )
        with self.assertRaisesRegex(
            protocol.ProtocolError, "unauthorized_sender"
        ):
            validate_request(
                wrapped,
                directory=directory2,
                method="POST",
                path="/v1/messages",
                now_ms=self.activation + 1,
            )

        inverted = wrap_request(
            {},
            keys=old_sender,
            method="POST",
            path="/v1/claims",
            now_ms=NOW + 60_000,
        )
        inverted["auth"]["expires_at_ms"] = NOW + 30_000
        inverted["auth"]["signature"]["value"] = b64url(
            old_sender.signing_private.sign(
                auth_preimage(inverted["auth"])
            )
        )
        with self.assertRaisesRegex(
            protocol.ProtocolError, "expired_request"
        ):
            validate_request(
                inverted,
                directory=self.directory,
                method="POST",
                path="/v1/claims",
                now_ms=NOW,
            )

    def test_service_durable_time_rejects_old_key_after_clock_rollback(self):
        candidate, _ = self.compose()
        directory2 = Directory(sign_directory(candidate))
        current = self.material["bundles"]["alice"]
        activate_staged_bundle(
            current,
            self.staged["alice"],
            directory2,
            now_ms=self.activation + 1,
        )
        next_sender = KeyBundle.load(current)
        old_sender = KeyBundle.load(
            next(
                path
                for path in self.tmp.glob("base/alice.keys.json.pre-*")
            )
        )
        body = {"recipient_id": "alice", "limit": 1, "lease_ms": 1_000}
        post_cut = wrap_request(
            body,
            keys=next_sender,
            method="POST",
            path="/v1/claims",
            now_ms=self.activation + 1,
        )
        backdated = wrap_request(
            body,
            keys=old_sender,
            method="POST",
            path="/v1/claims",
            now_ms=self.activation - 1,
        )

        # This is the exact stateless regression: D+1 accepts the old key when
        # the caller supplies a rolled-back receive time.
        validate_request(
            backdated,
            directory=directory2,
            method="POST",
            path="/v1/claims",
            now_ms=self.activation - 1,
        )

        class Clock:
            value = self.activation + 1

            def __call__(clock_self):
                return clock_self.value

        clock = Clock()
        service = TribeV1Service(
            SQLiteBroker(self.tmp / "trusted-time.sqlite"),
            directory2,
            build_commit="a" * 40,
            local_agent_ids=frozenset(self.material["agents"]),
            clock_ms=clock,
        )
        self.assertEqual(service.post("/v1/claims", post_cut)[0], 200)
        clock.value = self.activation - 1
        with self.assertRaises(ClockRollback):
            service.post("/v1/claims", backdated)

        # The high-water is durable across service/broker restart.
        restarted = TribeV1Service(
            SQLiteBroker(self.tmp / "trusted-time.sqlite"),
            directory2,
            build_commit="a" * 40,
            local_agent_ids=frozenset(self.material["agents"]),
            clock_ms=clock,
        )
        with self.assertRaises(ClockRollback):
            restarted.post("/v1/claims", backdated)

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

        value = json.loads(staged.read_text())
        value["encryption"] = [value["encryption"][0]]
        missing_successor = self.tmp / "missing-successor-stage.json"
        missing_successor.write_text(json.dumps(value))
        os.chmod(missing_successor, 0o600)
        with self.assertRaisesRegex(
            DirectoryError, "missing the latest encryption key"
        ):
            activate_staged_bundle(
                self.material["bundles"]["alice"],
                missing_successor,
                directory2,
                now_ms=self.activation + 1,
            )

    def test_activation_rejects_symlink_and_current_path_swap(self):
        candidate, _ = self.compose()
        signed = sign_directory(candidate)
        directory2 = Directory(signed)
        current = self.material["bundles"]["alice"]
        staged = self.staged["alice"]
        staged_link = self.tmp / "staged-link.json"
        staged_link.symlink_to(staged)
        with self.assertRaises((OSError, RotationError)):
            activate_staged_bundle(
                current,
                staged_link,
                directory2,
                now_ms=self.activation + 1,
            )

        replacement = self.tmp / "replacement.json"
        replacement.write_bytes(current.read_bytes())
        os.chmod(replacement, 0o600)

        def swap(_phase):
            current.unlink()
            current.symlink_to(replacement)

        with self.assertRaisesRegex(
            RotationError, "changed during activation"
        ):
            activate_staged_bundle(
                current,
                staged,
                directory2,
                now_ms=self.activation + 1,
                fault_hook=swap,
            )

    def test_forward_recovery_advances_and_refuses_to_strand_agent(self):
        candidate, _ = self.compose()
        signed = sign_directory(candidate)
        recovered = build_forward_recovery(
            signed,
            self.material["roots"],
            {"alice/sig/1", "alice/enc/1"},
            now_ms=self.activation + 1,
        )
        self.assertEqual(recovered["directory_epoch"], 3)
        self.assertEqual(recovered["previous_sha256"], Directory(signed).hash)
        alice = next(a for a in recovered["agents"] if a["id"] == "alice")
        self.assertEqual(alice["signing_keys"][0]["status"], "revoked")
        self.assertLessEqual(
            recovered["expires_at_ms"], signed["expires_at_ms"]
        )
        for agent in recovered["agents"]:
            for purpose in ("signing_keys", "encryption_keys"):
                self.assertTrue(
                    any(
                        key["status"] == "active"
                        and key["not_before_ms"] <= recovered["issued_at_ms"]
                        and (
                            key["not_after_ms"] is None
                            or recovered["expires_at_ms"]
                            <= key["not_after_ms"]
                        )
                        for key in agent[purpose]
                    )
                )
        with self.assertRaisesRegex(
            RotationError, "requires a pre-existing uncompromised successor"
        ):
            build_forward_recovery(
                signed,
                self.material["roots"],
                {"alice/sig/2", "alice/enc/2"},
                now_ms=self.activation + 1,
            )


if __name__ == "__main__":
    unittest.main()
