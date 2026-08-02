import copy
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from tribe_crypto_v1 import (  # noqa: E402
    KeyBundle,
    b64url,
    decrypt_envelope,
    encrypt_envelope,
    membership_payload,
    weave_payload,
)
from tribe_directory_v1 import Directory  # noqa: E402
from tribe_membership_v1 import (  # noqa: E402
    MembershipError,
    MembershipSigner,
    MembershipState,
    acceptance,
    founder_acceptance,
    founder_transfer,
    invitation,
    membership_change,
    tribe_declaration,
    verify,
)
from v1_fixtures import NOW, make_material  # noqa: E402


class FoundedMembershipAndWeaveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.material = make_material(self.root / "identity")
        self.directory = Directory.load(
            self.material["directory_path"], self.material["roots_path"],
            self.material["state_path"], now_ms=NOW,
        )
        self.alice = KeyBundle.load(self.material["bundles"]["alice"])
        self.worker = KeyBundle.load(self.material["bundles"]["worker@localhost"])
        self.local = frozenset(self.directory.agents)

    def test_typed_weave_payload_uses_same_encrypted_transport(self):
        message = {"schema": "dm.we.heads/v1", "being_ref": "being:test", "heads": []}
        payload = weave_payload(sender="alice", to="worker@localhost", message=message)
        envelope = encrypt_envelope(
            payload, directory=self.directory, keys=self.alice,
            audience_type="direct", audience_id="worker@localhost",
            local_agent_ids=self.local, now_ms=NOW,
        )
        self.assertEqual(envelope["content_type"], "application/vnd.daimon.we+json")
        self.assertEqual(
            decrypt_envelope(envelope, directory=self.directory, keys=self.worker, now_ms=NOW),
            payload,
        )
        mismatch = copy.deepcopy(envelope)
        mismatch["content_type"] = "application/vnd.tribe.message+json"
        with self.assertRaises(Exception):
            decrypt_envelope(mismatch, directory=self.directory, keys=self.worker, now_ms=NOW)

    def test_founder_only_single_use_invitation_and_leave(self):
        founder = MembershipSigner("alice", "alice/sig", Ed25519PrivateKey.generate())
        member = MembershipSigner("worker@localhost", "worker/sig", Ed25519PrivateKey.generate())
        keys = {
            founder.kid: {"owner": founder.principal_id, "public_key": b64url(founder.private_key.public_key().public_bytes_raw())},
            member.kid: {"owner": member.principal_id, "public_key": b64url(member.private_key.public_key().public_bytes_raw())},
        }
        declaration = tribe_declaration(
            signer=founder, policy_ref="policy:one",
            nonce="n" * 43, created_at_ms=NOW,
        )
        verify(declaration, keys)
        invite = invitation(
            declaration, invitee_principal_id="worker@localhost", signer=founder,
            now_ms=NOW, expires_at_ms=NOW + 60_000,
        )
        accepted = acceptance(invite, signer=member, now_ms=NOW + 1)
        verify(invite, keys)
        verify(accepted, keys)
        state = MembershipState(declaration["tribe_ref"], "alice", keys)
        state.accept(invite, accepted)
        self.assertIn("worker@localhost", state.members)
        with self.assertRaisesRegex(MembershipError, "already used"):
            state.accept(invite, accepted)

        leave = membership_change(
            tribe_ref=state.tribe_ref, founder_epoch=1,
            member_principal_id="worker@localhost", action="leave",
            signer=member, occurred_at_ms=NOW + 2,
        )
        state.change(leave)
        self.assertNotIn("worker@localhost", state.members)

    def test_expulsion_and_dual_signed_founder_transfer(self):
        founder = MembershipSigner("alice", "alice/sig", Ed25519PrivateKey.generate())
        successor = MembershipSigner("worker@localhost", "worker/sig", Ed25519PrivateKey.generate())
        keys = {
            founder.kid: {"owner": founder.principal_id, "public_key": b64url(founder.private_key.public_key().public_bytes_raw())},
            successor.kid: {"owner": successor.principal_id, "public_key": b64url(successor.private_key.public_key().public_bytes_raw())},
        }
        state = MembershipState("tribe:" + "a" * 64, "alice", keys, members={"worker@localhost", "mirror"})
        expelled = membership_change(
            tribe_ref=state.tribe_ref, founder_epoch=1,
            member_principal_id="mirror", action="expel", signer=founder,
            occurred_at_ms=NOW,
        )
        state.change(expelled)
        self.assertNotIn("mirror", state.members)
        transfer = founder_transfer(
            tribe_ref=state.tribe_ref, founder_epoch=1,
            successor_principal_id="worker@localhost", signer=founder,
            occurred_at_ms=NOW + 1,
        )
        accepted = founder_acceptance(transfer, signer=successor, occurred_at_ms=NOW + 2)
        state.transfer(transfer, accepted)
        self.assertEqual(state.founder_principal_id, "worker@localhost")
        self.assertEqual(state.founder_epoch, 2)

    def test_membership_payload_is_typed(self):
        payload = membership_payload(
            sender="alice", to="worker@localhost",
            artifact={"schema": "tribe-invitation/v1"},
        )
        envelope = encrypt_envelope(
            payload, directory=self.directory, keys=self.alice,
            audience_type="direct", audience_id="worker@localhost",
            local_agent_ids=self.local, now_ms=NOW,
        )
        self.assertEqual(envelope["content_type"], "application/vnd.tribe.membership+json")
        self.assertEqual(decrypt_envelope(envelope, directory=self.directory, keys=self.worker, now_ms=NOW), payload)

    def test_membership_rejects_open_fields_and_wrong_invitee(self):
        founder = MembershipSigner("alice", "alice/sig", Ed25519PrivateKey.generate())
        invited = MembershipSigner("worker@localhost", "worker/sig", Ed25519PrivateKey.generate())
        other = MembershipSigner("other", "other/sig", Ed25519PrivateKey.generate())
        signers = (founder, invited, other)
        keys = {
            signer.kid: {
                "owner": signer.principal_id,
                "public_key": b64url(signer.private_key.public_key().public_bytes_raw()),
            }
            for signer in signers
        }
        declaration = tribe_declaration(
            signer=founder, policy_ref="policy:one", nonce="n" * 43,
            created_at_ms=NOW,
        )
        invite = invitation(
            declaration, invitee_principal_id=invited.principal_id,
            signer=founder, now_ms=NOW, expires_at_ms=NOW + 60_000,
        )
        opened = dict(invite)
        opened["unexpected"] = "authority"
        with self.assertRaisesRegex(MembershipError, "fields"):
            verify(opened, keys)

        wrong = other.sign({
            "schema": "tribe-acceptance/v1",
            "tribe_ref": invite["tribe_ref"],
            "founder_epoch": invite["founder_epoch"],
            "invite_id": invite["invite_id"],
            "invitation_hash": invite["artifact_hash"],
            "member_principal_id": other.principal_id,
            "accepted_at_ms": NOW + 1,
        })
        state = MembershipState(declaration["tribe_ref"], founder.principal_id, keys)
        with self.assertRaisesRegex(MembershipError, "does not match invitee"):
            state.accept(invite, wrong)


if __name__ == "__main__":
    unittest.main()
