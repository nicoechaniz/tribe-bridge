#!/usr/bin/env python3
"""Regenerate Tribe v1 conformance vectors with public test-only keys.

HPKE encapsulations are randomized, so reruns are semantically reproducible
but intentionally not byte-for-byte identical.
"""

from __future__ import annotations

import base64
import copy
import json
import sys
import uuid
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import tribe_protocol_v1 as protocol  # noqa: E402


ISSUED = 1_735_689_600_000
EXPIRES = ISSUED + 3_600_000
PRIVATE_SEED = bytes(range(1, 33))
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(PRIVATE_SEED)
RECIPIENT_PRIVATE_KEYS = {
    "worker@localhost": x25519.X25519PrivateKey.from_private_bytes(
        bytes(range(33, 65))
    ),
    "peer": x25519.X25519PrivateKey.from_private_bytes(bytes(range(65, 97))),
}
DIRECT_CEK = sha256(b"tribe-v1-test-direct-cek").digest()
GROUP_CEK = sha256(b"tribe-v1-test-group-cek").digest()
DIRECT_NONCE = bytes(range(12))
GROUP_NONCE = bytes(range(12, 24))
DIRECT_PLAINTEXT = b'{"kind":"message","text":"hola v1"}'
GROUP_PLAINTEXT = b'{"kind":"message","text":"hola test-group v1"}'
HPKE_SUITE = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def uuid7(timestamp_ms: int, random_bits: int) -> str:
    value = (timestamp_ms & ((1 << 48) - 1)) << 80
    value |= 7 << 76
    value |= (random_bits >> 62) << 64
    value |= 0b10 << 62
    value |= random_bits & ((1 << 62) - 1)
    return str(uuid.UUID(int=value))


def unsigned_base(
    random_bits: int = 0x123456789ABCDEF0123,
    nonce: bytes = DIRECT_NONCE,
) -> dict:
    return {
        "protocol": "tribe",
        "version": 1,
        "message_id": uuid7(ISSUED, random_bits),
        "issued_at_ms": ISSUED,
        "expires_at_ms": EXPIRES,
        "sender": {
            "id": "sender",
            "signing_kid": "sender/sig/7",
        },
        "audience": {
            "type": "direct",
            "id": "worker@localhost",
            "epoch": 4,
        },
        "content_type": "application/vnd.tribe.message+json",
        "suite": protocol.SUITE,
        "payload": {
            "nonce": b64url(nonce),
            "ciphertext": "",
        },
        "recipients": [
            {
                "id": "worker@localhost",
                "encryption_kid": "worker@localhost/enc/4",
                "enc": "",
                "wrapped_cek": "",
            }
        ],
    }


def encrypt(unsigned: dict, plaintext: bytes, cek: bytes) -> dict:
    envelope = copy.deepcopy(unsigned)
    nonce = decode_b64url(envelope["payload"]["nonce"])
    envelope["payload"]["ciphertext"] = b64url(
        ChaCha20Poly1305(cek).encrypt(
            nonce,
            plaintext,
            protocol.payload_aad(envelope),
        )
    )
    for recipient in envelope["recipients"]:
        private_key = RECIPIENT_PRIVATE_KEYS[recipient["id"]]
        hpke_output = HPKE_SUITE.encrypt(
            cek,
            private_key.public_key(),
            info=protocol.recipient_hpke_context(envelope, recipient),
        )
        recipient["enc"] = b64url(hpke_output[:32])
        recipient["wrapped_cek"] = b64url(hpke_output[32:])
    return envelope


def sign(unsigned: dict) -> dict:
    envelope = copy.deepcopy(unsigned)
    envelope["signature"] = {
        "alg": "Ed25519",
        "kid": unsigned["sender"]["signing_kid"],
        "value": "",
    }
    signature = PRIVATE_KEY.sign(protocol.signature_preimage(envelope))
    envelope["signature"]["value"] = b64url(signature)
    return envelope


def base_context(public_key: str) -> dict:
    return {
        "now_ms": ISSUED + 60_000,
        "receiver_id": "worker@localhost",
        "seen": [],
        "authorized_audiences": ["direct:worker@localhost:4"],
        "receiver_audiences": ["direct:worker@localhost:4"],
        "audience_members": {
            "direct:worker@localhost:4": ["worker@localhost"]
        },
        "signing_keys": {
            "sender/sig/7": {
                "owner": "sender",
                "status": "active",
                "not_before_ms": ISSUED - 86_400_000,
                "not_after_ms": EXPIRES + 86_400_000,
                "public_key": public_key,
            }
        },
        "encryption_keys": {
            "worker@localhost/enc/4": {
                "owner": "worker@localhost",
                "status": "active",
            }
        },
    }


def case(
    case_id: str,
    envelope: dict,
    context: dict,
    broker: str,
    endpoint: str,
    expected_plaintext: str | None = None,
) -> dict:
    value = {
        "id": case_id,
        "envelope": envelope,
        "context": context,
        "expected": {"broker": broker, "endpoint": endpoint},
    }
    if expected_plaintext is not None:
        value["expected_plaintext"] = expected_plaintext
    return value


def build() -> dict:
    public_key = b64url(PRIVATE_KEY.public_key().public_bytes_raw())
    valid = sign(encrypt(unsigned_base(), DIRECT_PLAINTEXT, DIRECT_CEK))
    context = base_context(public_key)
    replay_key = f'sender:{valid["message_id"]}'

    group_unsigned = unsigned_base(
        0x223456789ABCDEF0123,
        GROUP_NONCE,
    )
    group_unsigned["audience"] = {
        "type": "group",
        "id": "test-group",
        "epoch": 9,
    }
    group_unsigned["recipients"].append(
        {
            "id": "peer",
            "encryption_kid": "peer/enc/3",
            "enc": "",
            "wrapped_cek": "",
        }
    )
    group = sign(encrypt(group_unsigned, GROUP_PLAINTEXT, GROUP_CEK))
    group_context = base_context(public_key)
    group_context["authorized_audiences"] = ["group:test-group:9"]
    group_context["receiver_audiences"] = ["group:test-group:9"]
    group_context["audience_members"] = {
        "group:test-group:9": ["worker@localhost", "peer"]
    }
    group_context["encryption_keys"]["peer/enc/3"] = {
        "owner": "peer",
        "status": "active",
    }
    missing_group_member_unsigned = copy.deepcopy(group)
    missing_group_member_unsigned["recipients"] = [
        missing_group_member_unsigned["recipients"][0]
    ]
    del missing_group_member_unsigned["signature"]
    missing_group_member = sign(missing_group_member_unsigned)

    tampered = copy.deepcopy(valid)
    tampered["payload"]["ciphertext"] = b64url(bytes(range(33, 81)))

    malformed = copy.deepcopy(valid)
    del malformed["payload"]

    v0 = copy.deepcopy(valid)
    v0["version"] = 0

    downgrade = copy.deepcopy(valid)
    downgrade["suite"] = "TB0_AES256GCM_GROUP"

    bad_recipients = copy.deepcopy(valid)
    bad_recipients["recipients"][0]["id"] = "peer"

    expired_context = copy.deepcopy(context)
    expired_context["now_ms"] = EXPIRES

    revoked_context = copy.deepcopy(context)
    revoked_context["signing_keys"]["sender/sig/7"]["status"] = "compromised"

    replay_context = copy.deepcopy(context)
    replay_context["seen"] = [replay_key]

    wrong_audience_context = copy.deepcopy(context)
    wrong_audience_context["receiver_id"] = "peer"
    wrong_audience_context["receiver_audiences"] = ["direct:peer:1"]

    unauthorized_context = copy.deepcopy(context)
    unauthorized_context["authorized_audiences"] = []

    unknown_key_context = copy.deepcopy(context)
    unknown_key_context["signing_keys"] = {}

    vectors = [
        case(
            "valid-direct",
            valid,
            context,
            "accept",
            "accept",
            DIRECT_PLAINTEXT.decode("utf-8"),
        ),
        case(
            "valid-group",
            group,
            group_context,
            "accept",
            "accept",
            GROUP_PLAINTEXT.decode("utf-8"),
        ),
        case(
            "group-member-omitted",
            missing_group_member,
            group_context,
            "invalid_recipient_set",
            "invalid_recipient_set",
        ),
        case(
            "tampered-ciphertext",
            tampered,
            context,
            "invalid_signature",
            "invalid_signature",
        ),
        case(
            "wrong-endpoint-audience",
            valid,
            wrong_audience_context,
            "accept",
            "wrong_audience",
        ),
        case("replay", valid, replay_context, "replay", "replay"),
        case("expired", valid, expired_context, "expired", "expired"),
        case(
            "compromised-signing-key",
            valid,
            revoked_context,
            "revoked_key",
            "revoked_key",
        ),
        case(
            "malformed-missing-payload",
            malformed,
            context,
            "malformed_envelope",
            "malformed_envelope",
        ),
        case(
            "v0-envelope",
            v0,
            context,
            "unsupported_version",
            "unsupported_version",
        ),
        case(
            "suite-downgrade",
            downgrade,
            context,
            "downgrade_rejected",
            "downgrade_rejected",
        ),
        case(
            "recipient-audience-mismatch",
            bad_recipients,
            context,
            "invalid_recipient_set",
            "invalid_recipient_set",
        ),
        case(
            "unauthorized-sender-for-audience",
            valid,
            unauthorized_context,
            "unauthorized_audience",
            "accept",
            DIRECT_PLAINTEXT.decode("utf-8"),
        ),
        case(
            "unknown-signing-key",
            valid,
            unknown_key_context,
            "unknown_key",
            "unknown_key",
        ),
    ]
    return {
        "format": "tribe-v1-conformance-vectors/1",
        "warning": "All keys and byte strings are public test material; HPKE encapsulations are randomized.",
        "test_signing_private_seed": b64url(PRIVATE_SEED),
        "test_signing_public_key": public_key,
        "test_recipient_private_keys": {
            recipient_id: b64url(private_key.private_bytes_raw())
            for recipient_id, private_key in RECIPIENT_PRIVATE_KEYS.items()
        },
        "valid_direct_canonical_unsigned_sha256": sha256(
            protocol.canonical_json(protocol.unsigned_envelope(valid))
        ).hexdigest(),
        "valid_direct_signature_preimage_sha256": sha256(
            protocol.signature_preimage(valid)
        ).hexdigest(),
        "valid_direct_envelope_sha256": protocol.envelope_sha256(valid),
        "cases": vectors,
    }


def main() -> None:
    destination = Path(__file__).with_name("test-vectors") / "vectors.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(build(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(destination)


if __name__ == "__main__":
    main()
