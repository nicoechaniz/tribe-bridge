"""The only Tribe v1 envelope crypto implementation used by all components."""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

import tribe_protocol_v1 as protocol
from tribe_directory_v1 import Directory, DirectoryError, b64url_decode, strict_json


HPKE_SUITE = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)
KEY_BUNDLE_FIELDS = {"schema", "agent_id", "signing", "encryption"}
PRIVATE_KEY_FIELDS = {"kid", "private_key"}
MESSAGE_FIELDS = {
    "schema",
    "kind",
    "from",
    "to",
    "text",
    "classification",
    "reply_to",
}
MAX_PLAINTEXT_BYTES = 512 * 1024


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def uuid7(now_ms: int | None = None) -> str:
    timestamp = int(time.time() * 1000) if now_ms is None else now_ms
    if not 0 <= timestamp < (1 << 48):
        raise ValueError("UUIDv7 timestamp out of range")
    random_bits = int.from_bytes(secrets.token_bytes(10), "big") & (
        (1 << 74) - 1
    )
    value = timestamp << 80
    value |= 7 << 76
    value |= ((random_bits >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= random_bits & ((1 << 62) - 1)
    return str(uuid.UUID(int=value))


@dataclass(frozen=True)
class KeyBundle:
    agent_id: str
    signing_kid: str
    signing_private: ed25519.Ed25519PrivateKey
    encryption_private: dict[str, x25519.X25519PrivateKey]

    @classmethod
    def load(cls, path: Path | str) -> "KeyBundle":
        path = Path(path)
        stat = path.stat()
        mode = stat.st_mode & 0o777
        if stat.st_uid != os.getuid():
            raise PermissionError(f"private key bundle has wrong owner: {path}")
        if mode & 0o077:
            raise PermissionError(
                f"private key bundle must not be group/world accessible: {path}"
            )
        value = strict_json(path.read_bytes(), max_bytes=64 * 1024)
        if not isinstance(value, dict) or set(value) != KEY_BUNDLE_FIELDS:
            raise ValueError("invalid key bundle fields")
        if value["schema"] != "tribe-key-bundle/v1":
            raise ValueError("unsupported key bundle schema")
        agent_id = value["agent_id"]
        if not isinstance(agent_id, str) or not protocol.IDENTIFIER.fullmatch(
            agent_id
        ):
            raise ValueError("invalid key-bundle agent ID")
        signing = value["signing"]
        if (
            not isinstance(signing, dict)
            or set(signing) != PRIVATE_KEY_FIELDS
            or not isinstance(signing["kid"], str)
            or not protocol.IDENTIFIER.fullmatch(signing["kid"])
        ):
            raise ValueError("invalid signing key entry")
        signing_private = ed25519.Ed25519PrivateKey.from_private_bytes(
            b64url_decode(signing["private_key"], 32)
        )
        encryption = value["encryption"]
        if not isinstance(encryption, list) or not encryption:
            raise ValueError("key bundle needs encryption keys")
        encryption_private = {}
        for entry in encryption:
            if (
                not isinstance(entry, dict)
                or set(entry) != PRIVATE_KEY_FIELDS
                or not isinstance(entry["kid"], str)
                or not protocol.IDENTIFIER.fullmatch(entry["kid"])
                or entry["kid"] in encryption_private
            ):
                raise ValueError("invalid encryption key entry")
            encryption_private[entry["kid"]] = (
                x25519.X25519PrivateKey.from_private_bytes(
                    b64url_decode(entry["private_key"], 32)
                )
            )
        return cls(
            agent_id=agent_id,
            signing_kid=signing["kid"],
            signing_private=signing_private,
            encryption_private=encryption_private,
        )

    def verify_against(self, directory: Directory, now_ms: int) -> None:
        signing = directory.signing_keys.get(self.signing_kid)
        if (
            not signing
            or signing["owner"] != self.agent_id
            or signing["status"] != "active"
            or b64url(self.signing_private.public_key().public_bytes_raw())
            != signing["public_key"]
        ):
            raise DirectoryError("local signing key does not match directory")
        for kid, private_key in self.encryption_private.items():
            record = directory.encryption_keys.get(kid)
            if (
                not record
                or record["owner"] != self.agent_id
                or record["status"] not in {"active", "retired"}
                or b64url(private_key.public_key().public_bytes_raw())
                != record["public_key"]
            ):
                raise DirectoryError(
                    f"local encryption key {kid} does not match directory"
                )
        active = directory.active_key(self.agent_id, "signing", now_ms)
        if active["kid"] != self.signing_kid:
            raise DirectoryError("key bundle is not using latest signing key")


def message_payload(
    *,
    sender: str,
    to: str,
    text: str,
    classification: str = "private",
    reply_to: str | None = None,
) -> dict[str, Any]:
    if classification not in {"private", "tribe-public"}:
        raise ValueError("classification must be private or tribe-public")
    if not isinstance(text, str) or not text or len(text) > 200_000:
        raise ValueError("message text must contain 1..200000 characters")
    if not isinstance(sender, str) or not protocol.IDENTIFIER.fullmatch(sender):
        raise ValueError("invalid sender")
    if not isinstance(to, str) or not protocol.IDENTIFIER.fullmatch(to):
        raise ValueError("invalid target")
    if reply_to is not None:
        try:
            if uuid.UUID(reply_to).version != 7:
                raise ValueError
        except ValueError as exc:
            raise ValueError("reply_to must be a UUIDv7") from exc
    return {
        "schema": "tribe-message/v1",
        "kind": "message",
        "from": sender,
        "to": to,
        "text": text,
        "classification": classification,
        "reply_to": reply_to,
    }


def _validate_message_payload(
    payload: Any, envelope: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != MESSAGE_FIELDS:
        raise protocol.ProtocolError("invalid_plaintext")
    if (
        payload["schema"] != "tribe-message/v1"
        or payload["kind"] != "message"
        or payload["from"] != envelope["sender"]["id"]
        or payload["to"] != envelope["audience"]["id"]
        or payload["classification"] not in {"private", "tribe-public"}
        or not isinstance(payload["text"], str)
    ):
        raise protocol.ProtocolError("invalid_plaintext")
    return payload


def encrypt_envelope(
    payload: dict[str, Any],
    *,
    directory: Directory,
    keys: KeyBundle,
    audience_type: str,
    audience_id: str,
    audience_epoch: int | None = None,
    now_ms: int | None = None,
    ttl_ms: int = 60 * 60 * 1000,
    message_id: str | None = None,
) -> dict[str, Any]:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if not 1_000 <= ttl_ms <= protocol.MAX_TTL_MS:
        raise ValueError("ttl_ms must be between 1 second and 24 hours")
    keys.verify_against(directory, now)
    audience = directory.audience(
        audience_type, audience_id, audience_epoch
    )
    if keys.agent_id not in audience["allowed_senders"]:
        raise DirectoryError("sender is not authorized for audience")
    if payload.get("from") != keys.agent_id or payload.get("to") != audience_id:
        raise ValueError("payload sender/target does not match envelope")

    active_signing = directory.active_key(keys.agent_id, "signing", now)
    envelope = {
        "protocol": protocol.PROTOCOL,
        "version": protocol.VERSION,
        "message_id": message_id or uuid7(now),
        "issued_at_ms": now,
        "expires_at_ms": now + ttl_ms,
        "sender": {
            "id": keys.agent_id,
            "signing_kid": active_signing["kid"],
        },
        "audience": {
            "type": audience["type"],
            "id": audience["id"],
            "epoch": audience["epoch"],
        },
        "content_type": "application/vnd.tribe.message+json",
        "suite": protocol.SUITE,
        "payload": {"nonce": "", "ciphertext": ""},
        "recipients": [],
    }
    for recipient_id in audience["members"]:
        key = directory.active_key(recipient_id, "encryption", now)
        envelope["recipients"].append(
            {
                "id": recipient_id,
                "encryption_kid": key["kid"],
                "enc": "",
                "wrapped_cek": "",
            }
        )
    envelope["recipients"].sort(key=lambda item: item["id"])

    plaintext = protocol.canonical_json(payload)
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError("plaintext exceeds v1 limit")
    cek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    envelope["payload"]["nonce"] = b64url(nonce)
    envelope["payload"]["ciphertext"] = b64url(
        ChaCha20Poly1305(cek).encrypt(
            nonce, plaintext, protocol.payload_aad(envelope)
        )
    )
    for recipient in envelope["recipients"]:
        record = directory.encryption_keys[recipient["encryption_kid"]]
        public_key = x25519.X25519PublicKey.from_public_bytes(
            b64url_decode(record["public_key"], 32)
        )
        hpke_output = HPKE_SUITE.encrypt(
            cek,
            public_key,
            info=protocol.recipient_hpke_context(envelope, recipient),
        )
        recipient["enc"] = b64url(hpke_output[:32])
        recipient["wrapped_cek"] = b64url(hpke_output[32:])

    envelope["signature"] = {
        "alg": "Ed25519",
        "kid": keys.signing_kid,
        "value": "",
    }
    envelope["signature"]["value"] = b64url(
        keys.signing_private.sign(protocol.signature_preimage(envelope))
    )
    context = directory.context(
        sender_id=keys.agent_id, now_ms=now
    )
    protocol.validate_broker_admission(envelope, context)
    return envelope


def decrypt_envelope(
    envelope: dict[str, Any],
    *,
    directory: Directory,
    keys: KeyBundle,
    now_ms: int | None = None,
    seen: list[str] | None = None,
) -> dict[str, Any]:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    context = directory.context(
        receiver_id=keys.agent_id,
        now_ms=now,
        seen=seen,
    )
    protocol.validate_endpoint_receive(envelope, context)
    recipient = next(
        item
        for item in envelope["recipients"]
        if item["id"] == keys.agent_id
    )
    private_key = keys.encryption_private.get(
        recipient["encryption_kid"]
    )
    if private_key is None:
        raise protocol.ProtocolError("key_not_available")
    try:
        cek = HPKE_SUITE.decrypt(
            b64url_decode(recipient["enc"], 32)
            + b64url_decode(recipient["wrapped_cek"], 48),
            private_key,
            info=protocol.recipient_hpke_context(envelope, recipient),
        )
        plaintext = ChaCha20Poly1305(cek).decrypt(
            b64url_decode(envelope["payload"]["nonce"], 12),
            b64url_decode(
                envelope["payload"]["ciphertext"],
                len(
                    base64.urlsafe_b64decode(
                        envelope["payload"]["ciphertext"]
                        + "="
                        * (-len(envelope["payload"]["ciphertext"]) % 4)
                    )
                ),
            ),
            protocol.payload_aad(envelope),
        )
    except Exception as exc:
        raise protocol.ProtocolError("decryption_failed") from exc
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise protocol.ProtocolError("invalid_plaintext")
    payload = strict_json(plaintext, max_bytes=MAX_PLAINTEXT_BYTES)
    return _validate_message_payload(payload, envelope)


def write_key_bundle(path: Path | str, value: dict[str, Any]) -> None:
    """Create a private key bundle without ever overwriting one."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
