"""Protocol-level validation shared by Tribe v1 brokers and endpoints.

This module intentionally does not implement HPKE or payload decryption.  It
defines the fail-closed envelope parser, canonical signing input, registry
checks, authorization checks, and replay/expiry semantics that both sides
must agree on before the crypto and storage implementations are merged.
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from hashlib import sha256
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PROTOCOL = "tribe"
VERSION = 1
SUITE = "TB1_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS"
SIGNATURE_DOMAIN = b"tribe/v1/envelope-signature\x00"
MAX_TTL_MS = 48 * 60 * 60 * 1000
MAX_CLOCK_SKEW_MS = 5 * 60 * 1000
MAX_RECIPIENTS = 256
MAX_ENVELOPE_BYTES = 1024 * 1024

TOP_LEVEL_FIELDS = {
    "protocol",
    "version",
    "message_id",
    "issued_at_ms",
    "expires_at_ms",
    "sender",
    "audience",
    "content_type",
    "suite",
    "payload",
    "recipients",
    "signature",
}
SENDER_FIELDS = {"id", "signing_kid"}
AUDIENCE_FIELDS = {"type", "id", "epoch"}
PAYLOAD_FIELDS = {"nonce", "ciphertext"}
RECIPIENT_FIELDS = {"id", "encryption_kid", "enc", "wrapped_cek"}
SIGNATURE_FIELDS = {"alg", "kid", "value"}
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._@/-]{0,126}[a-z0-9])?$")
CONTENT_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$")


class ProtocolError(ValueError):
    """Stable, non-sensitive rejection reason used by conformance tests."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def parse_envelope(raw: bytes | str) -> dict[str, Any]:
    """Parse one bounded UTF-8 envelope while rejecting duplicate names."""
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ProtocolError("malformed_envelope") from exc
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        raise ProtocolError("malformed_envelope")
    if not encoded or len(encoded) > MAX_ENVELOPE_BYTES:
        raise ProtocolError("envelope_too_large")

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ProtocolError("duplicate_property")
            value[key] = item
        return value

    def exact_integer(token: str) -> int:
        if token == "-0":
            raise ProtocolError("malformed_envelope")
        value = int(token)
        if abs(value) > 9_007_199_254_740_991:
            raise ProtocolError("malformed_envelope")
        return value

    try:
        parsed = json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_int=exact_integer,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ProtocolError("malformed_envelope")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProtocolError("malformed_envelope")
            ),
        )
    except ProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("malformed_envelope") from exc
    if not isinstance(parsed, dict):
        raise ProtocolError("malformed_envelope")
    return parsed


def _reject_if_not_exact_fields(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtocolError("malformed_envelope")
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_identifier(value: Any) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ProtocolError("malformed_envelope")
    return value


def _decode_b64url(value: Any, expected_size: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ProtocolError("malformed_envelope")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ProtocolError("malformed_envelope") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ProtocolError("malformed_envelope")
    if expected_size is not None and len(decoded) != expected_size:
        raise ProtocolError("malformed_envelope")
    return decoded


def _validate_json_value(value: Any) -> None:
    """Enforce the I-JSON subset used by the protocol's JCS profile."""
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise ProtocolError("malformed_envelope") from exc
        return
    if _is_int(value):
        if abs(value) > 9_007_199_254_740_991:
            raise ProtocolError("malformed_envelope")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError("malformed_envelope")
            _validate_json_value(key)
            _validate_json_value(item)
        return
    # Floats are deliberately absent from every v1 schema.
    raise ProtocolError("malformed_envelope")


def canonical_json(value: Any) -> bytes:
    """Return the protocol's RFC 8785 profile for its integer-only schemas.

    All envelope property names are protocol-defined ASCII.  Floats and
    extension properties are rejected, avoiding cross-runtime number and
    property-order ambiguity while remaining valid JCS.
    """
    _validate_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def unsigned_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in envelope.items() if key != "signature"}


def signature_preimage(envelope: dict[str, Any]) -> bytes:
    return SIGNATURE_DOMAIN + canonical_json(unsigned_envelope(envelope))


def protected_metadata(envelope: dict[str, Any]) -> dict[str, Any]:
    """Fields bound as payload AAD and into every recipient HPKE context."""
    return {
        "protocol": envelope["protocol"],
        "version": envelope["version"],
        "message_id": envelope["message_id"],
        "issued_at_ms": envelope["issued_at_ms"],
        "expires_at_ms": envelope["expires_at_ms"],
        "sender": envelope["sender"],
        "audience": envelope["audience"],
        "content_type": envelope["content_type"],
        "suite": envelope["suite"],
    }


def payload_aad(envelope: dict[str, Any]) -> bytes:
    return b"tribe/v1/payload-aad\x00" + canonical_json(
        protected_metadata(envelope)
    )


def recipient_hpke_context(
    envelope: dict[str, Any], recipient: dict[str, Any]
) -> bytes:
    return b"tribe/v1/cek-wrap\x00" + canonical_json(
        {
            "protected": protected_metadata(envelope),
            "recipient_id": recipient["id"],
            "encryption_kid": recipient["encryption_kid"],
        }
    )


def _validate_uuid7(message_id: Any, issued_at_ms: int) -> None:
    if not isinstance(message_id, str):
        raise ProtocolError("malformed_envelope")
    try:
        parsed = uuid.UUID(message_id)
    except (ValueError, AttributeError) as exc:
        raise ProtocolError("malformed_envelope") from exc
    if parsed.version != 7 or parsed.variant != uuid.RFC_4122:
        raise ProtocolError("malformed_envelope")
    encoded_timestamp = parsed.int >> 80
    if abs(encoded_timestamp - issued_at_ms) > MAX_CLOCK_SKEW_MS:
        raise ProtocolError("malformed_envelope")


def validate_structure(envelope: Any) -> dict[str, Any]:
    envelope = _reject_if_not_exact_fields(envelope, TOP_LEVEL_FIELDS)
    if envelope["protocol"] != PROTOCOL:
        raise ProtocolError("unsupported_protocol")
    if envelope["version"] != VERSION:
        raise ProtocolError("unsupported_version")
    if envelope["suite"] != SUITE:
        raise ProtocolError("downgrade_rejected")

    issued = envelope["issued_at_ms"]
    expires = envelope["expires_at_ms"]
    if not _is_int(issued) or not _is_int(expires) or expires <= issued:
        raise ProtocolError("malformed_envelope")
    if expires - issued > MAX_TTL_MS:
        raise ProtocolError("malformed_envelope")
    _validate_uuid7(envelope["message_id"], issued)

    sender = _reject_if_not_exact_fields(envelope["sender"], SENDER_FIELDS)
    sender_id = _require_identifier(sender["id"])
    signing_kid = _require_identifier(sender["signing_kid"])

    audience = _reject_if_not_exact_fields(
        envelope["audience"], AUDIENCE_FIELDS
    )
    if audience["type"] not in {"direct", "group"}:
        raise ProtocolError("malformed_envelope")
    _require_identifier(audience["id"])
    if not _is_int(audience["epoch"]) or audience["epoch"] < 1:
        raise ProtocolError("malformed_envelope")

    content_type = envelope["content_type"]
    if not isinstance(content_type, str) or not CONTENT_TYPE.fullmatch(
        content_type
    ):
        raise ProtocolError("malformed_envelope")

    payload = _reject_if_not_exact_fields(envelope["payload"], PAYLOAD_FIELDS)
    _decode_b64url(payload["nonce"], 12)
    if len(_decode_b64url(payload["ciphertext"])) < 16:
        raise ProtocolError("malformed_envelope")

    recipients = envelope["recipients"]
    if (
        not isinstance(recipients, list)
        or not recipients
        or len(recipients) > MAX_RECIPIENTS
    ):
        raise ProtocolError("invalid_recipient_set")
    seen_recipients: set[str] = set()
    for recipient in recipients:
        recipient = _reject_if_not_exact_fields(recipient, RECIPIENT_FIELDS)
        recipient_id = _require_identifier(recipient["id"])
        if recipient_id in seen_recipients:
            raise ProtocolError("invalid_recipient_set")
        seen_recipients.add(recipient_id)
        _require_identifier(recipient["encryption_kid"])
        _decode_b64url(recipient["enc"], 32)
        # HPKE seals a 32-byte CEK; the selected AEAD adds a 16-byte tag.
        _decode_b64url(recipient["wrapped_cek"], 48)
    if (
        audience["type"] == "direct"
        and audience["id"] not in seen_recipients
    ):
        raise ProtocolError("invalid_recipient_set")

    signature = _reject_if_not_exact_fields(
        envelope["signature"], SIGNATURE_FIELDS
    )
    if (
        signature["alg"] != "Ed25519"
        or signature["kid"] != signing_kid
    ):
        raise ProtocolError("malformed_envelope")
    _decode_b64url(signature["value"], 64)

    # Ensures strings, integers, and nested values fit the canonical profile.
    canonical_json(envelope)
    return envelope


def _key_record(context: dict[str, Any], kid: str) -> dict[str, Any]:
    record = context.get("signing_keys", {}).get(kid)
    if not isinstance(record, dict):
        raise ProtocolError("unknown_key")
    return record


def _validate_key_and_signature(
    envelope: dict[str, Any], context: dict[str, Any]
) -> None:
    sender = envelope["sender"]
    record = _key_record(context, sender["signing_kid"])
    if record.get("owner") != sender["id"]:
        raise ProtocolError("unauthorized_sender")
    status = record.get("status")
    if status in {"compromised", "revoked"}:
        raise ProtocolError("revoked_key")
    if status not in {"active", "retired"}:
        raise ProtocolError("unknown_key")
    issued = envelope["issued_at_ms"]
    if issued < record.get("not_before_ms", 0):
        raise ProtocolError("key_not_valid")
    not_after = record.get("not_after_ms")
    if not_after is not None and issued >= not_after:
        raise ProtocolError("key_not_valid")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _decode_b64url(record.get("public_key"), 32)
        )
        public_key.verify(
            _decode_b64url(envelope["signature"]["value"], 64),
            signature_preimage(envelope),
        )
    except InvalidSignature as exc:
        raise ProtocolError("invalid_signature") from exc
    except (TypeError, ValueError) as exc:
        raise ProtocolError("unknown_key") from exc


def _validate_time_and_replay(
    envelope: dict[str, Any], context: dict[str, Any]
) -> None:
    now = context.get("now_ms")
    if not _is_int(now):
        raise ProtocolError("invalid_context")
    if envelope["issued_at_ms"] > now + MAX_CLOCK_SKEW_MS:
        raise ProtocolError("issued_in_future")
    if envelope["expires_at_ms"] <= now:
        raise ProtocolError("expired")
    replay_key = f'{envelope["sender"]["id"]}:{envelope["message_id"]}'
    if replay_key in context.get("seen", []):
        raise ProtocolError("replay")


def _audience_key(envelope: dict[str, Any]) -> str:
    audience = envelope["audience"]
    return f'{audience["type"]}:{audience["id"]}:{audience["epoch"]}'


def _encryption_key_is_valid(
    key: Any,
    owner: str,
    issued_at_ms: int,
    *,
    allow_retired: bool,
) -> bool:
    if not isinstance(key, dict) or key.get("owner") != owner:
        return False
    allowed_statuses = {"active", "retired"} if allow_retired else {"active"}
    if key.get("status") not in allowed_statuses:
        return False
    if issued_at_ms < key.get("not_before_ms", 0):
        return False
    not_after = key.get("not_after_ms")
    return not_after is None or issued_at_ms < not_after


def validate_broker_admission(
    envelope: Any, context: dict[str, Any]
) -> dict[str, Any]:
    """Validate before an atomic durable insert at a v1 broker."""
    envelope = validate_structure(envelope)
    _validate_key_and_signature(envelope, context)
    _validate_time_and_replay(envelope, context)
    if _audience_key(envelope) not in context.get("authorized_audiences", []):
        raise ProtocolError("unauthorized_audience")

    encryption_keys = context.get("encryption_keys", {})
    audience_key = _audience_key(envelope)
    expected_members = context.get("audience_members", {}).get(audience_key)
    actual_members = {recipient["id"] for recipient in envelope["recipients"]}
    if not isinstance(expected_members, list) or actual_members != set(
        expected_members
    ):
        raise ProtocolError("invalid_recipient_set")
    for recipient in envelope["recipients"]:
        key = encryption_keys.get(recipient["encryption_kid"])
        if not _encryption_key_is_valid(
            key,
            recipient["id"],
            envelope["issued_at_ms"],
            allow_retired=False,
        ):
            raise ProtocolError("invalid_recipient_set")
    return envelope


def validate_endpoint_receive(
    envelope: Any, context: dict[str, Any]
) -> dict[str, Any]:
    """Validate before CEK unwrap, decryption, or any external side effect."""
    envelope = validate_structure(envelope)
    _validate_key_and_signature(envelope, context)
    _validate_time_and_replay(envelope, context)

    receiver = context.get("receiver_id")
    audience = envelope["audience"]
    receiver_audiences = context.get("receiver_audiences", [])
    if not isinstance(receiver, str) or _audience_key(envelope) not in receiver_audiences:
        raise ProtocolError("wrong_audience")
    expected_members = context.get("audience_members", {}).get(
        _audience_key(envelope)
    )
    actual_members = {recipient["id"] for recipient in envelope["recipients"]}
    expected_sets = context.get("audience_recipient_sets", {}).get(
        _audience_key(envelope)
    )
    if expected_sets is None:
        expected_sets = [expected_members]
    valid_recipient_set = isinstance(expected_sets, list) and any(
        isinstance(expected, list)
        and bool(expected)
        and len(expected) == len(set(expected))
        and actual_members == set(expected)
        for expected in expected_sets
    )
    if not valid_recipient_set:
        raise ProtocolError("invalid_recipient_set")
    wraps = [
        recipient
        for recipient in envelope["recipients"]
        if recipient["id"] == receiver
    ]
    if len(wraps) != 1:
        raise ProtocolError("not_recipient")
    key = context.get("encryption_keys", {}).get(wraps[0]["encryption_kid"])
    if not _encryption_key_is_valid(
        key,
        receiver,
        envelope["issued_at_ms"],
        allow_retired=True,
    ):
        raise ProtocolError("key_not_valid")
    return envelope


def envelope_sha256(envelope: dict[str, Any]) -> str:
    return sha256(canonical_json(envelope)).hexdigest()
