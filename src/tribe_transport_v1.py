"""Signed, replay-protected HTTP request wrappers for Tribe v1."""

from __future__ import annotations

import base64
import uuid
from hashlib import sha256
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import tribe_protocol_v1 as protocol
from tribe_crypto_v1 import KeyBundle, b64url, uuid7
from tribe_directory_v1 import Directory, b64url_decode


AUTH_DOMAIN = b"tribe/v1/http-auth\x00"
AUTH_FIELDS = {
    "schema",
    "agent_id",
    "signing_kid",
    "request_id",
    "issued_at_ms",
    "expires_at_ms",
    "method",
    "path",
    "body_sha256",
    "signature",
}
SIGNATURE_FIELDS = {"alg", "kid", "value"}
MAX_AUTH_TTL_MS = 2 * 60 * 1000


def auth_unsigned(auth: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in auth.items() if key != "signature"}


def auth_preimage(auth: dict[str, Any]) -> bytes:
    return AUTH_DOMAIN + protocol.canonical_json(auth_unsigned(auth))


def body_sha256(body: Any) -> str:
    return sha256(protocol.canonical_json(body)).hexdigest()


def wrap_request(
    body: Any,
    *,
    keys: KeyBundle,
    method: str,
    path: str,
    now_ms: int,
    ttl_ms: int = 60_000,
) -> dict[str, Any]:
    if method not in {"POST"} or not path.startswith("/v1/"):
        raise ValueError("unsupported signed request target")
    if not 1_000 <= ttl_ms <= MAX_AUTH_TTL_MS:
        raise ValueError("invalid request auth TTL")
    auth = {
        "schema": "tribe-http-auth/v1",
        "agent_id": keys.agent_id,
        "signing_kid": keys.signing_kid,
        "request_id": uuid7(now_ms),
        "issued_at_ms": now_ms,
        "expires_at_ms": now_ms + ttl_ms,
        "method": method,
        "path": path,
        "body_sha256": body_sha256(body),
        "signature": {
            "alg": "Ed25519",
            "kid": keys.signing_kid,
            "value": "",
        },
    }
    auth["signature"]["value"] = b64url(
        keys.signing_private.sign(auth_preimage(auth))
    )
    return {"auth": auth, "body": body}


def validate_request(
    wrapper: Any,
    *,
    directory: Directory,
    method: str,
    path: str,
    now_ms: int,
) -> tuple[dict[str, Any], Any]:
    if (
        not isinstance(wrapper, dict)
        or set(wrapper) != {"auth", "body"}
        or not isinstance(wrapper["auth"], dict)
        or set(wrapper["auth"]) != AUTH_FIELDS
    ):
        raise protocol.ProtocolError("malformed_request")
    auth = wrapper["auth"]
    if (
        auth["schema"] != "tribe-http-auth/v1"
        or auth["method"] != method
        or auth["path"] != path
        or not isinstance(auth["agent_id"], str)
        or not protocol.IDENTIFIER.fullmatch(auth["agent_id"])
        or not isinstance(auth["signing_kid"], str)
        or not protocol.IDENTIFIER.fullmatch(auth["signing_kid"])
    ):
        raise protocol.ProtocolError("malformed_request")
    try:
        request_id = uuid.UUID(auth["request_id"])
    except (ValueError, TypeError) as exc:
        raise protocol.ProtocolError("malformed_request") from exc
    if request_id.version != 7:
        raise protocol.ProtocolError("malformed_request")
    for field in ("issued_at_ms", "expires_at_ms"):
        if not isinstance(auth[field], int) or isinstance(auth[field], bool):
            raise protocol.ProtocolError("malformed_request")
    if (
        auth["expires_at_ms"] <= now_ms
        or auth["issued_at_ms"] > now_ms + protocol.MAX_CLOCK_SKEW_MS
        or auth["expires_at_ms"] - auth["issued_at_ms"] > MAX_AUTH_TTL_MS
    ):
        raise protocol.ProtocolError("expired_request")
    if auth["body_sha256"] != body_sha256(wrapper["body"]):
        raise protocol.ProtocolError("request_body_mismatch")
    signature = auth["signature"]
    if (
        not isinstance(signature, dict)
        or set(signature) != SIGNATURE_FIELDS
        or signature["alg"] != "Ed25519"
        or signature["kid"] != auth["signing_kid"]
    ):
        raise protocol.ProtocolError("malformed_request")
    record = directory.signing_keys.get(auth["signing_kid"])
    if (
        not record
        or record["owner"] != auth["agent_id"]
        or record["status"] != "active"
        or auth["issued_at_ms"] < record["not_before_ms"]
        or (
            record["not_after_ms"] is not None
            and auth["issued_at_ms"] >= record["not_after_ms"]
        )
    ):
        raise protocol.ProtocolError("unauthorized_sender")
    try:
        signature_bytes = b64url_decode(signature["value"], 64)
        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(record["public_key"], 32)
        )
        public_key.verify(signature_bytes, auth_preimage(auth))
    except InvalidSignature as exc:
        raise protocol.ProtocolError("invalid_signature") from exc
    return auth, wrapper["body"]
