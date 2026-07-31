#!/usr/bin/env python3
"""Shared client helpers for Tribe Bridge delivery scripts."""

import hashlib
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple


DEFAULT_PORT = 8585


class BridgeRequestError(RuntimeError):
    """An HTTP or transport error returned by an LCM endpoint."""


def load_roster(env_name: str) -> Dict[str, Any]:
    """Load a JSON roster from an environment variable."""
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return {}
    try:
        roster = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{env_name} must contain valid JSON: {exc}") from exc
    if not isinstance(roster, dict):
        raise ValueError(f"{env_name} must contain a JSON object")
    return roster


def roster_address(
    roster: Dict[str, Any], agent: str, route: Optional[str] = None
) -> Optional[str]:
    """Return an address from a flat or route-aware roster entry."""
    entry = roster.get(agent)
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict) and route:
        address = entry.get(route)
        return address if isinstance(address, str) else None
    return None


def resolve_address(address: str, default_port: int = DEFAULT_PORT) -> Tuple[str, int]:
    """Resolve ``host`` or ``host:port`` into a host/port pair."""
    value = address.strip()
    if value.startswith("http://"):
        value = value[7:]
    value = value.rstrip("/")
    if not value:
        raise ValueError("endpoint address cannot be empty")

    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            raise ValueError(f"invalid endpoint address: {address}")
        host = value[1:closing]
        remainder = value[closing + 1 :]
        if not remainder:
            return host, default_port
        if not remainder.startswith(":"):
            raise ValueError(f"invalid endpoint address: {address}")
        return host, int(remainder[1:])

    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, default_port


def endpoint_key(address: str) -> Tuple[str, int]:
    """Return a normalized endpoint key suitable for equality checks."""
    return resolve_address(address)


def endpoint_url(address: str, path: str) -> str:
    """Build an HTTP URL for an LCM endpoint."""
    host, port = resolve_address(address)
    display_host = f"[{host}]" if ":" in host else host
    return f"http://{display_host}:{port}{path}"


def envelope_from_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the original signed envelope from an inbox record."""
    fields = ("ciphertext", "nonce", "tag", "signature", "signer")
    envelope = {field: record.get(field, "") for field in fields}
    missing = [field for field in fields if not envelope[field]]
    if missing:
        raise ValueError(
            "inbox record is missing envelope fields: " + ", ".join(missing)
        )
    return envelope


def logical_message_id(record: Dict[str, Any]) -> str:
    """Return a stable logical ID, with an envelope fingerprint for legacy data."""
    decrypted = record.get("decrypted")
    if isinstance(decrypted, dict):
        message_id = decrypted.get("message_id")
        if isinstance(message_id, str) and message_id:
            return f"message:{message_id}"

    stable_envelope = {
        field: record.get(field, "")
        for field in ("ciphertext", "nonce", "tag", "signer")
    }
    serialized = json.dumps(
        stable_envelope, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "envelope:" + hashlib.sha256(serialized).hexdigest()


def post_envelope(
    address: str, envelope: Dict[str, Any], timeout: float
) -> Dict[str, Any]:
    """POST a signed envelope to an LCM endpoint."""
    request = urllib.request.Request(
        endpoint_url(address, "/send"),
        data=json.dumps(envelope).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BridgeRequestError(
            f"{address} rejected the message: HTTP {exc.code} - {detail}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BridgeRequestError(f"{address} is unavailable: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BridgeRequestError(
            f"{address} returned an invalid send response"
        ) from exc
    if not isinstance(result, dict):
        raise BridgeRequestError(f"{address} returned an invalid send response")
    return result
