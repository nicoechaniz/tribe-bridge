"""Verification and compilation of signed Tribe v1 directory snapshots."""

from __future__ import annotations

import base64
import fcntl
import json
import os
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import tribe_protocol_v1 as protocol


DIRECTORY_DOMAIN = b"tribe/v1/directory\x00"
TOP_FIELDS = {
    "schema",
    "directory_epoch",
    "issued_at_ms",
    "expires_at_ms",
    "previous_sha256",
    "agents",
    "audiences",
    "governance",
}
GOVERNANCE_FIELDS = {"threshold", "signatures"}
SIGNATURE_FIELDS = {"kid", "alg", "value"}
AGENT_FIELDS = {"id", "status", "signing_keys", "encryption_keys"}
KEY_FIELDS = {
    "kid",
    "epoch",
    "public_key",
    "status",
    "not_before_ms",
    "not_after_ms",
}
AUDIENCE_FIELDS = {
    "type",
    "id",
    "epoch",
    "status",
    "members",
    "allowed_senders",
}
AUDIENCE_OPTIONAL_FIELDS = {"observers"}
ROOTS_FIELDS = {"schema", "threshold", "keys"}
STATE_FIELDS = {
    "schema",
    "directory_epoch",
    "directory_sha256",
    "roots_sha256",
}


class DirectoryError(ValueError):
    pass


def b64url_decode(value: Any, size: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise DirectoryError("non-canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise DirectoryError("invalid base64url") from exc
    if len(decoded) != size:
        raise DirectoryError("invalid key or signature size")
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise DirectoryError("non-canonical base64url")
    return decoded


def strict_json(raw: bytes | str, *, max_bytes: int = 1024 * 1024) -> Any:
    if isinstance(raw, str):
        encoded = raw.encode("utf-8", errors="strict")
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        raise DirectoryError("JSON input must be bytes or string")
    if not encoded or len(encoded) > max_bytes:
        raise DirectoryError("invalid JSON size")

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise DirectoryError(f"duplicate JSON property: {key}")
            value[key] = item
        return value

    def exact_integer(token):
        if token == "-0":
            raise DirectoryError("negative zero is forbidden")
        value = int(token)
        if abs(value) > 9_007_199_254_740_991:
            raise DirectoryError("integer exceeds I-JSON range")
        return value

    try:
        return json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_int=exact_integer,
            parse_float=lambda _value: (_ for _ in ()).throw(
                DirectoryError("floats are forbidden")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                DirectoryError("non-finite numbers are forbidden")
            ),
        )
    except DirectoryError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DirectoryError("invalid JSON") from exc


def directory_unsigned(snapshot: dict[str, Any]) -> dict[str, Any]:
    value = dict(snapshot)
    value["governance"] = {
        "threshold": snapshot["governance"]["threshold"]
    }
    return value


def directory_preimage(snapshot: dict[str, Any]) -> bytes:
    return DIRECTORY_DOMAIN + protocol.canonical_json(
        directory_unsigned(snapshot)
    )


def directory_sha256(snapshot: dict[str, Any]) -> str:
    return sha256(protocol.canonical_json(snapshot)).hexdigest()


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise DirectoryError(f"invalid {label} fields")
    return value


def _exact_with_optional(
    value: Any,
    fields: set[str],
    optional_fields: set[str],
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not fields <= set(value)
        or not set(value) <= fields | optional_fields
    ):
        raise DirectoryError(f"invalid {label} fields")
    return value


def audience_recipients(audience: dict[str, Any]) -> list[str]:
    """Return members and explicitly governed observers for an audience."""
    return [*audience["members"], *audience.get("observers", [])]


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not protocol.IDENTIFIER.fullmatch(value):
        raise DirectoryError("invalid identifier")
    return value


def _integer(value: Any, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > 9_007_199_254_740_991
    ):
        raise DirectoryError("invalid integer")
    return value


def load_roots(path: Path | str) -> dict[str, Any]:
    path = Path(path)
    roots = strict_json(path.read_bytes(), max_bytes=64 * 1024)
    _exact(roots, ROOTS_FIELDS, "governance roots")
    if roots["schema"] != "tribe-governance-roots/v1":
        raise DirectoryError("unsupported governance roots schema")
    threshold = _integer(roots["threshold"], minimum=1)
    if not isinstance(roots["keys"], dict) or threshold > len(roots["keys"]):
        raise DirectoryError("invalid governance threshold")
    for kid, public_key in roots["keys"].items():
        _identifier(kid)
        b64url_decode(public_key, 32)
    return roots


def validate_directory(
    snapshot: Any,
    roots: dict[str, Any],
    *,
    now_ms: int,
) -> dict[str, Any]:
    snapshot = _exact(snapshot, TOP_FIELDS, "directory")
    if snapshot["schema"] != "tribe-directory/v1":
        raise DirectoryError("unsupported directory schema")
    epoch = _integer(snapshot["directory_epoch"], minimum=1)
    issued = _integer(snapshot["issued_at_ms"])
    expires = _integer(snapshot["expires_at_ms"], minimum=1)
    if (
        issued > now_ms + protocol.MAX_CLOCK_SKEW_MS
        or expires <= now_ms
        or expires <= issued
    ):
        raise DirectoryError("directory is not currently valid")
    previous = snapshot["previous_sha256"]
    if previous is not None and (
        not isinstance(previous, str)
        or len(previous) != 64
        or any(c not in "0123456789abcdef" for c in previous)
    ):
        raise DirectoryError("invalid previous directory hash")

    governance = _exact(
        snapshot["governance"], GOVERNANCE_FIELDS, "governance"
    )
    if governance["threshold"] != roots["threshold"]:
        raise DirectoryError("directory cannot change local threshold")
    signatures = governance["signatures"]
    if not isinstance(signatures, list):
        raise DirectoryError("invalid governance signatures")
    valid_signers = set()
    preimage = directory_preimage(snapshot)
    for signature in signatures:
        _exact(signature, SIGNATURE_FIELDS, "governance signature")
        kid = _identifier(signature["kid"])
        if signature["alg"] != "Ed25519" or kid in valid_signers:
            raise DirectoryError("invalid or duplicate governance signature")
        public_value = roots["keys"].get(kid)
        if public_value is None:
            raise DirectoryError("unknown governance signer")
        try:
            Ed25519PublicKey.from_public_bytes(
                b64url_decode(public_value, 32)
            ).verify(
                b64url_decode(signature["value"], 64),
                preimage,
            )
        except InvalidSignature as exc:
            raise DirectoryError("invalid governance signature") from exc
        valid_signers.add(kid)
    if len(valid_signers) < roots["threshold"]:
        raise DirectoryError("governance signature threshold not met")

    agents = snapshot["agents"]
    if not isinstance(agents, list) or not agents:
        raise DirectoryError("directory must contain agents")
    agent_ids = set()
    all_kids = set()
    for agent in agents:
        _exact(agent, AGENT_FIELDS, "agent")
        agent_id = _identifier(agent["id"])
        if agent_id in agent_ids:
            raise DirectoryError("duplicate agent")
        agent_ids.add(agent_id)
        if agent["status"] not in {"active", "suspended", "retired"}:
            raise DirectoryError("invalid agent status")
        for purpose in ("signing_keys", "encryption_keys"):
            keys = agent[purpose]
            if not isinstance(keys, list) or not keys:
                raise DirectoryError(f"agent has no {purpose}")
            epochs = set()
            for key in keys:
                _exact(key, KEY_FIELDS, "agent key")
                kid = _identifier(key["kid"])
                key_epoch = _integer(key["epoch"], minimum=1)
                if kid in all_kids or key_epoch in epochs:
                    raise DirectoryError("duplicate key ID or purpose epoch")
                all_kids.add(kid)
                epochs.add(key_epoch)
                b64url_decode(key["public_key"], 32)
                if key["status"] not in {
                    "active",
                    "retired",
                    "revoked",
                    "compromised",
                }:
                    raise DirectoryError("invalid key status")
                not_before = _integer(key["not_before_ms"])
                not_after = key["not_after_ms"]
                if not_after is not None:
                    not_after = _integer(not_after, minimum=1)
                    if not_after <= not_before:
                        raise DirectoryError("invalid key validity window")

    audiences = snapshot["audiences"]
    if not isinstance(audiences, list) or not audiences:
        raise DirectoryError("directory must contain audiences")
    audience_keys = set()
    for audience in audiences:
        _exact_with_optional(
            audience,
            AUDIENCE_FIELDS,
            AUDIENCE_OPTIONAL_FIELDS,
            "audience",
        )
        if audience["type"] not in {"direct", "group"}:
            raise DirectoryError("invalid audience type")
        audience_id = _identifier(audience["id"])
        audience_epoch = _integer(audience["epoch"], minimum=1)
        key = (audience["type"], audience_id, audience_epoch)
        if key in audience_keys:
            raise DirectoryError("duplicate audience epoch")
        audience_keys.add(key)
        if audience["status"] not in {"active", "retired", "revoked"}:
            raise DirectoryError("invalid audience status")
        for field in ("members", "allowed_senders"):
            values = audience[field]
            if (
                not isinstance(values, list)
                or not values
                or len(values) > protocol.MAX_RECIPIENTS
            ):
                raise DirectoryError(f"invalid audience {field}")
            normalized = [_identifier(value) for value in values]
            if len(set(normalized)) != len(normalized):
                raise DirectoryError(f"duplicate audience {field}")
            if not set(normalized) <= agent_ids:
                raise DirectoryError(f"unknown agent in audience {field}")
        if audience["type"] == "direct" and audience["members"] != [
            audience_id
        ]:
            raise DirectoryError("direct audience must contain only its ID")
        observers = audience.get("observers")
        if observers is not None:
            if audience["type"] != "direct":
                raise DirectoryError(
                    "observers are only valid for direct audiences"
                )
            if (
                not isinstance(observers, list)
                or not observers
                or len(observers) >= protocol.MAX_RECIPIENTS
            ):
                raise DirectoryError("invalid audience observers")
            normalized = [_identifier(value) for value in observers]
            if len(set(normalized)) != len(normalized):
                raise DirectoryError("duplicate audience observers")
            if not set(normalized) <= agent_ids:
                raise DirectoryError("unknown agent in audience observers")
            if set(normalized) & set(audience["members"]):
                raise DirectoryError("audience observers must not be members")
            if set(normalized) & set(audience["allowed_senders"]):
                raise DirectoryError(
                    "audience observers must not be allowed senders"
                )
            if len(audience_recipients(audience)) > protocol.MAX_RECIPIENTS:
                raise DirectoryError("too many audience recipients")
    protocol.canonical_json(snapshot)
    return snapshot


def _write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


class Directory:
    def __init__(self, snapshot: dict[str, Any]):
        self.snapshot = snapshot
        self.hash = directory_sha256(snapshot)
        self.epoch = snapshot["directory_epoch"]
        self.agents = {agent["id"]: agent for agent in snapshot["agents"]}
        self.audiences = {
            (item["type"], item["id"], item["epoch"]): item
            for item in snapshot["audiences"]
        }
        self.signing_keys = {}
        self.encryption_keys = {}
        for agent in snapshot["agents"]:
            for key in agent["signing_keys"]:
                self.signing_keys[key["kid"]] = {
                    **key,
                    "owner": agent["id"],
                }
            for key in agent["encryption_keys"]:
                self.encryption_keys[key["kid"]] = {
                    **key,
                    "owner": agent["id"],
                }

    @classmethod
    def load(
        cls,
        directory_path: Path | str,
        roots_path: Path | str,
        state_path: Path | str,
        *,
        now_ms: int,
    ) -> "Directory":
        snapshot = strict_json(Path(directory_path).read_bytes())
        roots = load_roots(roots_path)
        roots_hash = sha256(protocol.canonical_json(roots)).hexdigest()
        validate_directory(snapshot, roots, now_ms=now_ms)
        instance = cls(snapshot)
        state_path = Path(state_path)
        state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_fd = os.open(f"{state_path}.lock", lock_flags, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if state_path.exists():
                state = strict_json(
                    state_path.read_bytes(), max_bytes=16 * 1024
                )
                _exact(state, STATE_FIELDS, "directory state")
                if state["schema"] != "tribe-directory-state/v1":
                    raise DirectoryError("unsupported directory state")
                previous_epoch = _integer(
                    state["directory_epoch"], minimum=1
                )
                previous_hash = state["directory_sha256"]
                if state["roots_sha256"] != roots_hash:
                    raise DirectoryError(
                        "governance roots changed without explicit reprovision"
                    )
                if (
                    not isinstance(previous_hash, str)
                    or len(previous_hash) != 64
                    or any(
                        c not in "0123456789abcdef"
                        for c in previous_hash
                    )
                ):
                    raise DirectoryError(
                        "invalid persisted directory hash"
                    )
                if instance.epoch < previous_epoch:
                    raise DirectoryError("directory rollback rejected")
                if instance.epoch == previous_epoch:
                    if instance.hash != previous_hash:
                        raise DirectoryError(
                            "directory split view rejected"
                        )
                    return instance
                if (
                    instance.epoch != previous_epoch + 1
                    or snapshot["previous_sha256"] != previous_hash
                ):
                    raise DirectoryError("directory chain discontinuity")
            elif snapshot["previous_sha256"] is not None:
                raise DirectoryError(
                    "initial local directory must have no previous hash"
                )
            _write_state(
                state_path,
                {
                    "schema": "tribe-directory-state/v1",
                    "directory_epoch": instance.epoch,
                    "directory_sha256": instance.hash,
                    "roots_sha256": roots_hash,
                },
            )
            return instance
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def audience(
        self,
        audience_type: str,
        audience_id: str,
        epoch: int | None = None,
    ) -> dict[str, Any]:
        candidates = [
            value
            for key, value in self.audiences.items()
            if key[0] == audience_type
            and key[1] == audience_id
            and (epoch is None or key[2] == epoch)
            and value["status"] == "active"
        ]
        if not candidates:
            raise DirectoryError("unknown or inactive audience")
        return max(candidates, key=lambda value: value["epoch"])

    def active_key(
        self, agent_id: str, purpose: str, now_ms: int
    ) -> dict[str, Any]:
        agent = self.agents.get(agent_id)
        if not agent or agent["status"] != "active":
            raise DirectoryError("unknown or inactive agent")
        field = (
            "signing_keys" if purpose == "signing" else "encryption_keys"
        )
        candidates = [
            key
            for key in agent[field]
            if key["status"] == "active"
            and key["not_before_ms"] <= now_ms
            and (
                key["not_after_ms"] is None
                or now_ms < key["not_after_ms"]
            )
        ]
        if not candidates:
            raise DirectoryError(f"no active {purpose} key for {agent_id}")
        return max(candidates, key=lambda key: key["epoch"])

    def context(
        self,
        *,
        sender_id: str | None = None,
        receiver_id: str | None = None,
        now_ms: int,
        seen: list[str] | None = None,
    ) -> dict[str, Any]:
        authorized = []
        receiver_audiences = []
        audience_members = {}
        for audience in self.audiences.values():
            status = audience["status"]
            if status not in {"active", "retired"}:
                continue
            key = (
                f'{audience["type"]}:{audience["id"]}:'
                f'{audience["epoch"]}'
            )
            recipients = audience_recipients(audience)
            if status == "active":
                audience_members[key] = recipients
                if sender_id in audience["allowed_senders"]:
                    authorized.append(key)
            if receiver_id in recipients:
                audience_members[key] = recipients
                receiver_audiences.append(key)
        return {
            "now_ms": now_ms,
            "receiver_id": receiver_id,
            "seen": seen or [],
            "authorized_audiences": authorized,
            "receiver_audiences": receiver_audiences,
            "audience_members": audience_members,
            "signing_keys": self.signing_keys,
            "encryption_keys": self.encryption_keys,
        }
