"""Founded Tribe membership artifacts independent from transport audiences."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b"tribe/membership/v1\x00"
MAX_INVITATION_MS = 7 * 24 * 60 * 60 * 1000
SCHEMA_FIELDS = {
    "tribe-declaration/v1": {
        "schema", "founder_principal_id", "founder_epoch", "policy_ref",
        "nonce", "created_at_ms", "tribe_ref",
    },
    "tribe-invitation/v1": {
        "schema", "tribe_ref", "founder_epoch", "invite_id",
        "invitee_principal_id", "issued_at_ms", "expires_at_ms", "nonce",
        "founder_principal_id",
    },
    "tribe-acceptance/v1": {
        "schema", "tribe_ref", "founder_epoch", "invite_id",
        "invitation_hash", "member_principal_id", "accepted_at_ms",
    },
    "tribe-membership-change/v1": {
        "schema", "tribe_ref", "founder_epoch", "action",
        "member_principal_id", "actor_principal_id", "occurred_at_ms",
    },
    "tribe-founder-transfer/v1": {
        "schema", "tribe_ref", "founder_epoch",
        "current_founder_principal_id", "successor_principal_id",
        "occurred_at_ms",
    },
    "tribe-founder-acceptance/v1": {
        "schema", "tribe_ref", "previous_founder_epoch", "new_founder_epoch",
        "transfer_hash", "successor_principal_id", "occurred_at_ms",
    },
}


class MembershipError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode(value: str, size: int) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise MembershipError("invalid base64url") from exc
    if len(raw) != size or b64url(raw) != value:
        raise MembershipError("invalid base64url")
    return raw


def artifact_hash(core: Mapping[str, Any]) -> str:
    return hashlib.sha256(DOMAIN + canonical(core)).hexdigest()


def _validate_core(core: Any) -> dict[str, Any]:
    if not isinstance(core, dict) or core.get("schema") not in SCHEMA_FIELDS:
        raise MembershipError("unsupported membership artifact")
    if set(core) != SCHEMA_FIELDS[core["schema"]]:
        raise MembershipError("invalid membership artifact fields")
    tribe_ref = core["tribe_ref"]
    if (
        not isinstance(tribe_ref, str)
        or not tribe_ref.startswith("tribe:")
        or len(tribe_ref) != 70
        or any(char not in "0123456789abcdef" for char in tribe_ref[6:])
    ):
        raise MembershipError("invalid tribe_ref")
    for key, value in core.items():
        if key.endswith("_principal_id") and (
            not isinstance(value, str) or not 1 <= len(value) <= 128
        ):
            raise MembershipError(f"invalid {key}")
        if (key.endswith("_ms") or key.endswith("_epoch")) and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise MembershipError(f"invalid {key}")
        if key.endswith("_hash") and (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise MembershipError(f"invalid {key}")
    if core["schema"] == "tribe-declaration/v1" and core["founder_epoch"] != 1:
        raise MembershipError("declaration must start at founder epoch 1")
    if core["schema"] == "tribe-invitation/v1":
        try:
            uuid.UUID(core["invite_id"])
        except (ValueError, TypeError) as exc:
            raise MembershipError("invalid invite_id") from exc
        if not core["issued_at_ms"] < core["expires_at_ms"] <= core["issued_at_ms"] + MAX_INVITATION_MS:
            raise MembershipError("invalid invitation lifetime")
    if core["schema"] == "tribe-membership-change/v1" and core["action"] not in {"expel", "leave"}:
        raise MembershipError("invalid membership action")
    if core["schema"] == "tribe-founder-acceptance/v1" and core["new_founder_epoch"] != core["previous_founder_epoch"] + 1:
        raise MembershipError("invalid founder epoch transition")
    return core


def tribe_declaration(*, signer: "MembershipSigner", policy_ref: str, nonce: str, created_at_ms: int) -> dict[str, Any]:
    core = {
        "schema": "tribe-declaration/v1", "founder_principal_id": signer.principal_id,
        "founder_epoch": 1, "policy_ref": policy_ref, "nonce": nonce,
        "created_at_ms": created_at_ms,
    }
    tribe_ref = "tribe:" + hashlib.sha256(b"tribe/ref/v1\x00" + canonical(core)).hexdigest()
    return signer.sign({**core, "tribe_ref": tribe_ref})


@dataclass(frozen=True)
class MembershipSigner:
    principal_id: str
    kid: str
    private_key: Ed25519PrivateKey

    def sign(self, core: Mapping[str, Any]) -> dict[str, Any]:
        digest = artifact_hash(core)
        signature = self.private_key.sign(DOMAIN + bytes.fromhex(digest))
        return {**core, "artifact_hash": digest, "signature": {"alg": "Ed25519", "kid": self.kid, "value": b64url(signature)}}


def verify(artifact: Any, public_keys: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(artifact, dict) or set(artifact) < {"artifact_hash", "signature"}:
        raise MembershipError("invalid artifact")
    core = {key: value for key, value in artifact.items() if key not in {"artifact_hash", "signature"}}
    _validate_core(core)
    if artifact["artifact_hash"] != artifact_hash(core):
        raise MembershipError("artifact hash mismatch")
    signature = artifact["signature"]
    if not isinstance(signature, dict) or set(signature) != {"alg", "kid", "value"} or signature["alg"] != "Ed25519":
        raise MembershipError("invalid signature")
    key_record = public_keys.get(signature["kid"])
    if key_record is None:
        raise MembershipError("unknown signer")
    if isinstance(key_record, dict):
        public = key_record.get("public_key")
        owner = key_record.get("owner")
    else:
        public = key_record
        owner = None
    actor_fields = {
        "tribe-declaration/v1": "founder_principal_id",
        "tribe-invitation/v1": "founder_principal_id",
        "tribe-acceptance/v1": "member_principal_id",
        "tribe-membership-change/v1": "actor_principal_id",
        "tribe-founder-transfer/v1": "current_founder_principal_id",
        "tribe-founder-acceptance/v1": "successor_principal_id",
    }
    actor_field = actor_fields.get(core.get("schema"))
    if actor_field is None or (owner is not None and owner != core.get(actor_field)):
        raise MembershipError("signer does not own artifact actor")
    try:
        Ed25519PublicKey.from_public_bytes(decode(public, 32)).verify(
            decode(signature["value"], 64), DOMAIN + bytes.fromhex(artifact["artifact_hash"])
        )
    except (InvalidSignature, ValueError) as exc:
        raise MembershipError("invalid signature") from exc
    return artifact


def invitation(
    declaration: Mapping[str, Any], *, invitee_principal_id: str,
    signer: MembershipSigner, expires_at_ms: int, now_ms: int | None = None,
) -> dict[str, Any]:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if signer.principal_id != declaration["founder_principal_id"]:
        raise MembershipError("only founder may invite")
    if not now < expires_at_ms <= now + MAX_INVITATION_MS:
        raise MembershipError("invalid invitation expiry")
    return signer.sign({
        "schema": "tribe-invitation/v1", "tribe_ref": declaration["tribe_ref"],
        "founder_epoch": declaration["founder_epoch"], "invite_id": str(uuid.uuid4()),
        "invitee_principal_id": invitee_principal_id, "issued_at_ms": now,
        "expires_at_ms": expires_at_ms, "nonce": b64url(uuid.uuid4().bytes + uuid.uuid4().bytes),
        "founder_principal_id": signer.principal_id,
    })


def acceptance(invite: Mapping[str, Any], *, signer: MembershipSigner, now_ms: int | None = None) -> dict[str, Any]:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if signer.principal_id != invite["invitee_principal_id"] or now >= invite["expires_at_ms"]:
        raise MembershipError("invitation unavailable to principal")
    return signer.sign({
        "schema": "tribe-acceptance/v1", "tribe_ref": invite["tribe_ref"],
        "founder_epoch": invite["founder_epoch"], "invite_id": invite["invite_id"],
        "invitation_hash": invite["artifact_hash"], "member_principal_id": signer.principal_id,
        "accepted_at_ms": now,
    })


def membership_change(
    *, tribe_ref: str, founder_epoch: int, member_principal_id: str,
    action: str, signer: MembershipSigner, occurred_at_ms: int,
) -> dict[str, Any]:
    if action not in {"expel", "leave"}:
        raise MembershipError("invalid membership action")
    if action == "leave" and signer.principal_id != member_principal_id:
        raise MembershipError("member must sign leave")
    return signer.sign({
        "schema": "tribe-membership-change/v1", "tribe_ref": tribe_ref,
        "founder_epoch": founder_epoch, "action": action,
        "member_principal_id": member_principal_id, "actor_principal_id": signer.principal_id,
        "occurred_at_ms": occurred_at_ms,
    })


def founder_transfer(
    *, tribe_ref: str, founder_epoch: int, successor_principal_id: str,
    signer: MembershipSigner, occurred_at_ms: int,
) -> dict[str, Any]:
    return signer.sign({
        "schema": "tribe-founder-transfer/v1", "tribe_ref": tribe_ref,
        "founder_epoch": founder_epoch, "current_founder_principal_id": signer.principal_id,
        "successor_principal_id": successor_principal_id, "occurred_at_ms": occurred_at_ms,
    })


def founder_acceptance(transfer: Mapping[str, Any], *, signer: MembershipSigner, occurred_at_ms: int) -> dict[str, Any]:
    if signer.principal_id != transfer["successor_principal_id"]:
        raise MembershipError("only successor may accept founder role")
    return signer.sign({
        "schema": "tribe-founder-acceptance/v1", "tribe_ref": transfer["tribe_ref"],
        "previous_founder_epoch": transfer["founder_epoch"],
        "new_founder_epoch": transfer["founder_epoch"] + 1,
        "transfer_hash": transfer["artifact_hash"],
        "successor_principal_id": signer.principal_id, "occurred_at_ms": occurred_at_ms,
    })


@dataclass
class MembershipState:
    tribe_ref: str
    founder_principal_id: str
    public_keys: Mapping[str, Any]
    founder_epoch: int = 1
    members: set[str] = field(default_factory=set)
    used_invites: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.members.add(self.founder_principal_id)

    def accept(self, invite: Mapping[str, Any], accepted: Mapping[str, Any]) -> None:
        verify(invite, self.public_keys)
        verify(accepted, self.public_keys)
        if invite["tribe_ref"] != self.tribe_ref or invite["founder_epoch"] != self.founder_epoch or invite["founder_principal_id"] != self.founder_principal_id:
            raise MembershipError("invitation from inactive founder")
        if accepted["invitation_hash"] != invite["artifact_hash"] or accepted["invite_id"] != invite["invite_id"]:
            raise MembershipError("acceptance does not bind invitation")
        if accepted["member_principal_id"] != invite["invitee_principal_id"]:
            raise MembershipError("acceptance principal does not match invitee")
        if not invite["issued_at_ms"] <= accepted["accepted_at_ms"] < invite["expires_at_ms"]:
            raise MembershipError("acceptance outside invitation lifetime")
        if invite["invite_id"] in self.used_invites:
            raise MembershipError("invitation already used")
        self.used_invites.add(invite["invite_id"])
        self.members.add(accepted["member_principal_id"])

    def change(self, artifact: Mapping[str, Any]) -> None:
        verify(artifact, self.public_keys)
        if artifact["tribe_ref"] != self.tribe_ref or artifact["founder_epoch"] != self.founder_epoch:
            raise MembershipError("membership change at wrong epoch")
        if artifact["action"] == "expel" and artifact["actor_principal_id"] != self.founder_principal_id:
            raise MembershipError("only founder may expel")
        if artifact["action"] == "leave" and artifact["actor_principal_id"] != artifact["member_principal_id"]:
            raise MembershipError("invalid leave")
        if artifact["member_principal_id"] == self.founder_principal_id:
            raise MembershipError("founder must transfer before leaving")
        self.members.discard(artifact["member_principal_id"])

    def transfer(self, transfer: Mapping[str, Any], accepted: Mapping[str, Any]) -> None:
        verify(transfer, self.public_keys)
        verify(accepted, self.public_keys)
        if transfer["tribe_ref"] != self.tribe_ref or transfer["founder_epoch"] != self.founder_epoch or transfer["current_founder_principal_id"] != self.founder_principal_id:
            raise MembershipError("invalid founder transfer")
        if accepted["transfer_hash"] != transfer["artifact_hash"] or accepted["new_founder_epoch"] != self.founder_epoch + 1:
            raise MembershipError("invalid founder acceptance")
        if accepted["successor_principal_id"] != transfer["successor_principal_id"]:
            raise MembershipError("founder acceptance principal mismatch")
        if accepted["successor_principal_id"] not in self.members:
            raise MembershipError("founder successor is not a member")
        if accepted["occurred_at_ms"] < transfer["occurred_at_ms"]:
            raise MembershipError("founder acceptance predates transfer")
        self.founder_principal_id = accepted["successor_principal_id"]
        self.founder_epoch += 1
