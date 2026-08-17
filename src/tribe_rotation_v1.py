"""Local-only, forward-only Tribe v1 agent key rotation ceremony.

The transport carrying an announcement is never authority.  Announcements are
bound to an exact signed directory and governance-roots hash and are signed by
the agent's currently active signing key.  Governance composition is keyless:
it consumes public announcements and emits an unsigned successor for the
existing offline threshold-signing tools.
"""

from __future__ import annotations

import copy
import fcntl
import json
import os
import secrets
import stat
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

import tribe_protocol_v1 as protocol
from tribe_crypto_v1 import KeyBundle, b64url
from tribe_directory_v1 import (
    Directory,
    DirectoryError,
    b64url_decode,
    directory_sha256,
    validate_directory,
    validate_unsigned_directory_candidate,
)


ANNOUNCEMENT_DOMAIN = b"tribe/v1/key-rotation-announcement\x00"
ANNOUNCEMENT_SCHEMA = "tribe-key-rotation-announcement/v1"
RECEIPT_SCHEMA = "tribe-key-rotation-compose-receipt/v1"
MS_PER_DAY = 86_400_000
MAX_ANNOUNCEMENT_LIFETIME_MS = 7 * MS_PER_DAY
DEFAULT_DRAIN_MS = 72 * 60 * 60 * 1000
ROTATION_VALIDITY_DAYS = 30

ANNOUNCEMENT_FIELDS = {
    "schema",
    "ceremony_id",
    "agent_id",
    "base_directory_epoch",
    "base_directory_sha256",
    "roots_sha256",
    "previous_signing_kid",
    "previous_encryption_kid",
    "next_signing",
    "next_encryption",
    "activation_at_ms",
    "issued_at_ms",
    "expires_at_ms",
    "nonce",
    "signer_kid",
    "signature",
}
PUBLIC_KEY_FIELDS = {"kid", "epoch", "public_key"}


class RotationError(ValueError):
    """A closed rotation precondition or artifact was invalid."""


def roots_sha256(roots: dict[str, Any]) -> str:
    return sha256(protocol.canonical_json(roots)).hexdigest()


def _unsigned_announcement(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


def announcement_preimage(value: dict[str, Any]) -> bytes:
    return ANNOUNCEMENT_DOMAIN + protocol.canonical_json(
        _unsigned_announcement(value)
    )


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RotationError(f"invalid {label} fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not protocol.IDENTIFIER.fullmatch(value):
        raise RotationError(f"invalid {label}")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > 9_007_199_254_740_991
    ):
        raise RotationError(f"invalid {label}")
    return value


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _serialize(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def prepare_rotation(
    directory: Directory,
    roots: dict[str, Any],
    current_bundle_path: Path | str,
    staged_bundle_path: Path | str,
    *,
    ceremony_id: str,
    activation_at_ms: int,
    expires_at_ms: int,
    now_ms: int,
) -> dict[str, Any]:
    """Generate one local successor bundle and public signed announcement.

    The current bundle is never changed.  The staged private bundle is created
    with exclusive create and retains the old encryption private keys needed
    to drain already-encrypted envelopes.
    """
    _identifier(ceremony_id, "ceremony ID")
    activation = _integer(activation_at_ms, "activation time", minimum=1)
    issued = _integer(now_ms, "issuance time", minimum=1)
    expires = _integer(expires_at_ms, "announcement expiry", minimum=1)
    if not issued < expires <= activation:
        raise RotationError(
            "announcement must expire after issuance and no later than activation"
        )
    if expires - issued > MAX_ANNOUNCEMENT_LIFETIME_MS:
        raise RotationError("announcement lifetime exceeds seven days")
    try:
        validate_directory(directory.snapshot, roots, now_ms=issued)
    except DirectoryError as exc:
        raise RotationError("rotation base is not a valid signed directory") from exc

    bundle = KeyBundle.load(current_bundle_path)
    bundle.verify_against(directory, issued)
    agent = directory.agents[bundle.agent_id]
    current_signing = directory.active_key(bundle.agent_id, "signing", issued)
    current_encryption = directory.active_key(
        bundle.agent_id, "encryption", issued
    )
    if current_encryption["kid"] not in bundle.encryption_private:
        raise RotationError("current encryption private key is absent")

    signing_epoch = max(key["epoch"] for key in agent["signing_keys"]) + 1
    encryption_epoch = (
        max(key["epoch"] for key in agent["encryption_keys"]) + 1
    )
    signing_kid = f"{bundle.agent_id}/sig/{signing_epoch}"
    encryption_kid = f"{bundle.agent_id}/enc/{encryption_epoch}"
    known_kids = set(directory.signing_keys) | set(directory.encryption_keys)
    if signing_kid in known_kids or encryption_kid in known_kids:
        raise RotationError("successor key ID collides with the base directory")

    next_signing = ed25519.Ed25519PrivateKey.generate()
    next_encryption = x25519.X25519PrivateKey.generate()
    staged = {
        "schema": "tribe-key-bundle/v1",
        "agent_id": bundle.agent_id,
        "signing": {
            "kid": signing_kid,
            "private_key": b64url(next_signing.private_bytes_raw()),
        },
        "encryption": [
            {
                "kid": kid,
                "private_key": b64url(private.private_bytes_raw()),
            }
            for kid, private in sorted(bundle.encryption_private.items())
        ]
        + [
            {
                "kid": encryption_kid,
                "private_key": b64url(next_encryption.private_bytes_raw()),
            }
        ],
    }
    _write_exclusive(Path(staged_bundle_path), _serialize(staged), 0o600)

    announcement = {
        "schema": ANNOUNCEMENT_SCHEMA,
        "ceremony_id": ceremony_id,
        "agent_id": bundle.agent_id,
        "base_directory_epoch": directory.epoch,
        "base_directory_sha256": directory.hash,
        "roots_sha256": roots_sha256(roots),
        "previous_signing_kid": current_signing["kid"],
        "previous_encryption_kid": current_encryption["kid"],
        "next_signing": {
            "kid": signing_kid,
            "epoch": signing_epoch,
            "public_key": b64url(next_signing.public_key().public_bytes_raw()),
        },
        "next_encryption": {
            "kid": encryption_kid,
            "epoch": encryption_epoch,
            "public_key": b64url(
                next_encryption.public_key().public_bytes_raw()
            ),
        },
        "activation_at_ms": activation,
        "issued_at_ms": issued,
        "expires_at_ms": expires,
        "nonce": b64url(secrets.token_bytes(24)),
        "signer_kid": bundle.signing_kid,
        "signature": "",
    }
    announcement["signature"] = b64url(
        bundle.signing_private.sign(announcement_preimage(announcement))
    )
    return announcement


def verify_announcement(
    snapshot: dict[str, Any],
    roots: dict[str, Any],
    announcement: Any,
    *,
    now_ms: int,
    ceremony_id: str,
    activation_at_ms: int,
) -> dict[str, Any]:
    try:
        validate_directory(snapshot, roots, now_ms=now_ms)
    except DirectoryError as exc:
        raise RotationError("announcement base is not a valid signed directory") from exc
    value = _exact(announcement, ANNOUNCEMENT_FIELDS, "announcement")
    if value["schema"] != ANNOUNCEMENT_SCHEMA:
        raise RotationError("unsupported announcement schema")
    if value["ceremony_id"] != ceremony_id:
        raise RotationError("announcement ceremony mismatch")
    directory = Directory(snapshot)
    if (
        value["base_directory_epoch"] != directory.epoch
        or value["base_directory_sha256"] != directory.hash
        or value["roots_sha256"] != roots_sha256(roots)
    ):
        raise RotationError("announcement is bound to a different base")
    issued = _integer(value["issued_at_ms"], "issuance time", minimum=1)
    expires = _integer(value["expires_at_ms"], "expiry time", minimum=1)
    if (
        not issued < expires
        or issued > now_ms + protocol.MAX_CLOCK_SKEW_MS
        or not now_ms < expires
    ):
        raise RotationError("announcement is not currently valid")
    if expires - issued > MAX_ANNOUNCEMENT_LIFETIME_MS:
        raise RotationError("announcement lifetime exceeds seven days")
    if value["activation_at_ms"] != activation_at_ms or expires > activation_at_ms:
        raise RotationError("announcement activation mismatch")
    agent_id = _identifier(value["agent_id"], "agent ID")
    agent = directory.agents.get(agent_id)
    if not agent or agent["status"] != "active":
        raise RotationError("unknown or inactive announcing agent")

    current_signing = directory.active_key(agent_id, "signing", issued)
    current_encryption = directory.active_key(agent_id, "encryption", issued)
    if (
        value["previous_signing_kid"] != current_signing["kid"]
        or value["previous_encryption_kid"] != current_encryption["kid"]
        or value["signer_kid"] != current_signing["kid"]
    ):
        raise RotationError("announcement is not authorized by current keys")

    next_signing = _exact(
        value["next_signing"], PUBLIC_KEY_FIELDS, "next signing key"
    )
    next_encryption = _exact(
        value["next_encryption"], PUBLIC_KEY_FIELDS, "next encryption key"
    )
    expected_signing_epoch = (
        max(key["epoch"] for key in agent["signing_keys"]) + 1
    )
    expected_encryption_epoch = (
        max(key["epoch"] for key in agent["encryption_keys"]) + 1
    )
    known_kids = set(directory.signing_keys) | set(directory.encryption_keys)
    expectations = (
        (next_signing, expected_signing_epoch, "sig"),
        (next_encryption, expected_encryption_epoch, "enc"),
    )
    for key, expected_epoch, purpose in expectations:
        kid = _identifier(key["kid"], "successor key ID")
        if (
            key["epoch"] != expected_epoch
            or kid != f"{agent_id}/{purpose}/{expected_epoch}"
            or kid in known_kids
        ):
            raise RotationError("non-monotonic or colliding successor key")
        b64url_decode(key["public_key"], 32)
    b64url_decode(value["nonce"], 24)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(
            b64url_decode(current_signing["public_key"], 32)
        ).verify(
            b64url_decode(value["signature"], 64),
            announcement_preimage(value),
        )
    except InvalidSignature as exc:
        raise RotationError("invalid announcement signature") from exc
    return value


def compose_rotation(
    snapshot: dict[str, Any],
    roots: dict[str, Any],
    announcements: list[dict[str, Any]],
    *,
    now_ms: int,
    ceremony_id: str,
    activation_at_ms: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build one content-addressed D+1 from an exact announcement set."""
    active_agents = sorted(
        agent["id"] for agent in snapshot["agents"] if agent["status"] == "active"
    )
    verified: dict[str, dict[str, Any]] = {}
    nonces: set[str] = set()
    for announcement in announcements:
        value = verify_announcement(
            snapshot,
            roots,
            announcement,
            now_ms=now_ms,
            ceremony_id=ceremony_id,
            activation_at_ms=activation_at_ms,
        )
        agent_id = value["agent_id"]
        if agent_id in verified or value["nonce"] in nonces:
            raise RotationError("duplicate agent or replayed announcement")
        verified[agent_id] = value
        nonces.add(value["nonce"])
    if sorted(verified) != active_agents:
        raise RotationError("rotation requires exactly every active agent")

    # A ceremony may shorten the authority window of the keys it replaces,
    # but it must never revive or extend one.  In particular, an activation
    # scheduled after a current key's original expiry would turn the assignment
    # below into an authority extension and would also create a validity gap
    # before the successor becomes active.
    for agent in snapshot["agents"]:
        rotation = verified.get(agent["id"])
        if rotation is None:
            continue
        for purpose, previous_field in (
            ("signing_keys", "previous_signing_kid"),
            ("encryption_keys", "previous_encryption_kid"),
        ):
            previous = next(
                key
                for key in agent[purpose]
                if key["kid"] == rotation[previous_field]
            )
            original_expiry = previous["not_after_ms"]
            if (
                original_expiry is not None
                and activation_at_ms > original_expiry
            ):
                raise RotationError(
                    "rotation activation exceeds a previous key expiry"
                )

    candidate = copy.deepcopy(snapshot)
    candidate["directory_epoch"] = snapshot["directory_epoch"] + 1
    candidate["previous_sha256"] = directory_sha256(snapshot)
    # Composition time is verification context, not candidate content.  The
    # exact signed announcement set therefore produces identical bytes across
    # processes, retries, ordering, and later (still-valid) compose times.
    candidate_issued_at_ms = max(
        value["issued_at_ms"] for value in verified.values()
    )
    candidate["issued_at_ms"] = candidate_issued_at_ms
    candidate["expires_at_ms"] = (
        candidate_issued_at_ms + ROTATION_VALIDITY_DAYS * MS_PER_DAY
    )
    if candidate["expires_at_ms"] <= activation_at_ms + DEFAULT_DRAIN_MS:
        raise RotationError("successor expires before the rotation drain completes")
    candidate["governance"] = {
        "threshold": snapshot["governance"]["threshold"],
        "signatures": [],
    }
    new_key_expiry = candidate["expires_at_ms"]
    for agent in candidate["agents"]:
        rotation = verified.get(agent["id"])
        if rotation is None:
            continue
        for purpose, previous_field in (
            ("signing_keys", "previous_signing_kid"),
            ("encryption_keys", "previous_encryption_kid"),
        ):
            for key in agent[purpose]:
                if key["kid"] == rotation[previous_field]:
                    # The old private decryption key remains in the staged
                    # bundle for queued pre-cut ciphertext, but neither old
                    # public key is authorized for newly issued traffic after
                    # the cut.
                    original_expiry = key["not_after_ms"]
                    key["not_after_ms"] = (
                        activation_at_ms
                        if original_expiry is None
                        else min(activation_at_ms, original_expiry)
                    )
        agent["signing_keys"].append(
            {
                **rotation["next_signing"],
                "status": "active",
                "not_before_ms": activation_at_ms,
                "not_after_ms": new_key_expiry,
            }
        )
        agent["encryption_keys"].append(
            {
                **rotation["next_encryption"],
                "status": "active",
                "not_before_ms": activation_at_ms,
                "not_after_ms": new_key_expiry,
            }
        )

    # Audience records have no temporal validity fields in the closed v1
    # schema.  Rotating them in a directory that may be preloaded would make
    # the successor epoch authoritative immediately, before key activation.
    # Key rotation therefore preserves the audience registry byte-for-byte;
    # an audience membership/epoch transition is a separate ceremony.

    # Validate every closed structural and semantic rule before emitting the
    # candidate.  This explicitly unsigned validation never grants runtime
    # authority; the normal loader still requires the governance threshold.
    try:
        validate_unsigned_directory_candidate(candidate, roots, now_ms=now_ms)
    except DirectoryError as exc:
        raise RotationError("rotation candidate is semantically invalid") from exc

    announcement_hashes = [
        sha256(protocol.canonical_json(verified[agent])).hexdigest()
        for agent in active_agents
    ]
    ceremony_descriptor = {
        "schema": "tribe-key-rotation-ceremony/v1",
        "ceremony_id": ceremony_id,
        "base_directory_epoch": snapshot["directory_epoch"],
        "base_directory_sha256": directory_sha256(snapshot),
        "roots_sha256": roots_sha256(roots),
        "activation_at_ms": activation_at_ms,
        "validity_days": ROTATION_VALIDITY_DAYS,
        "announcement_sha256": announcement_hashes,
    }
    ceremony_sha256 = sha256(
        protocol.canonical_json(ceremony_descriptor)
    ).hexdigest()
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "ceremony_id": ceremony_id,
        "base_directory_epoch": snapshot["directory_epoch"],
        "base_directory_sha256": directory_sha256(snapshot),
        "candidate_directory_epoch": candidate["directory_epoch"],
        "candidate_unsigned_sha256": directory_sha256(candidate),
        "roots_sha256": roots_sha256(roots),
        "activation_at_ms": activation_at_ms,
        "ceremony_sha256": ceremony_sha256,
        "agent_ids": active_agents,
        "announcement_sha256": announcement_hashes,
        "audience_successors": 0,
        "contains_private_material": False,
    }
    return candidate, receipt


def build_forward_recovery(
    signed_rotation: dict[str, Any],
    roots: dict[str, Any],
    compromised_kids: set[str],
    *,
    now_ms: int,
    validity_days: int = 30,
) -> dict[str, Any]:
    """Revoke keys only when signed D already has uncompromised coverage.

    This helper does not create replacement keys.  It is executable only for
    a base which already contains another active signing and encryption key
    covering each affected agent through the candidate expiry.
    """
    try:
        validate_directory(signed_rotation, roots, now_ms=now_ms)
    except DirectoryError as exc:
        raise RotationError("recovery base is not a valid signed directory") from exc
    if not compromised_kids:
        raise RotationError("forward recovery requires explicit key IDs")
    known = {
        key["kid"]
        for agent in signed_rotation["agents"]
        for purpose in ("signing_keys", "encryption_keys")
        for key in agent[purpose]
    }
    if not compromised_kids <= known:
        raise RotationError("forward recovery names an unknown key")
    candidate = copy.deepcopy(signed_rotation)
    candidate["directory_epoch"] += 1
    candidate["previous_sha256"] = directory_sha256(signed_rotation)
    candidate["issued_at_ms"] = now_ms
    requested_expiry = now_ms + validity_days * MS_PER_DAY
    candidate["expires_at_ms"] = min(
        requested_expiry, signed_rotation["expires_at_ms"]
    )
    if candidate["expires_at_ms"] <= now_ms:
        raise RotationError("forward recovery has no remaining validity")
    candidate["governance"] = {
        "threshold": signed_rotation["governance"]["threshold"],
        "signatures": [],
    }
    for agent in candidate["agents"]:
        for purpose in ("signing_keys", "encryption_keys"):
            for key in agent[purpose]:
                if key["kid"] in compromised_kids:
                    key["status"] = "revoked"
                    key["not_after_ms"] = min(
                        key["not_after_ms"] or now_ms, now_ms
                    )
    for agent in candidate["agents"]:
        for purpose in ("signing_keys", "encryption_keys"):
            if not any(
                key["status"] == "active"
                and key["not_before_ms"] <= now_ms
                and (
                    key["not_after_ms"] is None
                    or candidate["expires_at_ms"] <= key["not_after_ms"]
                )
                for key in agent[purpose]
            ):
                raise RotationError(
                    "forward recovery requires a pre-existing uncompromised "
                    f"successor covering {agent['id']} {purpose}"
                )
    protocol.canonical_json(candidate)
    return candidate


def activate_staged_bundle(
    current_bundle_path: Path | str,
    staged_bundle_path: Path | str,
    directory: Directory,
    *,
    now_ms: int,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Atomically activate a locally staged successor; safe to retry."""
    current_path = Path(current_bundle_path)
    staged_path = Path(staged_bundle_path)
    lock_path = current_path.with_name(current_path.name + ".rotation.lock")
    lock_fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _validate_private_descriptor(lock_fd, lock_path)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        # Inspect and open only after the lock.  Each bundle is read exactly
        # once from an O_NOFOLLOW descriptor; parsing, verification and the
        # eventual copy all consume those same immutable byte strings.
        current_bytes, current_stat = _read_private_regular(current_path)
        staged_bytes, _ = _read_private_regular(staged_path)
        current = KeyBundle.from_bytes(current_bytes)
        staged = KeyBundle.from_bytes(staged_bytes)
        if current.agent_id != staged.agent_id:
            raise RotationError("staged bundle belongs to another agent")
        # Revalidate even the idempotent path.  Equality with the on-disk
        # bundle is not authority if the successor is early, expired, revoked,
        # or lacks the encryption key selected by the signed directory.
        staged.verify_against(directory, now_ms)
        if current.signing_kid == staged.signing_kid:
            if current_bytes != staged_bytes:
                raise RotationError("activated bundle differs from staged bundle")
            return {
                "activated": False,
                "reason": "already-current",
                "agent_id": staged.agent_id,
                "signing_kid": staged.signing_kid,
            }
        if not set(current.encryption_private) <= set(staged.encryption_private):
            raise RotationError("staged bundle drops encryption keys before drain")
        for kid, private in current.encryption_private.items():
            if (
                private.private_bytes_raw()
                != staged.encryption_private[kid].private_bytes_raw()
            ):
                raise RotationError(
                    "staged bundle substitutes retained private material"
                )
        backup = current_path.with_name(
            f"{current_path.name}.pre-{staged.signing_kid.replace('/', '_')}"
        )
        try:
            _write_exclusive(backup, current_bytes, 0o600)
        except FileExistsError:
            backup_bytes, _ = _read_private_regular(backup)
            if backup_bytes != current_bytes:
                raise RotationError("activation backup conflicts with current bundle")
        descriptor, name = tempfile.mkstemp(
            dir=current_path.parent, prefix=f".{current_path.name}.", suffix=".tmp"
        )
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(staged_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            if fault_hook:
                fault_hook("before-commit")
            _assert_same_regular(current_path, current_stat)
            os.replace(temporary, current_path)
            directory_fd = os.open(current_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return {
            "activated": True,
            "agent_id": staged.agent_id,
            "previous_signing_kid": current.signing_kid,
            "signing_kid": staged.signing_kid,
            "retained_encryption_kids": sorted(current.encryption_private),
            "backup": backup.name,
        }
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _validate_private_descriptor(descriptor: int, path: Path) -> os.stat_result:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise RotationError(f"rotation file is not regular: {path.name}")
    if info.st_uid != os.geteuid():
        raise RotationError(f"rotation file has wrong owner: {path.name}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RotationError(f"rotation file is not owner-only: {path.name}")
    return info


def _read_private_regular(path: Path) -> tuple[bytes, os.stat_result]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RotationError(f"rotation file is not regular: {path.name}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = _validate_private_descriptor(descriptor, path)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise RotationError(f"rotation file changed while opening: {path.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(64 * 1024 + 1)
        after = os.fstat(descriptor)
        if len(payload) > 64 * 1024 or (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RotationError(f"rotation file changed while reading: {path.name}")
        return payload, after
    finally:
        os.close(descriptor)


def _assert_same_regular(path: Path, expected: os.stat_result) -> None:
    current = path.lstat()
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.geteuid()
        or stat.S_IMODE(current.st_mode) & 0o077
        or (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )
        != (
            expected.st_dev,
            expected.st_ino,
            expected.st_size,
            expected.st_mtime_ns,
            expected.st_ctime_ns,
        )
    ):
        raise RotationError("current bundle changed during activation")
