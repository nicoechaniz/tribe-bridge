"""Content-addressed, zero-SSH provisioning for an authorized Tribe client.

Provisioning is not enrollment or governance.  A signed package can only bind
public deployment configuration to an already governance-signed directory and
to private keys which are already present on the client.  Apply preserves the
anti-rollback high-water mark and uses a restartable journal.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import stat
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import tribe_protocol_v1 as protocol
from tribe_crypto_v1 import KeyBundle, b64url
from tribe_directory_v1 import (
    Directory,
    b64url_decode,
    directory_sha256,
    strict_json,
    validate_directory,
)


MANIFEST_DOMAIN = b"tribe/v1/provisioning-manifest\x00"
MANIFEST_SCHEMA = "tribe-provisioning/v1"
AUTHORITY_SCHEMA = "tribe-provisioning-authority/v1"
PRIVATE_AUTHORITY_SCHEMA = "tribe-provisioning-private/v1"
STATE_SCHEMA = "tribe-directory-state/v1"
JOURNAL_SCHEMA = "tribe-provisioning-journal/v1"
HIGH_WATER_SCHEMA = "tribe-provisioning-high-water/v1"
MAX_MANIFEST_LIFETIME_MS = 7 * 86_400_000
MAX_ARTIFACT_BYTES = 1024 * 1024
PACKAGE_FILES = {
    "directory.json",
    "governance-roots.json",
    "manifest.json",
}

MANIFEST_FIELDS = {
    "schema",
    "provisioning_id",
    "agent_id",
    "created_at_ms",
    "expires_at_ms",
    "directory_epoch",
    "directory_sha256",
    "roots_sha256",
    "artifacts",
    "expected_signing_kid",
    "expected_encryption_kids",
    "required_audiences",
    "routes",
    "inbox_endpoints",
    "local_agent_ids",
    "build_commit",
    "signer_kid",
    "signature",
}
AUDIENCE_FIELDS = {"type", "id", "epoch"}
AUTHORITY_FIELDS = {"schema", "kid", "public_key"}
PRIVATE_AUTHORITY_FIELDS = {"schema", "kid", "private_key"}
STATE_FIELDS = {
    "schema",
    "directory_epoch",
    "directory_sha256",
    "roots_sha256",
}
HIGH_WATER_FIELDS = {
    "schema",
    "target_agent_id",
    "directory_epoch",
    "directory_sha256",
    "roots_sha256",
    "package_sha256",
}
JOURNAL_FIELDS = {
    "schema",
    "package_sha256",
    "agent_id",
    "target_directory_sha256",
    "authorized_at_ms",
}


class ProvisioningError(ValueError):
    """A package, local precondition, or crash-recovery state was invalid."""


def _serialize(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _hash(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _roots_hash(roots: dict[str, Any]) -> str:
    return sha256(protocol.canonical_json(roots)).hexdigest()


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProvisioningError(f"invalid {label} fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not protocol.IDENTIFIER.fullmatch(value):
        raise ProvisioningError(f"invalid {label}")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > 9_007_199_254_740_991
    ):
        raise ProvisioningError(f"invalid {label}")
    return value


def _regular_file(path: Path, *, private: bool = False) -> bytes:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProvisioningError(f"artifact is not a regular file: {path.name}")
    if info.st_uid != os.geteuid():
        raise ProvisioningError(f"artifact has the wrong owner: {path.name}")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise ProvisioningError(f"private artifact is not owner-only: {path.name}")
    if info.st_size <= 0 or info.st_size > MAX_ARTIFACT_BYTES:
        raise ProvisioningError(f"artifact has invalid size: {path.name}")
    return path.read_bytes()


def _validate_package_inventory(package: Path) -> None:
    try:
        info = package.lstat()
        names = {entry.name for entry in package.iterdir()}
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        raise ProvisioningError("invalid provisioning package directory") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or names != PACKAGE_FILES
    ):
        raise ProvisioningError("invalid provisioning package inventory")


def _write_atomic(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
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


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _manifest_preimage(value: dict[str, Any]) -> bytes:
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    return MANIFEST_DOMAIN + protocol.canonical_json(unsigned)


def _validate_url(value: Any, label: str, *, loopback_only: bool) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ProvisioningError(f"invalid {label}")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ProvisioningError(f"invalid {label}")
    if loopback_only and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ProvisioningError("@localhost provisioning routes must be loopback")
    return value


def _validate_routes(value: Any, *, loopback_only: bool) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 256:
        raise ProvisioningError("invalid routes")
    for target, routes in value.items():
        _identifier(target, "route target")
        if not isinstance(routes, dict) or not routes or set(routes) - {"direct", "hub"}:
            raise ProvisioningError("invalid route map")
        for kind, url in routes.items():
            _validate_url(url, f"{kind} route", loopback_only=loopback_only)
    return value


def _validate_audiences(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ProvisioningError("at least one required audience is needed")
    seen = set()
    for audience in value:
        _exact(audience, AUDIENCE_FIELDS, "required audience")
        if audience["type"] not in {"direct", "group"}:
            raise ProvisioningError("invalid required audience type")
        _identifier(audience["id"], "required audience ID")
        _integer(audience["epoch"], "required audience epoch", minimum=1)
        key = (audience["type"], audience["id"], audience["epoch"])
        if key in seen:
            raise ProvisioningError("duplicate required audience")
        seen.add(key)
    return value


def create_provisioning_authority(
    *, kid: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create an in-memory synthetic authority pair for explicit storage."""
    _identifier(kid, "provisioning authority key ID")
    private = Ed25519PrivateKey.generate()
    return (
        {
            "schema": PRIVATE_AUTHORITY_SCHEMA,
            "kid": kid,
            "private_key": b64url(private.private_bytes_raw()),
        },
        {
            "schema": AUTHORITY_SCHEMA,
            "kid": kid,
            "public_key": b64url(private.public_key().public_bytes_raw()),
        },
    )


def build_package(
    package_dir: Path | str,
    directory_path: Path | str,
    roots_path: Path | str,
    private_authority_path: Path | str,
    *,
    provisioning_id: str,
    agent_id: str,
    required_audiences: list[dict[str, Any]],
    routes: dict[str, Any],
    inbox_endpoints: list[str],
    local_agent_ids: list[str],
    build_commit: str,
    now_ms: int,
    expires_at_ms: int,
) -> dict[str, Any]:
    """Build one public-only package for an already authorized principal."""
    package = Path(package_dir)
    if package.exists():
        raise ProvisioningError("package directory already exists")
    _identifier(provisioning_id, "provisioning ID")
    _identifier(agent_id, "agent ID")
    if (
        not isinstance(build_commit, str)
        or len(build_commit) != 40
        or any(character not in "0123456789abcdef" for character in build_commit)
    ):
        raise ProvisioningError("build commit must be an exact lowercase SHA-1")
    created = _integer(now_ms, "creation time", minimum=1)
    expires = _integer(expires_at_ms, "expiry time", minimum=1)
    if not created < expires <= created + MAX_MANIFEST_LIFETIME_MS:
        raise ProvisioningError("provisioning manifest lifetime is invalid")

    directory_bytes = _regular_file(Path(directory_path))
    roots_bytes = _regular_file(Path(roots_path))
    snapshot = strict_json(directory_bytes)
    roots = strict_json(roots_bytes, max_bytes=64 * 1024)
    validate_directory(snapshot, roots, now_ms=created)
    directory = Directory(snapshot)
    if agent_id not in directory.agents or directory.agents[agent_id]["status"] != "active":
        raise ProvisioningError("agent is not active in the signed directory")
    loopback_only = agent_id.endswith("@localhost")
    _validate_routes(routes, loopback_only=loopback_only)
    if not isinstance(inbox_endpoints, list) or not inbox_endpoints:
        raise ProvisioningError("at least one inbox endpoint is required")
    for endpoint in inbox_endpoints:
        _validate_url(endpoint, "inbox endpoint", loopback_only=loopback_only)
    normalized_local = [_identifier(item, "local agent ID") for item in local_agent_ids]
    if len(set(normalized_local)) != len(normalized_local):
        raise ProvisioningError("duplicate local agent ID")
    if agent_id not in normalized_local:
        raise ProvisioningError("provisioned agent must be explicitly local")
    if any(
        item not in directory.agents
        or directory.agents[item]["status"] != "active"
        for item in normalized_local
    ):
        raise ProvisioningError("local-agent set names an inactive principal")
    required = _validate_audiences(required_audiences)
    for item in required:
        audience = directory.audiences.get((item["type"], item["id"], item["epoch"]))
        if not audience or audience["status"] != "active" or agent_id not in audience["members"]:
            raise ProvisioningError("agent is not a member of a required audience")
    direct = [item for item in required if item["type"] == "direct" and item["id"] == agent_id]
    if not direct:
        raise ProvisioningError("principal's active direct audience is required")

    private_value = strict_json(
        _regular_file(Path(private_authority_path), private=True),
        max_bytes=16 * 1024,
    )
    _exact(private_value, PRIVATE_AUTHORITY_FIELDS, "private authority")
    if private_value["schema"] != PRIVATE_AUTHORITY_SCHEMA:
        raise ProvisioningError("unsupported private authority schema")
    signer_kid = _identifier(private_value["kid"], "signer key ID")
    signer = Ed25519PrivateKey.from_private_bytes(
        b64url_decode(private_value["private_key"], 32)
    )
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "provisioning_id": provisioning_id,
        "agent_id": agent_id,
        "created_at_ms": created,
        "expires_at_ms": expires,
        "directory_epoch": directory.epoch,
        "directory_sha256": directory.hash,
        "roots_sha256": _roots_hash(roots),
        "artifacts": {
            "directory.json": _hash(directory_bytes),
            "governance-roots.json": _hash(roots_bytes),
        },
        "expected_signing_kid": directory.active_key(agent_id, "signing", created)["kid"],
        "expected_encryption_kids": [
            directory.active_key(agent_id, "encryption", created)["kid"]
        ],
        "required_audiences": required,
        "routes": routes,
        "inbox_endpoints": inbox_endpoints,
        "local_agent_ids": sorted(normalized_local),
        "build_commit": build_commit,
        "signer_kid": signer_kid,
        "signature": "",
    }
    manifest["signature"] = b64url(signer.sign(_manifest_preimage(manifest)))
    package.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(
        tempfile.mkdtemp(
            dir=package.parent, prefix=f".{package.name}.", suffix=".staging"
        )
    )
    try:
        os.chmod(staging, 0o700)
        _write_exclusive(staging / "directory.json", directory_bytes, 0o644)
        _write_exclusive(
            staging / "governance-roots.json", roots_bytes, 0o644
        )
        _write_exclusive(
            staging / "manifest.json", _serialize(manifest), 0o644
        )
        if package.exists():
            raise ProvisioningError("package directory already exists")
        os.rename(staging, package)
        parent_fd = os.open(package.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return manifest


def verify_package(
    package_dir: Path | str,
    authority_path: Path | str,
    *,
    now_ms: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    package = Path(package_dir)
    _validate_package_inventory(package)
    manifest = strict_json(_regular_file(package / "manifest.json"))
    _exact(manifest, MANIFEST_FIELDS, "provisioning manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ProvisioningError("unsupported provisioning manifest")
    authority = strict_json(
        _regular_file(Path(authority_path)), max_bytes=16 * 1024
    )
    _exact(authority, AUTHORITY_FIELDS, "provisioning authority")
    if authority["schema"] != AUTHORITY_SCHEMA or authority["kid"] != manifest["signer_kid"]:
        raise ProvisioningError("provisioning authority mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(
            b64url_decode(authority["public_key"], 32)
        ).verify(
            b64url_decode(manifest["signature"], 64),
            _manifest_preimage(manifest),
        )
    except InvalidSignature as exc:
        raise ProvisioningError("invalid provisioning manifest signature") from exc
    created = _integer(manifest["created_at_ms"], "creation time", minimum=1)
    expires = _integer(manifest["expires_at_ms"], "expiry time", minimum=1)
    if (
        not created < expires
        or created > now_ms + protocol.MAX_CLOCK_SKEW_MS
        or not now_ms < expires
    ):
        raise ProvisioningError("provisioning manifest is not currently valid")
    if expires - created > MAX_MANIFEST_LIFETIME_MS:
        raise ProvisioningError("provisioning manifest lifetime exceeds seven days")
    _identifier(manifest["provisioning_id"], "provisioning ID")
    agent_id = _identifier(manifest["agent_id"], "agent ID")
    if (
        not isinstance(manifest["build_commit"], str)
        or len(manifest["build_commit"]) != 40
        or any(
            character not in "0123456789abcdef"
            for character in manifest["build_commit"]
        )
    ):
        raise ProvisioningError("invalid exact build commit")
    _integer(manifest["directory_epoch"], "directory epoch", minimum=1)
    for field in ("directory_sha256", "roots_sha256"):
        value = manifest[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ProvisioningError(f"invalid {field}")
    _identifier(manifest["expected_signing_kid"], "expected signing key ID")
    if not isinstance(manifest["expected_encryption_kids"], list) or not manifest["expected_encryption_kids"]:
        raise ProvisioningError("expected encryption keys are missing")
    for kid in manifest["expected_encryption_kids"]:
        _identifier(kid, "expected encryption key ID")
    required = _validate_audiences(manifest["required_audiences"])
    loopback_only = agent_id.endswith("@localhost")
    _validate_routes(manifest["routes"], loopback_only=loopback_only)
    if not isinstance(manifest["inbox_endpoints"], list) or not manifest["inbox_endpoints"]:
        raise ProvisioningError("inbox endpoints are missing")
    for endpoint in manifest["inbox_endpoints"]:
        _validate_url(endpoint, "inbox endpoint", loopback_only=loopback_only)
    if not isinstance(manifest["local_agent_ids"], list):
        raise ProvisioningError("invalid local agent IDs")
    local_ids = [_identifier(item, "local agent ID") for item in manifest["local_agent_ids"]]
    if local_ids != sorted(set(local_ids)) or agent_id not in local_ids:
        raise ProvisioningError("invalid local agent boundary")

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {"directory.json", "governance-roots.json"}:
        raise ProvisioningError("invalid provisioning artifacts")
    directory_bytes = _regular_file(package / "directory.json")
    roots_bytes = _regular_file(package / "governance-roots.json")
    if _hash(directory_bytes) != artifacts["directory.json"] or _hash(roots_bytes) != artifacts["governance-roots.json"]:
        raise ProvisioningError("provisioning artifact hash mismatch")
    snapshot = strict_json(directory_bytes)
    roots = strict_json(roots_bytes, max_bytes=64 * 1024)
    validate_directory(snapshot, roots, now_ms=now_ms)
    directory = Directory(snapshot)
    if (
        directory.epoch != manifest["directory_epoch"]
        or directory.hash != manifest["directory_sha256"]
        or _roots_hash(roots) != manifest["roots_sha256"]
    ):
        raise ProvisioningError("manifest does not bind the signed directory")
    if any(
        item not in directory.agents
        or directory.agents[item]["status"] != "active"
        for item in local_ids
    ):
        raise ProvisioningError("local-agent set names an inactive principal")
    for item in required:
        audience = directory.audiences.get((item["type"], item["id"], item["epoch"]))
        if not audience or audience["status"] != "active" or agent_id not in audience["members"]:
            raise ProvisioningError("required audience authorization is absent")
    # Recheck after reading the bound files so a package which changed during
    # verification does not become an accepted open-ended container.
    _validate_package_inventory(package)
    return manifest, snapshot, roots


def _state_for(snapshot: dict[str, Any], roots: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "directory_epoch": snapshot["directory_epoch"],
        "directory_sha256": directory_sha256(snapshot),
        "roots_sha256": _roots_hash(roots),
    }


def _render_environment(
    manifest: dict[str, Any], destination: Path, keys_path: Path
) -> bytes:
    agent_id = manifest["agent_id"]
    slug = agent_id.replace("@", "_").replace("/", "_")
    values = {
        "TRIBE_CLIENT_ID": agent_id,
        "TRIBE_V1_BUILD_COMMIT": manifest["build_commit"],
        "TRIBE_V1_CLIENT_DB": str(destination / "state" / f"{slug}-client.sqlite"),
        "TRIBE_V1_CLIENT_INBOX_DB": str(destination / "state" / f"{slug}-inbox.sqlite"),
        "TRIBE_V1_DIRECTORY": str(destination / "directory.json"),
        "TRIBE_V1_DIRECTORY_STATE": str(destination / "state" / f"{slug}-directory-state.json"),
        "TRIBE_V1_GOVERNANCE_ROOTS": str(destination / "governance-roots.json"),
        "TRIBE_V1_INBOX_ENDPOINTS": json.dumps(manifest["inbox_endpoints"], separators=(",", ":")),
        "TRIBE_V1_KEYS": str(keys_path),
        "TRIBE_V1_LOCAL_AGENT_IDS": json.dumps(manifest["local_agent_ids"], separators=(",", ":")),
        "TRIBE_V1_ROUTES": json.dumps(manifest["routes"], sort_keys=True, separators=(",", ":")),
    }
    return "".join(
        f"{key}={json.dumps(value, ensure_ascii=True)}\n"
        for key, value in sorted(values.items())
    ).encode("utf-8")


def apply_package(
    package_dir: Path | str,
    authority_path: Path | str,
    keys_path: Path | str,
    destination: Path | str,
    *,
    authorized_local_agent_ids: frozenset[str],
    now_ms: int,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Validate then restartably install one package without network access."""
    package_dir = Path(package_dir)
    authority_path = Path(authority_path)
    destination = Path(destination)
    # Avoid creating any target state for a package which is already invalid
    # at the trusted invocation time of a fresh installation.
    fresh_validation = None
    if not destination.exists():
        fresh_validation = verify_package(
            package_dir, authority_path, now_ms=now_ms
        )
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination_info = destination.lstat()
    if (
        stat.S_ISLNK(destination_info.st_mode)
        or not stat.S_ISDIR(destination_info.st_mode)
        or destination_info.st_uid != os.geteuid()
        or stat.S_IMODE(destination_info.st_mode) & 0o077
    ):
        raise ProvisioningError("provisioning destination must be owner-only")
    state_dir = destination / "state"
    state_dir.mkdir(exist_ok=True, mode=0o700)
    state_info = state_dir.lstat()
    if (
        stat.S_ISLNK(state_info.st_mode)
        or not stat.S_ISDIR(state_info.st_mode)
        or state_info.st_uid != os.geteuid()
        or stat.S_IMODE(state_info.st_mode) & 0o077
    ):
        raise ProvisioningError("provisioning state directory must be owner-only")
    journal_path = destination / "provision-journal.json"
    high_water_path = destination / "provision-high-water.json"
    lock_fd = os.open(
        destination / ".provision.lock",
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != os.geteuid()
            or stat.S_IMODE(lock_info.st_mode) & 0o077
        ):
            raise ProvisioningError("provisioning lock must be owner-only")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        journal = None
        validation_time = now_ms
        if journal_path.exists():
            journal = strict_json(_regular_file(journal_path, private=True))
            _exact(journal, JOURNAL_FIELDS, "provisioning journal")
            if journal["schema"] != JOURNAL_SCHEMA:
                raise ProvisioningError("unsupported provisioning journal")
            validation_time = _integer(
                journal["authorized_at_ms"],
                "journal authorization time",
                minimum=1,
            )
            # The journal grants continuation only to the exact signed package
            # whose transaction was durably started while it was current.
            unverified_manifest = strict_json(
                _regular_file(package_dir / "manifest.json")
            )
            if (
                _hash(protocol.canonical_json(unverified_manifest))
                != journal["package_sha256"]
            ):
                raise ProvisioningError(
                    "another provisioning transaction is unfinished"
                )

        if journal is None and fresh_validation is not None:
            manifest, snapshot, roots = fresh_validation
        else:
            manifest, snapshot, roots = verify_package(
                package_dir, authority_path, now_ms=validation_time
            )

        package_hash = _hash(protocol.canonical_json(manifest))
        expected_journal = {
            "schema": JOURNAL_SCHEMA,
            "package_sha256": package_hash,
            "agent_id": manifest["agent_id"],
            "target_directory_sha256": manifest["directory_sha256"],
            "authorized_at_ms": validation_time,
        }
        if journal is not None:
            if journal != expected_journal:
                raise ProvisioningError("another provisioning transaction is unfinished")

        if frozenset(manifest["local_agent_ids"]) != authorized_local_agent_ids:
            raise ProvisioningError(
                "package local-agent set lacks an exact harness authorization"
            )
        keys_path = Path(keys_path).resolve()
        bundle = KeyBundle.load(keys_path)
        directory = Directory(snapshot)
        if bundle.agent_id != manifest["agent_id"]:
            raise ProvisioningError("private bundle belongs to another agent")
        bundle.verify_against(directory, validation_time)
        if (
            bundle.signing_kid != manifest["expected_signing_kid"]
            or not set(manifest["expected_encryption_kids"])
            <= set(bundle.encryption_private)
        ):
            raise ProvisioningError("local private keys do not match the package")

        agent_slug = manifest["agent_id"].replace("@", "_").replace("/", "_")
        directory_path = destination / "directory.json"
        roots_path = destination / "governance-roots.json"
        state_path = state_dir / f"{agent_slug}-directory-state.json"
        environment_path = destination / f"{agent_slug}.client.env"

        target_high_water = {
            "schema": HIGH_WATER_SCHEMA,
            "target_agent_id": manifest["agent_id"],
            "directory_epoch": manifest["directory_epoch"],
            "directory_sha256": manifest["directory_sha256"],
            "roots_sha256": manifest["roots_sha256"],
            "package_sha256": package_hash,
        }
        previous_high_water = None
        if high_water_path.exists():
            previous_high_water = strict_json(
                _regular_file(high_water_path, private=True)
            )
            _exact(
                previous_high_water,
                HIGH_WATER_FIELDS,
                "provisioning high-water",
            )
            if previous_high_water["schema"] != HIGH_WATER_SCHEMA:
                raise ProvisioningError("unsupported provisioning high-water")
            if previous_high_water["target_agent_id"] != manifest["agent_id"]:
                raise ProvisioningError("provisioning target identity changed")
            previous_epoch = _integer(
                previous_high_water["directory_epoch"],
                "high-water directory epoch",
                minimum=1,
            )
            if previous_epoch > manifest["directory_epoch"]:
                raise ProvisioningError("provisioning package rollback rejected")
            if previous_epoch == manifest["directory_epoch"]:
                if previous_high_water != target_high_water:
                    raise ProvisioningError(
                        "provisioning package conflicts at the high-water epoch"
                    )
            elif previous_epoch + 1 != manifest["directory_epoch"]:
                raise ProvisioningError("provisioning high-water discontinuity")
        elif not journal_path.exists() and any(
            path.exists()
            for path in (directory_path, roots_path, state_path, environment_path)
        ):
            raise ProvisioningError(
                "existing target lacks a durable provisioning high-water"
            )

        if roots_path.exists():
            if _regular_file(roots_path) != _serialize(roots) and strict_json(roots_path.read_bytes()) != roots:
                raise ProvisioningError("governance roots change requires reprovision authority")

        target_state = _state_for(snapshot, roots)
        previous_state = None
        if state_path.exists():
            previous_state = strict_json(_regular_file(state_path, private=True))
            _exact(previous_state, STATE_FIELDS, "directory state")
            if previous_state["schema"] != STATE_SCHEMA or previous_state["roots_sha256"] != target_state["roots_sha256"]:
                raise ProvisioningError("existing anti-rollback state is incompatible")
            if previous_state["directory_epoch"] > target_state["directory_epoch"]:
                raise ProvisioningError("directory rollback rejected")
            if previous_state["directory_epoch"] == target_state["directory_epoch"] and previous_state != target_state:
                raise ProvisioningError("directory split view rejected")
            if previous_state["directory_epoch"] + 1 < target_state["directory_epoch"]:
                raise ProvisioningError("directory chain discontinuity")

        if directory_path.exists():
            installed = strict_json(_regular_file(directory_path))
            installed_hash = directory_sha256(installed)
            if installed_hash != target_state["directory_sha256"]:
                if (
                    previous_state is None
                    or installed_hash != previous_state["directory_sha256"]
                    or snapshot["previous_sha256"] != installed_hash
                    or snapshot["directory_epoch"] != installed["directory_epoch"] + 1
                ):
                    raise ProvisioningError("installed directory is not the package predecessor")

        # Only persist a journal after every read-only compatibility check has
        # passed.  Invalid rollback/root/split-view attempts therefore cannot
        # leave a denial-of-service journal behind.
        if not journal_path.exists():
            _write_atomic(journal_path, _serialize(expected_journal), 0o600)
        if not roots_path.exists():
            _write_atomic(roots_path, _serialize(roots), 0o644)
        directory_bytes = _serialize(snapshot)
        if not directory_path.exists() or strict_json(directory_path.read_bytes()) != snapshot:
            _write_atomic(directory_path, directory_bytes, 0o644)
        if fault_hook:
            fault_hook("directory-installed")
        if not state_path.exists() or strict_json(state_path.read_bytes()) != target_state:
            _write_atomic(state_path, _serialize(target_state), 0o600)
        if fault_hook:
            fault_hook("state-installed")
        environment = _render_environment(manifest, destination.resolve(), keys_path)
        if not environment_path.exists() or environment_path.read_bytes() != environment:
            _write_atomic(environment_path, environment, 0o600)
        if fault_hook:
            fault_hook("environment-installed")
        if (
            previous_high_water != target_high_water
            or not high_water_path.exists()
        ):
            _write_atomic(
                high_water_path, _serialize(target_high_water), 0o600
            )
        if fault_hook:
            fault_hook("high-water-installed")
        journal_path.unlink()
        directory_fd = os.open(destination, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        receipt = {
            "schema": "tribe-provisioning-receipt/v1",
            "provisioning_id": manifest["provisioning_id"],
            "agent_id": manifest["agent_id"],
            "directory_epoch": manifest["directory_epoch"],
            "directory_sha256": manifest["directory_sha256"],
            "roots_sha256": manifest["roots_sha256"],
            "environment": environment_path.name,
            "signing_kid": bundle.signing_kid,
            "encryption_kids": sorted(bundle.encryption_private),
            "network_access": False,
            "ssh_access": False,
            "contains_private_material": False,
            "package_sha256": package_hash,
        }
        return receipt
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def doctor(
    destination: Path | str,
    keys_path: Path | str,
    *,
    agent_id: str,
    now_ms: int,
) -> dict[str, Any]:
    """Run a local-only diagnostic; it deliberately emits no transport ACK."""
    destination = Path(destination)
    slug = agent_id.replace("@", "_").replace("/", "_")
    directory = Directory.load(
        destination / "directory.json",
        destination / "governance-roots.json",
        destination / "state" / f"{slug}-directory-state.json",
        now_ms=now_ms,
    )
    keys = KeyBundle.load(keys_path)
    if keys.agent_id != agent_id:
        raise ProvisioningError("doctor key bundle belongs to another agent")
    keys.verify_against(directory, now_ms)
    audiences = sorted(
        f"{kind}:{identifier}:{epoch}"
        for (kind, identifier, epoch), value in directory.audiences.items()
        if value["status"] == "active" and agent_id in value["members"]
    )
    return {
        "schema": "tribe-provisioning-doctor/v1",
        "ok": True,
        "agent_id": agent_id,
        "directory_epoch": directory.epoch,
        "directory_sha256": directory.hash,
        "signing_kid": keys.signing_kid,
        "encryption_kids": sorted(keys.encryption_private),
        "active_audiences": audiences,
        "network_checked": False,
        "matrix_receipt": False,
    }
