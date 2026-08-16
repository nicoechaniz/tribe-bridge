"""Tribe v1 directory administration: validity renewal and client-side updates.

Pure-validity renewal builds epoch N+1 from the installed signed directory
without touching agents, audiences, or keys; client updates fetch a signed
directory from a canonical URL and install it only after full chain
verification. Everything fails closed: no mutation happens unless every check
passes.
"""

import copy
import json
import os
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import tribe_protocol_v1 as protocol
from tribe_crypto_v1 import b64url
from tribe_directory_v1 import (
    Directory,
    DirectoryError,
    b64url_decode,
    directory_preimage,
    directory_sha256,
    strict_json,
)

GOVERNANCE_KEY_SCHEMA = "tribe-governance-private/v1"
DEFAULT_VALIDITY_DAYS = 30
DEFAULT_RENEWAL_WINDOW_DAYS = 7
MS_PER_DAY = 86_400_000


class RenewalError(RuntimeError):
    """Any renewal/update precondition or verification failure."""


def _now_ms() -> int:
    return int(time.time() * 1000)


def days_until_expiry(snapshot, *, now_ms: int) -> float:
    return (snapshot["expires_at_ms"] - now_ms) / MS_PER_DAY


def build_next_epoch(
    snapshot,
    *,
    now_ms: int,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
):
    """Return an unsigned epoch-N+1 snapshot: pure validity renewal.

    Only directory_epoch, previous_sha256, issued_at_ms, expires_at_ms and the
    (cleared) signature list change. Any other mutation is a manual ceremony
    and is rejected here.
    """
    if snapshot.get("schema") != "tribe-directory/v1":
        raise RenewalError("unsupported directory schema")
    epoch = snapshot.get("directory_epoch")
    if not isinstance(epoch, int) or epoch < 1:
        raise RenewalError("invalid current directory epoch")
    if now_ms >= snapshot["expires_at_ms"]:
        # Renewable in principle, but callers must understand the chain may
        # already be broken for clients; keep it allowed so recovery works.
        pass
    nxt = copy.deepcopy(snapshot)
    nxt["directory_epoch"] = epoch + 1
    nxt["previous_sha256"] = directory_sha256(snapshot)
    nxt["issued_at_ms"] = now_ms
    nxt["expires_at_ms"] = now_ms + int(validity_days * MS_PER_DAY)
    nxt["governance"] = {"threshold": snapshot["governance"]["threshold"], "signatures": []}
    return nxt


def load_governance_private_key(path):
    key = strict_json(Path(path).read_bytes(), max_bytes=16 * 1024)
    if (
        not isinstance(key, dict)
        or set(key) != {"schema", "kid", "private_key"}
        or key["schema"] != GOVERNANCE_KEY_SCHEMA
        or not protocol.IDENTIFIER.fullmatch(key["kid"])
    ):
        raise RenewalError("invalid governance private key")
    if Path(path).stat().st_mode & 0o077:
        raise RenewalError("governance private key must be mode 0600")
    return key


def sign_snapshot(snapshot, governance_key):
    """Append a governance signature in-place (sign_directory_v1 semantics)."""
    private = Ed25519PrivateKey.from_private_bytes(
        b64url_decode(governance_key["private_key"], 32)
    )
    snapshot["governance"]["signatures"].append(
        {
            "kid": governance_key["kid"],
            "alg": "Ed25519",
            "value": b64url(private.sign(directory_preimage(snapshot))),
        }
    )
    return snapshot


def write_atomic(path, payload: bytes, mode: int = 0o600):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def serialize_signed(snapshot) -> bytes:
    return (json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def verify_chain(directory_path, roots_path, state_path, *, now_ms: int) -> Directory:
    """Fail-closed chain verification against a COPY of the given state."""
    state_copy = Path(state_path).parent / (Path(state_path).name + ".verify-tmp")
    state_copy.write_bytes(Path(state_path).read_bytes())
    try:
        return Directory.load(directory_path, roots_path, state_copy, now_ms=now_ms)
    finally:
        try:
            os.unlink(state_copy)
            os.unlink(str(state_copy) + ".lock")
        except OSError:
            pass


def renew_synthetic_single_holder_directory(
    v1_dir,
    governance_key_path,
    *,
    now_ms: int | None = None,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
    window_days: float = DEFAULT_RENEWAL_WINDOW_DAYS,
    force: bool = False,
    dry_run: bool = False,
):
    """Synthetic fixture: renew one local directory with one holder key.

    This deliberately has no publishing, service, or remote-install surface.
    A release ceremony must instead compose an unsigned successor and collect
    the configured offline threshold signatures independently.
    """
    now_ms = now_ms if now_ms is not None else _now_ms()
    v1_dir = Path(v1_dir)
    directory_path = v1_dir / "directory.json"
    roots_path = v1_dir / "governance-roots.json"
    if not directory_path.exists():
        raise RenewalError(f"missing installed directory: {directory_path}")
    if not roots_path.exists():
        raise RenewalError(f"missing governance roots: {roots_path}")

    current = strict_json(directory_path.read_bytes())
    current_hash = directory_sha256(current)
    remaining = days_until_expiry(current, now_ms=now_ms)
    summary = {
        "renewed": False,
        "current_epoch": current["directory_epoch"],
        "current_sha256": current_hash,
        "expires_in_days": round(remaining, 2),
        "dry_run": dry_run,
    }
    if remaining > window_days and not force:
        summary["reason"] = "within-validity-window"
        return summary

    nxt = build_next_epoch(
        current, now_ms=now_ms, validity_days=validity_days
    )
    key = load_governance_private_key(governance_key_path)
    sign_snapshot(nxt, key)
    next_hash = directory_sha256(nxt)
    summary.update(
        {
            "next_epoch": nxt["directory_epoch"],
            "next_sha256": next_hash,
            "next_expires_at_ms": nxt["expires_at_ms"],
        }
    )

    # Verify the chain against EVERY local client state before installing.
    states = sorted(v1_dir.glob("*-directory-state.json"))
    if not states:
        raise RenewalError("no *-directory-state.json files found; refusing to install")
    if dry_run:
        verify_dir = Path(tempfile.mkdtemp(prefix="renew-verify-"))
        candidate = verify_dir / "directory.json"
        candidate.write_bytes(serialize_signed(nxt))
        for state in states:
            verify_chain(candidate, roots_path, state, now_ms=now_ms)
        summary["verified_states"] = [s.name for s in states]
        summary["reason"] = "dry-run"
        return summary

    audit = v1_dir / "renewals" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now_ms / 1000))
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "directory-unsigned.json").write_bytes(
        serialize_signed({**nxt, "governance": {**nxt["governance"], "signatures": []}})
    )
    signed_bytes = serialize_signed(nxt)
    candidate_path = audit / "directory-signed.json"
    candidate_path.write_bytes(signed_bytes)
    os.chmod(candidate_path, 0o600)
    for state in states:
        verify_chain(candidate_path, roots_path, state, now_ms=now_ms)
    summary["verified_states"] = [s.name for s in states]
    summary["audit_dir"] = str(audit)

    backup = v1_dir / f"directory.json.bak-epoch{current['directory_epoch']}"
    if not backup.exists():
        backup.write_bytes(directory_path.read_bytes())
    summary["backup"] = str(backup)
    write_atomic(directory_path, signed_bytes, mode=0o600)
    summary["renewed"] = True
    return summary


def update_client_directory(
    url,
    *,
    directory_path,
    roots_path,
    state_path,
    now_ms: int | None = None,
    dry_run: bool = False,
    timeout: float = 20.0,
):
    """Fetch a signed directory from a canonical URL and install it if newer.

    Fail closed: any fetch, parse, chain, or expiry problem leaves the
    installed file untouched.
    """
    import urllib.request

    now_ms = now_ms if now_ms is not None else _now_ms()
    directory_path = Path(directory_path)
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = response.read()
    if len(payload) > 64 * 1024:
        raise RenewalError("fetched directory exceeds size limit")
    fetched = strict_json(payload)

    installed = strict_json(directory_path.read_bytes()) if directory_path.exists() else None
    if installed is not None and fetched.get("directory_epoch") == installed.get("directory_epoch"):
        return {
            "updated": False,
            "reason": "already-current",
            "epoch": fetched["directory_epoch"],
            "sha256": directory_sha256(fetched),
        }

    candidate = Path(tempfile.mkdtemp(prefix="directory-update-")) / "directory.json"
    candidate.write_bytes(serialize_signed(fetched))
    # Directory.load validates schema, governance signature, chain linkage
    # (epoch prev+1 + previous_sha256), and expiry — all fail-closed.
    directory = verify_chain(candidate, roots_path, state_path, now_ms=now_ms)
    result = {
        "updated": False,
        "epoch": fetched["directory_epoch"],
        "sha256": directory_sha256(fetched),
        "dry_run": dry_run,
    }
    if dry_run:
        result["reason"] = "dry-run"
        return result
    backup = directory_path.with_name(directory_path.name + ".bak-preupdate")
    if directory_path.exists() and not backup.exists():
        backup.write_bytes(directory_path.read_bytes())
    write_atomic(directory_path, serialize_signed(fetched), mode=0o600)
    result["updated"] = True
    result["directory_epoch_loaded"] = getattr(directory, "epoch", None)
    return result
