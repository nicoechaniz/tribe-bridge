#!/usr/bin/env python3
"""Append one offline governance signature to a Tribe v1 directory."""

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import tribe_protocol_v1 as protocol
from tribe_crypto_v1 import b64url
from tribe_directory_v1 import (
    DIRECTORY_DOMAIN,
    b64url_decode,
    directory_preimage,
    strict_json,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--governance-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    if args.governance_key.stat().st_mode & 0o077:
        parser.error("governance private key must be mode 0600")
    snapshot = strict_json(args.directory.read_bytes())
    key = strict_json(args.governance_key.read_bytes(), max_bytes=16 * 1024)
    if (
        not isinstance(key, dict)
        or set(key) != {"schema", "kid", "private_key"}
        or key["schema"] != "tribe-governance-private/v1"
        or not protocol.IDENTIFIER.fullmatch(key["kid"])
    ):
        parser.error("invalid governance private key")
    governance = snapshot.get("governance")
    if (
        not isinstance(governance, dict)
        or set(governance) != {"threshold", "signatures"}
        or not isinstance(governance["signatures"], list)
    ):
        parser.error("directory has invalid governance block")
    if any(item.get("kid") == key["kid"] for item in governance["signatures"]):
        parser.error("directory already has a signature from this key")
    private = Ed25519PrivateKey.from_private_bytes(
        b64url_decode(key["private_key"], 32)
    )
    governance["signatures"].append(
        {
            "kid": key["kid"],
            "alg": "Ed25519",
            "value": b64url(private.sign(directory_preimage(snapshot))),
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


if __name__ == "__main__":
    main()
