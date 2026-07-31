#!/usr/bin/env python3
"""Create non-overwriting Tribe v1 agent or governance key material."""

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import tribe_protocol_v1 as protocol
from tribe_crypto_v1 import b64url, write_key_bundle


def write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    agent = commands.add_parser("agent")
    agent.add_argument("--agent-id", required=True)
    agent.add_argument("--epoch", type=int, default=1)
    agent.add_argument("--output", type=Path, required=True)
    governance = commands.add_parser("governance")
    governance.add_argument("--kid", required=True)
    governance.add_argument("--private-output", type=Path, required=True)
    governance.add_argument("--roots-output", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "agent":
        if (
            not protocol.IDENTIFIER.fullmatch(args.agent_id)
            or args.epoch < 1
        ):
            parser.error("invalid agent ID or epoch")
        signing = ed25519.Ed25519PrivateKey.generate()
        encryption = x25519.X25519PrivateKey.generate()
        signing_kid = f"{args.agent_id}/sig/{args.epoch}"
        encryption_kid = f"{args.agent_id}/enc/{args.epoch}"
        write_key_bundle(
            args.output,
            {
                "schema": "tribe-key-bundle/v1",
                "agent_id": args.agent_id,
                "signing": {
                    "kid": signing_kid,
                    "private_key": b64url(signing.private_bytes_raw()),
                },
                "encryption": [
                    {
                        "kid": encryption_kid,
                        "private_key": b64url(
                            encryption.private_bytes_raw()
                        ),
                    }
                ],
            },
        )
        public = {
            "id": args.agent_id,
            "signing": {
                "kid": signing_kid,
                "epoch": args.epoch,
                "public_key": b64url(
                    signing.public_key().public_bytes_raw()
                ),
            },
            "encryption": {
                "kid": encryption_kid,
                "epoch": args.epoch,
                "public_key": b64url(
                    encryption.public_key().public_bytes_raw()
                ),
            },
        }
        print(json.dumps(public, sort_keys=True))
        return

    if not protocol.IDENTIFIER.fullmatch(args.kid):
        parser.error("invalid governance key ID")
    private = ed25519.Ed25519PrivateKey.generate()
    write_private(
        args.private_output,
        {
            "schema": "tribe-governance-private/v1",
            "kid": args.kid,
            "private_key": b64url(private.private_bytes_raw()),
        },
    )
    roots = {
        "schema": "tribe-governance-roots/v1",
        "threshold": 1,
        "keys": {
            args.kid: b64url(private.public_key().public_bytes_raw())
        },
    }
    write_private(args.roots_output, roots)
    os.chmod(args.roots_output, 0o644)
    print(json.dumps(roots, sort_keys=True))


if __name__ == "__main__":
    main()
