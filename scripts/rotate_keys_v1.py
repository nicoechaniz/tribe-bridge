#!/usr/bin/env python3
"""Prepare, compose, activate, or forward-recover a Tribe v1 rotation.

Every path is explicit.  This command has no network, service, SSH, publish, or
governance-signing capability.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_directory_v1 import Directory, load_roots, strict_json  # noqa: E402
from tribe_rotation_v1 import (  # noqa: E402
    RotationError,
    activate_staged_bundle,
    build_forward_recovery,
    compose_rotation,
    prepare_rotation,
)


def write_exclusive(path: Path, value, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def directory_arguments(parser):
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--roots", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    directory_arguments(prepare)
    prepare.add_argument("--keys", type=Path, required=True)
    prepare.add_argument("--staged-keys", type=Path, required=True)
    prepare.add_argument("--announcement", type=Path, required=True)
    prepare.add_argument("--ceremony-id", required=True)
    prepare.add_argument("--activation-at-ms", type=int, required=True)
    prepare.add_argument("--expires-at-ms", type=int, required=True)

    compose = commands.add_parser("compose")
    directory_arguments(compose)
    compose.add_argument("--announcement", type=Path, action="append", required=True)
    compose.add_argument("--ceremony-id", required=True)
    compose.add_argument("--activation-at-ms", type=int, required=True)
    compose.add_argument("--output", type=Path, required=True)
    compose.add_argument("--receipt", type=Path, required=True)

    activate = commands.add_parser("activate")
    directory_arguments(activate)
    activate.add_argument("--keys", type=Path, required=True)
    activate.add_argument("--staged-keys", type=Path, required=True)

    recovery = commands.add_parser("forward-recovery")
    directory_arguments(recovery)
    recovery.add_argument("--revoke-kid", action="append", required=True)
    recovery.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    now_ms = int(time.time() * 1000)

    try:
        directory = Directory.load(
            arguments.directory,
            arguments.roots,
            arguments.state,
            now_ms=now_ms,
        )
        roots = load_roots(arguments.roots)
        if arguments.command == "prepare":
            announcement = prepare_rotation(
                directory,
                roots,
                arguments.keys,
                arguments.staged_keys,
                ceremony_id=arguments.ceremony_id,
                activation_at_ms=arguments.activation_at_ms,
                expires_at_ms=arguments.expires_at_ms,
                now_ms=now_ms,
            )
            write_exclusive(arguments.announcement, announcement)
            result = {
                "ok": True,
                "prepared": True,
                "agent_id": announcement["agent_id"],
                "announcement": str(arguments.announcement),
                "staged_keys": str(arguments.staged_keys),
            }
        elif arguments.command == "compose":
            announcements = [
                strict_json(path.read_bytes()) for path in arguments.announcement
            ]
            candidate, receipt = compose_rotation(
                directory.snapshot,
                roots,
                announcements,
                now_ms=now_ms,
                ceremony_id=arguments.ceremony_id,
                activation_at_ms=arguments.activation_at_ms,
            )
            write_exclusive(arguments.output, candidate)
            write_exclusive(arguments.receipt, receipt)
            result = {
                "ok": True,
                "composed": True,
                "candidate_epoch": candidate["directory_epoch"],
                "candidate": str(arguments.output),
                "receipt": str(arguments.receipt),
                "requires_offline_threshold_signatures": True,
            }
        elif arguments.command == "activate":
            result = {
                "ok": True,
                **activate_staged_bundle(
                    arguments.keys,
                    arguments.staged_keys,
                    directory,
                    now_ms=now_ms,
                ),
            }
        else:
            candidate = build_forward_recovery(
                directory.snapshot,
                roots,
                set(arguments.revoke_kid),
                now_ms=now_ms,
            )
            write_exclusive(arguments.output, candidate)
            result = {
                "ok": True,
                "forward_recovery_epoch": candidate["directory_epoch"],
                "candidate": str(arguments.output),
                "requires_offline_threshold_signatures": True,
            }
    except (OSError, ValueError, RotationError) as exception:
        print(json.dumps({"ok": False, "error": str(exception)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
