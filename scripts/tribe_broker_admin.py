#!/usr/bin/env python3
"""Offline-safe operational commands for a Tribe v1 SQLite broker."""

import argparse
import json
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_broker_v1 import SQLiteBroker, StorageError


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument(
        "--journal-mode",
        choices=("auto", "delete", "wal"),
        default="auto",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init")
    subparsers.add_parser("runtime")
    subparsers.add_parser("metrics")
    subparsers.add_parser("integrity")
    backup = subparsers.add_parser("backup")
    backup.add_argument("destination", type=Path)
    maintain = subparsers.add_parser("maintain")
    maintain.add_argument(
        "--retain-terminal-days",
        type=int,
        default=30,
    )
    args = parser.parse_args()

    if args.command != "init" and not args.db.is_file():
        parser.error(f"database does not exist: {args.db}")
    try:
        broker = SQLiteBroker(args.db, journal_mode=args.journal_mode)
        if args.command in {"init", "runtime"}:
            result = broker.runtime_info()
        elif args.command == "metrics":
            result = broker.metrics()
        elif args.command == "integrity":
            checks = broker.integrity_check()
            result = {"ok": checks == ["ok"], "results": checks}
            if not result["ok"]:
                print(json.dumps(result, indent=2, sort_keys=True))
                return 2
        elif args.command == "backup":
            result = broker.backup_to(args.destination)
        else:
            cutoff = int(time.time() * 1000) - (
                args.retain_terminal_days * 24 * 60 * 60 * 1000
            )
            result = broker.maintenance(terminal_before_ms=cutoff)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except StorageError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
