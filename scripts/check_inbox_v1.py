#!/usr/bin/env python3
"""Claim, decrypt, deduplicate, and acknowledge Tribe v1 messages."""

import argparse
import json
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_client_v1 import InboxStore, claim_and_process
from tribe_crypto_v1 import KeyBundle
from tribe_directory_v1 import Directory


def required(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def claim_limit(value):
    """Parse the broker's bounded claim limit at the CLI boundary."""
    parsed = int(value)
    if not 1 <= parsed <= 3:
        raise argparse.ArgumentTypeError("must be between 1 and 3")
    return parsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", action="append")
    parser.add_argument("--limit", type=claim_limit, default=3)
    args = parser.parse_args()
    now = int(time.time() * 1000)
    directory = Directory.load(
        required("TRIBE_V1_DIRECTORY"),
        required("TRIBE_V1_GOVERNANCE_ROOTS"),
        required("TRIBE_V1_DIRECTORY_STATE"),
        now_ms=now,
    )
    keys = KeyBundle.load(required("TRIBE_V1_KEYS"))
    endpoints = args.endpoint or json.loads(
        required("TRIBE_V1_INBOX_ENDPOINTS")
    )
    if not isinstance(endpoints, list) or not endpoints:
        raise RuntimeError("inbox endpoints must be a non-empty JSON list")
    store = InboxStore(
        os.environ.get(
            "TRIBE_V1_CLIENT_INBOX_DB",
            str(Path.home() / ".tribe-bridge/v1/inbox.sqlite"),
        )
    )
    messages = []
    failures = []
    succeeded = 0
    for endpoint in endpoints:
        try:
            messages.extend(
                claim_and_process(
                    endpoint,
                    directory=directory,
                    keys=keys,
                    store=store,
                    limit=args.limit,
                    now_ms=now,
                )
            )
            succeeded += 1
        except Exception as exc:
            failures.append({"endpoint": endpoint, "error": str(exc)})
    # Inbox endpoints are redundant views over deduplicated deliveries:
    # the poll only fails closed when EVERY endpoint is unreachable.
    ok = succeeded > 0
    print(
        json.dumps(
            {
                "ok": ok,
                "protocol": "tribe/v1",
                "build_commit": required("TRIBE_V1_BUILD_COMMIT"),
                "messages": messages,
                "count": len(messages),
                "failures": failures,
            },
            ensure_ascii=False,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
