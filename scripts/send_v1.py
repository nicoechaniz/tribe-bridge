#!/usr/bin/env python3
"""Encrypt and deliver one Tribe v1 message with durable fallback."""

import argparse
import json
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_broker_v1 import SQLiteBroker
from tribe_client_v1 import route_endpoints, send_with_fallback
from tribe_crypto_v1 import KeyBundle, encrypt_envelope, message_payload
from tribe_directory_v1 import Directory


def required(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def main():
    parser = argparse.ArgumentParser()
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--to")
    target.add_argument("--group")
    text_source = parser.add_mutually_exclusive_group(required=True)
    text_source.add_argument("--text")
    text_source.add_argument("--text-stdin", action="store_true")
    parser.add_argument(
        "--classification",
        choices=("private", "tribe-public"),
        default="private",
    )
    parser.add_argument("--reply-to")
    parser.add_argument("--ttl-seconds", type=int, default=3600)
    parser.add_argument("--endpoint", action="append")
    args = parser.parse_args()
    text = sys.stdin.read(200_001) if args.text_stdin else args.text
    if len(text) > 200_000:
        parser.error("message text exceeds 200000 characters")

    now = int(time.time() * 1000)
    directory = Directory.load(
        required("TRIBE_V1_DIRECTORY"),
        required("TRIBE_V1_GOVERNANCE_ROOTS"),
        required("TRIBE_V1_DIRECTORY_STATE"),
        now_ms=now,
    )
    keys = KeyBundle.load(required("TRIBE_V1_KEYS"))
    audience_type = "group" if args.group else "direct"
    audience_id = args.group or args.to
    if args.classification == "tribe-public" and audience_type != "group":
        parser.error("tribe-public messages require an explicit --group")
    payload = message_payload(
        sender=keys.agent_id,
        to=audience_id,
        text=text,
        classification=args.classification,
        reply_to=args.reply_to,
    )
    envelope = encrypt_envelope(
        payload,
        directory=directory,
        keys=keys,
        audience_type=audience_type,
        audience_id=audience_id,
        now_ms=now,
        ttl_ms=args.ttl_seconds * 1000,
    )

    if args.endpoint:
        endpoints = args.endpoint
    else:
        routes = json.loads(required("TRIBE_V1_ROUTES"))
        if not isinstance(routes, dict):
            raise RuntimeError("TRIBE_V1_ROUTES must be a JSON object")
        endpoints = route_endpoints(routes, audience_id)
        if not endpoints:
            raise RuntimeError(f"no v1 route for {audience_id}")
    outbox = SQLiteBroker(
        os.environ.get(
            "TRIBE_V1_CLIENT_DB",
            str(Path.home() / ".tribe-bridge/v1/client.sqlite"),
        )
    )
    result = send_with_fallback(
        envelope,
        endpoints,
        keys=keys,
        outbox=outbox,
        now_ms=now,
    )
    print(
        json.dumps(
            {
                "ok": True,
                "protocol": "tribe/v1",
                "build_commit": required("TRIBE_V1_BUILD_COMMIT"),
                "message_id": envelope["message_id"],
                **result,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
