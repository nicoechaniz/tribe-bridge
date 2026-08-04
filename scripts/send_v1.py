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
from tribe_locality_v1 import parse_local_agent_ids
from tribe_protocol_v1 import MAX_TTL_MS
from tribe_sent_gate_v1 import (
    append_sent,
    default_log_path,
    find_duplicates,
    format_evidence,
)


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
    parser.add_argument("--force", action="store_true",
                        help="send even if a materially identical message "
                             "was already sent to this audience")
    parser.add_argument("--ttl-seconds", type=int, default=MAX_TTL_MS // 1000)
    parser.add_argument("--endpoint", action="append")
    args = parser.parse_args()
    text = sys.stdin.read(200_001) if args.text_stdin else args.text
    if len(text) > 200_000:
        parser.error("message text exceeds 200000 characters")

    # ── duplicate gate (2026-08-02, Nico's rule) ──────────────────────
    # Before composing, review what was already sent to this audience.
    # A materially identical message blocks with evidence; on a TTY the
    # operator is asked, otherwise re-run with --force.
    audience_id_for_gate = args.group or args.to
    hits = find_duplicates(default_log_path(),
                           audience=audience_id_for_gate, text=text)
    if hits and not args.force:
        evidence = format_evidence(hits)
        if sys.stdin.isatty():
            print(evidence, file=sys.stderr)
            answer = input("send anyway? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print(json.dumps({"ok": False, "blocked": "duplicate",
                                  "similar": [h["message_id"]
                                              for h in hits]}))
                sys.exit(2)
        else:
            print(evidence, file=sys.stderr)
            print(json.dumps({"ok": False, "blocked": "duplicate",
                              "hint": "do NOT re-send the same content; "
                                      "--force is only for genuinely new "
                                      "information",
                              "similar": [h["message_id"] for h in hits]}))
            sys.exit(2)

    now = int(time.time() * 1000)
    directory = Directory.load(
        required("TRIBE_V1_DIRECTORY"),
        required("TRIBE_V1_GOVERNANCE_ROOTS"),
        required("TRIBE_V1_DIRECTORY_STATE"),
        now_ms=now,
    )
    keys = KeyBundle.load(required("TRIBE_V1_KEYS"))
    local_agent_ids = parse_local_agent_ids(
        required("TRIBE_V1_LOCAL_AGENT_IDS")
    )
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
        local_agent_ids=local_agent_ids,
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
    try:
        result = send_with_fallback(
            envelope,
            endpoints,
            keys=keys,
            local_agent_ids=local_agent_ids,
            outbox=outbox,
            now_ms=now,
        )
    except Exception:
        # staged in the outbox for a later flush — the intent was
        # expressed, and the gate must see it next time
        append_sent(
            default_log_path(),
            audience=audience_id,
            classification=args.classification,
            text=text,
            message_id=envelope["message_id"],
            result="queued",
        )
        raise
    append_sent(
        default_log_path(),
        audience=audience_id,
        classification=args.classification,
        text=text,
        message_id=envelope["message_id"],
        result="delivered" if result.get("receipt") else "queued",
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
