#!/usr/bin/env python3
"""Mirror only explicitly addressed tribe-public v1 messages to Telegram."""

import json
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import tribe_protocol_v1 as protocol
from tribe_client_v1 import InboxStore, make_ack, post_signed
from tribe_crypto_v1 import KeyBundle, decrypt_envelope
from tribe_directory_v1 import Directory
from tribe_mirror_v1 import MirrorPolicyError, TelegramClient, TelegramPolicy


def required(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def json_list(name):
    value = json.loads(required(name))
    if not isinstance(value, list):
        raise RuntimeError(f"{name} must be a JSON list")
    return value


def main():
    now = int(time.time() * 1000)
    directory = Directory.load(
        required("TRIBE_V1_DIRECTORY"),
        required("TRIBE_V1_GOVERNANCE_ROOTS"),
        required("TRIBE_V1_DIRECTORY_STATE"),
        now_ms=now,
    )
    keys = KeyBundle.load(required("TRIBE_V1_KEYS"))
    endpoints = json_list("TRIBE_V1_INBOX_ENDPOINTS")
    policy = TelegramPolicy.from_values(
        chat_ids=json_list("TRIBE_TELEGRAM_ALLOWED_CHAT_IDS"),
        user_ids=json_list("TRIBE_TELEGRAM_ALLOWED_USER_IDS"),
        audiences=json_list("TRIBE_V1_MIRROR_AUDIENCES"),
        classifications=json.loads(
            os.environ.get(
                "TRIBE_V1_MIRROR_CLASSIFICATIONS", '["tribe-public"]'
            )
        ),
    )
    telegram = TelegramClient(
        required("TRIBE_TELEGRAM_BOT_TOKEN"),
        int(required("TRIBE_TELEGRAM_CHAT_ID")),
        policy,
    )
    store = InboxStore(
        os.environ.get(
            "TRIBE_V1_MIRROR_DB",
            str(Path.home() / ".tribe-bridge/v1/mirror.sqlite"),
        )
    )
    failures = []
    mirrored = 0
    for endpoint in endpoints:
        try:
            response = post_signed(
                endpoint,
                "/v1/claims",
                {
                    "recipient_id": keys.agent_id,
                    "limit": 3,
                    "lease_ms": 60_000,
                },
                keys=keys,
                now_ms=now,
            )
            claims = response.get("claims")
            if not isinstance(claims, list):
                raise RuntimeError("claim response has no claims list")
            for claim in claims:
                sender = claim["sender_id"]
                message_id = claim["message_id"]
                prior = store.begin(
                    sender,
                    message_id,
                    claim["envelope_sha256"],
                    now_ms=now,
                )
                if prior == "processing":
                    continue
                outcome = (
                    "terminal_failed"
                    if prior == "terminal_failed"
                    else "processed"
                )
                if prior == "new":
                    try:
                        payload = decrypt_envelope(
                            claim["envelope"],
                            directory=directory,
                            keys=keys,
                            now_ms=now,
                        )
                        rendered = policy.render(
                            payload, claim["envelope"]
                        )
                        telegram.send_rendered(rendered)
                        store.finish(
                            sender,
                            message_id,
                            "processed",
                            payload=payload,
                            now_ms=now,
                        )
                        mirrored += 1
                        outcome = "processed"
                    except (
                        MirrorPolicyError,
                        protocol.ProtocolError,
                        ValueError,
                    ):
                        store.finish(
                            sender,
                            message_id,
                            "terminal_failed",
                            payload=None,
                            now_ms=now,
                        )
                        outcome = "terminal_failed"
                    except RuntimeError:
                        store.release(sender, message_id)
                        outcome = "retryable_failed"
                ack = make_ack(
                    claim, keys=keys, outcome=outcome, now_ms=now
                )
                post_signed(
                    endpoint,
                    "/v1/acks",
                    ack,
                    keys=keys,
                    now_ms=now,
                )
        except Exception as exc:
            failures.append({"endpoint": endpoint, "error": str(exc)})
    print(
        json.dumps(
            {
                "ok": not failures,
                "protocol": "tribe/v1",
                "build_commit": required("TRIBE_V1_BUILD_COMMIT"),
                "mirrored": mirrored,
                "failures": failures,
            }
        )
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
