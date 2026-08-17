#!/usr/bin/env python3
"""Mirror only explicitly allowed Tribe v1 messages to Telegram."""

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
from tribe_mirror_v1 import (
    MirrorDeliveryError,
    MirrorPolicyError,
    MirrorProgressStore,
    TelegramClient,
    TelegramPolicy,
    deliver_rendered_parts,
)


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


def optional_json_list(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return list(default)
    value = json.loads(raw)
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
        audience_types=optional_json_list(
            "TRIBE_V1_MIRROR_AUDIENCE_TYPES", ["group"]
        ),
        classifications=optional_json_list(
            "TRIBE_V1_MIRROR_CLASSIFICATIONS", ["tribe-public"]
        ),
    )
    telegram = TelegramClient(
        required("TRIBE_TELEGRAM_BOT_TOKEN"),
        int(required("TRIBE_TELEGRAM_CHAT_ID")),
        policy,
    )
    store_path = os.environ.get(
        "TRIBE_V1_MIRROR_DB",
        str(Path.home() / ".tribe-bridge/v1/mirror.sqlite"),
    )
    store = InboxStore(store_path)
    progress = MirrorProgressStore(store_path)
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
                        parts = policy.render_parts(
                            payload, claim["envelope"]
                        )
                        deliver_rendered_parts(
                            progress,
                            sender_id=sender,
                            message_id=message_id,
                            envelope_sha256=claim["envelope_sha256"],
                            parts=parts,
                            send=telegram.send_rendered,
                            now_ms=now,
                        )
                        store.finish(
                            sender,
                            message_id,
                            "processed",
                            payload=payload,
                            now_ms=now,
                        )
                        progress.clear(sender, message_id)
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
                        progress.clear(sender, message_id)
                        outcome = "terminal_failed"
                    except MirrorDeliveryError as exc:
                        store.release(sender, message_id)
                        outcome = "retryable_failed"
                        failures.append(
                            exc.failure_record(
                                endpoint=endpoint,
                                message_id=message_id,
                            )
                        )
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
