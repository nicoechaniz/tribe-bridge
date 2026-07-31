#!/usr/bin/env python3
"""Retry durable Tribe v1 outbox messages after offline operation or crashes."""

import json
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tribe_broker_v1 import SQLiteBroker
from tribe_client_v1 import flush_outbox
from tribe_crypto_v1 import KeyBundle


def required(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def main():
    keys = KeyBundle.load(required("TRIBE_V1_KEYS"))
    routes = json.loads(required("TRIBE_V1_ROUTES"))
    if not isinstance(routes, dict):
        raise RuntimeError("TRIBE_V1_ROUTES must be a JSON object")
    outbox = SQLiteBroker(
        os.environ.get(
            "TRIBE_V1_CLIENT_DB",
            str(Path.home() / ".tribe-bridge/v1/client.sqlite"),
        )
    )
    result = flush_outbox(
        outbox,
        routes,
        keys=keys,
        now_ms=int(time.time() * 1000),
    )
    print(
        json.dumps(
            {
                "ok": not result["pending"],
                "protocol": "tribe/v1",
                "build_commit": required("TRIBE_V1_BUILD_COMMIT"),
                **result,
            }
        )
    )
    return 0 if not result["pending"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
