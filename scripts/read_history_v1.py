#!/usr/bin/env python3
"""Decrypt tribe v1 broker history without claiming (read-only review)."""
import json, os, sqlite3, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from tribe_crypto_v1 import KeyBundle, decrypt_envelope
from tribe_directory_v1 import Directory

def required(name):
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"{name} is required")
    return v

def main():
    since = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    keys = KeyBundle.load(required("TRIBE_V1_KEYS"))
    db = sqlite3.connect(os.path.expanduser("~/.tribe-bridge/v1/broker.sqlite"))
    rows = db.execute(
        "SELECT id, sender_id, audience_id, envelope_json, received_at_ms, "
        "datetime(received_at_ms/1000,'unixepoch') FROM messages WHERE id >= ? ORDER BY id",
        (since,),
    ).fetchall()
    for mid, sender, aud, env_json, recv_ms, ts in rows:
        env = json.loads(env_json)
        try:
            directory = Directory.load(
                required("TRIBE_V1_DIRECTORY"),
                required("TRIBE_V1_GOVERNANCE_ROOTS"),
                required("TRIBE_V1_DIRECTORY_STATE"),
                now_ms=recv_ms,
            )
            body = decrypt_envelope(env, directory=directory, keys=keys, now_ms=recv_ms)
            text = body.get("text", json.dumps(body, ensure_ascii=False))
        except Exception as exc:
            text = f"[_error: {exc}]"
        print(f"--- [{mid}] {ts} from={sender} to={aud}")
        print(text)
        print()

if __name__ == "__main__":
    main()
