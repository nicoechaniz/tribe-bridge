#!/usr/bin/env python3
"""Tribe Bridge mirror bot — copies LCM messages to Telegram group.

Reads all configured agent inboxes and mirrors new messages to the
tribe Telegram group.  Humans see every message in real time.

Environment:
  TELEGRAM_BOT_TOKEN   — bot token from @BotFather
  TELEGRAM_CHAT_ID     — target group chat ID
  TRIBE_ROSTER         — agent→IP mapping (same as lcm-server)
  TRIBE_BRIDGE_PORT    — LCM port (default 8585)
  POLL_INTERVAL        — seconds between polls (default 15)
"""

import json
import os
import sys
import time
import urllib.request
from typing import Dict, List


def load_roster() -> Dict[str, str]:
    raw = os.environ.get("TRIBE_ROSTER", "{}")
    return json.loads(raw)


def fetch_inbox(ip: str, port: int, since: int) -> List[dict]:
    url = f"http://{ip}:{port}/inbox?since={since}&limit=50&decrypt=true"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("messages", [])
    except Exception:
        return []


def send_telegram(token: str, chat_id: str, text: str):
    """Send a message to a Telegram chat. Returns True on success."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as exc:
        print(f"[mirror] Telegram send failed: {exc}", file=sys.stderr)
        return False


def format_message(msg: dict) -> str:
    """Format an LCM message for Telegram display."""
    # Mirror fetches with ?decrypt=true — use decrypted payload
    decrypted = msg.get("decrypted") or msg
    sender = decrypted.get("from") or msg.get("signer", "?")
    recipient = decrypted.get("to", "?")
    text = decrypted.get("text", "") or msg.get("ciphertext", "")[:40] + "..."
    reply = decrypted.get("reply_to", "")

    # HTML-safe
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    if reply:
        return (
            f"<b>{sender}</b> → <b>{recipient}</b> (reply to <code>{reply}</code>):\n"
            f"{text}"
        )
    return f"<b>{sender}</b> → <b>{recipient}</b>:\n{text}"


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        sys.stderr.write(
            "ERROR: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set.\n"
        )
        sys.exit(1)

    roster = load_roster()
    if not roster:
        sys.stderr.write("ERROR: TRIBE_ROSTER is empty.\n")
        sys.exit(1)

    port = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
    interval = int(os.environ.get("POLL_INTERVAL", "15"))

    # Track last seen per agent
    last_seen: Dict[str, int] = {name: int(time.time()) for name in roster}

    print(f"[mirror] starting — {len(roster)} agents, poll={interval}s, "
          f"telegram={chat_id}", file=sys.stderr)

    while True:
        for name, ip in roster.items():
            since = last_seen.get(name, int(time.time()))
            messages = fetch_inbox(ip, port, since)

            for msg in messages:
                formatted = format_message(msg)
                if send_telegram(token, chat_id, formatted):
                    ts = msg.get("received_at", 0)
                    if ts > last_seen.get(name, 0):
                        last_seen[name] = ts

        time.sleep(interval)


if __name__ == "__main__":
    main()
