#!/usr/bin/env python3
"""Tribe Bridge mirror bot — bidirectional LCM ↔ Telegram bridge.

LCM → Telegram: polls all agent inboxes and mirrors messages to the group.
Telegram → LCM: reads @agent mentions from the group and routes them
to the target agent's LCM server. Messages are SSH-signed as "tribu".

Environment:
  TELEGRAM_BOT_TOKEN   — bot token from @BotFather
  TELEGRAM_CHAT_ID     — target group chat ID
  TRIBE_ROSTER         — agent→IP mapping
  TRIBE_BRIDGE_PORT    — LCM port (default 8585)
  MIRROR_SSH_KEY       — path to SSH private key for signing (default ~/.ssh/id_ed25519)
  POLL_INTERVAL        — seconds between polls (default 15)
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Dict, List


def load_roster() -> Dict[str, str]:
    raw = os.environ.get("TRIBE_ROSTER", "{}")
    return json.loads(raw)


def fetch_inbox(ip: str, port: int, since: int) -> List[dict]:
    url = f"http://{ip}:{port}/inbox?since={since}&limit=50&decrypt=true"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode()).get("messages", [])
    except Exception:
        return []


def send_telegram(token: str, chat_id: str, text: str):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({"chat_id": chat_id, "text": text,
                          "parse_mode": "HTML"}).encode("utf-8")
    req = urllib.request.Request(url, data=payload,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as exc:
        print(f"[mirror] Telegram send failed: {exc}", file=sys.stderr)
        return False


def fetch_telegram_mentions(token: str, offset: int, roster: Dict[str, str]) -> list:
    """Poll Telegram for @agent mentions. Returns [(agent_name, text, update_id), ...]."""
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    if offset:
        url += f"?offset={offset}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return [], offset

    results = []
    new_offset = offset
    for update in data.get("result", []):
        uid = update.get("update_id", 0)
        if uid > new_offset:
            new_offset = uid
        msg = update.get("message") or update.get("channel_post")
        if not msg:
            continue
        text = msg.get("text", "") or msg.get("caption", "")
        chat = msg.get("chat", {})
        from_user = msg.get("from", {})

        # Find @agent mentions in the text
        mentioned = set()
        for word in text.split():
            if word.startswith("@") and word[1:] in roster:
                mentioned.add(word[1:])

        if mentioned:
            sender_name = from_user.get("first_name", "alguien")
            for agent in mentioned:
                clean = re.sub(rf"@{agent}\b", "", text).strip()
                body = f"{sender_name}: {clean}"
                results.append((agent, body, uid))

    return results, new_offset + 1 if new_offset > offset else offset


def _sign_data(data: str) -> tuple:
    """Sign a string payload with the mirror bot's SSH key.
    Returns (signature_armored, signer_name)."""
    key_path = os.path.expanduser(
        os.environ.get("MIRROR_SSH_KEY", "~/.ssh/id_ed25519"))
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        result = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", key_path, "-n", "tribe-bridge", path],
            capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return "", ""
        sig = Path(path + ".sig").read_text().strip()
        return sig, "tribu"
    finally:
        Path(path).unlink(missing_ok=True)
        Path(path + ".sig").unlink(missing_ok=True)


def route_to_lcm(ip: str, port: int, target: str, text: str) -> bool:
    """Send a signed message to an agent's LCM server."""
    payload = {"from": "tribu", "to": target, "text": text,
               "ts": int(time.time())}
    try:
        from lcm_server import encrypt_payload
    except ImportError:
        # Fallback: import via importlib
        import importlib.util
        kit_root = Path(__file__).resolve().parent
        spec = importlib.util.spec_from_file_location("lcm", kit_root / "lcm-server.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        encrypt_payload = mod.encrypt_payload

    plain = json.dumps(payload)
    enc = encrypt_payload(plain)
    ct_json = json.dumps({"ciphertext": enc["ciphertext"], "nonce": enc["nonce"],
                          "tag": enc["tag"]}, separators=(",", ":"))
    sig, signer = _sign_data(ct_json)
    if not sig:
        return False

    envelope = {"ciphertext": enc["ciphertext"], "nonce": enc["nonce"],
                "tag": enc["tag"], "signature": sig, "signer": signer}
    url = f"http://{ip}:{port}/send"
    req = urllib.request.Request(url, data=json.dumps(envelope).encode(),
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as exc:
        print(f"[mirror] route to {target} failed: {exc}", file=sys.stderr)
        return False


def format_message(msg: dict) -> str:
    decrypted = msg.get("decrypted") or msg
    sender = decrypted.get("from") or msg.get("signer", "?")
    recipient = decrypted.get("to", "?")
    text = decrypted.get("text", "") or msg.get("ciphertext", "")[:40] + "..."
    reply = decrypted.get("reply_to", "")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if reply:
        return (f"<b>{sender}</b> → <b>{recipient}</b> "
                f"(reply to <code>{reply}</code>):\n{text}")
    return f"<b>{sender}</b> → <b>{recipient}</b>:\n{text}"


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        sys.stderr.write("ERROR: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set.\n")
        sys.exit(1)

    roster = load_roster()
    if not roster:
        sys.stderr.write("ERROR: TRIBE_ROSTER is empty.\n")
        sys.exit(1)

    port = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
    interval = int(os.environ.get("POLL_INTERVAL", "15"))
    last_seen: Dict[str, int] = {name: int(time.time()) for name in roster}
    tg_offset = 0
    offset_file = Path(os.environ.get("TRIBE_BRIDGE_DIR",
                     os.path.expanduser("~/.tribe-bridge"))) / ".tg_offset"
    if offset_file.exists():
        try:
            tg_offset = int(offset_file.read_text().strip())
        except Exception:
            pass

    print(f"[mirror] starting — {len(roster)} agents, poll={interval}s, "
          f"telegram={chat_id}, bidirectional, tg_offset={tg_offset}", file=sys.stderr)

    seen_ids: set = set()  # dedup across agents sharing a hub

    while True:
        # 1. Telegram → LCM: route @agent mentions
        mentions, tg_offset = fetch_telegram_mentions(token, tg_offset, roster)
        for agent_name, text, _ in mentions:
            ip = roster.get(agent_name)
            if ip:
                if route_to_lcm(ip, port, agent_name, text):
                    print(f"[mirror] routed mention → {agent_name}", file=sys.stderr)

        # 2. LCM → Telegram: mirror agent messages (deduped)
        for name, ip in roster.items():
            since = last_seen.get(name, int(time.time()))
            messages = fetch_inbox(ip, port, since)
            for msg in messages:
                msg_id = msg.get("id", "")
                if msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)
                formatted = format_message(msg)
                if send_telegram(token, chat_id, formatted):
                    ts = msg.get("received_at", 0)
                    if ts > last_seen.get(name, 0):
                        last_seen[name] = ts

        # persist tg_offset so restarts don't reprocess old messages
        try:
            offset_file.write_text(str(tg_offset))
        except Exception:
            pass

        time.sleep(interval)


if __name__ == "__main__":
    main()
