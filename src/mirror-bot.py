#!/usr/bin/env python3
"""Tribe Bridge mirror bot — bidirectional LCM ↔ Telegram bridge.

Roster values support 'ip' or 'ip:port' format — the port in the
roster overrides TRIBE_BRIDGE_PORT for per-agent LCM instances
(needed for hub model where agents share a host on different ports).
"""

import json, os, re, subprocess, sys, tempfile, time, urllib.request
import importlib.util
from pathlib import Path
from typing import Dict

def load_roster() -> Dict[str, str]:
    return json.loads(os.environ.get("TRIBE_ROSTER", "{}"))

def _resolve_addr(addr: str, default_port: int) -> tuple:
    """Resolve roster address. Supports 'ip' or 'ip:port'."""
    if ":" in addr:
        host, p = addr.rsplit(":", 1)
        return host, int(p)
    return addr, default_port

def fetch_inbox(ip: str, port: int, since: int) -> list:
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

def fetch_telegram_mentions(token: str, offset: int, roster: Dict[str, str]) -> tuple:
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
        from_user = msg.get("from", {})

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
    payload = {"from": "tribu", "to": target, "text": text,
               "ts": int(time.time())}
    kit_root = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("lcm", kit_root / "lcm-server.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
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

    default_port = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
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
          f"tg_offset={tg_offset}", file=sys.stderr)

    seen_ids: set = set()

    while True:
        # 1. Telegram → LCM: route @agent mentions
        mentions, tg_offset = fetch_telegram_mentions(token, tg_offset, roster)
        for agent_name, text, _ in mentions:
            addr = roster.get(agent_name, "")
            if addr:
                ip, rport = _resolve_addr(addr, default_port)
                if route_to_lcm(ip, rport, agent_name, text):
                    print(f"[mirror] routed mention → {agent_name}", file=sys.stderr)

        # 2. LCM → Telegram: mirror agent messages (deduped)
        for name, addr in roster.items():
            ip, rport = _resolve_addr(addr, default_port)
            since = last_seen.get(name, int(time.time()))
            messages = fetch_inbox(ip, rport, since)
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

        try:
            offset_file.write_text(str(tg_offset))
        except Exception:
            pass

        time.sleep(interval)

if __name__ == "__main__":
    main()
