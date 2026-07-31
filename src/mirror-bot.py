#!/usr/bin/env python3
"""Tribe Bridge mirror bot — bidirectional LCM ↔ Telegram bridge.

Roster values support 'ip' or 'ip:port' format — the port in the
roster overrides TRIBE_BRIDGE_PORT for per-agent LCM instances
(needed for hub model where agents share a host on different ports).
"""

import base64
import html
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict

def load_roster() -> Dict[str, str]:
    roster = json.loads(os.environ.get("TRIBE_ROSTER", "{}"))
    if not isinstance(roster, dict) or not all(
        isinstance(name, str) and isinstance(address, str)
        for name, address in roster.items()
    ):
        raise ValueError("TRIBE_ROSTER must map agent names to addresses")
    return roster

def load_id_allowlist(name: str) -> set[str]:
    return {
        item.strip()
        for item in os.environ.get(name, "").split(",")
        if item.strip()
    }

def _resolve_addr(addr: str, default_port: int) -> tuple:
    """Resolve roster address. Supports 'ip' or 'ip:port'."""
    if ":" in addr:
        host, p = addr.rsplit(":", 1)
        return host, int(p)
    return addr, default_port

def fetch_inbox(ip: str, port: int, since: int) -> list:
    # Re-read the prior second because server timestamps have one-second
    # resolution; the caller deduplicates stable record IDs.
    safe_since = max(0, since - 1)
    url_path = f"/inbox?since={safe_since}&limit=50&decrypt=true"
    url = f"http://{ip}:{port}{url_path}"
    # Server request authentication deliberately signs only the URL path.
    signature, signer = _sign_data("GET /inbox")
    headers = {}
    if signature:
        headers = {
            "X-Tribe-Signature": base64.b64encode(
                signature.encode("utf-8")
            ).decode("ascii"),
            "X-Tribe-Signer": signer,
        }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode()).get("messages", [])
    except Exception as exc:
        print(f"[mirror] inbox read failed for {ip}:{port}: {exc}", file=sys.stderr)
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
    except urllib.error.HTTPError as exc:
        # Do not stringify HTTPError: its URL contains the Telegram bot token.
        print(
            f"[mirror] Telegram send failed: HTTP {exc.code}",
            file=sys.stderr,
        )
        return False
    except Exception as exc:
        print(
            f"[mirror] Telegram send failed: {type(exc).__name__}",
            file=sys.stderr,
        )
        return False

def fetch_telegram_mentions(
    token: str,
    offset: int,
    roster: Dict[str, str],
    allowed_chat_ids: set[str],
    allowed_user_ids: set[str],
) -> tuple:
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
        chat_id = str(msg.get("chat", {}).get("id", ""))
        text = msg.get("text", "") or msg.get("caption", "")
        from_user = msg.get("from", {})
        user_id = str(from_user.get("id", ""))
        if chat_id not in allowed_chat_ids or user_id not in allowed_user_ids:
            print(
                f"[mirror] ignored unauthorized Telegram update {uid}",
                file=sys.stderr,
            )
            continue

        mentioned = set()
        for word in text.split():
            name = word[1:] if word.startswith("@") else None
            if name and name in roster:
                mentioned.add(name)
            elif word == "@daimons":
                mentioned.update(roster.keys())

        if mentioned:
            sender_name = from_user.get("first_name", "alguien")
            # Replace mentions with names (preserve readability)
            clean = text
            for agent in mentioned:
                clean = re.sub(rf"@{re.escape(agent)}\b", agent, clean)
            clean = re.sub(r"@daimons\b", "daimons", clean).strip()
            body = f"{sender_name}: {clean}"
            provenance = {
                "platform": "telegram",
                "chat_id": chat_id,
                "user_id": user_id,
                "username": from_user.get("username", ""),
                "update_id": uid,
            }
            # Route as group: all recipients in one message
            results.append((sorted(mentioned), body, uid, provenance))

    return results, new_offset + 1 if new_offset > offset else offset

def _sign_data(data: str) -> tuple:
    """Return an armored SSH signature and its configured principal."""
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
            print(
                f"[mirror] ssh signing failed: {result.stderr.strip()}",
                file=sys.stderr,
            )
            return "", ""
        sig_armored = Path(path + ".sig").read_text().strip()
        return sig_armored, os.environ.get("MIRROR_PRINCIPAL", "tribu")
    finally:
        Path(path).unlink(missing_ok=True)
        Path(path + ".sig").unlink(missing_ok=True)

def route_to_lcm(
    ip: str,
    port: int,
    target: str,
    text: str,
    provenance: dict | None = None,
) -> bool:
    mirror_sender = os.environ.get("MIRROR_PRINCIPAL", "tribu")
    payload = {"from": mirror_sender, "to": target, "text": text,
               "ts": int(time.time()), "classification": "tribe-public"}
    if provenance:
        payload["provenance"] = provenance
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
    sender = html.escape(str(decrypted.get("from") or msg.get("signer", "?")))
    recipient = html.escape(str(decrypted.get("to", "?")))
    text = decrypted.get("text", "") or msg.get("ciphertext", "")[:40] + "..."
    reply = html.escape(str(decrypted.get("reply_to", "")))
    text = html.escape(str(text))
    if reply:
        return (f"<b>{sender}</b> → <b>{recipient}</b> "
                f"(reply to <code>{reply}</code>):\n{text}")
    return f"<b>{sender}</b> → <b>{recipient}</b>:\n{text}"

def is_telegram_public(msg: dict) -> bool:
    """Legacy v0 is public; explicit non-public labels are fail-closed."""
    decrypted = msg.get("decrypted") or msg
    return decrypted.get("classification", "tribe-public") == "tribe-public"

def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        sys.stderr.write("ERROR: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set.\n")
        sys.exit(1)

    try:
        roster = load_roster()
    except (json.JSONDecodeError, ValueError) as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        sys.exit(1)
    if not roster:
        sys.stderr.write("ERROR: TRIBE_ROSTER is empty.\n")
        sys.exit(1)

    mirror_principal = os.environ.get("MIRROR_PRINCIPAL", "tribu").strip()
    if not mirror_principal:
        sys.stderr.write("ERROR: MIRROR_PRINCIPAL must not be empty.\n")
        sys.exit(1)
    mirror_key = Path(
        os.path.expanduser(
            os.environ.get("MIRROR_SSH_KEY", "~/.ssh/id_ed25519")
        )
    )
    if not mirror_key.is_file():
        sys.stderr.write(f"ERROR: MIRROR_SSH_KEY not found: {mirror_key}\n")
        sys.exit(1)

    allowed_chat_ids = load_id_allowlist("TELEGRAM_ALLOWED_CHAT_IDS")
    allowed_user_ids = load_id_allowlist("TELEGRAM_ALLOWED_USER_IDS")
    if chat_id not in allowed_chat_ids:
        sys.stderr.write(
            "ERROR: TELEGRAM_CHAT_ID must be present in "
            "TELEGRAM_ALLOWED_CHAT_IDS.\n"
        )
        sys.exit(1)
    if not allowed_user_ids:
        sys.stderr.write(
            "ERROR: TELEGRAM_ALLOWED_USER_IDS must explicitly list humans "
            "authorized to route messages.\n"
        )
        sys.exit(1)

    default_port = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
    interval = int(os.environ.get("POLL_INTERVAL", "15"))
    # v0 history is intentionally not replayed after a mirror restart.
    startup_time = int(time.time())
    last_seen: Dict[str, int] = {name: startup_time for name in roster}
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
    seen_mentions: set = set()  # dedup mention routing across cycles

    while True:
        # 1. Telegram → LCM: route @agent mentions
        mentions, tg_offset = fetch_telegram_mentions(
            token,
            tg_offset,
            roster,
            allowed_chat_ids,
            allowed_user_ids,
        )
        for recipients, text, update_id, provenance in mentions:
            mention_key = (tuple(recipients), update_id)
            if mention_key in seen_mentions:
                continue
            seen_mentions.add(mention_key)
            if len(seen_mentions) > 10000:
                seen_mentions.clear()
                seen_mentions.add(mention_key)
            for agent in recipients:
                addr = roster.get(agent, "")
                if addr:
                    ip, rport = _resolve_addr(addr, default_port)
                    if route_to_lcm(ip, rport, agent, text, provenance):
                        print(f"[mirror] routed mention → {agent}", file=sys.stderr)

        # 2. LCM → Telegram + relay: mirror + forward to recipients
        for name, addr in roster.items():
            ip, rport = _resolve_addr(addr, default_port)
            since = last_seen.get(name, int(time.time()))
            messages = fetch_inbox(ip, rport, since)
            for msg in messages:
                msg_id = msg.get("id", "")
                if msg_id in seen_ids:
                    continue
                # Mirror to Telegram
                decrypted = msg.get("decrypted") or msg
                if not is_telegram_public(msg):
                    print(
                        f"[mirror] blocked non-public message {msg_id}",
                        file=sys.stderr,
                    )
                    seen_ids.add(msg_id)
                    ts = msg.get("received_at", 0)
                    if ts > last_seen.get(name, 0):
                        last_seen[name] = ts
                else:
                    formatted = format_message(msg)
                    if send_telegram(token, chat_id, formatted):
                        seen_ids.add(msg_id)
                        ts = msg.get("received_at", 0)
                        if ts > last_seen.get(name, 0):
                            last_seen[name] = ts
                if len(seen_ids) > 50000:
                    seen_ids.clear()
                    seen_ids.add(msg_id)

                # Relay: forward to recipient if they have their own LCM
                recipient = decrypted.get("to", "")
                if recipient and recipient != name and recipient in roster:
                    r_addr = roster[recipient]
                    r_ip, r_rport = _resolve_addr(r_addr, default_port)
                    # Only relay if recipient has a different LCM from the inbox
                    if (r_ip, r_rport) != (ip, rport):
                        text = decrypted.get("text", "")
                        sender = decrypted.get("from", decrypted.get("signer", "?"))
                        relay_text = f"{sender}: {text}"
                        if route_to_lcm(r_ip, r_rport, recipient, relay_text):
                            print(f"[mirror] relayed → {recipient}",
                                  file=sys.stderr)

        try:
            offset_file.write_text(str(tg_offset))
            offset_file.chmod(0o600)
        except Exception:
            pass

        time.sleep(interval)

if __name__ == "__main__":
    main()
