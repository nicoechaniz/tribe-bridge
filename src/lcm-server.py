#!/usr/bin/env python3
"""Tribe Bridge — lightweight inter-agent message server.

Each tribe member runs one instance on their AnyVPN IP, port 8585.
No dependencies beyond Python stdlib. Messages are stored as JSON
files in ~/.tribe-bridge/ (one file per message).

Endpoints:
  POST /send          — deliver a message to this agent
  GET  /inbox         — list messages (optional ?since=<unix_ts>)
  GET  /inbox/pending — count of unread messages (optional ?agent=<name>)
  GET  /health        — liveness check

Message format (POST /send):
  {"from": "compaii", "to": "oliva", "text": "¿cómo va?", "reply_to": null}

On disk: ~/.tribe-bridge/inbox/<ts>-<sha>.json
"""

import hashlib
import json
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs


BRIDGE_DIR = Path(os.environ.get("TRIBE_BRIDGE_DIR", os.path.expanduser("~/.tribe-bridge")))
INBOX_DIR = BRIDGE_DIR / "inbox"
PORT = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
AGENT_NAME = os.environ.get("TRIBE_AGENT_NAME", "")


def ensure_dirs():
    INBOX_DIR.mkdir(parents=True, exist_ok=True)


class BridgeHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Silence access logs unless TRIBE_BRIDGE_VERBOSE is set."""
        if os.environ.get("TRIBE_BRIDGE_VERBOSE"):
            sys.stderr.write(f"[tribe-bridge] {args[0]}\n")

    def do_POST(self):
        if self.path != "/send":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")

        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        required = ["from", "to", "text"]
        missing = [f for f in required if f not in msg]
        if missing:
            self._respond(400, {"error": f"missing fields: {missing}"})
            return

        ts = int(time.time())
        body_hash = hashlib.sha256(body.encode()).hexdigest()[:12]
        filename = f"{ts:010d}-{body_hash}.json"
        msg["received_at"] = ts
        msg["id"] = filename.replace(".json", "")

        (INBOX_DIR / filename).write_text(json.dumps(msg, indent=2), encoding="utf-8")
        self._respond(201, {"ok": True, "id": msg["id"]})

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._respond(200, {"ok": True, "agent": AGENT_NAME, "port": PORT})
            return

        if parsed.path == "/inbox/pending":
            params = parse_qs(parsed.query)
            agent_filter = params.get("agent", [None])[0]
            count = 0
            for f in sorted(INBOX_DIR.glob("*.json")):
                try:
                    msg = json.loads(f.read_text())
                    if agent_filter and msg.get("from") != agent_filter:
                        continue
                    count += 1
                except Exception:
                    continue
            self._respond(200, {"pending": count})
            return

        if parsed.path == "/inbox":
            params = parse_qs(parsed.query)
            since = int(params.get("since", [0])[0])
            agent_filter = params.get("agent", [None])[0]
            limit = min(int(params.get("limit", [20])[0]), 100)

            messages = []
            for f in sorted(INBOX_DIR.glob("*.json")):
                try:
                    msg = json.loads(f.read_text())
                    ts = msg.get("received_at", 0)
                    if ts <= since:
                        continue
                    if agent_filter and msg.get("from") != agent_filter:
                        continue
                    messages.append(msg)
                except Exception:
                    continue

            messages.sort(key=lambda m: m.get("received_at", 0))
            self._respond(200, {"messages": messages[-limit:], "count": len(messages)})
            return

        self.send_error(404)

    def _respond(self, code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    if not AGENT_NAME:
        sys.stderr.write("ERROR: TRIBE_AGENT_NAME not set. Export it before starting.\n")
        sys.exit(1)

    ensure_dirs()
    server = HTTPServer(("0.0.0.0", PORT), BridgeHandler)
    print(f"[tribe-bridge] {AGENT_NAME} listening on 0.0.0.0:{PORT}", file=sys.stderr)
    print(f"[tribe-bridge] inbox: {INBOX_DIR}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[tribe-bridge] shutting down", file=sys.stderr)
        server.server_close()


if __name__ == "__main__":
    main()
