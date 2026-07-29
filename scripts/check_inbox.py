#!/usr/bin/env python3
"""Check Tribe Bridge inbox for messages.

Usage:
  TRIBE_AGENT_NAME=compaii python3 scripts/check_inbox.py
  TRIBE_AGENT_NAME=compaii python3 scripts/check_inbox.py --since 1785320000
  TRIBE_AGENT_NAME=compaii python3 scripts/check_inbox.py --json  # machine-readable

Any AI agent (Codex, Claude Code, Kimi, Grok, Hermes) can call this
from their terminal. Returns decrypted messages from the agent's inbox.
"""
import argparse, base64, json, os, subprocess, sys, tempfile, urllib.request
from pathlib import Path

def sign_get(path: str) -> tuple:
    """Sign a GET request path (no query params) with the agent's SSH key."""
    key = os.path.expanduser(os.environ.get("TRIBE_SSH_KEY", "~/.ssh/id_ed25519"))
    # Strip query params — server only verifies the base path
    base_path = path.split("?")[0]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(f"GET {base_path}")
        tmp = f.name
    try:
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", "tribe-bridge", tmp],
                      capture_output=True, timeout=10)
        armored = Path(tmp + ".sig").read_text().strip()
        return base64.b64encode(armored.encode()).decode(), os.environ.get("TRIBE_AGENT_NAME", "unknown")
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(tmp + ".sig").unlink(missing_ok=True)

def main():
    p = argparse.ArgumentParser(description="Check Tribe Bridge inbox")
    p.add_argument("--json", action="store_true", help="Output raw JSON (for agent consumption)")
    p.add_argument("--since", type=int, default=0, help="Only messages after this timestamp")
    p.add_argument("--limit", type=int, default=10, help="Max messages to return")
    p.add_argument("--hub", default="127.0.0.1:8585", help="Hub address (host:port)")
    args = p.parse_args()

    agent = os.environ.get("TRIBE_AGENT_NAME", "")
    hub_host, _, hub_port = args.hub.partition(":")
    hub_port = int(hub_port) if hub_port else 8585

    path = f"/inbox?decrypt=true&since={args.since}&limit={args.limit}"
    sig, signer = sign_get(path)
    url = f"http://{hub_host}:{hub_port}{path}"

    try:
        req = urllib.request.Request(url,
            headers={"X-Tribe-Signature": sig, "X-Tribe-Signer": signer})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())

        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            msgs = data.get("messages", [])
            print(f"{data.get('count', len(msgs))} messages:")
            for m in msgs:
                p = m.get("decrypted", m)
                print(f"  [{p.get('from', '?')} → {p.get('to', '?')}] {p.get('text', '')}")
    except urllib.error.HTTPError as e:
        err = json.loads(e.read().decode()) if e.code >= 400 else {"error": str(e)}
        if args.json:
            json.dump(err, sys.stdout, ensure_ascii=False)
        else:
            print(f"Error {e.code}: {err.get('error', str(e))}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
