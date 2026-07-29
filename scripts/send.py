#!/usr/bin/env python3
"""Send an encrypted, signed message to a tribe agent.

Usage:
  TRIBE_AGENT_NAME=compaii python3 scripts/send.py --to oliva --text "hola"
  python3 scripts/send.py --to oliva --text "hola" --from compaii --hub 144.217.95.152:8585

Requires TRIBE_AGENT_NAME or --from to be set.
"""
import argparse, json, os, subprocess, sys, tempfile, time, urllib.request
import importlib.util
from pathlib import Path
from typing import Optional

def sign_data(data: str, key_path: Optional[str] = None) -> tuple:
    key = key_path or os.environ.get("TRIBE_SSH_KEY") or str(Path.home() / ".ssh" / "id_ed25519")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(data); path = f.name
    try:
        r = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", "tribe-bridge", path],
                          capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            sys.exit(f"ssh-keygen failed: {r.stderr}")
        sig = Path(path + ".sig").read_text().strip()
        import base64; return base64.b64encode(sig.encode()).decode(), "sender"
    finally:
        Path(path).unlink(missing_ok=True); Path(path+".sig").unlink(missing_ok=True)

def main():
    p = argparse.ArgumentParser(description="Send an encrypted message through Tribe Bridge")
    p.add_argument("--to", required=True, help="Recipient agent name")
    p.add_argument("--text", required=True, help="Message body")
    p.add_argument("--sender", help="Sender name (default: $TRIBE_AGENT_NAME)")
    p.add_argument("--hub", default="144.217.95.152:8585", help="Hub address (host:port)")
    p.add_argument("--key", help="SSH key path (default: ~/.ssh/id_ed25519)")
    args = p.parse_args()

    agent_name = args.sender or os.environ.get("TRIBE_AGENT_NAME")
    hub_host, _, hub_port = args.hub.partition(":")
    hub_port = int(hub_port) if hub_port else 8585

    # Import lcm_server (from repo, not installed as package)
    repo = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("lcm", repo / "src" / "lcm-server.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader; spec.loader.exec_module(mod)

    # Encrypt
    payload = {"from": agent_name, "to": args.to, "text": args.text, "ts": int(time.time())}
    enc = mod.encrypt_payload(json.dumps(payload))

    # Sign ciphertext wrapper (raw armored for POST body)
    ct = json.dumps({"ciphertext": enc["ciphertext"], "nonce": enc["nonce"],
                     "tag": enc["tag"]}, separators=(",", ":"))
    sig = sign_data(ct, args.key)
    # sign_data returns b64-encoded for headers; decode back to armored for POST body
    import base64
    sig_armored = base64.b64decode(sig[0]).decode()

    # Send (armored sig in body — newlines are fine in JSON)
    envelope = {"ciphertext": enc["ciphertext"], "nonce": enc["nonce"],
                "tag": enc["tag"], "signature": sig_armored, "signer": agent_name}
    url = f"http://{hub_host}:{hub_port}/send"
    req = urllib.request.Request(url, data=json.dumps(envelope).encode(),
                                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read())
            print(f"Sent: {result.get('id', result)}")
    except urllib.error.HTTPError as e:
        sys.exit(f"Hub rejected: {e.code} - {e.read().decode()}")

if __name__ == "__main__":
    main()
