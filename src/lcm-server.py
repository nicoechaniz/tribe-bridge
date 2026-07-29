#!/usr/bin/env python3
"""Tribe Bridge — inter-agent messaging with gopass-style group encryption.

Security model:
  - Signing: each message is SSH-signed by the sender (non-repudiation)
  - Encryption: messages are encrypted with a group symmetric key derived
    deterministically from the allowed_signers roster. Any tribe member
    with the roster can decrypt. The server stores only ciphertext.

  This mirrors gopass: anyone with a key in the pool can read, signing
  proves authorship.

Endpoints:
  POST /send          — deliver an encrypted, signed message
  GET  /inbox         — list ciphertext messages (with ?decrypt=true to decrypt)
  GET  /inbox/pending — count of unread messages
  GET  /health        — liveness check

Encrypted message envelope:
  {
    "ciphertext": "base64-aes-gcm-ciphertext",
    "nonce": "base64-12-byte-nonce",
    "tag": "base64-16-byte-gcm-tag",
    "signature": "ssh-armored-signature-of-ciphertext",
    "signer": "compaii"
  }
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AESGCM = True
except ImportError:
    HAS_AESGCM = False

BRIDGE_DIR = Path(os.environ.get("TRIBE_BRIDGE_DIR", os.path.expanduser("~/.tribe-bridge")))
INBOX_DIR = BRIDGE_DIR / "inbox"
ALLOWED_SIGNERS = BRIDGE_DIR / "allowed_signers"
PORT = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
AGENT_NAME = os.environ.get("TRIBE_AGENT_NAME", "")
SIGN_NAMESPACE = "tribe-bridge"


def ensure_dirs():
    INBOX_DIR.mkdir(parents=True, exist_ok=True)


def derive_group_key() -> bytes:
    """Derive a 256-bit group key from the allowed_signers roster.

    The key is HMAC-SHA256 over sorted, deduplicated public keys.
    Any agent with the same set of pubkeys derives the identical key,
    regardless of file ordering.
    """
    if not ALLOWED_SIGNERS.exists():
        return secrets.token_bytes(32)

    # Parse pubkeys, sort by (name, pubkey), dedup
    parsed = set()
    for line in ALLOWED_SIGNERS.read_text().strip().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 3:
                parsed.add((parts[0], parts[1]))  # (name, ssh-ed25519 AAAA...)
    sorted_keys = "\n".join(f"{n} {k}" for n, k in sorted(parsed))
    return hmac.new(sorted_keys.encode("utf-8"), b"tribe-bridge-group-key", hashlib.sha256).digest()


def encrypt_payload(plaintext: str) -> dict:
    """Encrypt plaintext with AES-256-GCM using the group key."""
    if not HAS_AESGCM:
        return {"_unencrypted": plaintext}

    key = derive_group_key()
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # AES-GCM returns ciphertext || tag (last 16 bytes)
    ct_bytes = ciphertext[:-16]
    tag_bytes = ciphertext[-16:]

    return {
        "ciphertext": base64.b64encode(ct_bytes).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag_bytes).decode(),
    }


def decrypt_payload(enc: dict) -> str:
    """Decrypt an AES-256-GCM ciphertext with the group key."""
    if not HAS_AESGCM or "_unencrypted" in enc:
        return enc.get("_unencrypted", json.dumps(enc))

    key = derive_group_key()
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ciphertext"])
    tag = base64.b64decode(enc["tag"])
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct + tag, None)
    return plaintext.decode("utf-8")


def verify_signature(payload_bytes: bytes, signature: str, signer: str) -> bool:
    if not ALLOWED_SIGNERS.exists():
        return False

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sig", delete=False) as sf:
        sf.write(signature)
        sig_path = sf.name

    try:
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(ALLOWED_SIGNERS),
             "-I", signer, "-n", SIGN_NAMESPACE, "-s", sig_path],
            input=payload_bytes.decode("utf-8"),
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False
    finally:
        Path(sig_path).unlink(missing_ok=True)


class BridgeHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        ensure_dirs()
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        if os.environ.get("TRIBE_BRIDGE_VERBOSE"):
            sys.stderr.write(f"[tribe-bridge] {args[0]}\n")

    def do_POST(self):
        if self.path != "/send":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)
        body = raw_body.decode("utf-8")

        try:
            envelope = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        ciphertext = envelope.get("ciphertext")
        signature = envelope.get("signature", "")
        signer = envelope.get("signer", "")

        if not ciphertext or not signature or not signer:
            self._respond(400, {"error": "ciphertext, signature, and signer are required"})
            return

        # Verify SSH signature over the ciphertext JSON
        ct_for_signing = json.dumps({
            "ciphertext": ciphertext,
            "nonce": envelope.get("nonce", ""),
            "tag": envelope.get("tag", ""),
        }, separators=(",", ":"))

        if not verify_signature(ct_for_signing.encode("utf-8"), signature, signer):
            self._respond(403, {"error": f"invalid signature for {signer}"})
            return

        # Store ciphertext (server never decrypts)
        ts = int(time.time())
        body_hash = hashlib.sha256(raw_body).hexdigest()[:12]
        filename = f"{ts:010d}-{body_hash}.json"
        msg_record = {
            "ciphertext": ciphertext,
            "nonce": envelope.get("nonce", ""),
            "tag": envelope.get("tag", ""),
            "signature": signature,
            "signer": signer,
            "received_at": ts,
            "id": filename.replace(".json", ""),
        }
        (INBOX_DIR / filename).write_text(json.dumps(msg_record), encoding="utf-8")
        self._respond(201, {"ok": True, "id": msg_record["id"]})

    def _require_auth(self) -> bool:
        """Require SSH signature on inbox reads. Returns True if valid."""
        sig_header = self.headers.get("X-Tribe-Signature", "")
        signer = self.headers.get("X-Tribe-Signer", "")
        if not sig_header or not signer:
            return False
        # Signature is base64-encoded armored SSH signature for header transport
        import base64 as _b64
        try:
            signature = _b64.b64decode(sig_header).decode("utf-8")
        except Exception:
            return False
        # Sign path only (query params excluded — they can vary)
        parsed_path = urlparse(self.path).path
        request_data = f"{self.command} {parsed_path}".encode("utf-8")
        return verify_signature(request_data, signature, signer)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._respond(200, {"ok": True, "agent": AGENT_NAME,
                                "port": PORT, "encryption": HAS_AESGCM})
            return

        if parsed.path == "/inbox/pending":
            if not self._require_auth():
                self._respond(401, {"error": "signature required"})
                return
            params = parse_qs(parsed.query)
            agent_filter = params.get("agent", [None])[0]
            count = 0
            for f in sorted(INBOX_DIR.glob("*.json")):
                try:
                    msg = json.loads(f.read_text())
                    if agent_filter and msg.get("signer") != agent_filter:
                        continue
                    count += 1
                except Exception:
                    continue
            self._respond(200, {"pending": count})
            return

        if parsed.path == "/inbox":
            if not self._require_auth():
                self._respond(401, {"error": "signature required"})
                return
            params = parse_qs(parsed.query)
            since = int(params.get("since", [0])[0])
            agent_filter = params.get("agent", [None])[0]
            do_decrypt = params.get("decrypt", ["false"])[0].lower() == "true"
            limit = min(int(params.get("limit", [20])[0]), 100)

            messages = []
            for f in sorted(INBOX_DIR.glob("*.json")):
                try:
                    msg = json.loads(f.read_text())
                    ts = msg.get("received_at", 0)
                    if ts <= since:
                        continue
                    if agent_filter and msg.get("signer") != agent_filter:
                        continue
                    if do_decrypt and "ciphertext" in msg:
                        plaintext = decrypt_payload(msg)
                        msg["decrypted"] = json.loads(plaintext)
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
        sys.stderr.write("ERROR: TRIBE_AGENT_NAME not set.\n")
        sys.exit(1)

    ensure_dirs()

    if not HAS_AESGCM:
        sys.stderr.write("WARNING: cryptography not installed — encryption disabled.\n"
                         "  pip install cryptography\n")

    if not ALLOWED_SIGNERS.exists():
        sys.stderr.write(f"WARNING: {ALLOWED_SIGNERS} not found.\n")
    else:
        sys.stderr.write(f"[tribe-bridge] allowed_signers loaded "
                         f"({ALLOWED_SIGNERS.stat().st_size} bytes)\n")
        group_key = derive_group_key()
        sys.stderr.write(f"[tribe-bridge] group key derived "
                         f"(SHA256:{hashlib.sha256(group_key).hexdigest()[:16]}...)\n")

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
