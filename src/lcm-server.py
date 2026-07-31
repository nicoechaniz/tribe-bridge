#!/usr/bin/env python3
"""Tribe Bridge v0 — authenticated tribe-public inter-agent messaging.

Security model:
  - Signing: each message is SSH-signed for sender authentication
  - Obfuscation at rest: messages use AES-GCM with a key derived entirely
    from the public allowed_signers roster.
  - Confidentiality: NONE. Anyone who obtains the roster can derive the key.

  Treat all v0 traffic and retained history as tribe-public. The AES-GCM layer
  is retained only for wire compatibility until protocol v1 replaces it with
  recipient-bound encryption.

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
import binascii
import hashlib
import hmac
import json
import os
import secrets
import socketserver
import subprocess
import sys
import tempfile
import threading
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
LOCAL_ALLOWED_SIGNERS = BRIDGE_DIR / "local_allowed_signers"
PORT = int(os.environ.get("TRIBE_BRIDGE_PORT", "8585"))
BIND_HOST = os.environ.get("TRIBE_BRIDGE_BIND", "127.0.0.1").strip()
AGENT_NAME = os.environ.get("TRIBE_AGENT_NAME", "")
SIGN_NAMESPACE = "tribe-bridge"
MAX_BODY_BYTES = int(os.environ.get("TRIBE_MAX_BODY_BYTES", "65536"))
MAX_RECORD_BYTES = int(os.environ.get("TRIBE_MAX_RECORD_BYTES", "131072"))
MAX_RESPONSE_BYTES = int(os.environ.get("TRIBE_MAX_RESPONSE_BYTES", "1048576"))
MAX_MESSAGES = int(os.environ.get("TRIBE_MAX_MESSAGES", "100"))
MAX_INBOX_RECORDS = int(os.environ.get("TRIBE_MAX_INBOX_RECORDS", "10000"))
SOCKET_TIMEOUT = float(os.environ.get("TRIBE_SOCKET_TIMEOUT", "10"))
MAX_CONCURRENT_REQUESTS = int(
    os.environ.get("TRIBE_MAX_CONCURRENT_REQUESTS", "16")
)


class ConfigurationError(RuntimeError):
    """Raised when v0 would otherwise start in an unsafe configuration."""


def env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def signer_principals() -> set[str]:
    """Return valid principals from both SSH allowed-signers files."""
    principals: set[str] = set()
    for signers_file in (ALLOWED_SIGNERS, LOCAL_ALLOWED_SIGNERS):
        if not signers_file.exists():
            continue
        for line in signers_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 3:
                principals.update(
                    name.strip()
                    for name in parts[0].split(",")
                    if name.strip()
                )
    return principals


def inbox_readers() -> set[str]:
    """Return principals authorized to read this server's inbox."""
    configured = {
        item.strip()
        for item in os.environ.get("TRIBE_INBOX_READERS", "").split(",")
        if item.strip()
    }
    return {AGENT_NAME, *configured}


def validate_runtime_configuration() -> None:
    """Fail closed instead of silently disabling security controls."""
    if not AGENT_NAME:
        raise ConfigurationError("TRIBE_AGENT_NAME is required")
    if not HAS_AESGCM:
        raise ConfigurationError(
            "the cryptography package with AESGCM support is required"
        )
    if not ALLOWED_SIGNERS.exists():
        raise ConfigurationError(f"{ALLOWED_SIGNERS} is required")

    principals = signer_principals()
    if not principals:
        raise ConfigurationError("allowed_signers contains no valid principals")
    if AGENT_NAME not in principals:
        raise ConfigurationError(
            f"TRIBE_AGENT_NAME {AGENT_NAME!r} is not an allowed principal"
        )

    unknown_readers = inbox_readers() - principals
    if unknown_readers:
        raise ConfigurationError(
            "TRIBE_INBOX_READERS contains unknown principals: "
            + ", ".join(sorted(unknown_readers))
        )

    global_binds = {"", "0.0.0.0", "::", "[::]"}
    if BIND_HOST in global_binds and not env_truthy("TRIBE_ALLOW_GLOBAL_BIND"):
        raise ConfigurationError(
            "global bind rejected; use a loopback/anyVPN address or explicitly "
            "set TRIBE_ALLOW_GLOBAL_BIND=true"
        )

    numeric_limits = {
        "TRIBE_MAX_BODY_BYTES": MAX_BODY_BYTES,
        "TRIBE_MAX_RECORD_BYTES": MAX_RECORD_BYTES,
        "TRIBE_MAX_RESPONSE_BYTES": MAX_RESPONSE_BYTES,
        "TRIBE_MAX_MESSAGES": MAX_MESSAGES,
        "TRIBE_MAX_INBOX_RECORDS": MAX_INBOX_RECORDS,
        "TRIBE_MAX_CONCURRENT_REQUESTS": MAX_CONCURRENT_REQUESTS,
    }
    invalid = [name for name, value in numeric_limits.items() if value < 1]
    if invalid or SOCKET_TIMEOUT <= 0:
        raise ConfigurationError(
            "request limits and socket timeout must be positive"
        )


def ensure_dirs():
    BRIDGE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    INBOX_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    BRIDGE_DIR.chmod(0o700)
    INBOX_DIR.chmod(0o700)


def derive_group_key() -> bytes:
    """Derive a 256-bit group key from the allowed_signers roster.

    The key is HMAC-SHA256 over sorted, deduplicated public keys.
    Any agent with the same set of pubkeys derives the identical key,
    regardless of file ordering.
    """
    # Parse pubkeys, sort by (name, pubkey), dedup
    parsed = set()
    for line in ALLOWED_SIGNERS.read_text().strip().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 3:
                parsed.add((parts[0], parts[1]))  # (name, ssh-ed25519 AAAA...)
    if not parsed:
        raise ConfigurationError("allowed_signers contains no valid keys")
    sorted_keys = "\n".join(f"{n} {k}" for n, k in sorted(parsed))
    return hmac.new(sorted_keys.encode("utf-8"), b"tribe-bridge-group-key", hashlib.sha256).digest()


def encrypt_payload(plaintext: str) -> dict:
    """Encrypt plaintext with AES-256-GCM using the group key."""
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
    if "_unencrypted" in enc:
        raise ValueError("unencrypted v0 payloads are rejected")

    key = derive_group_key()
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ciphertext"])
    tag = base64.b64decode(enc["tag"])
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct + tag, None)
    return plaintext.decode("utf-8")


def validate_envelope(envelope: object) -> str | None:
    """Return an error string for malformed v0 envelopes."""
    if not isinstance(envelope, dict):
        return "envelope must be a JSON object"
    required = ("ciphertext", "nonce", "tag", "signature", "signer")
    for field in required:
        value = envelope.get(field)
        if not isinstance(value, str) or not value:
            return f"{field} must be a non-empty string"
    if len(envelope["signer"]) > 256 or any(
        ord(character) < 32 for character in envelope["signer"]
    ):
        return "signer is invalid"
    try:
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        tag = base64.b64decode(envelope["tag"], validate=True)
    except (ValueError, binascii.Error):
        return "ciphertext, nonce, and tag must be valid base64"
    if not ciphertext:
        return "ciphertext must not be empty"
    if len(nonce) != 12:
        return "nonce must decode to 12 bytes"
    if len(tag) != 16:
        return "tag must decode to 16 bytes"
    return None


def verify_signature(payload_bytes: bytes, signature: str, signer: str) -> bool:
    """Verify SSH signature against allowed_signers (tribe + local)."""
    ensure_dirs()
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=INBOX_DIR,
        prefix=".verify-",
        suffix=".sig",
        delete=False,
    ) as temporary:
        temporary.write(signature)
        sig_path = Path(temporary.name)
    sig_path.chmod(0o600)
    try:
        for signers_file in [ALLOWED_SIGNERS, LOCAL_ALLOWED_SIGNERS]:
            if not signers_file.exists():
                if os.environ.get("TRIBE_BRIDGE_VERBOSE"):
                    sys.stderr.write(f"[verify] {signers_file} not found\n")
                continue
            result = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", str(signers_file),
                 "-I", signer, "-n", SIGN_NAMESPACE, "-s", str(sig_path)],
                input=payload_bytes.decode("utf-8"),
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return True
            if os.environ.get("TRIBE_BRIDGE_VERBOSE"):
                sys.stderr.write(f"[verify] {signers_file.name}: {result.stderr.strip()}\n")
        return False
    except Exception:
        return False
    finally:
        sig_path.unlink(missing_ok=True)


class BoundedThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Threaded HTTP server with an explicit global concurrency ceiling."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler_class):
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class BridgeHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        ensure_dirs()
        super().__init__(*args, **kwargs)

    def setup(self):
        super().setup()
        self.connection.settimeout(SOCKET_TIMEOUT)

    def log_message(self, format, *args):
        if os.environ.get("TRIBE_BRIDGE_VERBOSE"):
            sys.stderr.write(f"[tribe-bridge] {args[0]}\n")

    def do_POST(self):
        if self.path != "/send":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._respond(400, {"error": "invalid Content-Length"})
            return
        if length < 1:
            self._respond(411, {"error": "Content-Length is required"})
            return
        if length > MAX_BODY_BYTES:
            self._respond(413, {"error": "request body too large"})
            return

        raw_body = self.rfile.read(length)
        if len(raw_body) != length:
            self._respond(400, {"error": "incomplete request body"})
            return
        try:
            body = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            self._respond(400, {"error": "request body must be UTF-8"})
            return

        try:
            envelope = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        envelope_error = validate_envelope(envelope)
        if envelope_error:
            self._respond(400, {"error": envelope_error})
            return
        ciphertext = envelope["ciphertext"]
        signature = envelope["signature"]
        signer = envelope["signer"]

        # Verify SSH signature over the ciphertext JSON
        ct_for_signing = json.dumps({
            "ciphertext": ciphertext,
            "nonce": envelope.get("nonce", ""),
            "tag": envelope.get("tag", ""),
        }, separators=(",", ":"))

        if not verify_signature(ct_for_signing.encode("utf-8"), signature, signer):
            self._respond(403, {"error": f"invalid signature for {signer}"})
            return

        # Store the authenticated v0 record atomically.
        ts = int(time.time())
        body_hash = hashlib.sha256(raw_body).hexdigest()[:12]
        filename = f"{ts:010d}-{body_hash}.json"
        destination = INBOX_DIR / filename
        if (
            not destination.exists()
            and sum(1 for _ in INBOX_DIR.glob("*.json")) >= MAX_INBOX_RECORDS
        ):
            self._respond(507, {"error": "inbox capacity reached"})
            return
        msg_record = {
            "ciphertext": ciphertext,
            "nonce": envelope.get("nonce", ""),
            "tag": envelope.get("tag", ""),
            "signature": signature,
            "signer": signer,
            "received_at": ts,
            "id": filename.replace(".json", ""),
        }
        record_body = json.dumps(msg_record, ensure_ascii=False).encode("utf-8")
        if len(record_body) > MAX_RECORD_BYTES:
            self._respond(413, {"error": "message record too large"})
            return
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=INBOX_DIR,
            prefix=".incoming-",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(record_body)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        try:
            temporary_path.chmod(0o600)
            temporary_path.replace(destination)
        finally:
            temporary_path.unlink(missing_ok=True)
        self._respond(201, {"ok": True, "id": msg_record["id"]})

    def _authenticated_signer(self) -> str | None:
        """Return a verified SSH principal, or None."""
        sig_header = self.headers.get("X-Tribe-Signature", "")
        signer = self.headers.get("X-Tribe-Signer", "")
        if not sig_header or not signer:
            return None
        # Signature is base64-encoded armored SSH signature for header transport
        import base64 as _b64
        try:
            signature = _b64.b64decode(sig_header).decode("utf-8")
        except Exception:
            return None
        # Sign path only (query params excluded — they can vary)
        parsed_path = urlparse(self.path).path
        request_data = f"{self.command} {parsed_path}".encode("utf-8")
        if not verify_signature(request_data, signature, signer):
            return None
        return signer

    def _require_inbox_auth(self) -> bool:
        """Require both authentication and per-inbox authorization."""
        signer = self._authenticated_signer()
        if signer is None:
            self._respond(401, {"error": "valid signature required"})
            return False
        if signer not in inbox_readers():
            self._respond(403, {"error": "principal is not authorized for this inbox"})
            return False
        return True

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._respond(200, {"ok": True, "agent": AGENT_NAME,
                                "port": PORT, "encryption": HAS_AESGCM})
            return

        if parsed.path == "/inbox/pending":
            if not self._require_inbox_auth():
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
            if not self._require_inbox_auth():
                return
            params = parse_qs(parsed.query)
            try:
                since = int(params.get("since", [0])[0])
                requested_limit = int(params.get("limit", [20])[0])
            except ValueError:
                self._respond(400, {"error": "since and limit must be integers"})
                return
            if since < 0 or requested_limit < 1:
                self._respond(400, {"error": "since and limit must be positive"})
                return
            agent_filter = params.get("agent", [None])[0]
            do_decrypt = params.get("decrypt", ["false"])[0].lower() == "true"
            limit = min(requested_limit, MAX_MESSAGES)

            messages = []
            for f in sorted(INBOX_DIR.glob("*.json")):
                try:
                    if f.stat().st_size > MAX_RECORD_BYTES:
                        continue
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
        if len(body) > MAX_RESPONSE_BYTES:
            code = 413
            body = json.dumps({"error": "response too large"}).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            # Slow or disconnected clients must not produce noisy worker
            # tracebacks or affect other bounded request slots.
            return


def main():
    try:
        validate_runtime_configuration()
    except ConfigurationError as exc:
        sys.stderr.write(f"ERROR: unsafe configuration: {exc}\n")
        sys.exit(1)

    ensure_dirs()
    sys.stderr.write(
        f"[tribe-bridge] allowed_signers loaded "
        f"({ALLOWED_SIGNERS.stat().st_size} bytes)\n"
    )
    sys.stderr.write(
        "[tribe-bridge] SECURITY: v0 traffic is tribe-public; "
        "roster-derived AES-GCM does not provide confidentiality\n"
    )

    server = BoundedThreadingHTTPServer((BIND_HOST, PORT), BridgeHandler)
    print(
        f"[tribe-bridge] {AGENT_NAME} listening on {BIND_HOST}:{PORT}",
        file=sys.stderr,
    )
    print(f"[tribe-bridge] inbox: {INBOX_DIR}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[tribe-bridge] shutting down", file=sys.stderr)
        server.server_close()


if __name__ == "__main__":
    main()
