import base64
import http.client
import importlib.util
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock


SERVER_PATH = Path(__file__).resolve().parents[1] / "src" / "lcm-server.py"
SPEC = importlib.util.spec_from_file_location("tribe_lcm_server_test", SERVER_PATH)
assert SPEC and SPEC.loader
lcm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lcm)


def generate_key(directory: Path, name: str) -> tuple[Path, str]:
    private_key = directory / name
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(private_key),
        ],
        check=True,
    )
    key_type, key_blob, *_ = Path(str(private_key) + ".pub").read_text().split()
    return private_key, f"{key_type} {key_blob}"


def sign(private_key: Path, content: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temporary:
        temporary.write(content)
        path = Path(temporary.name)
    try:
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-Y",
                "sign",
                "-f",
                str(private_key),
                "-n",
                "tribe-bridge",
                str(path),
            ],
            check=True,
        )
        return Path(str(path) + ".sig").read_text().strip()
    finally:
        path.unlink(missing_ok=True)
        Path(str(path) + ".sig").unlink(missing_ok=True)


class LcmConfigurationTests(unittest.TestCase):
    def test_malformed_envelope_is_rejected_before_signature_verification(self):
        self.assertIn("JSON object", lcm.validate_envelope([]))
        self.assertIn(
            "valid base64",
            lcm.validate_envelope(
                {
                    "ciphertext": "not-base64!",
                    "nonce": "bm9uY2U=",
                    "tag": "dGFn",
                    "signature": "signature",
                    "signer": "alice",
                }
            ),
        )

    def test_missing_crypto_fails_closed(self):
        with (
            mock.patch.object(lcm, "AGENT_NAME", "alice"),
            mock.patch.object(lcm, "HAS_AESGCM", False),
        ):
            with self.assertRaisesRegex(lcm.ConfigurationError, "cryptography"):
                lcm.validate_runtime_configuration()

    def test_global_bind_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, public_key = generate_key(root, "alice")
            allowed = root / "allowed_signers"
            allowed.write_text(f"alice {public_key}\n")
            with (
                mock.patch.object(lcm, "AGENT_NAME", "alice"),
                mock.patch.object(lcm, "ALLOWED_SIGNERS", allowed),
                mock.patch.object(lcm, "LOCAL_ALLOWED_SIGNERS", root / "missing"),
                mock.patch.object(lcm, "BIND_HOST", "0.0.0.0"),
                mock.patch.dict(os.environ, {}, clear=True),
            ):
                with self.assertRaisesRegex(lcm.ConfigurationError, "global bind"):
                    lcm.validate_runtime_configuration()

    def test_unknown_inbox_reader_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, public_key = generate_key(root, "alice")
            allowed = root / "allowed_signers"
            allowed.write_text(f"alice {public_key}\n")
            with (
                mock.patch.object(lcm, "AGENT_NAME", "alice"),
                mock.patch.object(lcm, "ALLOWED_SIGNERS", allowed),
                mock.patch.object(lcm, "LOCAL_ALLOWED_SIGNERS", root / "missing"),
                mock.patch.object(lcm, "BIND_HOST", "127.0.0.1"),
                mock.patch.dict(
                    os.environ,
                    {"TRIBE_INBOX_READERS": "unknown"},
                    clear=True,
                ),
            ):
                with self.assertRaisesRegex(lcm.ConfigurationError, "unknown"):
                    lcm.validate_runtime_configuration()


class LcmServerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.alice_key, alice_public = generate_key(self.root, "alice")
        self.bob_key, bob_public = generate_key(self.root, "bob")
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(
            f"alice {alice_public}\n"
            f"bob {bob_public}\n",
            encoding="utf-8",
        )
        self.bridge = self.root / "bridge"
        self.inbox = self.bridge / "inbox"

        patches = [
            mock.patch.object(lcm, "BRIDGE_DIR", self.bridge),
            mock.patch.object(lcm, "INBOX_DIR", self.inbox),
            mock.patch.object(lcm, "ALLOWED_SIGNERS", self.allowed),
            mock.patch.object(
                lcm, "LOCAL_ALLOWED_SIGNERS", self.root / "local-missing"
            ),
            mock.patch.object(lcm, "AGENT_NAME", "alice"),
            mock.patch.object(lcm, "MAX_BODY_BYTES", 4096),
            mock.patch.object(lcm, "MAX_RECORD_BYTES", 8192),
            mock.patch.object(lcm, "MAX_RESPONSE_BYTES", 65536),
            mock.patch.object(lcm, "MAX_MESSAGES", 10),
            mock.patch.object(lcm, "MAX_INBOX_RECORDS", 10),
            mock.patch.object(lcm, "MAX_CONCURRENT_REQUESTS", 1),
            mock.patch.object(lcm, "SOCKET_TIMEOUT", 2),
            mock.patch.dict(os.environ, {}, clear=True),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

        self.server = lcm.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), lcm.BridgeHandler
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def post_message(self) -> dict:
        payload = {
            "from": "alice",
            "to": "alice",
            "text": "hello",
            "classification": "tribe-public",
        }
        encrypted = lcm.encrypt_payload(json.dumps(payload))
        signed_content = json.dumps(
            {
                "ciphertext": encrypted["ciphertext"],
                "nonce": encrypted["nonce"],
                "tag": encrypted["tag"],
            },
            separators=(",", ":"),
        )
        envelope = {
            **encrypted,
            "signature": sign(self.alice_key, signed_content),
            "signer": "alice",
        }
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/send",
            data=json.dumps(envelope).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            self.assertEqual(response.status, 201)
            return json.loads(response.read())

    def get_inbox(self, principal: str, private_key: Path):
        signature = sign(private_key, "GET /inbox")
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/inbox?decrypt=true",
            headers={
                "X-Tribe-Signature": base64.b64encode(
                    signature.encode("utf-8")
                ).decode("ascii"),
                "X-Tribe-Signer": principal,
            },
        )
        return urllib.request.urlopen(request, timeout=2)

    def test_owner_can_read_but_other_member_cannot(self):
        self.post_message()
        with self.get_inbox("alice", self.alice_key) as response:
            body = json.loads(response.read())
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["messages"][0]["decrypted"]["text"], "hello")

        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.get_inbox("bob", self.bob_key)
        self.assertEqual(raised.exception.code, 403)

    def test_stored_record_and_directories_are_private(self):
        self.post_message()
        record = next(self.inbox.glob("*.json"))
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.bridge.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.inbox.stat().st_mode & 0o777, 0o700)

    def test_oversized_body_is_rejected_before_parsing(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(
            "POST",
            "/send",
            body=b"x" * 4097,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read()
        connection.close()

    def test_concurrency_is_bounded_and_saturated_server_returns_503(self):
        slow_client = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        self.addCleanup(slow_client.close)
        slow_client.sendall(
            b"POST /send HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 10\r\n\r\n"
            b"x"
        )
        deadline = time.monotonic() + 1
        while (
            getattr(self.server._request_slots, "_value", 1) != 0
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", "/health")
        response = connection.getresponse()
        self.assertEqual(response.status, 503)
        response.read()
        connection.close()


if __name__ == "__main__":
    unittest.main()
