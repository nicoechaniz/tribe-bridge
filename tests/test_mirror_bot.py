import base64
import importlib.util
import io
import json
import types
import unittest
from pathlib import Path
from unittest import mock


MIRROR_PATH = Path(__file__).resolve().parents[1] / "src" / "mirror-bot.py"
SPEC = importlib.util.spec_from_file_location("tribe_mirror_test", MIRROR_PATH)
assert SPEC and SPEC.loader
mirror = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mirror)


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.body


class MirrorTests(unittest.TestCase):
    def test_explicit_non_public_message_is_not_telegram_public(self):
        self.assertFalse(
            mirror.is_telegram_public(
                {"decrypted": {"classification": "private"}}
            )
        )
        self.assertTrue(mirror.is_telegram_public({"decrypted": {}}))

    def test_telegram_http_errors_do_not_log_bot_token(self):
        stderr = io.StringIO()
        error = mirror.urllib.error.HTTPError(
            "https://api.telegram.org/botSECRET/sendMessage",
            403,
            "Forbidden",
            {},
            None,
        )
        with (
            mock.patch.object(
                mirror.urllib.request, "urlopen", side_effect=error
            ),
            mock.patch.object(mirror.sys, "stderr", stderr),
        ):
            self.assertFalse(mirror.send_telegram("SECRET", "-100", "text"))
        self.assertNotIn("SECRET", stderr.getvalue())
        self.assertIn("HTTP 403", stderr.getvalue())

    def test_format_message_escapes_all_html_controlled_fields(self):
        formatted = mirror.format_message(
            {
                "decrypted": {
                    "from": "<admin>",
                    "to": "&group",
                    "text": "<script>",
                    "reply_to": '"><b>oops</b>',
                }
            }
        )
        self.assertNotIn("<admin>", formatted)
        self.assertNotIn("<script>", formatted)
        self.assertIn("&lt;admin&gt;", formatted)
        self.assertIn("&lt;script&gt;", formatted)

    def test_inbox_signature_covers_path_only_and_header_is_base64(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse({"messages": []})

        with (
            mock.patch.object(
                mirror,
                "_sign_data",
                return_value=("-----BEGIN SSH SIGNATURE-----", "tribu"),
            ) as signer,
            mock.patch.object(mirror.urllib.request, "urlopen", fake_urlopen),
        ):
            self.assertEqual(mirror.fetch_inbox("127.0.0.1", 8585, 10), [])

        signer.assert_called_once_with("GET /inbox")
        request = captured["request"]
        encoded = request.headers["X-tribe-signature"]
        self.assertEqual(
            base64.b64decode(encoded).decode("utf-8"),
            "-----BEGIN SSH SIGNATURE-----",
        )
        self.assertEqual(request.headers["X-tribe-signer"], "tribu")
        self.assertIn("since=9", request.full_url)

    def test_route_posts_armored_signature_and_public_provenance(self):
        fake_module = types.SimpleNamespace()
        fake_loader = mock.Mock()
        fake_loader.exec_module.side_effect = lambda module: setattr(
            module,
            "encrypt_payload",
            lambda plaintext: {
                "ciphertext": "cipher",
                "nonce": "nonce",
                "tag": "tag",
            },
        )
        fake_spec = types.SimpleNamespace(loader=fake_loader)
        captured = {}

        def fake_urlopen(request, timeout):
            captured["envelope"] = json.loads(request.data)
            return FakeResponse({"ok": True})

        with (
            mock.patch.object(
                mirror.importlib.util,
                "spec_from_file_location",
                return_value=fake_spec,
            ),
            mock.patch.object(
                mirror.importlib.util,
                "module_from_spec",
                return_value=fake_module,
            ),
            mock.patch.object(
                mirror,
                "_sign_data",
                return_value=("-----BEGIN SSH SIGNATURE-----", "tribu"),
            ),
            mock.patch.object(mirror.urllib.request, "urlopen", fake_urlopen),
        ):
            result = mirror.route_to_lcm(
                "127.0.0.1",
                8585,
                "compaii",
                "hello",
                {"platform": "telegram", "user_id": "42"},
            )

        self.assertTrue(result)
        self.assertEqual(
            captured["envelope"]["signature"],
            "-----BEGIN SSH SIGNATURE-----",
        )
        self.assertEqual(captured["envelope"]["signer"], "tribu")

    def test_telegram_allowlists_filter_and_preserve_provenance(self):
        updates = {
            "result": [
                {
                    "update_id": 1,
                    "message": {
                        "chat": {"id": -100},
                        "from": {
                            "id": 42,
                            "first_name": "Nico",
                            "username": "nico",
                        },
                        "text": "@compaii hola",
                    },
                },
                {
                    "update_id": 2,
                    "message": {
                        "chat": {"id": -999},
                        "from": {"id": 42, "first_name": "Nico"},
                        "text": "@compaii unauthorized chat",
                    },
                },
                {
                    "update_id": 3,
                    "message": {
                        "chat": {"id": -100},
                        "from": {"id": 7, "first_name": "Mallory"},
                        "text": "@compaii unauthorized user",
                    },
                },
            ]
        }
        with mock.patch.object(
            mirror.urllib.request,
            "urlopen",
            return_value=FakeResponse(updates),
        ):
            mentions, offset = mirror.fetch_telegram_mentions(
                token="token",
                offset=0,
                roster={"compaii": "127.0.0.1:8585"},
                allowed_chat_ids={"-100"},
                allowed_user_ids={"42"},
            )

        self.assertEqual(offset, 4)
        self.assertEqual(len(mentions), 1)
        recipients, text, update_id, provenance = mentions[0]
        self.assertEqual(recipients, ["compaii"])
        self.assertEqual(text, "Nico: compaii hola")
        self.assertEqual(update_id, 1)
        self.assertEqual(
            provenance,
            {
                "platform": "telegram",
                "chat_id": "-100",
                "user_id": "42",
                "username": "nico",
                "update_id": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()
