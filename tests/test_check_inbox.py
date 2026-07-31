import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_inbox


def message(message_id, received_at, via="hub", server_id=None):
    return {
        "id": server_id or f"server-{message_id}",
        "received_at": received_at,
        "ciphertext": f"cipher-{message_id}",
        "nonce": f"nonce-{message_id}",
        "tag": f"tag-{message_id}",
        "signature": f"signature-{message_id}",
        "signer": "oliva",
        "decrypted": {
            "from": "oliva",
            "to": "codex",
            "text": message_id,
            "message_id": message_id,
            "via": via,
        },
    }


class CheckInboxTests(unittest.TestCase):
    def test_merge_deduplicates_local_and_hub_by_logical_id(self):
        local = message("same", 100, via="direct", server_id="local-record")
        hub = message("same", 200, via="direct", server_id="hub-record")

        merged = check_inbox.merge_messages([local], [hub])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "local-record")

    def test_mirror_reposts_original_signed_envelope(self):
        direct = message("direct-1", 100, via="direct")
        mirrored_ids = set()

        with mock.patch.object(
            check_inbox, "post_envelope", return_value={"id": "hub-record"}
        ) as post:
            warnings = check_inbox.mirror_direct_messages(
                [direct], [], "hub.example:8586", mirrored_ids, 5.0
            )

        self.assertEqual(warnings, [])
        self.assertEqual(mirrored_ids, {"message:direct-1"})
        post.assert_called_once_with(
            "hub.example:8586",
            {
                "ciphertext": direct["ciphertext"],
                "nonce": direct["nonce"],
                "tag": direct["tag"],
                "signature": direct["signature"],
                "signer": direct["signer"],
            },
            5.0,
        )

    def test_existing_hub_copy_prevents_repost(self):
        direct = message("direct-1", 100, via="direct")
        hub = message("direct-1", 200, via="direct")
        mirrored_ids = set()

        with mock.patch.object(check_inbox, "post_envelope") as post:
            warnings = check_inbox.mirror_direct_messages(
                [direct], [hub], "hub.example:8586", mirrored_ids, 5.0
            )

        self.assertEqual(warnings, [])
        self.assertEqual(mirrored_ids, {"message:direct-1"})
        post.assert_not_called()

    def test_drain_state_returns_each_message_once(self):
        state = {"seen_ids": set(), "mirrored_ids": set()}
        first = message("first", 100)
        second = message("second", 200)

        first_drain = check_inbox.drain_messages([first, second], [], state, 1)
        second_drain = check_inbox.drain_messages([first, second], [], state, 1)
        third_drain = check_inbox.drain_messages([first, second], [], state, 1)

        self.assertEqual([item["decrypted"]["message_id"] for item in first_drain], ["second"])
        self.assertEqual([item["decrypted"]["message_id"] for item in second_drain], ["first"])
        self.assertEqual(third_drain, [])

    def test_state_round_trip(self):
        state = {
            "seen_ids": {"message:one"},
            "mirrored_ids": {"message:two"},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            check_inbox.save_state(path, state)
            loaded = check_inbox.load_state(path)

        self.assertEqual(loaded, state)

    def test_main_drains_and_mirrors_only_once(self):
        direct = message("direct-1", 100, via="direct")
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            arguments = [
                "check_inbox.py",
                "--local",
                "local.example:8585",
                "--hub",
                "hub.example:8586",
                "--state-file",
                str(state_path),
            ]

            def fake_fetch(address, *args, **kwargs):
                return [direct] if address.startswith("local.") else []

            environment = {"TRIBE_AGENT_NAME": "codex"}
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(sys, "argv", arguments),
                mock.patch.object(check_inbox, "fetch_inbox", side_effect=fake_fetch),
                mock.patch.object(
                    check_inbox, "post_envelope", return_value={"id": "hub-record"}
                ) as post,
                contextlib.redirect_stdout(io.StringIO()) as first_output,
            ):
                check_inbox.main()

            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(sys, "argv", arguments),
                mock.patch.object(check_inbox, "fetch_inbox", side_effect=fake_fetch),
                mock.patch.object(check_inbox, "post_envelope") as second_post,
                contextlib.redirect_stdout(io.StringIO()) as second_output,
            ):
                check_inbox.main()

        self.assertIn("1 messages:", first_output.getvalue())
        self.assertIn("0 messages:", second_output.getvalue())
        post.assert_called_once()
        second_post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
