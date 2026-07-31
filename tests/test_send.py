import os
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import client_common
import send


class SendTests(unittest.TestCase):
    def setUp(self):
        self.build_patch = mock.patch.object(
            send,
            "build_envelope",
            side_effect=lambda module, payload, signer, key: {
                "payload": payload,
                "signer": signer,
            },
        )
        self.build_envelope = self.build_patch.start()
        self.addCleanup(self.build_patch.stop)

    def test_direct_delivery_succeeds_without_hub_write(self):
        with (
            mock.patch.object(send.uuid, "uuid4", return_value="message-1"),
            mock.patch.object(send.time, "time", return_value=100),
            mock.patch.object(
                send, "post_envelope", return_value={"id": "direct-record"}
            ) as post,
        ):
            route, result, message_id = send.deliver_message(
                recipient="oliva",
                text="hello",
                sender="codex",
                direct="10.8.0.5:8585",
                hub="hub.example:8587",
                lcm_module=object(),
            )

        self.assertEqual(route, "direct")
        self.assertEqual(result["id"], "direct-record")
        self.assertEqual(message_id, "message-1")
        post.assert_called_once()
        address, envelope, timeout = post.call_args.args
        self.assertEqual(address, "10.8.0.5:8585")
        self.assertEqual(timeout, 4.0)
        self.assertEqual(envelope["payload"]["via"], "direct")
        self.assertEqual(envelope["payload"]["message_id"], "message-1")

    def test_direct_failure_falls_back_with_same_logical_id(self):
        with (
            mock.patch.object(send.uuid, "uuid4", return_value="message-2"),
            mock.patch.object(send.time, "time", return_value=100),
            mock.patch.object(
                send,
                "post_envelope",
                side_effect=[
                    client_common.BridgeRequestError("offline"),
                    {"id": "hub-record"},
                ],
            ) as post,
            mock.patch.object(send.sys, "stderr"),
        ):
            route, result, message_id = send.deliver_message(
                recipient="oliva",
                text="hello",
                sender="codex",
                direct="10.8.0.5:8585",
                hub="hub.example:8587",
                lcm_module=object(),
            )

        self.assertEqual(route, "hub")
        self.assertEqual(result["id"], "hub-record")
        self.assertEqual(message_id, "message-2")
        self.assertEqual(post.call_count, 2)
        direct_payload = post.call_args_list[0].args[1]["payload"]
        hub_payload = post.call_args_list[1].args[1]["payload"]
        self.assertEqual(direct_payload["via"], "direct")
        self.assertEqual(hub_payload["via"], "hub")
        self.assertEqual(direct_payload["message_id"], hub_payload["message_id"])

    def test_missing_direct_endpoint_sends_to_hub_only(self):
        with mock.patch.object(
            send, "post_envelope", return_value={"id": "hub-record"}
        ) as post:
            route, _, _ = send.deliver_message(
                recipient="oliva",
                text="hello",
                sender="codex",
                direct=None,
                hub="hub.example:8587",
                lcm_module=object(),
            )

        self.assertEqual(route, "hub")
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], "hub.example:8587")
        self.assertEqual(post.call_args.args[1]["payload"]["via"], "hub")

    def test_endpoint_resolution_uses_flat_direct_and_separate_hub_rosters(self):
        environment = {
            "TRIBE_ROSTER": '{"oliva":"10.8.0.5:8585"}',
            "TRIBE_HUB_ROSTER": '{"oliva":"hub.example:8587"}',
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            direct, hub = send.resolve_endpoints("oliva")

        self.assertEqual(direct, "10.8.0.5:8585")
        self.assertEqual(hub, "hub.example:8587")


if __name__ == "__main__":
    unittest.main()
