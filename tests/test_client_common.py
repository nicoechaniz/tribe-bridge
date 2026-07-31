import sys
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import client_common


class ClientCommonTests(unittest.TestCase):
    def test_resolve_address_supports_host_port_and_ipv6(self):
        self.assertEqual(client_common.resolve_address("10.8.0.5"), ("10.8.0.5", 8585))
        self.assertEqual(
            client_common.resolve_address("10.8.0.5:9000"), ("10.8.0.5", 9000)
        )
        self.assertEqual(
            client_common.resolve_address("[fd00::5]:9000"), ("fd00::5", 9000)
        )

    def test_roster_address_accepts_flat_and_route_aware_entries(self):
        flat = {"oliva": "10.8.0.5:8585"}
        nested = {
            "oliva": {
                "direct": "10.8.0.5:8585",
                "hub": "144.217.95.152:8587",
            }
        }
        self.assertEqual(
            client_common.roster_address(flat, "oliva"), "10.8.0.5:8585"
        )
        self.assertEqual(
            client_common.roster_address(nested, "oliva", "direct"),
            "10.8.0.5:8585",
        )
        self.assertEqual(
            client_common.roster_address(nested, "oliva", "hub"),
            "144.217.95.152:8587",
        )

    def test_logical_message_id_prefers_payload_id(self):
        record = {
            "id": "server-specific",
            "decrypted": {"message_id": "logical-123"},
        }
        self.assertEqual(
            client_common.logical_message_id(record), "message:logical-123"
        )

    def test_legacy_fingerprint_is_stable_across_inboxes(self):
        local = {
            "id": "100-local",
            "received_at": 100,
            "ciphertext": "cipher",
            "nonce": "nonce",
            "tag": "tag",
            "signature": "sig-a",
            "signer": "oliva",
        }
        hub = {
            **local,
            "id": "200-hub",
            "received_at": 200,
            "signature": "sig-b",
        }
        self.assertEqual(
            client_common.logical_message_id(local),
            client_common.logical_message_id(hub),
        )


if __name__ == "__main__":
    unittest.main()
