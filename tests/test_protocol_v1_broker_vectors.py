import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import tribe_protocol_v1 as protocol


VECTORS = (
    ROOT / "protocol" / "v1" / "test-vectors" / "vectors.json"
)


class BrokerVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_broker_admission_consumes_all_shared_vectors(self):
        for vector in self.vectors["cases"]:
            with self.subTest(vector=vector["id"]):
                try:
                    protocol.validate_broker_admission(
                        vector["envelope"], vector["context"]
                    )
                    actual = "accept"
                except protocol.ProtocolError as exc:
                    actual = exc.code
                self.assertEqual(actual, vector["expected"]["broker"])

    def test_schema_and_vector_documents_are_valid_json(self):
        schema_dir = ROOT / "protocol" / "v1" / "schema"
        schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in schema_dir.glob("*.schema.json")
        }
        self.assertEqual(
            schemas["envelope.schema.json"]["properties"]["version"]["const"],
            1,
        )
        self.assertEqual(
            schemas["directory.schema.json"]["properties"]["schema"]["const"],
            "tribe-directory/v1",
        )
        self.assertEqual(
            schemas["ack.schema.json"]["properties"]["schema"]["const"],
            "tribe-ack/v1",
        )
        self.assertEqual(
            self.vectors["format"], "tribe-v1-conformance-vectors/1"
        )

    def test_wire_parser_rejects_duplicate_properties_and_oversize(self):
        with self.assertRaisesRegex(
            protocol.ProtocolError, "duplicate_property"
        ):
            protocol.parse_envelope('{"protocol":"tribe","protocol":"v0"}')
        with self.assertRaisesRegex(
            protocol.ProtocolError, "envelope_too_large"
        ):
            protocol.parse_envelope(b"x" * (protocol.MAX_ENVELOPE_BYTES + 1))
        for invalid_number in ('{"n":-0}', '{"n":1.0}'):
            with self.subTest(value=invalid_number), self.assertRaisesRegex(
                protocol.ProtocolError, "malformed_envelope"
            ):
                protocol.parse_envelope(invalid_number)


if __name__ == "__main__":
    unittest.main()
