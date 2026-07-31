import base64
import json
import sys
import unittest
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

try:
    from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite
except ImportError:
    Suite = None


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import tribe_protocol_v1 as protocol


VECTORS = (
    ROOT / "protocol" / "v1" / "test-vectors" / "vectors.json"
)


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class EndpointVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_endpoint_receive_consumes_all_shared_vectors(self):
        for vector in self.vectors["cases"]:
            with self.subTest(vector=vector["id"]):
                try:
                    protocol.validate_endpoint_receive(
                        vector["envelope"], vector["context"]
                    )
                    actual = "accept"
                except protocol.ProtocolError as exc:
                    actual = exc.code
                self.assertEqual(actual, vector["expected"]["endpoint"])

    @unittest.skipIf(
        Suite is None,
        "cryptography>=49 is required for native RFC 9180 HPKE vectors",
    )
    def test_endpoint_decrypts_every_accepted_real_hpke_vector(self):
        suite = Suite(
            KEM.X25519,
            KDF.HKDF_SHA256,
            AEAD.CHACHA20_POLY1305,
        )
        for vector in self.vectors["cases"]:
            if vector["expected"]["endpoint"] != "accept":
                continue
            with self.subTest(vector=vector["id"]):
                envelope = vector["envelope"]
                receiver = vector["context"]["receiver_id"]
                recipient = next(
                    item
                    for item in envelope["recipients"]
                    if item["id"] == receiver
                )
                private_key = x25519.X25519PrivateKey.from_private_bytes(
                    decode(
                        self.vectors["test_recipient_private_keys"][receiver]
                    )
                )
                cek = suite.decrypt(
                    decode(recipient["enc"])
                    + decode(recipient["wrapped_cek"]),
                    private_key,
                    info=protocol.recipient_hpke_context(
                        envelope, recipient
                    ),
                )
                plaintext = ChaCha20Poly1305(cek).decrypt(
                    decode(envelope["payload"]["nonce"]),
                    decode(envelope["payload"]["ciphertext"]),
                    protocol.payload_aad(envelope),
                )
                self.assertEqual(
                    plaintext.decode("utf-8"),
                    vector["expected_plaintext"],
                )

    def test_valid_vector_canonical_hashes_and_test_key_are_reproducible(self):
        envelope = self.vectors["cases"][0]["envelope"]
        unsigned_hash = sha256(
            protocol.canonical_json(protocol.unsigned_envelope(envelope))
        ).hexdigest()
        preimage_hash = sha256(
            protocol.signature_preimage(envelope)
        ).hexdigest()
        self.assertEqual(
            unsigned_hash,
            self.vectors["valid_direct_canonical_unsigned_sha256"],
        )
        self.assertEqual(
            preimage_hash,
            self.vectors["valid_direct_signature_preimage_sha256"],
        )
        self.assertEqual(
            protocol.envelope_sha256(envelope),
            self.vectors["valid_direct_envelope_sha256"],
        )

        private_key = Ed25519PrivateKey.from_private_bytes(
            decode(self.vectors["test_signing_private_seed"])
        )
        self.assertEqual(
            base64.urlsafe_b64encode(
                private_key.public_key().public_bytes_raw()
            )
            .rstrip(b"=")
            .decode("ascii"),
            self.vectors["test_signing_public_key"],
        )


if __name__ == "__main__":
    unittest.main()
