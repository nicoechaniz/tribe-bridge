# Tribe v1 protocol package

This directory is the review boundary for the v1 wire and security contract.

- `THREAT-MODEL.md`: actors, assets, attacks, guarantees, and non-goals.
- `SPEC.md`: normative envelope, crypto, directory, replay, and cutover rules.
- `schema/*.schema.json`: closed envelope, directory, and acknowledgement
  schemas.
- `test-vectors/vectors.json`: positive and negative cases with real HPKE.
- `generate_vectors.py`: generator using test-only key material. HPKE creates
  fresh ephemeral keys, so regenerated wraps differ while remaining conformant.

Run both independent vector consumers:

```bash
python3 -m pip install -r protocol/v1/requirements-test.txt
python3 -m unittest \
  tests.test_protocol_v1_broker_vectors \
  tests.test_protocol_v1_endpoint_vectors -v
```

The generator's private seeds are public test material and MUST NOT be used
outside tests. Its envelopes contain real payload AEAD and HPKE CEK wraps using
PyCA's native RFC 9180 implementation.
