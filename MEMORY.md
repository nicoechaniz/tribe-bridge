# Tribe Bridge — durable project memory

## Current architecture boundary

Tribe Bridge v1 is the repository's sole supported protocol and remains a
transitional carrier while the integrated Matrix/Cluster release candidate is
completed. This describes code, not a live deployment. No service, host,
directory epoch or key custody is assumed current.

The implementation combines a governance-signed hash-chained directory,
purpose-separated endpoint keys, encrypted canonical envelopes, durable
SQLite delivery/ACK state, signed replay-protected HTTP operations, explicit
locality and explicit Telegram visibility.

## Durable decisions

- v0 history is disposable and is not migrated or backed up.
- No v0 compatibility, protocol negotiation, downgrade, dual read/write or
  rollback-to-v0 path exists.
- An audience epoch has exactly one recipient policy. Observer changes create
  a successor epoch; runtime never accepts a compatibility flag to widen a
  retired epoch.
- Direct delivery may fall back to a hub after an ambiguous failure using the
  same signed envelope and message ID; endpoint replay state deduplicates the
  possible two-broker copy.
- Delivery is at-least-once. External effects require the durable
  `(sender_id, message_id)` idempotency key.
- Telegram multipart retries resume from a durable local cursor and never
  replay the recorded prefix. The current part can remain ambiguous because
  Telegram has no request idempotency key. Payloads beyond four parts produce
  one hash-and-provenance notice instead; no content classifier decides this.
- Tribe ACK proves only Tribe delivery state. Matrix intake and semantic
  receipts are separate authenticated facts.
- WAL is forbidden on SQLite versions affected by the 2026 WAL-reset bug.
- Directory rollback repair is a forward successor and never reinstates an
  older accepted state.

## Integrated release-candidate references

- Tribe PR #65 / issues #64 and #66 merged as
  `294e1194db6cd60d9349a2d43938475bbd1c8c20` (tree
  `bcba9989a38519df87ecbb6c87a33a2f9740b85d`). The receipt binds the stable
  qualified source `8ce2c9d4c6b3e4e94108600d4170f169ced26303` (tree
  `0431882544ebd72bfbfbb343677b2557ea4fdbce`).
- Matrix merged: `bf5f7415f075af09442973144bc529f4c5ce7985`
  (tree `f38862427d5713b21ca9d0859a80ddbacfefa255`).
- Cluster merged: `78b29af5e04eb008f5090dbcd3338ed7c011ee4b`
  (tree `8c787d51cbcbb35ebd494c0b6dbf5e167f5d3fdb`).

These references are provenance, not deployment evidence. The external
integrated manifest records the final three repository heads after this
metadata handoff merges; this file cannot name its own future merge commit.
Canonical tracking lives in `nicoechaniz/tribe-bridge` issues and AlterMundi
Project #8. Human
approval is still required for real custody, participant contact, publication,
provisioning, service changes, cutover and eventual retirement.
