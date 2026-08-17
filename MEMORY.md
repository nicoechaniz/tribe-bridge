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
  Telegram has no request idempotency key. Payloads beyond eight parts and
  large opaque encodings produce one hash-and-provenance notice instead.
- Tribe ACK proves only Tribe delivery state. Matrix intake and semantic
  receipts are separate authenticated facts.
- WAL is forbidden on SQLite versions affected by the 2026 WAL-reset bug.
- Directory rollback repair is a forward successor and never reinstates an
  older accepted state.

## Integrated release-candidate references

- Tribe PR #65 / issues #64 and #66: the exact qualified source boundary and
  independent review state are recorded in the release-candidate receipt and
  PR checks.
- Matrix merged: `09414d6edd9586f539be8272c4979d0b36c86b87`
  (tree `d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`).
- Cluster merged: `820e3792a227b1848681a3421b113e8822c8d08a`
  (tree `4f62eb4f6eff1dfafbd477339a86fa7d5e70a5d8`).

These references are provenance, not deployment evidence. Canonical tracking
lives in `nicoechaniz/tribe-bridge` issues and AlterMundi Project #8. Human
approval is still required for real custody, participant contact, publication,
provisioning, service changes, cutover and eventual retirement.
