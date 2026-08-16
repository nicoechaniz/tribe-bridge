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
- Tribe ACK proves only Tribe delivery state. Matrix intake and semantic
  receipts are separate authenticated facts.
- WAL is forbidden on SQLite versions affected by the 2026 WAL-reset bug.
- Directory rollback repair is a forward successor and never reinstates an
  older accepted state.

## Integrated release-candidate references

- Tribe PR #65 / issue #64: reviewed pre-cleanup head
  `7b9acda839423aa21afceae22abcd47008bbeba6` (tree
  `e443706cf191ab31d93252a128ed04530f6da39f`); the cleanup head requires a new
  exact review before merge.
- Matrix merged: `75b34804f8d013d348129946c0cd541a4448e71d`
  (tree `38f3edb002ac52aac2d51fbf533cb58c38b813c5`).
- Cluster code boundary: `93230a890ffad78aa1d10af2b68a33a45ff9845c`
  (tree `598f502df42408d3f6e0dc788e765461fb54081b`).

These references are provenance, not deployment evidence. Canonical tracking
lives in `nicoechaniz/tribe-bridge` issues and AlterMundi Project #8. Human
approval is still required for real custody, participant contact, publication,
provisioning, service changes, cutover and eventual retirement.
