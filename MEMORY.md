# Tribe Bridge — durable project memory

## Current architecture

Tribe Bridge v1 is the sole target architecture. It combines:

- a governance-signed, hash-chained identity/audience directory;
- HPKE-wrapped per-message CEKs and signed canonical envelopes;
- a hub that routes and persists ciphertext but cannot decrypt;
- transactional SQLite delivery, claims, leases, ACKs, outbox, retries,
  dead-letter state, integrity, and backup;
- signed replay-protected HTTP operations;
- one shared crypto library used by CLI, broker boundary, mirror, and Hermes;
- an explicit `tribe-public` group recipient for Telegram visibility.

## Decisions

- v0 message history is disposable and is not migrated or backed up.
- No v0 compatibility, protocol negotiation, downgrade, dual read/write, or
  rollback-to-v0 path exists.
- Direct delivery may fall back to a hub after an ambiguous failure using the
  same signed envelope and message ID; endpoint replay state deduplicates the
  possible two-broker copy.
- Delivery is at-least-once. External effects require the durable
  `(sender_id, message_id)` idempotency key.
- WAL is forbidden on SQLite versions affected by the 2026 WAL-reset bug.
- Production activation requires independent review and a one-way cutover
  drill at an exact build commit.

## Coordination

Canonical work is tracked in `nicoechaniz/tribe-bridge` issues and AlterMundi
Project #8. The v1 implementation is intentionally split into reviewable,
stacked PRs: protocol, durable broker, then clients/mirror/Hermes cutover.
