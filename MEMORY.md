# Tribe Bridge — durable project memory

## Current architecture boundary

Tribe Bridge v1 is the repository's sole implemented protocol, but the carrier
is superseded and scheduled for retirement in favor of native Matrix
communication. It is not a stable Matrix release gate. This describes code,
not a live deployment. No service, host, directory epoch or key custody is
assumed current.

The implementation combines a governance-signed hash-chained directory,
purpose-separated endpoint keys, encrypted canonical envelopes, durable
SQLite delivery/ACK state, signed replay-protected HTTP operations, explicit
locality and explicit Telegram visibility.

## Durable decisions

- All Tribe operational state is disposable and is not migrated or backed up:
  this includes v0/v1 messages, queues, directories, keys, databases, profiles,
  routes, timers and configuration. Public Git provenance is preserved.
- No v0 compatibility, protocol negotiation, downgrade, dual read/write or
  rollback-to-v0 path exists.
- Matrix qualification must run with Tribe absent; there is no fallback,
  compatibility or dual-run phase.
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
- Matrix PR #126 merged on `main` as
  `899c6d95cc0205b1b7a327dda48095fc8bf94821` (tree
  `0af4dfdb3506cfe826ee53533f67eee88fb96389`). Its exact reviewed runtime
  material is `52945123ec4d323c03eaafe216dce8a1d7e48565`, with the same tree.
- Cluster PR #101 merged on `main` as
  `49a919c836aec927f443857edabf34d37c9494e8` (tree
  `cb7254899230b5264313681617e445a4df0ef14f`). Its approved head
  `417d8844c360265ade73c590cdf771a8c26b92fe` has the same tree and pins the
  exact Matrix runtime material above.

These references are provenance, not deployment evidence. The external
integrated manifest records the final three repository heads after this
metadata handoff merges; this file cannot name its own future merge commit.
Canonical tracking lives in `nicoechaniz/tribe-bridge` issues and AlterMundi
Project #8. Human approval is still required for real Matrix custody,
participant contact, publication and cutover. Tribe provisioning and rotation
issues #56 and #59 are superseded by issue #71; exact human GOs remain required
to remove any live experimental runtime and later archive this repository
read-only.
