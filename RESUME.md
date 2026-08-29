# V0 release-candidate resume checkpoint

Status: Tribe Bridge is a transitional, non-authoritative transport component.
Its v1 protocol is the repository's only supported protocol, but no running
service, host state, directory epoch, key custody or deployment is claimed by
this checkpoint. Treat infrastructure references in historical evidence as
non-current until a separate exact operational gate is approved.

Last reconciled: 2026-08-29.

## Exact integrated boundary

- Tribe PR #65 merged as commit
  `294e1194db6cd60d9349a2d43938475bbd1c8c20`, tree
  `bcba9989a38519df87ecbb6c87a33a2f9740b85d`. Its stable qualified
  functional/material source is
  `8ce2c9d4c6b3e4e94108600d4170f169ced26303`, tree
  `0431882544ebd72bfbfbb343677b2557ea4fdbce`; 148 tests completed with
  zero failures on every supported Python 3.10-3.13 interpreter.
- Matrix PR #126 is merged on `main` at
  `899c6d95cc0205b1b7a327dda48095fc8bf94821`, tree
  `0af4dfdb3506cfe826ee53533f67eee88fb96389`. Its exact reviewed runtime
  material is `52945123ec4d323c03eaafe216dce8a1d7e48565`, with the same tree.
- Cluster PR #101 is merged on `main` at
  `49a919c836aec927f443857edabf34d37c9494e8`, tree
  `cb7254899230b5264313681617e445a4df0ef14f`. Its exact approved head is
  `417d8844c360265ade73c590cdf771a8c26b92fe`, with the same tree, and it pins
  Matrix runtime material `52945123ec4d323c03eaafe216dce8a1d7e48565`.

These hashes identify code and review boundaries only. They do not assert that
any of the three components is deployed.

## Current protocol and operational boundary

- Tribe v1 is the only accepted protocol. There is no v0 parser, downgrade,
  migration, dual-write path or receive-policy compatibility valve.
- Each audience epoch has one immutable recipient policy. Observer changes use
  a successor epoch; invalid in-place mutation is not repaired by widening the
  runtime parser.
- Tribe authenticates transport, durable deduplication and ACK only. A Tribe
  ACK is never Matrix authenticated intake, relationship/grant consent or a
  Matrix semantic receipt.
- The rotation composer accepts signed public announcements from every active
  synthetic holder and holds no participant private key. Offline governance
  threshold signing remains a distinct ceremony.
- Provisioning is content-addressed and zero-SSH. It can bind an already
  authorized signed directory to an already local private bundle; it cannot
  enroll, authorize, widen locality, rotate roots or touch a remote system.
- Recovery after a signed/accepted directory advance is forward-only. Restoring
  an older directory or anti-rollback state is not a rollback mechanism.

## Time-critical historical fact, not authorization

The preserved epoch-5 evidence shows the earliest v1 keys expiring on
**2026-08-30 UTC**. A hypothetical rollout from that state would have needed to
finish by **2026-08-27 UTC** to retain margin. Those dates motivate synthetic
rotation and recovery tests; they do not authorize a live rotation.

## Successor qualification protocol

1. Any metadata successor is accepted only after exact-head checks,
   independent review and normal merge; it must not change the qualified
   functional/material tree implicitly.
2. The external integrated manifest, not self-referential prose in this
   repository, records the resulting final Matrix, Cluster and Tribe heads,
   exact artifacts and replayed offline-install evidence.
3. Keep issues #56 and #59 open for live human gates, or supersede them only
   with explicit traceability.
4. Do not activate, publish, provision a participant, create real custody,
   install services/timers, contact anyone or archive Tribe without a separate
   content-addressed plan and authorization.

The integrated roadmap is authoritative in the Matrix repository. Tribe's
component roadmap is
[`docs/adversarial-review-and-roadmap.md`](docs/adversarial-review-and-roadmap.md),
the local qualification is recorded in
[`docs/release-candidate-receipt.json`](docs/release-candidate-receipt.json),
and [`docs/v1-cutover.md`](docs/v1-cutover.md) is preserved as historical
evidence rather than current deployment state.
