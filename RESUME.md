# V0 release-candidate resume checkpoint

Status: Tribe Bridge is a transitional, non-authoritative transport component.
Its v1 protocol is the repository's only supported protocol, but no running
service, host state, directory epoch, key custody or deployment is claimed by
this checkpoint. Treat infrastructure references in historical evidence as
non-current until a separate exact operational gate is approved.

Last reconciled: 2026-08-16.

## Exact integrated boundary

- Tribe merged baseline: commit
  `187c61d881e6de830a029027144193645f2c7f62`, tree
  `84da16611be62581d9a049d9f567652c4cc4e61b`.
- Tribe PR #65 carries the issue #64 release-candidate lineage. Its exact
  qualified source boundary and independent review state are recorded in the
  release-candidate receipt and PR checks; no earlier candidate is current.
- Matrix is merged at commit
  `09414d6edd9586f539be8272c4979d0b36c86b87`, tree
  `d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`.
- Cluster is merged at commit
  `4b77d2e47f31258d0801bd3a881b8dcf1a7584be`, tree
  `726159a25d6708a8388380f81f7cbec9f51122a9`.

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

## Resume order

1. Qualify the final PR #65 head from a clean environment across Python
   3.10-3.13 and verify its content-addressed receipt.
2. Obtain independent review on that exact head and merge only after the issue
   claim, PR evidence and required checks agree.
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
