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
- Tribe PR #65 carries the issue #64 release-candidate lineage whose reviewed
  pre-cleanup head was commit
  `7b9acda839423aa21afceae22abcd47008bbeba6`, tree
  `e443706cf191ab31d93252a128ed04530f6da39f`. The final cleanup and receipt
  require review on their new exact head before merge.
- Matrix is merged at commit
  `75b34804f8d013d348129946c0cd541a4448e71d`, tree
  `38f3edb002ac52aac2d51fbf533cb58c38b813c5`.
- Cluster's current code boundary is commit
  `93230a890ffad78aa1d10af2b68a33a45ff9845c`, tree
  `598f502df42408d3f6e0dc788e765461fb54081b`.

These hashes identify code and review boundaries only. They do not assert that
Cluster is merged or that any of the three components is deployed.

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
and [`docs/v1-cutover.md`](docs/v1-cutover.md) is preserved as historical
evidence rather than current deployment state.
