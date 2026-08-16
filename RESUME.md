# V0 release-candidate resume checkpoint

Status: Tribe Bridge is a transitional, non-authoritative transport component.
No running service, host state, directory epoch, key custody, or deployment is
part of this checkpoint.  Treat every infrastructure reference in older
historical evidence as non-current until a separate, exact operational gate is
approved.

Last reconciled: 2026-08-16.

## Exact merged baseline

- Repository: `nicoechaniz/tribe-bridge`
- Commit: `187c61d881e6de830a029027144193645f2c7f62`
- Tree: `84da16611be62581d9a049d9f567652c4cc4e61b`
- PR #63 is merged. It consolidated and superseded the unreviewed PR #61.
- Integrated Matrix baseline:
  `e855148ffac5b2f4068ba56be6324d7b78fb430f`
- Integrated Cluster baseline:
  `734fd0037dcf84783ef7991415014af7435a46f2`

Issue #64 owns the release-candidate preparation. Its branch contains only
local/synthetic rotation, forward-recovery, provisioning, tests and documents
until independent review and merge. It has not published a directory, changed
custody, contacted a participant, installed a service, or touched a host.

## Time-critical fact, not an authorization

The preserved epoch-5 evidence shows the earliest v1 keys expiring on
**2026-08-30 UTC**, not 2026-09-01. A hypothetical live rollout would therefore
need to finish by **2026-08-27 UTC** to retain margin. These dates motivate the
code and synthetic rehearsal; they do not authorize a live rotation.

## Current boundary

- v0 remains permanently retired. There is no parser, fallback, migration,
  roster-derived key, or dual-write path to restore.
- Tribe authenticates transport, durable deduplication and ACK only. A Tribe
  ACK is never Matrix authenticated intake, relationship/grant consent, or a
  Matrix semantic receipt.
- The rotation composer accepts signed public announcements from every active
  synthetic holder and holds no participant private key. Offline governance
  threshold signing remains a distinct ceremony.
- Provisioning is content-addressed and zero-SSH. It can bind an already
  authorized signed directory to an already local private bundle; it cannot
  enroll, authorize, widen locality, rotate roots, or touch a remote system.
- Recovery after a signed/accepted directory advance is forward-only. Restoring
  an older directory or anti-rollback state is not a rollback mechanism.

## Resume order

1. Qualify issue #64 from a clean environment and obtain independent review on
   its exact commit.
2. Merge only after the coordination claim, PR evidence and checks agree.
3. Keep issues #56 (provisioning) and #59 (rotation) open for their live human
   gates or close/supersede them only with explicit traceability.
4. Do not activate, publish, provision a real participant, create real custody,
   install timers/services, contact anyone, or archive Tribe without a separate
   content-addressed plan and authorization.

The three-repository release-candidate roadmap is authoritative in the Matrix
repository. This repository's current transitional roadmap is
[`docs/adversarial-review-and-roadmap.md`](docs/adversarial-review-and-roadmap.md).
