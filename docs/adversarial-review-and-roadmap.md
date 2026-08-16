# Tribe Bridge transitional roadmap

Status: reconciled 2026-08-16 against merged baseline
`187c61d881e6de830a029027144193645f2c7f62` (tree
`84da16611be62581d9a049d9f567652c4cc4e61b`). Older draft-stack and deployment
tables are historical Git evidence, not this repository's current roadmap.

Integrated baselines are Matrix
`e855148ffac5b2f4068ba56be6324d7b78fb430f` and Cluster
`734fd0037dcf84783ef7991415014af7435a46f2`. No runtime, host, key, directory
epoch or external participant is asserted current by this document.

## Role in the integrated release candidate

Tribe Bridge remains a narrow transitional carrier:

- it may prove authenticated encrypted transport, durable enqueue/deduplication,
  claim and receiver ACK;
- it cannot prove Matrix authenticated recipient intake, relationship or grant
  consent, canonical event convergence, semantic processing or delivery;
- it must not dual-write or become an ambiguous fallback for Matrix;
- it retains no v0 compatibility, history migration or downgrade path.

## Closed local implementation gate — issue #64

The release-candidate branch must demonstrate, entirely with disposable state:

1. Each synthetic active agent independently generates successor private keys
   and signs a public announcement with its current key.
2. A keyless composer rejects forged, stale, wrong-base, duplicate, replayed or
   partial announcement sets; advances the directory and every active audience
   deterministically across process restarts and verification times; globally
   rejects successor KID reuse across signing/encryption purposes; performs
   full unsigned semantic validation; and emits only public content-addressed
   evidence. The human ceremony label is not authority: the exact announcement
   set and candidate hashes are.
3. Local activation is atomic, idempotent and retains old encryption keys for
   queued ciphertext through the bounded drain. It requires the currently
   selected signing and encryption keys even on retry, while trusted broker
   receipt time and HTTP verification fence both old public keys at the cut.
4. Recovery after an accepted advance produces a forward successor and rejects
   rollback or any recovery without active signing and encryption coverage for
   every agent through the candidate directory's exact expiry.
5. A content-addressed provisioning package applies without SSH or network
   access, matches already-local private keys, persists a target/epoch/hash/
   package high-water, accepts only exact replay at the same epoch, validates
   explicit locality, survives crashes including expiry during an exact
   journaled transaction, refuses to start an expired transaction and emits a
   sanitized receipt.
6. The complete supported-Python suite, protocol vectors, coordination audit,
   compilation and diff checks pass cleanly with no rerun used as evidence.
7. An independent adversarial reviewer approves the exact candidate hash before
   merge. The author does not self-approve or bypass branch protection.

## Known clock boundary

Preserved evidence shows the first keys expiring on 2026-08-30 UTC. A live
rotation would have needed to converge no later than 2026-08-27 UTC. Pure
directory-validity renewal does not extend key validity. The RC therefore
removes the automated remote single-holder renewal path and keeps its local
single-holder ceremony only as an explicitly synthetic fixture.

## Human and external gates after merge

None can be inferred from passing synthetic tests:

- name real custody owners and independently provision each holder;
- select the directory base/hash, activation waves, drain duration, canonical
  publication channel and independently pinned provisioning authority;
- obtain each participant's consent before contact or operation;
- approve generation of real keys and each governance signature;
- approve publication, client apply, service/timer installation, network
  health checks and authenticated round trips;
- define a content-addressed rollback/forward-recovery preflight and authorize
  the exact effects;
- authorize any Matrix cross-being canary and obtain the other being's
  independent consent/custody;
- authorize final Matrix cutover and eventual Tribe service/repository archive.

Until those gates are satisfied, the only honest claim is local reproducible
preparation. No physical or distributed-custody guarantee follows from the
synthetic holders.

## Threats retained by design

- A broker still observes timing, identifiers, sizes and availability.
- Shared GitHub accounts do not provide cryptographic agent attribution, and
  editable comments are not an immutable coordination ledger.
- Routes and health are deployment facts, not identity or authorization.
- A provisioning authority signs packaging, not governance. Compromise cannot
  enroll an agent but can misdirect network configuration until its pin is
  revoked by an operator.
- Retained old encryption keys expand local custody during the 72-hour drain;
  premature pruning strands queued ciphertext, while indefinite retention
  expands compromise exposure.
- Tribe ACKs terminate only Tribe delivery state. An application must use its
  own idempotency/effect record, and Matrix uses its own authenticated intake
  and semantic receipts.

## Exit from the transitional role

Archive or removal becomes eligible only after a separately approved Matrix
release/cutover proves native cross-being operation, assigns retry/cursor
ownership, preserves required evidence, and explicitly declares Tribe no
longer needed. The exit path never resurrects v0 or adds dual write.
