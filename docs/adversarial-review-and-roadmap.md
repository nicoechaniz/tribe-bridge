# Tribe Bridge transitional roadmap

Status: reconciled 2026-08-29. Tribe PR #65 merged issue #64's RC lineage plus
issue #66's mirror-retry repair as
`294e1194db6cd60d9349a2d43938475bbd1c8c20` (tree
`bcba9989a38519df87ecbb6c87a33a2f9740b85d`). Its stable qualified source is
`8ce2c9d4c6b3e4e94108600d4170f169ced26303` (tree
`0431882544ebd72bfbfbb343677b2557ea4fdbce`), with 148 tests and zero failures
on Python 3.10-3.13.

Matrix PR #126 is merged at
`899c6d95cc0205b1b7a327dda48095fc8bf94821` (tree
`0af4dfdb3506cfe826ee53533f67eee88fb96389`), with exact reviewed runtime
material `52945123ec4d323c03eaafe216dce8a1d7e48565` at the same tree. Cluster
PR #101 is merged at `49a919c836aec927f443857edabf34d37c9494e8`
(tree `cb7254899230b5264313681617e445a4df0ef14f`); approved head
`417d8844c360265ade73c590cdf771a8c26b92fe` has the same tree and pins that
runtime material. These are code/provenance facts, not claims of deployment or
live custody. The later external integrated manifest records the final
metadata heads without creating a repository self-reference.

## Role in the integrated release candidate

Tribe Bridge remains a narrow transitional carrier:

- it may prove authenticated encrypted transport, durable enqueue/deduplication,
  claim and receiver ACK;
- it cannot prove Matrix authenticated recipient intake, relationship or grant
  consent, canonical event convergence, semantic processing or delivery;
- it must not dual-write or become an ambiguous fallback for Matrix;
- it retains no v0 compatibility, history migration or downgrade path;
- each audience epoch has one recipient policy, with no compatibility valve
  for an in-place observer mutation.

## Completed local implementation gate — issues #64 and #66 / PR #65

The merged candidate lineage demonstrated the following entirely with
disposable state:

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
   compilation and diff checks pass cleanly with no rerun used as evidence. A
   checked-in receipt binds the qualified source archive and exact requirements
   by SHA-256 and records rather than crosses the remaining human gates.
7. Telegram multipart retry persists the deterministic rendering and next
   unconfirmed part, never replays the durable prefix, reports the exact failed
   part without plaintext, and deterministically collapses every payload above
   four parts to one content-addressed human notice without attempting to
   classify its contents. The current part's response-loss ambiguity
   is explicit rather than overstated as global exactly-once delivery.
8. An independent adversarial reviewer approved each exact corrected candidate
   before normal merge. The author did not self-approve or bypass branch
   protection.

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

The exact local suite, requirements and qualified source archive are recorded
in [`release-candidate-receipt.json`](release-candidate-receipt.json). The
receipt intentionally records a source commit rather than claiming its own
record-only commit is part of the qualified archive.

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
