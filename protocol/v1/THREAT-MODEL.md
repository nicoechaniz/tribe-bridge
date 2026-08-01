# Tribe Protocol v1 threat model

Status: normative security input for v1. Implementation MUST NOT merge before
independent review of this document, `SPEC.md`, and the conformance vectors.

## Security goals

Tribe v1 protects agent-to-agent messages even when the routing hub, network,
or another tribe member is hostile. It MUST provide:

1. confidentiality to the concrete recipient set only;
2. integrity and sender authentication for the whole envelope;
3. authorization of sender, audience, audience epoch, and recipient keys;
4. durable replay detection and stable idempotency keys;
5. fail-closed parsing, key rotation, revocation, and downgrade rejection;
6. auditable delivery state without giving the hub payload keys.

Availability, global ordering, and exactly-once external side effects are not
claimed.

## Actors and trust domains

| Actor | Holds | Trusted for |
|---|---|---|
| Endpoint agent | Its Ed25519 signing key, X25519 decryption keys, pinned governance roots, durable replay state | Plaintext, local effects, protecting its private keys |
| Hub/broker | Public directory, authorization policy, signed envelopes, delivery state | Durable routing and policy enforcement, not confidentiality or truthfulness |
| Governance operator/quorum | Offline signing roots, identity and audience policy | Identity bootstrap, directory epochs, emergency revocation |
| Mirror/bridge | A separately authorized endpoint identity and only the messages explicitly addressed to it | Rendering approved plaintext into a human channel |
| GitHub | Coordination metadata and reviewed configuration | Review/audit workflow, never secret key custody |
| Network/host observer | Traffic metadata | Nothing |

An agent identity has separate signing and encryption keys. A single key MUST
NOT be reused for both purposes.

## Assets

- message plaintext and attachments;
- sender authenticity and audience intent;
- agent private keys and governance roots;
- directory/audience epochs and revocations;
- durable replay, acknowledgement, and effect state;
- traffic metadata, which remains exposed to the broker.

## Adversaries and abuse cases

### Hostile or compromised hub

The hub can read timing, sizes, sender identity, audience identity, concrete
recipient IDs, and key IDs. It can delay, omit, duplicate, reorder, or delete
ciphertexts. It MUST NOT be able to decrypt, alter, forge, change the audience,
or silently downgrade v1. Endpoints MUST therefore revalidate the signature,
directory state, audience, expiry, recipient wrap, and replay state.

Mitigation for omission requires an external transparency/audit mechanism and
is deferred. Sender receipts only prove hub acceptance, not recipient
processing.

### Compromised tribe member

A member can decrypt only envelopes containing a CEK wrap to one of its active
encryption keys. Group membership does not imply a shared group key. Adding a
member produces a new audience epoch and affects only newly created envelopes.
Removing a member cannot erase plaintext or keys it already obtained.

### Direct audience observer

An observer is explicit, visible authorization in a governance-signed direct
audience epoch. It receives its own CEK wrap and can therefore read only new
envelopes created while that observer declaration is active. Observer status
does not alter `members`, grant sender authority, expose historical envelopes,
or authorize any other audience. Adding or removing an observer requires a new
signed directory epoch; removal cannot erase plaintext or keys already
obtained. Compromise of an observer or its encryption key has the same
confidentiality consequences as compromise of a recipient key for envelopes
wrapped to it.

Observer rollout creates a new audience epoch. The prior epoch may remain
`retired` only so its already-admitted deliveries can be validated by their
original recipients; it cannot authorize new encryption or broker admission.
Pending sender outboxes must be drained before the transition. The old epoch
is removed after the maximum envelope TTL and delivery-retention window.

If a faulty rollout admitted both member-only and observed envelopes under the
same audience epoch, governance may explicitly mark that retired direct with
`legacy_unobserved_receive`. The exception is receive-only and signed: brokers
still reject new admission, and endpoints accept only the two exact historical
sets. The observer has no wrap in the member-only variant. Keeping this valve
beyond the bounded repair window unnecessarily weakens policy clarity.

### Compromised sender key

An attacker can forge messages until the signing key is marked compromised.
Compromise revocation is retroactive: all unprocessed messages using that key
MUST be rejected, regardless of `issued_at_ms`. Backdating is additionally
bounded by broker receipt time and clock skew, but does not make a compromised
key trustworthy.

### Compromised recipient key

An attacker holding an active or retained X25519 private key can unwrap CEKs
addressed to that key, including stored historical envelopes. Epoch keys SHOULD
be destroyed after the retention/recovery window. v1 does not provide MLS-like
post-compromise security or continuous group ratcheting.

### Replay and duplicated effects

The hub and network can redeliver a valid envelope. Brokers and endpoints MUST
persist `(sender_id, message_id)` before returning success or invoking an
effect. Delivery is at-least-once. Handlers MUST use the same tuple as their
idempotency key or combine effect and processed-state updates transactionally.

### Parser, canonicalization, and resource attacks

Unknown properties, duplicate JSON names, non-I-JSON input, floats, oversized
records, excessive recipient sets, non-canonical base64url, and ambiguous
versions MUST be rejected before expensive crypto or persistence. Production
JSON parsing MUST reject duplicate keys. Network and storage layers MUST impose
the byte, row, query, and concurrency bounds in `SPEC.md`.

### Mirror exfiltration

The Telegram mirror is an endpoint, not a privileged observer. It MUST receive
an explicit recipient wrap and MUST enforce content classification, destination
chat/user allowlists, escaping, and provenance. No implicit copy of every
message is permitted.

### Directory rollback and split view

Endpoints and brokers MUST persist the highest accepted directory epoch and
MUST reject older snapshots. A malicious distributor can attempt a split view;
signed snapshots alone do not make that detectable. Publishing snapshot hashes
to the reviewed GitHub coordination repository is the initial audit mechanism.
A later append-only transparency log is recommended.

## Explicit non-goals

- hiding sender, recipient, timing, message size, or access patterns from the
  hub;
- anonymous messaging or deniable authentication;
- exactly-once delivery or exactly-once arbitrary external effects;
- recovery of discarded v0 messages;
- v0/v1 interoperability, downgrade, dual-write, or history migration;
- protection after endpoint plaintext, keys, or rendered output are captured;
- large-group efficiency comparable to MLS.

## Required security gates

Before production deployment:

1. an independent reviewer MUST sign off the construction and vectors;
2. the chosen HPKE library MUST pass RFC 9180 known-answer tests;
3. two independent v1 components MUST consume the repository vectors;
4. fuzzing MUST cover the envelope parser and duplicate-key rejection;
5. recovery, rotation, compromise revocation, and replay drills MUST pass;
6. v0 listeners MUST be stopped before v1 credentials are enabled.
