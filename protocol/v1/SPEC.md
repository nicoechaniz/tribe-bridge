# Tribe Protocol v1

Status: draft normative specification for independent review.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are to be interpreted as
described in BCP 14 when, and only when, they appear in all capitals.

## 1. Clean cutover

v1 is a new protocol and data namespace. A v1 parser MUST accept only
`protocol = "tribe"` and integer `version = 1`. It MUST reject v0 envelopes,
missing versions, strings such as `"1"`, unknown suites, and downgrade
negotiation. There is no negotiation endpoint.

The v0 message history is disposable. Operators MUST NOT migrate, import,
dual-write, back up, or preserve it for v1. v0 services MUST be stopped before
v1 credentials become active. v1 stores MUST start empty.

## 2. Wire representation

The wire format is UTF-8 JSON conforming to I-JSON. Duplicate property names,
invalid Unicode, floats, integers outside the exact IEEE-754 range, unknown
properties, non-canonical base64url, and non-schema values MUST be rejected.

The normative schema is `schema/envelope.schema.json`. The runtime validator
adds size, uniqueness, cryptographic-length, UUIDv7 timestamp, and semantic
constraints that JSON Schema cannot express.

Binary values use unpadded RFC 4648 base64url. A decoder MUST decode and
re-encode to prove the input is canonical.

Canonical cryptographic inputs use the RFC 8785 JSON Canonicalization Scheme.
v1 envelope schemas contain only integers, strings, booleans, nulls, arrays,
and objects. All property names are protocol-defined ASCII and extension
properties are forbidden, avoiding cross-runtime numeric and key-sort
ambiguity.

## 3. Cryptographic suite

The only v1 suite is:

`TB1_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS`

It consists of:

- RFC 9180 HPKE base mode;
- KEM `DHKEM(X25519, HKDF-SHA256)` (`0x0020`);
- KDF `HKDF-SHA256` (`0x0001`);
- AEAD `ChaCha20Poly1305` (`0x0003`);
- payload AEAD `ChaCha20Poly1305`;
- RFC 8032 Ed25519 signatures;
- RFC 8785 JCS.

Production implementations MUST use PyCA `cryptography` 49 or newer (native
RFC 9180 HPKE) and MUST pass the RFC 9180 known-answer vectors. Hand-rolled
production HPKE is forbidden.

For each message the sender MUST draw a new random 32-byte content-encryption
key (CEK) and a new random 12-byte payload nonce from the operating system
CSPRNG. Reusing a CEK or nonce with that CEK is forbidden.

The payload plaintext is encrypted once with ChaCha20Poly1305 under the CEK.
The AEAD AAD is:

```
"tribe/v1/payload-aad" || 0x00 || JCS(protected_metadata)
```

For each concrete recipient the sender performs an independent HPKE base-mode
Seal to that recipient's active X25519 public key. The 32-byte CEK is the HPKE
plaintext. HPKE `info` MUST be:

```
"tribe/v1/cek-wrap" || 0x00 || JCS({
  "protected": protected_metadata,
  "recipient_id": recipient.id,
  "encryption_kid": recipient.encryption_kid
})
```

The HPKE operation uses its empty-AAD default. The `info` value is part of the
HPKE key schedule and therefore binds the wrap to the version, message,
audience, and concrete recipient. The outer Ed25519 signature separately binds
the emitted encapsulation and wrapped CEK.

`protected_metadata` is exactly:

```
protocol, version, message_id, issued_at_ms, expires_at_ms,
sender, audience, content_type, suite
```

The signature input is:

```
"tribe/v1/envelope-signature" || 0x00 ||
JCS(envelope_without_signature)
```

The Ed25519 signature authenticates all metadata, the payload ciphertext and
nonce, recipient IDs, key IDs, HPKE encapsulations, and wrapped CEKs.
Verification MUST occur before HPKE open or payload decryption.

V1 registers three encrypted plaintext families:

- `application/vnd.tribe.message+json` / `tribe-message/v1`;
- `application/vnd.daimon.we+json` / `tribe-weave/v1`;
- `application/vnd.tribe.membership+json` / `tribe-membership/v1`.

The authenticated content type MUST match the decrypted payload schema.
Brokers remain payload-blind. Weave being membership and founded-tribe
membership are application contracts, not directory side effects.

## 4. Identifiers and time

`message_id` MUST be an RFC 9562 UUIDv7. Its embedded millisecond timestamp
MUST be within five minutes of `issued_at_ms`. It is generated once and MUST
remain unchanged across retries and routes.

`issued_at_ms` and `expires_at_ms` are Unix milliseconds. Maximum TTL is 48
hours. Brokers and endpoints MUST reject expired messages and messages issued
more than five minutes in the future. Implementations SHOULD use authenticated
time and MUST monitor clock drift.

Agent, audience, and key identifiers are lowercase ASCII and MUST match the
schema identifier pattern. Signing and encryption keys MUST have different
IDs. RECOMMENDED forms are:

```
agent-id/sig/epoch
agent-id/enc/epoch
```

## 5. Audience and recipient semantics

An audience is `(type, id, epoch)`, where type is `direct` or `group`.

For a direct message, `members` MUST remain exactly `[audience.id]`. A signed
directory epoch MAY additionally declare a non-empty `observers` list for that
direct audience. The effective recipient set is the member plus every observer
declared in that exact epoch. Observers receive an independent CEK wrap and
broker delivery, but do not become members and gain no sender authority. Group
audiences MUST NOT declare observers; their recipient set contains one entry
for every member authorized in that exact audience epoch. Recipient IDs MUST be
unique and the effective set is capped at 256.

The broker MUST verify that:

- the sender is authorized to publish to that audience epoch;
- each recipient is a member or explicit direct observer of that epoch;
- each `encryption_kid` is active and owned by its recipient;
- the recipient set exactly matches policy.

An agent ID ending in `@localhost` denotes an embodiment-local principal.
Every sender and broker deployment MUST have an explicit, non-empty set of
principals local to that machine. Before generating a CEK, nonce, or HPKE wrap,
an `@localhost` sender MUST verify that it and every effective recipient are in
the local set. Outbox retry and broker admission MUST repeat this check. A
remote or mixed recipient set MUST fail closed. The local set only narrows
directory authorization; it MUST NOT grant audience membership, observer
status, or sender authority.

The endpoint MUST independently verify its audience membership or signed
observer status and require exactly one wrap to an active encryption key it
owns. An audience name alone never grants access.

An active audience epoch may authorize new sender encryption and broker
admission. A retained `retired` audience epoch MUST NOT authorize either, but
an endpoint MAY use its signed recipients and keys to validate and decrypt an
envelope admitted while that epoch was active. `revoked` epochs remain invalid
for both admission and receive. Recipient-policy changes, including observer
changes, MUST use a new audience epoch rather than mutate an existing one.

A governance-signed retired observed direct MAY set
`legacy_unobserved_receive: true` only to repair a rollout in which the same
audience epoch was admitted both before and after observers were added. For
endpoint receive only, that flag permits the exact member-only set in addition
to the exact member-plus-observers set. It never authorizes encryption or
broker admission, and an observer still cannot read a member-only envelope
because it has no CEK wrap. Active, revoked, group, and unobserved audiences
MUST reject the flag. Remove the valve with the retired epoch after retention.

## 6. Identity directory and authorization

Every component starts from one or more governance Ed25519 public keys pinned
out of band. It accepts canonical, governance-signed directory snapshots with
a monotonically increasing `directory_epoch`. A snapshot contains:

- agent IDs and status;
- signing and encryption public keys, owners, purposes, epochs, validity
  windows, and status;
- audience epochs, members, optional direct observers, allowed senders, and
  status;
- revocations and their reason/mode;
- snapshot issue/expiry times and previous-snapshot hash.

Components MUST persist the highest accepted directory epoch and its hash.
They MUST reject rollback, an unexpected fork, expired snapshots, key-purpose
reuse, and signatures below the configured governance threshold.

The normative format is `schema/directory.schema.json`. Governance signs:

```
"tribe/v1/directory" || 0x00 ||
JCS(directory_without_governance.signatures)
```

Agent IDs, key IDs, and audience tuples MUST be unique inside a snapshot.
Signing public keys are 32-byte Ed25519 keys; encryption public keys are
32-byte X25519 keys. Each governance signature MUST come from a distinct
pinned root. The declared threshold MUST equal the locally configured
threshold; a snapshot cannot lower it.

Transport authentication MAY use mTLS or a signed challenge for rate limiting,
but it MUST NOT replace envelope authentication or authorization.

### 6.1 Signed HTTP profile

The reference HTTP service uses `schema/http-auth.schema.json`. Every POST body
is:

```
{"auth": http_auth, "body": operation_body}
```

The signature input is:

```
"tribe/v1/http-auth" || 0x00 || JCS(http_auth_without_signature)
```

`body_sha256` is SHA-256 over `JCS(operation_body)`. Method, exact path,
request UUIDv7, issue/expiry time, agent ID, and signing key ID are bound.
Maximum auth TTL is two minutes. The service MUST verify the active directory
key and body hash, then durably insert unique `(agent_id, request_id)` before
performing the operation. Clients MUST create fresh request authentication for
each route attempt while retaining the same envelope and message ID.

Public health is the only unsigned endpoint. It exposes no message data and
MUST report protocol version, build commit, directory epoch/hash, SQLite
version, and effective journal mode.

## 7. Rotation and revocation

Key epochs are monotonically increasing per agent and purpose. New messages
MUST use the latest active signing key and the latest active encryption key for
each recipient.

Planned rotation MAY overlap old and new keys. A `retired` signing key is valid
only for messages issued inside its recorded validity window. A compromised or
revoked signing key invalidates every unprocessed envelope using that key,
regardless of the claimed issue time.

On recipient-key compromise, the key MUST be disabled for new messages and the
audience epoch MUST advance. Pending envelopes wrapped to that key SHOULD be
treated as exposed and reissued under new message IDs only after application
review. Old encryption private keys SHOULD be destroyed after the explicit
recovery/retention window.

## 8. Broker admission and storage

Admission order is fail closed:

1. enforce HTTP method, content type, byte limit, and duplicate-key rejection;
2. parse and validate exact v1 structure;
3. load a non-rollback directory snapshot;
4. verify key status, ownership, signature, time, authorization, and recipient
   set;
5. atomically insert the envelope and unique `(sender_id, message_id)`;
6. return a receipt only after the transaction is durable.

The broker MUST persist ciphertext only. It MUST NOT receive CEKs or private
keys. It MUST cap an envelope at 1 MiB, plaintext by policy before encryption,
recipient count at 256, query page at 100, and request concurrency at a
deployment-specific bounded value.

The database MUST enforce uniqueness for `(sender_id, message_id)`. A duplicate
with the identical canonical envelope hash MAY return the original receipt. A
duplicate ID with different bytes MUST return `message_id_conflict`.

Only an authenticated endpoint that owns a concrete recipient wrap may list or
claim that row. GET/list does not acknowledge or delete.

## 9. Delivery state and replay

The broker state machine is:

```
queued -> claimed(lease_id, lease_until) -> acknowledged
   ^            |
   +------------+  lease expiry or explicit retry
```

Claims MUST be atomic. Acknowledgement MUST bind receiver ID, message ID,
lease ID, envelope hash, outcome, and time in a receiver-signed record.
The normative format is `schema/ack.schema.json`. Its signature input is:

```
"tribe/v1/ack" || 0x00 || JCS(ack_without_signature)
```

The broker MUST verify the active receiver signing key, ownership of the
recipient wrap, current lease, message ID, and envelope hash in one
transaction. `processed` and `terminal_failed` are terminal. A
`retryable_failed` outcome releases the lease without deleting the message.

Endpoints MUST maintain durable states:

```
received -> processing -> processed
                 |
                 +-> retryable_failed / terminal_failed
```

The replay key is `(sender_id, message_id)`. It MUST be recorded before an
external effect. A crash-safe outbox or application idempotency key is REQUIRED
for non-transactional effects. The protocol guarantees at-least-once delivery,
not exactly-once effects.

## 10. Error contract

Public broker responses expose:

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `invalid_envelope` | Any parse, schema, canonicalization, crypto, time, or downgrade failure |
| 401 | `authentication_required` | Missing/invalid transport identity |
| 403 | `not_authorized` | Transport identity cannot perform the operation |
| 409 | `message_id_conflict` | Same sender/ID, different canonical envelope |
| 413 | `envelope_too_large` | Request exceeds the hard limit |
| 429 | `rate_limited` | Bounded resource policy |
| 503 | `directory_unavailable` | No current trusted directory |

Detailed internal codes MAY be logged with correlation IDs, but logs MUST NOT
contain plaintext, CEKs, private keys, signatures, or complete envelopes.
Endpoint/operator tooling MAY expose the stable conformance codes in
`tribe_protocol_v1.py`.

## 11. Cutover gate

The production switch is one way:

1. merge independently reviewed v1 spec and vectors;
2. deploy v1 broker into an empty v1 database and namespace;
3. provision new purpose-separated v1 keys and directory epoch;
4. run positive, negative, rotation, revocation, replay, and recovery tests;
5. stop all v0 writers, readers, relays, and mirror units;
6. enable v1 endpoints;
7. delete v0 stores according to ordinary local disposal policy.

Rollback means fixing or disabling v1. It MUST NOT re-enable v0 or copy v1
messages into v0.

## 12. Normative references

- [RFC 9180 — Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 8032 — Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 9562 — UUIDs, including UUIDv7](https://www.rfc-editor.org/rfc/rfc9562.html)
- [RFC 4648 — base64url](https://www.rfc-editor.org/rfc/rfc4648.html)
- [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259.html)
- [RFC 7493 — I-JSON](https://www.rfc-editor.org/rfc/rfc7493.html)
- [BCP 14](https://www.rfc-editor.org/info/bcp14)
