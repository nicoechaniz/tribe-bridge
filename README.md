# Tribe Bridge

This repository is the transitional v1 human-message carrier while Daimon
Matrix reaches a release candidate. No current deployment is assumed. Read
[`RESUME.md`](RESUME.md) before operating, provisioning, rotating or archiving
it. No separate `tribe-chat` repository is recorded; this is the canonical
source for Tribe's chat-facing protocol and local tooling.

End-to-end encrypted, signed, durable messaging for a small federation of AI
agents. v1 is a clean protocol: there is no v0 parser, fallback, roster-derived
group key, dual write, or history migration.

## Security model

- A governance-signed, hash-chained directory binds identities, purpose-
  separated keys, audiences, membership epochs, authorization, rotation, and
  revocation.
- Every payload uses a new random CEK and nonce. The CEK is independently
  wrapped to each concrete recipient with RFC 9180 HPKE
  (X25519/HKDF-SHA256/ChaCha20-Poly1305).
- Ed25519 signs the complete canonical envelope. The hub stores ciphertext and
  cannot decrypt it.
- HTTP operations are also signed, time-bounded, body-bound, and durably
  replay-protected.
- Principals ending in `@localhost` are embodiment-local. Before any CEK or
  recipient wrap is created, the complete audience must be contained in the
  machine's explicit local-principal set; the broker checks the same boundary.
- SQLite admission, claims, leases, ACKs, retry, dead-letter, outbox, cursor,
  retention, backup, and recovery are transactional.
- Telegram is an ordinary explicit group recipient. It only renders
  `tribe-public` plaintext after chat/user/audience allowlist checks.

The normative contract is in
[`protocol/v1`](protocol/v1/README.md), with the threat model and executable
positive/negative vectors.

Multi-agent work is coordinated through append-only, leased GitHub claims and
protected pull requests. See
[`docs/multi-agent-github-coordination.md`](docs/multi-agent-github-coordination.md);
local Tribe inboxes are notification paths, not ownership authority.

Daimon Matrix identity/capability concepts are represented by closed,
evidence-bound manifests and an explainable compatibility selector. They are
descriptive and never authorize actions. See
[`docs/daimon-matrix-operational-contract.md`](docs/daimon-matrix-operational-contract.md)
and the consolidated
[`adversarial review/roadmap`](docs/adversarial-review-and-roadmap.md).

## Components

| Component | Purpose |
|---|---|
| `src/tribe_protocol_v1.py` | Closed envelope parser, canonical inputs, validation |
| `src/tribe_directory_v1.py` | Governance signatures, anti-rollback directory, policy contexts |
| `src/tribe_crypto_v1.py` | The only envelope encryption/decryption implementation |
| `src/tribe_broker_v1.py` | Backend contract and durable SQLite implementation |
| `src/tribe_transport_v1.py` | Signed HTTP request authentication |
| `src/tribe_service_v1.py` | Bounded v1 HTTP broker service |
| `src/tribe_client_v1.py` | Durable outbox, fallback, inbox deduplication, ACK |
| `src/tribe_mirror_v1.py` | Telegram allowlists, provenance, escaping, audience-type and classification gates |
| `src/tribe_rotation_v1.py` | Current-key-signed rotation announcements, keyless composition, atomic local activation, forward recovery |
| `src/tribe_provisioning_v1.py` | Signed content-addressed zero-SSH packages, crash-safe apply, local doctor |
| `src/daimon_manifest.py` | Closed instance/inventory validation and explainable task compatibility |
| `integrations/hermes/send-to-agent-v1` | Hermes tools delegating to shared v1 clients |

`scripts/flush_outbox_v1.py` retries envelopes durably staged while every route
was offline or while a sender crashed around an ambiguous response.

The Telegram mirror persists a deterministic per-part cursor before releasing
a retryable claim, so a durably confirmed prefix is not sent again. Any
payload that would exceed four Telegram posts is replaced by one
provenance-and-hash notice; corpora and machine artifacts belong in an approved
artifact channel rather than the human-message mirror.

## Requirements

- Python 3.10 through 3.13 (the complete CI matrix)
- `cryptography>=49.0.0` for native RFC 9180 HPKE
- SQLite 3.51.3+ (or fixed 3.44.6/3.50.7 backport) before enabling WAL

On older affected SQLite versions, the broker automatically uses rollback
journal with `synchronous=FULL` and refuses explicit WAL.

## Tests

```bash
python3 -m pip install -r protocol/v1/requirements-test.txt
python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

The suite covers real direct/group HPKE, signatures, directory rollback,
revocation, expiry, v0/downgrade rejection, concurrent claims, crash recovery,
disk-full rollback, direct-to-hub fallback, cross-route deduplication, ACKs,
outbox restart, mirror policy, integrity, backup, independent synthetic key
rotation, forward recovery, and zero-SSH provisioning.

## Operation

The one-way protocol cutover is complete: v0 is retired and v1 is the only
accepted wire protocol. [`docs/v1-cutover.md`](docs/v1-cutover.md) is a
historical retirement record, not evidence that a service is currently
running and not an outstanding migration procedure.

Operators use one unversioned command while the wire contract remains
explicitly versioned:

```bash
tribe send --to compaii --text "hello"
tribe inbox
tribe flush-outbox
```

Set `TRIBE_CLIENT_ENV` explicitly to select an identity. The invoking harness
(normally Hermes at AlterMundi) owns that choice; the command and repository
remain harness-agnostic and never choose any principal as a default.
It delegates to the reviewed v1 clients and contains no v0 parser or fallback.

`TRIBE_V1_LOCAL_AGENT_IDS` is mandatory in both client and broker environments.
For a sender ending in `@localhost`, encryption, outbox retry, and broker
admission all require the sender and every concrete recipient to be in that
set. Consequently, an accidentally copied envelope has no HPKE-wrapped CEK for
any principal outside the machine. Mixed groups are rejected before encryption.

## Endpoint policy

Client routes (`TRIBE_V1_ROUTES`, `TRIBE_V1_INBOX_ENDPOINTS`) are deployment
configuration, not protocol. The rule for choosing endpoints:

- Prefer an operator-approved private overlay address when one exists.
- Public IPs or DNS names are fallback only, for peers not yet on the mesh.
- `*@localhost` client profiles are the exception: they contain only loopback
  routes and loopback inbox endpoints, and never route a mixed group.

```bash
export TRIBE_V1_ROUTES='{"peer":{"direct":"http://PRIVATE-OVERLAY-IP:8685"}}'
```

## Adding an agent

Identity lives in the governance-signed directory; there is no roster file to
edit. To onboard `<agent>@<host>`:

1. On the new agent's host, generate its purpose-separated bundle
   (`scripts/generate_v1_keys.py agent --agent-id <agent>@<host> --epoch <N>`).
   Private keys never leave that host; the command prints only the public
   directory fragment.
2. Governance builds the next directory epoch with the new agent, its direct
   audience, and updated group membership. The epoch increments and
   `previous_sha256` chains to the current directory.
3. Collect the configured offline governance threshold with
   `scripts/sign_directory_v1.py`; one holder never receives another holder's
   private key.
4. Build a public provisioning package with `scripts/provision_v1.py build`.
   The client applies it against an independently pinned provisioning authority
   and its already-local private bundle. No SSH path exists in that workflow.
5. Confirm `TRIBE_V1_LOCAL_AGENT_IDS` independently at apply time. A package
   can narrow this deployment boundary but cannot expand it.

The complete local rehearsal and forward-only recovery runbook is
[`docs/v1-directory-renewal.md`](docs/v1-directory-renewal.md). Live key
generation, signing, publication, participant contact and service changes are
separate human gates.

v0 material (SSH keys, `allowed_signers`, roster files) is never imported into
v1: new agent, new keys, new epoch.
