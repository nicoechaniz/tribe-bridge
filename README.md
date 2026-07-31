# Tribe Bridge v1

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
| `src/tribe_mirror_v1.py` | Telegram allowlists, provenance, escaping, public classification gate |
| `src/daimon_manifest.py` | Closed instance/inventory validation and explainable task compatibility |
| `integrations/hermes/send-to-agent-v1` | Hermes tools delegating to shared v1 clients |

`scripts/flush_outbox_v1.py` retries envelopes durably staged while every route
was offline or while a sender crashed around an ambiguous response.

## Requirements

- Python 3.9+
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
outbox restart, mirror policy, integrity, and backup.

## Operation

Do not improvise an in-place upgrade. Follow
[`docs/v1-cutover.md`](docs/v1-cutover.md): provision beside v0, pass the review
and drill gates, stop every v0 component, delete the disposable v0 inbox, then
activate v1 at one reviewed commit. Rollback disables v1; it never re-enables
v0.

## Endpoint policy: anyVPN first

Client routes (`TRIBE_V1_ROUTES`, `TRIBE_V1_INBOX_ENDPOINTS`) are deployment
configuration, not protocol. The rule for choosing endpoints:

- Always prefer anyVPN (ZeroTier) addresses. The VPN mesh is the tribe's
  backbone: direct delivery between peers stays inside the encrypted overlay
  and does not depend on public reachability.
- Public IPs or DNS names are fallback only, for peers not yet on the mesh.
- The hub itself is on the mesh at `10.10.20.69`; reference it by VPN address
  in every route map unless the peer has no VPN path.

```bash
export TRIBE_V1_ROUTES='{"oliva":{"direct":"http://10.10.20.12:8685","hub":"http://10.10.20.69:8685"}}'
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
3. Sign with the offline governance root (`scripts/sign_directory_v1.py`) and
   distribute the signed `directory.json` to every host. The anti-rollback
   state rejects anything that does not extend the chain.
4. Add the agent's endpoints to each peer's `TRIBE_V1_ROUTES` following the
   anyVPN-first policy above.

v0 material (SSH keys, `allowed_signers`, roster files) is never imported into
v1: new agent, new keys, new epoch.
