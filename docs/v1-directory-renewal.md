# Tribe v1 rotation, forward recovery and zero-SSH provisioning

Status: release-candidate tooling for local/synthetic rehearsal only. Nothing
in this runbook authorizes live custody, signing, publication, installation,
participant contact, network probes, service changes or remote access.

## Expiry boundary

The preserved epoch-5 artifact had staggered key expiry:

| Principals | first signing/encryption expiry (UTC) |
|---|---|
| `compaii`, `codex@localhost`, `mirror` | 2026-08-30 07:13:52 |
| `claude-code@localhost` | 2026-08-30 23:27:57 |
| `compaii@daimonmatrix`, `daimon`, `oliva` | 2026-08-31 23:33:31 |
| `eko@amapola` | 2026-09-01 03:29:46 |
| `oliva@mac-mini` | 2026-09-01 09:27:00 |

Epoch 5 itself expired later, on 2026-09-08 03:18:53 UTC. Pure validity
renewal cannot repair an expiring agent key. Any hypothetical live rotation
needed to converge by 2026-08-27 UTC to preserve margin before the first
2026-08-30 expiry. These are planning facts, not authority to act.

## Rotation contract

The ceremony is intentionally split so no composer holds participant keys:

1. Each holder locally runs `rotate_keys_v1.py prepare` against the exact same
   signed base directory and roots. It creates an owner-only staged bundle by
   exclusive create and emits only a public announcement.
2. The announcement is signed by that agent's current signing key and binds the
   ceremony ID, base epoch/hash, roots hash, previous and next KIDs/public keys,
   activation time, expiry and a random nonce. Successor KIDs are checked
   globally across signing and encryption purposes, including retired keys.
   The carrier is not authority.
3. `rotate_keys_v1.py compose` requires exactly one valid, non-replayed
   announcement for every active agent. It has no private-key input and emits
   deterministic unsigned D+1 plus a redacted receipt. Candidate issuance is
   derived from the exact announcement set rather than composer wall time, and
   the fixed 30-day validity policy is code-bound. Before output, the composer
   runs the complete directory structural/semantic validator in an explicitly
   unsigned mode which cannot establish runtime authority.
4. D+1 gives new keys a common future `not_before_ms` and ends both old public
   key validity windows exactly at activation. Old encryption *private* keys
   remain local for the drain, but cannot authorize post-cut traffic: broker
   admission and HTTP authentication check both issuance and the trusted
   receive time. Endpoint receive still checks the historical issuance window
   so ciphertext admitted before the cut remains decryptable. D+1 also retires
   every active audience predecessor and adds an identical active successor at
   the next audience epoch.
5. Independent governance holders append their signatures one at a time with
   `sign_directory_v1.py`. The configured threshold is verified by normal
   directory loading. The aggregator never receives all private keys.
6. After the signed successor is independently distributed and accepted,
   `rotate_keys_v1.py activate` atomically installs the local staged bundle. It
   refuses to drop or substitute old encryption keys, requires the directory's
   current signing and encryption keys, and revalidates those requirements on
   an idempotent retry.
7. Keep old encryption custody for at least the 48-hour maximum envelope TTL
   plus buffer (the synthetic policy uses 72 hours). Pruning is a later,
   separately authorized local action.

Representative synthetic invocation (all paths must point to disposable
fixtures):

```bash
python3 scripts/rotate_keys_v1.py prepare \
  --directory FIXTURE/directory.json \
  --roots FIXTURE/governance-roots.json \
  --state FIXTURE/agent-directory-state.json \
  --keys FIXTURE/agent.keys.json \
  --staged-keys FIXTURE/staging/agent.next.keys.json \
  --announcement FIXTURE/announcements/agent.json \
  --ceremony-id synthetic-rotation-1 \
  --activation-at-ms ACTIVATION_MS \
  --expires-at-ms ANNOUNCEMENT_EXPIRY_MS

python3 scripts/rotate_keys_v1.py compose \
  --directory FIXTURE/directory.json \
  --roots FIXTURE/governance-roots.json \
  --state FIXTURE/composer-directory-state.json \
  --announcement FIXTURE/announcements/agent-a.json \
  --announcement FIXTURE/announcements/agent-b.json \
  --ceremony-id synthetic-rotation-1 \
  --activation-at-ms ACTIVATION_MS \
  --output FIXTURE/directory-next-unsigned.json \
  --receipt FIXTURE/compose-receipt.json
```

The output is deliberately unsigned. Signing, publishing and live activation
are outside this command and require their own reviewed preflight.

`ceremony_id` is a human-readable label, not a globally allocated singleton.
The receipt's `ceremony_sha256` is the authoritative content address over the
base, roots, activation, fixed validity policy and sorted exact announcement
hashes (therefore their holder nonces and signatures). Reordering, restarting,
or composing one millisecond later yields the same candidate and receipt.
Recomposing the exact set is an idempotent replay of that content address, not a
second ceremony. A different set under the same label has a different content
address; governance must choose one exact candidate hash and must never sign
two forks from the same base. Preventing malicious governance equivocation
requires the separately gated canonical publication/transparency mechanism,
not mutable local composer state.

## Forward-only failure policy

- Before threshold signing, discard the candidate and local staging; D remains
  authoritative.
- After D+1 is signed or any anti-rollback state accepts it, never reinstall D,
  restore an older state file, reuse KIDs/epochs or silently change roots.
- Prebuild an unsigned forward-recovery D+2 that revokes the named D+1 keys and
  proves every agent still has an active signing and encryption key. It also
  requires offline threshold signing:

```bash
python3 scripts/rotate_keys_v1.py forward-recovery \
  --directory FIXTURE/directory-next-signed.json \
  --roots FIXTURE/governance-roots.json \
  --state FIXTURE/recovery-directory-state.json \
  --revoke-kid agent/sig/2 --revoke-kid agent/enc/2 \
  --output FIXTURE/directory-forward-recovery-unsigned.json
```

## Zero-SSH provisioning contract

Provisioning binds an already authorized signed directory to private material
which already exists on the client. It cannot enroll or generate participant
keys, sign a directory, rotate governance roots, widen `@localhost`, install a
service, contact a broker, or produce a Matrix receipt.

A package contains only:

- the signed directory and governance public roots;
- their exact hashes and epoch;
- expected public KIDs and required active audiences;
- HTTP(S) routes/inbox endpoints as deployment hints, never authorization;
- an explicit locality set, exact build commit and bounded validity;
- a signature by a separately pinned provisioning authority.

Apply checks the authority, every hash, directory signature/expiry, local
owner-only key bundle, direct/group membership, exact harness-approved locality
set, roots continuity and anti-rollback state. A separate owner-only durable
high-water binds the target agent, directory epoch/hash, roots hash and exact
package hash: exact replay is idempotent, while an older or same-epoch
conflicting package is rejected. Installation runs under a restartable journal,
so a crash can only leave D or a resumable D+1 transition. The journal records
the trusted time at which that exact signed package passed all validity checks;
only that byte-exact transaction may finish after package expiry. An expired
package with no pre-existing exact journal cannot start. Invalid rollback, root
or split-view attempts mutate no installed artifact and leave no journal.

```bash
# Synthetic authority; never treat this test key as live governance.
python3 scripts/provision_v1.py authority-create \
  --kid synthetic/provisioner/1 \
  --private-output FIXTURE/provisioner-private.json \
  --public-output FIXTURE/provisioner-public.json

python3 scripts/provision_v1.py build \
  --directory FIXTURE/directory.json \
  --roots FIXTURE/governance-roots.json \
  --private-authority FIXTURE/provisioner-private.json \
  --config FIXTURE/client-public-config.json \
  --package FIXTURE/package \
  --provisioning-id synthetic-client-1 --agent-id agent \
  --build-commit EXACT_40_HEX_COMMIT \
  --expires-at-ms EXPIRY_MS

python3 scripts/provision_v1.py apply \
  --package FIXTURE/package \
  --authority FIXTURE/provisioner-public.json \
  --keys FIXTURE/agent.keys.json \
  --destination FIXTURE/client \
  --local-agent-id agent

python3 scripts/provision_v1.py doctor \
  --destination FIXTURE/client \
  --keys FIXTURE/agent.keys.json --agent-id agent
```

Operational commands always use the system clock. Deterministic `now_ms`
injection exists only in the Python test fixtures and is not exposed by these
CLIs.

`doctor` is local-only. `network_checked: false` and `matrix_receipt: false`
are intentional: reachability, authenticated Tribe round-trip and Matrix
semantic intake are distinct later gates.

## Pure-validity fixture and remote update

`renew_directory_v1.py` is retained only as an explicitly named synthetic
single-holder local fixture. It has no publish, service, network or remote
install options. It cannot solve key expiry and is not a release ceremony.

`update_directory_client_v1.py` remains a fail-closed HTTP(S) fetch/verify/apply
primitive. Its templates are packaging assets only; this release candidate
does not install or enable them. A real canonical URL, authority, deployment
target and activation are separate operator choices.
