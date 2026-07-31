# Daimon Matrix operational contract

## Interpretation boundary

The [Daimon Matrix source](https://hackmd.io/@nicoechaniz/daimon-matrix)
describes identity, lineage, memory, embodiment, relation, and capability in a
poetic/conceptual language. It is valuable as a definition source. It is not an
authorization policy, network directory, capability attestation, or merge
algorithm.

The source observed on 2026-07-31 was last edited on 2026-07-07. Its rendered
text hash and the classification of each concept are recorded in
[`daimon/concept-inventory.json`](../daimon/concept-inventory.json). A source
change requires a new inventory review; it does not silently change executable
behavior.

## Three separate artifacts

1. `concept-inventory.json` states what is implemented, partial, metaphor, or
   aspirational. Metaphor is explicitly barred from executable mapping.
2. A `daimon-manifest/v1` describes one candidate instance, its embodiment,
   evidence-bound capabilities, memory/communication endpoints, trust domains,
   governance, and portable generation.
3. A `daimon-task-requirements/v1` describes requirements. The selector returns
   explainable compatibility and always says `authorization: not-evaluated`.

Selectors never parse the conceptual prose and never infer a capability from a
model response, self-description, endpoint reachability, or secret reference.

## Endpoint ownership

| Matrix concept | Operational mapping | Authority |
|---|---|---|
| `/me.memory` | HMK, LLM Wiki, HMK projection, collective publication endpoints | Per-endpoint memory ownership policy |
| `/me.skills` and advertised capability | Evidence-bound capability entries | Descriptive only; policy still authorizes use |
| `/me.body.*` | Realm/body/surface and capability ID references | Deployment descriptor |
| `/tribe` | Tribe v1 explicit audiences plus GitHub coordination | Tribe for messages; GitHub for work ownership |
| `/human` | Explicit human-scoped endpoint | Deployment-specific identity/consent |
| `/all`, `/near`, `/here` | Declared communication scopes | No implicit membership, proximity, or authorization |
| `/we.*`, `/source.pull`, `/species.pull.*` | Inventory entries only | Aspirational until merge/consent/provenance rules exist |

HMK is private operational memory. An independently authored Wiki is
authoritative for its documents. collective-memory is a reviewed downstream
publication/index. GitHub Issues/Project/PRs own work coordination. Tribe v1
owns encrypted message delivery. None replaces the others.

## Trust domains and secret handling

Trust domains close the set of classifications and endpoint URI schemes an
endpoint may claim. A selector can check that a task and manifest name a
compatible domain; it cannot decide that the endpoint is authenticated or that
an action is allowed.

Secrets are references only:

```json
{
  "name": "tribe-signing",
  "reference": "secret-store://tribe/agent/signing"
}
```

Only `env://` and `secret-store://` are accepted. Closed schemas and structural
secret checks reject embedded token/key-shaped values. GitHub and memory
artifacts remain unsuitable for key custody.

## Capability evidence and maturity

- `implemented` requires at least one immutable URI plus SHA-256 evidence.
- `partial` may be selected only when the task explicitly permits partial
  capability and returns its constraints as warnings.
- `aspirational` is never eligible.
- Capability presence is not quality attestation. Future independent
  measurements should be signed by a separate evaluator principal.

Example:

```bash
python3 scripts/select_daimon.py \
  --manifest daimon/examples/compaii.manifest.json \
  --task daimon/examples/github-task.json
```

Exit status is 0 for compatibility, 1 for incompatibility, and 2 for an invalid
contract. A compatible result is only a candidate for the authorization plane.

## compaii-sync / rebirth binding

A reviewed Daimon descriptor binds to a concrete
`compaii-state-manifest/v2` generation ID, the reviewed state commit, and the
artifact-index hash:

```bash
python3 scripts/bind_daimon_generation.py \
  --template daimon/examples/compaii.manifest.json \
  --state-repo /path/to/compaii-state \
  --state-commit <reviewed-full-git-sha>
```

The binder reads `manifest.json` directly from that immutable Git commit rather
than trusting the working tree. This is a dry run unless `--output` is
supplied. The bound descriptor is kept
outside the state generation it names. Embedding it in the same artifact index
would create an impossible recursive hash. A rebirth restores the reviewed
template/generation and then regenerates this external descriptor; it does not
copy a stale bound identity forward.

The binder does not claim that a restore succeeded. Restore receipts and
post-restore capability probes remain separate evidence.

## Current limitations

- The CompAII example is a review candidate, not a deployed/live attestation.
- Codex and CompAII still share one GitHub account.
- Tribe v1, the collective publication adapter, and the canonical HMK contract
  are implemented in draft branches but not deployed.
- `/we` discovery/diff/pull, species pull, proximity, realm controls, and
  independent capability measurement remain future work.
- Definition/species hashing uses the whole observed source until Nico defines
  a smaller canonical `/me` species block and inheritance rules.
