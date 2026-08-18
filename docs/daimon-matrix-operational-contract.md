# Daimon Matrix operational contract

## 2026-08-16 release-candidate boundary

This document preserves Tribe Bridge's local descriptor/selector boundary. It
does not define the current Matrix roadmap or authority model. The historical
starting baselines for the integrated work were Matrix
`e855148ffac5b2f4068ba56be6324d7b78fb430f`, Cluster
`734fd0037dcf84783ef7991415014af7435a46f2`, and Tribe
`187c61d881e6de830a029027144193645f2c7f62`. They are provenance only, not
current candidate pins.

The merged Matrix integration point is
`bf5f7415f075af09442973144bc529f4c5ce7985`, tree
`f38862427d5713b21ca9d0859a80ddbacfefa255`. The merged Cluster integration
point is `d384a8092658e27c2918a8ac81e90ad999bb22d4`, tree
`ad562c4216e47d7aa2a689758591c897783f3755`. Tribe itself merged the reviewed
software boundary `294e1194db6cd60d9349a2d43938475bbd1c8c20`, tree
`bcba9989a38519df87ecbb6c87a33a2f9740b85d`. A later metadata-only merge may
record these facts without changing their functional trees; the external
integrated manifest is authoritative for the resulting final repository heads.

No current deployment is assumed. Read [`../RESUME.md`](../RESUME.md) and the
Matrix repository `RESUME.md` before operational work. Tribe's
`daimon-manifest/v1` is descriptive evidence only: it cannot authorize a
Matrix action, override a Matrix root, or replace a root-authorized embodiment
credential. Tribe remains a separately accounted transitional carrier; its
transport ACK is neither authenticated Matrix intake nor a signed Matrix
semantic receipt.

## Interpretation boundary

The [Daimon Matrix source](https://hackmd.io/@nicoechaniz/daimon-matrix)
describes identity, lineage, memory, embodiment, relation, and capability in a
poetic/conceptual language. It is valuable as a definition source. It is not an
authorization policy, network directory, capability attestation, or merge
algorithm.

The historical source snapshot observed on 2026-07-31 was last edited on
2026-07-07. Its rendered text hash and concept classifications are recorded in
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
| `/we.*`, `/source.pull`, `/species.pull.*` | Implemented by the exact installed `daimon-matrix` release candidate | Matrix root, signed history and observer-local policy; Tribe inventory entries remain descriptive only |

HMK is private operational memory. An independently authored Wiki is
authoritative for its documents. collective-memory is a reviewed downstream
publication/index. GitHub Issues/Project/PRs own work coordination. Tribe v1
owns its transitional encrypted transport/deduplication/ACK evidence; Matrix
owns relationship/grant authority and canonical communication semantics. None
replaces the others.

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
  --state-commit <reviewed-full-git-sha> \
  --reviewed-ref refs/remotes/origin/<reviewed-branch>
```

The binder reads `manifest.json` directly from that immutable Git commit rather
than trusting the working tree. It also requires the commit to be reachable
from the named remote-tracking review ref; callers must fetch that ref before
binding. A merely local commit is not accepted as reviewed. This is a dry run
unless `--output` is supplied. The bound descriptor is kept
outside the state generation it names. Embedding it in the same artifact index
would create an impossible recursive hash. A rebirth restores the reviewed
template/generation and then regenerates this external descriptor; it does not
copy a stale bound identity forward.

The binder does not claim that a restore succeeded. Restore receipts and
post-restore capability probes remain separate evidence.

## Current limitations

- The CompAII example is a review candidate, not a deployed/live attestation.
- Multiple agents still share one GitHub account.
- No current Tribe deployment, directory epoch, custody or Matrix route is
  claimed. Rotation/provisioning evidence is synthetic until separately gated.
- Collective-memory integration, proximity/realm controls and independent
  capability measurement remain separate work.
- This repository's historical concept inventory is not a substitute for the
  current Matrix schemas, signed events, conformance registry or tracking.
