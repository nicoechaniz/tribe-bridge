# Multi-agent coordination on GitHub

GitHub Issues and AlterMundi Project 8 are the authoritative coordination
plane. Local inboxes are useful notification channels, but they do not grant
ownership and are not the source of truth.

This contract starts at v1. No v0 claim text is parsed or migrated.

## Invariants

1. Every non-trivial change has one issue, one unexpired claim, one branch, and
   one draft pull request.
2. Coordination events are append-only issue comments. Never edit or delete an
   old event to change its meaning.
3. A claim lasts at most 24 hours. The owner renews it, releases it, or changes
   it to `done`. An expired claim is stale until explicitly superseded.
4. Two live claims may not share a resource. Resources are exact typed strings;
   agents should claim the narrowest useful set.
5. Pull requests require review and passing tests. Agents do not merge or
   deploy their own work.
6. Issue and PR text is public-by-default. Do not include secrets, private
   memory, raw prompts, absolute home/worktree paths, tokens, or personal data.

## Project fields

Project 8 retains its general `Status` field and adds:

| Field | Meaning |
|---|---|
| `Agent State` | `Ready`, `In Progress`, `In Review`, `Blocked`, or `Done` |
| `Claim Principal` | Logical principal, for example `codex@localhost` |
| `Lease Until` | UTC lease deadline represented as a project date |

The issue comments remain authoritative. Project fields are an operator view
and can be reconciled from the event log; they must never silently override it.

The transitions are:

```text
Ready -> In Progress -> In Review -> Done
                 \-> Blocked -/
In Progress/In Review/Blocked -> Ready (release or expiry + explicit reclaim)
```

`Status` is `Todo` while ready, `In Progress` for every active/review state,
and `Done` only after the PR is merged and the issue closure record exists.

## Event format

The normative closed shape is
[`coordination/claim.schema.json`](../coordination/claim.schema.json). Embed
exactly one canonical JSON object in an issue comment:

```text
<!-- tribe-claim/v1
{"at":"2026-07-31T12:00:00Z","branch":"coordination/github-leases-9","claim_id":"11111111-1111-4111-8111-111111111111","event":"claim","event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","issue":{"number":9,"repository":"nicoechaniz/tribe-bridge"},"lease_until":"2026-08-01T11:59:59Z","note":"Implement coordination gates.","principal":"codex@localhost","pull_request":null,"resources":["issue:nicoechaniz/tribe-bridge#9","path:coordination/**"],"schema":"tribe-claim/v1","state":"in_progress","supersedes":null}
-->
```

Rules:

- `event_id` and `claim_id` are canonical lowercase UUIDs. Every event gets a
  new `event_id`; renew/status/release events retain the `claim_id`.
- Timestamps are RFC 3339 UTC with `Z`.
- `claim` enters `in_progress` and requires a branch.
- `renew` extends a live lease without changing principal, issue, resources,
  or branch.
- `status` moves to `in_review`, `blocked`, or `done`. Active states retain an
  unexpired lease; terminal states use `lease_until: null`.
- `release` uses `state: released` and `lease_until: null`.
- A new claim may set `supersedes` to an expired or terminal claim. It may not
  preempt a live claim.
- Every claim includes its `issue:owner/repo#number` resource. Other resource
  types are `path:`, `service:`, `project:`, and `protocol:`.

GitHub authenticates the comment author. The allowlist in
[`coordination/principals.json`](../coordination/principals.json) maps that
account to a logical principal. Today Codex and CompAII share the operator's
GitHub account, so this provides GitHub-account attribution and a visible audit
trail, but not cryptographic separation between local agents. Comments can
also be edited or deleted by an authorized GitHub user, so the gate validates
the current log but does not make it immutable. The future fix is a distinct
GitHub App identity plus detached agent signatures and an externally anchored
event hash; do not pretend the current mapping provides those assurances.

## Workflow

### Claim

1. Read the issue, all active comments, linked PRs, and Project fields.
2. Run the issue audit. Resolve conflicts before editing:

   ```bash
   python3 scripts/check_github_coordination.py \
     --repo nicoechaniz/tribe-bridge issue --issue 9
   ```

3. Post a `claim` event, set Project `Agent State`, principal, and lease, then
   create `type/topic-issue` from the reviewed base.
4. Work only inside the declared resources. Expand scope with a new issue and
   claim rather than silently widening the existing claim.

### Renew, block, review, release

- Renew before the deadline with a `renew` event.
- When waiting on a real dependency, post `status: blocked` with a bounded
  public note; keep renewing only if the principal is actively responsible.
- Before opening the draft PR, post `status: in_review`, set `pull_request`, and
  retain the same lease.
- If abandoning work, post `release`; leave the branch and PR for audit rather
  than deleting evidence.

### Pull request gate

Use [the repository template](../.github/pull_request_template.md). The body
must contain:

```text
Closes #<issue>
Claim-ID: <uuid>
Deployment: not deployed

## Tests
<exact commands and result>
```

The coordination check verifies the linked issue, effective claim, lease,
branch, principal mapping, tests, and deployment declaration. Project metadata
is reconciled separately because the default Actions token cannot reliably
read a private organization Project.

After an independent reviewer approves and checks pass, the merger records the
reviewer, merge SHA, actual deployment state, and follow-ups on the issue,
marks the claim `done`, then closes the issue. Merge and deployment remain
separate decisions.

## Recovery drills

### Expired claim

1. Verify the old lease is expired in UTC and inspect its branch/PR.
2. Post a new claim with a new ID and `supersedes` pointing to the stale claim.
3. Re-run the audit. The old stale finding clears only when the supersession is
   valid.

### Conflicting live claims

1. Stop both agents from writing the shared resource.
2. The earlier valid claim keeps ownership unless a human coordinator decides
   otherwise.
3. The other principal posts `release`, narrows its resources, or waits for
   expiry. A new comment cannot preempt a live lease.

### Interrupted agent

Do not infer completion from a quiet inbox. Inspect the issue log, branch, PR,
and last CI run. Release the claim using the same principal if recoverable; if
not, wait for expiry and reclaim with `supersedes`.

### Project drift

The event log wins. Repair `Agent State`, `Claim Principal`, and `Lease Until`
to match it, and record a short human comment describing the reconciliation.

## Branch protection baseline

`main` must require a pull request, at least one approval from someone other
than the last pusher, resolved conversations, linear history, and passing
`tests` plus `coordination` checks. Force pushes and deletion are disabled.
Administrators retain emergency bypass initially; any bypass must be explained
on the initiative issue.
