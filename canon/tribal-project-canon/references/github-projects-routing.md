# GitHub Projects routing and privacy

Verified semantics behind the routing rules in the parent canon. Verify against current GitHub documentation before relying on feature details that may change.

## Authoritative documentation

- Project visibility: https://docs.github.com/en/issues/planning-and-tracking-with-projects/managing-your-project/managing-visibility-of-your-projects
- Project access: https://docs.github.com/en/issues/planning-and-tracking-with-projects/managing-your-project/managing-access-to-your-projects
- Adding items and draft issues: https://docs.github.com/en/issues/planning-and-tracking-with-projects/managing-items-in-your-project/adding-items-to-your-project
- Converting drafts to Issues: https://docs.github.com/en/issues/planning-and-tracking-with-projects/managing-items-in-your-project/converting-draft-issues-to-issues

## Verified semantics as of 2026-08-07

### Project visibility

A Project may be public or private. A private Project is visible only to users granted at least read access.

Project visibility does not override repository visibility or permissions:

- a public-repository Issue remains public even when included in a private Project;
- an Issue from a private repository is visible only to people who can access that repository;
- Project access and repository access are separate checks.

### Draft items

A draft issue/item exists only in its Project until converted into a repository Issue. This makes a draft suitable for private coordination in a private Project when no repository owns the work.

Limitations documented by GitHub:

- users do not receive notifications when assigned or mentioned in a draft until it is converted to an Issue;
- repository, labels, and milestone require conversion to an Issue;
- drafts lack the repository-native discussion and implementation linkage of a normal Issue.

Use a draft for lightweight coordination, not as a hidden duplicate of an existing Issue.

Conversion paths: Project UI ("Convert to issue") or the GraphQL `convertProjectV2DraftIssueItemToIssue` mutation. `gh project item-create` only creates drafts; the gh CLI has no convert subcommand as of 2026-08.

### Routing examples

| Situation | Use |
|---|---|
| Fix a bug in `AlterMundi/example` and public discussion is acceptable | Issue in `AlterMundi/example` |
| The bug participates in a multi-repo release | Add that Issue to the release Project |
| Coordinate an internal event spanning software, operations, and people | Draft item in a private organization Project |
| An internal draft becomes a concrete code change in `AlterMundi/example` | Convert it to an Issue there if its content is safe at repository visibility |
| Sensitive implementation needs Issue features | Use an appropriately private repository or keep the sensitive context outside a public Issue; a private Project does not hide public Issue content |

## Dated AlterMundi observation

A read-only `gh project list --owner AlterMundi --format json` check on 2026-08-07 returned nine organization Projects (#2 through #10), all with `public: false`. Project #7 (`webapp · Beacon + PMP — Kanban GitHub`) was also directly verified as private.

This observation demonstrates that the intended private-Project pattern is already available and used. It is not a rule that every future AlterMundi Project must remain private regardless of an explicit human decision.

## Policy evolution

The prior convention "one Project per repository" was too rigid. The canon treats a Project as a real coordination boundary — product, program, team, event, roadmap, or workstream — and permits it to span repositories.

The prior convention "always link a real Issue; never use drafts" was also too rigid. The canon rule is:

- link the real Issue when one owns the work;
- use a private draft when no repository owns the work or the coordination is intentionally private;
- never keep a draft and Issue as parallel owners of the same task.
