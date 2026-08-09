---
name: tribal-project-canon
description: Use when coordinating tribe work across repos and agents.
version: 1.1.0
author: CompAII and Nicolás Echániz
license: MIT
metadata:
  hermes:
    tags: [tribe, canon, github, issues, projects-v2, coordination, cross-repo]
    related_skills: [github-workflows, tribe-bridge]
---

# Tribal Project Canon

This is the shared coordination canon of the tribe. It governs how agents and humans route, track, and coordinate work across repositories. It deliberately says nothing about how any individual repository organizes its own files.

Load this canon when: creating or routing tasks, deciding where a piece of work lives, entering a shared repository, or reconciling trackers.

## 1. Governing principle

Respect each repository's existing contract. No layout is imposed: not `MEMORY.md`, not `BITACORA.md`, not `Biblioteca/`, not `NOW.md`, not `CLAUDE.md`, not any tracker. If a repository declares its own workflow (an `AGENTS.md`, a bitacora, a local memory file, a domain-specific state doc), that workflow governs inside that repository.

The canon regulates coordination between agents and humans across repositories — never the filesystem of a project.

Recognized valid workflows, each respected where it exists:

- Mariano's tree workflow (root contract, bitacora, Biblioteca, recursive messages) — valid inside Mariano's tree; never imported, modified, or seeded elsewhere.
- Legacy local `MEMORY.md` / per-project conventions — valid where already adopted; never migrated without an explicit, project-scoped, no-loss plan approved by the user.
- Any repository's own declared contract — highest authority inside that repository.

## 2. Work routing

Every piece of work gets exactly ONE owning artifact. Route by kind:

| Kind of work | Owning artifact |
|---|---|
| Belongs clearly to one repository AND can carry that repository's visibility | GitHub Issue in that repository |
| Existing Issue that needs broader coordination | The same Issue added to a GitHub Project (never duplicated) |
| Cross-repo / cross-area work with no owning repository | Draft item in a private GitHub Project |
| Internal coordination that must not be public | Draft item in a private GitHub Project |
| Draft that matures into concrete implementation in a repository | Convert the draft to an Issue in the owning repository; the draft does not live on as a duplicate |
| Implementation itself | Branch, PR, checks, deployed runtime |
| Project-specific context | Whatever the project has adopted (memory file, bitacora, docs, etc.) |
| Agent-to-agent conversation | Tribe, linking the owning Issue or draft item |

**Uniqueness rule:** one work item = one owning artifact (Issue OR draft). Never both representing the same task. A Project entry referencing an Issue is a view of that Issue, not a second artifact.

## 3. GitHub Projects rules

- Owner: the AlterMundi organization. Visibility: private by default.
- Projects are created around a real coordination boundary (program, product, team, event, roadmap) — NOT automatically per repository. The "one repo = one Project" convention is retired; existing Projects are left as they are.
- Projects may span repositories and may mix linked Issues and draft items.
- Draft items live only inside the Project and inherit its visibility. They do not send notifications, have no repository labels/milestones, and cannot carry a full discussion: when a draft needs conversation or execution detail, convert it to an Issue.
- A private Project does NOT make a public-repository Issue private. Never put credentials, personal data, or sensitive infrastructure detail in any Issue of a public repository; treat all Issue text as public-by-default.

## 4. Channels and authority

- Tribe is authenticated transport and notification. It is never a task tracker and never evidence of implementation, merge, deployment, or publication.
- Implementation claims are verified against Git, PRs, checks, and live runtime — not against messages.
- Inside a repository, that repository's declared contract outranks this canon. Across repositories, this canon governs coordination.
- Before selecting the canonical GitHub repository for a task, verify ALL Git remotes; never assume `origin` is canonical.
- Human authorization is required for production deploys, merges where approval is required, destructive operations, and credential/permission/governance changes — an agent message is never authorization.

## 5. What this canon explicitly does NOT do

- Create files in existing repositories.
- Require bitacoras, libraries, cockpits, or any specific filenames anywhere.
- Require migrating any legacy workflow.
- Duplicate status: Project fields coordinate; they never mirror an Issue's body or discussion.
- Create a parallel source of truth: each question (what work is open? what happened? how does it run?) has exactly one authoritative surface.

## Quick checklist when entering shared work

1. Read the repository's declared contract, if any; follow it.
2. Verify all Git remotes; identify the canonical repository.
3. Find the owning artifact: existing Issue, or draft item in a private Project.
4. If none exists, create the right one per the routing table — never both.
5. Coordinate through Tribe by linking the owning artifact, not by restating its content.
6. Verify claims against Git/PR/CI/runtime before repeating them.

## References

- [`references/github-projects-routing.md`](references/github-projects-routing.md) — verified GitHub Projects privacy and draft-item semantics, with authoritative documentation links and the dated AlterMundi observation.
- [`references/adoption-and-pitfalls.md`](references/adoption-and-pitfalls.md) — convergence procedure for existing projects, relationship to Mariano's tree and CompAII legacy workflows, pitfalls, decision-presentation discipline, and the convergence verification checklist.
