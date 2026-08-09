# Adoption, Convergence, and Pitfalls

Operational companion to the canon: how to introduce it into existing projects and teams without disruption, what commonly goes wrong, and how to verify convergence. The SKILL.md rules are the authority; this file is procedure.

## Minimal convergence procedure

When introducing the canon to an existing project or team:

1. Inventory existing trackers and context surfaces read-only.
2. Preserve every existing workflow until an explicit project decision changes it.
3. Identify duplicates that represent the same work.
4. Choose one owning artifact for each active work unit.
5. Add existing Issues to a Project when coordination metadata is useful.
6. Use drafts only for work with no repository owner or intentional private coordination.
7. Retire duplicates only after links, discussion, ownership, and acceptance information are preserved.
8. Do not create new context files merely to demonstrate adoption.

## Relationship to known workflows

### Mariano's shared tree

Mariano's root contracts, recursive messages, bitacoras, research libraries, inbox, and librarian form a coherent workflow for his shared tree. Respect and follow it inside that tree. Learn from its separation of authority, chronology, research, and publication, but do not clone its file structure into tribal projects.

### CompAII legacy project memory

Projects that already use local `MEMORY.md`, Hermes Kanban, Lattice, or another cockpit may continue doing so. Those surfaces are project-local history and policy, not tribal defaults. Migration is optional and project-specific.

## Pitfalls

- Treating one project's successful filesystem layout as a universal template.
- Declaring Issues canonical for work that has no repository owner or should not be exposed at repository visibility.
- Treating a private Project as a privacy wrapper around a public Issue.
- Creating one Project per repository by reflex.
- Creating a draft and an Issue for the same work.
- Using Project fields as implementation evidence.
- Auto-proposing migration every time a legacy `MEMORY.md` or local tracker is discovered.
- Copying transient Tribe conversation into every durable surface.
- Sharing a large agent-private memory skill as the tribal canon.

## Decision-presentation discipline

Governance discussions become unusable when analysis obscures the proposed action. When presenting a policy change to the human coordinator:

1. Lead with **what will change**, in a numbered list.
2. Name the exact skills, files, trackers, or conventions affected.
3. Separate **adopt now**, **preserve unchanged**, and **defer**.
4. Use a compact routing table when several surfaces divide authority.
5. State whether any writes were applied.
6. Put background rationale after the proposal, not before it.

Avoid long, interleaved essays that mix history, architecture, alternatives, and implementation. The reader should be able to identify the proposed actions without reconstructing them from the analysis.

## Verification checklist

Before declaring coordination converged:

- [ ] The project-local workflow remains readable and respected.
- [ ] Each active work unit has one owning Issue or draft item.
- [ ] Existing Issues are linked into Projects rather than duplicated.
- [ ] Private coordination lives in a private Project and contains no accidental public Issue content.
- [ ] Draft limitations are acceptable for each draft item.
- [ ] Git/PR/CI/runtime evidence is not replaced by board status.
- [ ] Tribe handoffs point to durable work artifacts where appropriate.
- [ ] No unnecessary `MEMORY.md`, bitacora, research tree, status file, or new Project was created.
