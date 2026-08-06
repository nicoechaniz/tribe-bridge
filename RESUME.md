# Matrix migration resume checkpoint

Status: Tribe Bridge v1 remains the transitional deployed human-message
carrier. The project is intentionally paused before the Matrix DM-083 live
dogfood. This file authorizes no message, directory change, key operation,
service change, host access, migration or archive action.

Last reconciled: 2026-08-06.

## Exact state

- This repository is `nicoechaniz/tribe-bridge`; its deployed/runtime code
  baseline is `b81a683`. Documentation-only commits may advance repository
  `main`, so inspect Git instead of treating the runtime SHA as the docs head.
- Matrix DM-082 is merged at `AlterMundi/daimon-matrix@dad012d`. It now proves
  bilateral relationships, grants, encrypted logical delivery, authenticated
  recipient intake and signed semantic receipts in an isolated local journey.
- Matrix issue #111 / draft PR #112 owns the future real Legion ↔ daimonmatrix
  host dogfood. It deliberately uses Tribe v1 for one inert human message while
  Matrix carries `/me`, `/we` and sync. No such live DM-083 session has run.
- Daimon Cluster `main` `5cc2583` still pins a pre-DM-082 Matrix candidate;
  Cluster issue #52 owns the required V6 repin before dogfood.

No separate `tribe-chat` repository was found locally or under the recorded
`nicoechaniz`/`AlterMundi` GitHub owners. If “tribe-chat” refers to the current
chat-facing runtime, this repository is its canonical source until an exact
successor is recorded.

## Resume rules

1. Do not change this runtime merely to prepare Matrix/Cluster pins.
2. During authorized DM-083, keep Tribe evidence in its own lane: authenticated
   transport, deduplication and ACK do not become Matrix recipient intake,
   relationship consent, grant authority or semantic delivery.
3. Do not dual-write between Tribe and Matrix unless a later card specifies
   recipient authority, retry ownership, cursor cutover and rollback exactly.
4. Do not archive this repository or deployed v1 service until Matrix V0.1 is
   released and the explicit human-authorized Matrix migration/archive cards
   are complete.
5. V0 remains retired permanently; rollback repairs v1 or advances to a
   successor and never reinstalls the public-roster-derived group key.

The authoritative resume order is in `AlterMundi/daimon-matrix/RESUME.md` and
the live board is AlterMundi Project 9.
