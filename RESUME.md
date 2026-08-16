# Matrix migration resume checkpoint

Status: Tribe Bridge v1 remains the transitional deployed human-message
carrier. Matrix DM-083 and its final host qualification have run successfully;
the Tribe message remained a deliberately separate transport/ACK lane and did
not become Matrix intake or semantic-delivery evidence. No archive is
authorized.

Last reconciled: 2026-08-11.

## Exact state

- This repository is `nicoechaniz/tribe-bridge`. PR #61 / branch
  `hermes-client-environment` is at code commit `ecb51d8`; its 98-test local
  suite and CI pass, but it has no independent review. The deployed broker
  reports build `d49bf22` and remains healthy at directory epoch 5.
- Matrix issue #111 / draft PR #112 completed the real Legion ↔ daimonmatrix
  same-being dogfood. Exact host-qualified Matrix code is `915c56c`; Cluster
  PR #77 code `94d80ba` pins and hosts it.
- The separate Tribe v1 message succeeded with its own authenticated transport,
  deduplication and ACK evidence. It is not Matrix authenticated recipient
  intake, relationship/grant consent or a signed semantic receipt.
- The final cold host reboot recovered `tribe-bridge-v1.service` automatically
  with protocol `tribe/v1`, directory epoch 5 and the same deployed build.

No separate `tribe-chat` repository was found locally or under the recorded
`nicoechaniz`/`AlterMundi` GitHub owners. If “tribe-chat” refers to the current
chat-facing runtime, this repository is its canonical source until an exact
successor is recorded.

## Resume rules

1. Keep Tribe evidence in its own lane: authenticated
   transport, deduplication and ACK do not become Matrix recipient intake,
   relationship consent, grant authority or semantic delivery.
2. Do not dual-write between Tribe and Matrix unless a later card specifies
   recipient authority, retry ownership, cursor cutover and rollback exactly.
3. Do not archive this repository or deployed v1 service until Matrix V0.1 is
   released and the explicit human-authorized Matrix migration/archive cards
   are complete.
4. V0 remains retired permanently; rollback repairs v1 or advances to a
   successor and never reinstalls the public-roster-derived group key.
5. Independent review of PR #61, cross-being Matrix consent, fresh-host custody
   and final cutover/archive approval remain separate external gates.

The authoritative resume order is in `AlterMundi/daimon-matrix/RESUME.md` and
the live board is AlterMundi Project 9.
