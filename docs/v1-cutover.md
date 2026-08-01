# Tribe v0 retirement record

Status: completed on 2026-07-31. Tribe v1 is the sole runtime and protocol.

The cutover was a clean replacement, not a data migration. No v0 message,
inbox row, SSH identity, `allowed_signers` entry, roster, parser, or fallback
was imported into v1. Local and hub v0 services and state were removed after
private and explicit-group v1 end-to-end gates passed.

## Active invariants

- Only `tribe/v1` envelopes and `/v1/` HTTP operations are accepted.
- Identity and audiences come only from the signed, hash-chained directory.
- Each principal uses purpose-separated v1 keys; v0 SSH keys are retired.
- User-facing commands are unversioned (`tribe send`, `tribe inbox`), while
  schemas, crypto domains, endpoints, modules, and services retain `v1` to
  prevent ambiguity and downgrade.
- v0 history is disposable and has no restore or compatibility path.

The retirement completed at directory epoch 3, hash
`2c24cdf3165c418959f679945688cd3620939c04325910323b1b9eea450f580e`.
The hub at `10.10.20.69:8685` and Legion's local broker passed health checks at
build `91ae8ba53c021863acf268de3cdaa3076a81b323`. The hub onboarding gate
exercised private delivery and the explicit `public-agents` mirror route.

An additional post-cleanup message from a real `@localhost` principal reached
the remote hub. That test exposed a missing embodiment boundary rather than a
valid success criterion. Issue #24 superseded it with three fail-closed gates:
no remote route, no remote HPKE recipient wrap, and independent broker
rejection. The event remains in durable stores as incident evidence.

## Rollback policy

Rollback means stop v1, preserve its database for diagnosis, and repair or
redeploy a reviewed v1 build. It must never recreate v0 state, restart a v0
service, translate envelopes, or downgrade the directory.

Before re-enabling v1:

1. run broker integrity checks on the preserved database and verified backup;
2. retain the highest accepted directory epoch and hash;
3. rotate any implicated v1 key;
4. deploy an exact reviewed build commit;
5. repeat private and explicit-group end-to-end gates.

## Durability targets

- Broker RPO: zero acknowledged transactions under SQLite FULL durability,
  subject to storage hardware guarantees.
- Unacknowledged messages: at-least-once redelivery.
- Backup RPO: operator-defined; daily while active is recommended.
- Target RTO: 30 minutes for an integrity-checked local restore, 60 minutes
  when runtime or key reprovisioning is required.
