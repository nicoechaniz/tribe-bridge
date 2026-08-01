# Tribe v1 SQLite broker operations

The v1 broker uses a new empty database. It never opens, imports, migrates, or
backs up a v0 inbox.

## Embodiment-local principals

Every broker and sender requires a non-empty JSON
`TRIBE_V1_LOCAL_AGENT_IDS` set owned by the deployment. An ID ending in
`@localhost` may send only when both it and every concrete envelope recipient
are in that set. The sender checks before generating the CEK, nonce, or HPKE
wraps; outbox retry rechecks old envelopes; broker admission is the final
independent gate. A remote broker therefore rejects an `@localhost` principal,
and a mixed group cannot become an exfiltration path.

The set is an additional restriction, not an authority source: membership does
not override the governance-signed directory, audience epoch, or allowed
senders. Harnesses must inject `TRIBE_CLIENT_ENV`; the operator command has no
default identity.

## Protocol-aware directory rollout

Directory changes that introduce direct `observers` are code-first. Deploy a
build that accepts the optional field to every broker and active client, then
verify each client against the unsigned candidate before signing or installing
it. Older builds reject the closed audience shape, so advancing the directory
first causes a fail-closed outage.

Once all participants are compatible, sign and install one chained epoch and
verify that the direct member and every observer can claim their independent
delivery. Every observer-policy change creates a new active audience epoch;
the previous epoch becomes `retired` so endpoints can finish already-admitted
deliveries, but it cannot authorize new encryption or broker admission. Drain
all sender outboxes before the transition and remove retired epochs only after
the maximum message TTL and delivery-retention window. Rollback is a corrective
successor epoch; never restore an older snapshot over advanced anti-rollback
state.

If an incident already mutated an audience epoch in place, a corrective
successor may mark the retired observed direct with the signed
`legacy_unobserved_receive: true` valve. This preserves both exact historical
recipient variants for endpoint receive only; it does not permit new broker
admission. Record the affected window and remove the valve with the retired
epoch after the bounded retention period.

## Durability contract

- `BrokerBackend` is the backend-neutral interface: atomic `enqueue`, `claim`,
  and signed `acknowledge`. The shared protocol vectors and core lifecycle
  cases in `tests/test_tribe_broker_v1.py` are the conformance suite a future
  JetStream adapter must pass unchanged.
- Admission is one `BEGIN IMMEDIATE` transaction containing the message,
  concrete recipient deliveries, and unique `(sender_id, message_id)`.
- A byte-identical retry returns the original receipt. The same sender/ID with
  different canonical bytes fails with `message_id_conflict`.
- Claims are atomic leases. Expired leases return to the queue until the
  attempt cap, then enter the dead-letter state.
- Receiver-signed acknowledgements bind the message, active lease, envelope
  hash, receiver, outcome, and time.
- `processed` and `terminal_failed` are terminal. `retryable_failed` applies
  bounded exponential backoff.
- Delivery is at-least-once. Consumers must use `(sender_id, message_id)` as
  their durable effect idempotency key.
- The endpoint outbox is stored in the same engine with independent leases,
  retry/backoff, receipts, and dead letters.

## SQLite journal gate

SQLite versions 3.7.0 through 3.51.2 contain the WAL-reset race documented by
SQLite upstream. Recognized patched lines are 3.44.6+, 3.50.7+, and 3.51.3+.

`journal_mode=auto` enables WAL only on a recognized patched runtime. Otherwise
it selects rollback journal (`DELETE`). An explicit unsafe `wal` request fails.
All modes use foreign keys, a bounded busy timeout, and `synchronous=FULL`.

The current host Python runtime embeds SQLite 3.46.1, so it MUST operate in
`DELETE` mode until the runtime is upgraded. For 4–8 agents this conservative
single-writer mode is acceptable.

## Commands

Create a fresh private v1 database:

```bash
python3 scripts/tribe_broker_admin.py \
  --db ~/.tribe-bridge/v1/broker.sqlite init
```

Inspect the effective runtime and journal gate:

```bash
python3 scripts/tribe_broker_admin.py \
  --db ~/.tribe-bridge/v1/broker.sqlite runtime
```

Integrity, metrics, backup, and retention:

```bash
python3 scripts/tribe_broker_admin.py --db "$DB" integrity
python3 scripts/tribe_broker_admin.py --db "$DB" metrics
python3 scripts/tribe_broker_admin.py --db "$DB" backup /safe/broker.sqlite
python3 scripts/tribe_broker_admin.py --db "$DB" maintain \
  --retain-terminal-days 30
```

Backups refuse to overwrite a destination, use SQLite's online backup API,
pass `integrity_check`, are installed atomically at mode `0600`, and fsync the
file and parent directory.

## Recovery

1. Stop every writer using the v1 database.
2. Preserve the failed database for investigation.
3. Run `integrity` on the current database and the newest backup.
4. Restore only a backup whose result is exactly `ok`.
5. Start one broker and verify runtime, journal mode, metrics, claims, and ACK.
6. Redeliver unacknowledged messages. Never infer acknowledgement from a read
   cursor or from the absence of a client response.

Corruption and disk-full errors abort the transaction and surface as
`storage_corruption` or `storage_error`; the broker does not recreate or
truncate the database automatically.
