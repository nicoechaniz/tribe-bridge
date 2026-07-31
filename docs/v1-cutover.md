# Tribe v1 one-way cutover

This is a clean replacement, not a migration. v0 history has no operational
value and MUST NOT be copied, imported, backed up, transformed, or exposed to
v1. There is no v0 fallback.

## Review gate

Do not execute the cutover until independent review approves the stacked v1
protocol, broker, and client PRs. Record the reviewed commit SHA and use that
exact SHA as `TRIBE_V1_BUILD_COMMIT`.

## Provision without activating

1. Create `~/.tribe-bridge/v1` at mode `0700`.
2. Create a Python environment containing `cryptography>=49`.
3. Provision purpose-separated Ed25519/X25519 key bundles at mode `0600`.
4. Pin governance roots out of band.
5. Install one governance-signed directory and verify its epoch/hash.
6. Install `tribe-bridge-v1.service`, `tribe-mirror-v1.service`, and its timer.
7. Install the new Hermes `send-to-agent-v1` integration without enabling the
   old and new providers together.
8. Keep the v1 service bound to loopback unless an explicit firewall/reverse
   proxy decision permits a global bind.

Key helpers refuse to overwrite existing material:

```bash
scripts/generate_v1_keys.py agent \
  --agent-id compaii --epoch 1 --output ~/.tribe-bridge/v1/agent.keys.json
scripts/generate_v1_keys.py governance \
  --kid governance/root/1 \
  --private-output /offline/governance-root.json \
  --roots-output ~/.tribe-bridge/v1/governance-roots.json
scripts/sign_directory_v1.py \
  --directory /offline/directory-unsigned.json \
  --governance-key /offline/governance-root.json \
  --output ~/.tribe-bridge/v1/directory.json
```

The agent command prints only the public directory fragment. Governance private
keys stay offline and are never copied into a service environment.
The anti-rollback state pins the governance-roots hash as well as the directory
chain. Root rotation is a separate reviewed reprovisioning ceremony; replacing
both files in place is rejected.

## Preflight

All checks MUST pass:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/tribe_broker_admin.py --db "$V1_DB" runtime
python3 scripts/tribe_broker_admin.py --db "$V1_DB" integrity
systemd-analyze --user verify \
  templates/tribe-bridge-v1.service \
  templates/tribe-mirror-v1.service \
  templates/tribe-mirror-v1.timer
```

Run the direct, hub-fallback, duplicate-route, group mirror, expiry, revocation,
restart, and offline-outbox drills against disposable empty v1 databases.
Verify `scripts/flush_outbox_v1.py` sends the same envelope/message ID after a
client restart.
Confirm `/v1/health` reports `tribe/v1`, the reviewed build commit, the expected
directory epoch/hash, and a safe effective journal mode.

## Cutover window

1. Stop all v0 writers, readers, relays, mirrors, cron jobs, and Hermes tools.
2. Verify every v0 unit is inactive. Do not archive its inbox.
3. Delete only the resolved v0 inbox contents under
   `~/.tribe-bridge/inbox`; do not touch the v1 directory.
4. Enable/start `tribe-bridge-v1.service`.
5. Verify health and perform one private direct round trip.
6. Enable the Hermes v1 provider and remove/disable `send-to-agent` v0.
7. Perform one `tribe-public` group round trip with the mirror as an explicit
   directory member.
8. Enable `tribe-mirror-v1.timer`.
9. Observe metrics, dead letters, and service logs for one hour.

Every v1 delivery starts with an empty store. No step reads v0 records.

## Rollback

Rollback means stop/disable v1, preserve its database for diagnosis, and fix or
redeploy v1. It MUST NOT restart v0, translate v1 envelopes to v0, or restore a
v0 inbox. Human coordination may continue through GitHub/Telegram while v1 is
offline.

Before re-enabling v1:

1. run `integrity` on the preserved database and newest verified backup;
2. retain the higher directory epoch/hash;
3. rotate any key implicated in the failure;
4. deploy a reviewed build;
5. re-run the full disposable-store drill, then resume the existing v1 queue.

## RPO/RTO

- Broker RPO: zero acknowledged transactions under the SQLite FULL durability
  model, subject to storage hardware guarantees.
- Unacknowledged messages: at-least-once redelivery.
- Backup RPO: operator-defined; daily while active is recommended.
- Target RTO: 30 minutes for integrity-checked local restore, 60 minutes when
  runtime/key reprovisioning is required.
