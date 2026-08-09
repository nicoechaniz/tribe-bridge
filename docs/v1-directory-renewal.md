# Tribe v1 directory renewal and client auto-update

The signed v1 directory has a finite validity (30 days since epoch 5). These
two jobs keep the channel alive without human ceremony:

- **Renewal (one host, holds the governance working copy)** —
  `scripts/renew_directory_v1.py` signs epoch N+1 when the installed directory
  is within the renewal window (default 7 days), verifies the chain against
  every local client state, installs atomically with backup, publishes the
  artifact to the `directory-live` branch, and copies it to the hub.
- **Client update (every remote self-custody host)** —
  `scripts/update_directory_client_v1.py` fetches the canonical signed
  directory from the stable raw URL, verifies signature/chain/expiry fail
  closed, and installs it atomically. Idempotent; silent when current.

Neither touches agents, audiences, or keys. Key rotation (all agent keys
expire 2026-09-01) is a separate ceremony — see issue #59.

## Renewal host setup (legion)

```bash
# publishing clone on the directory-live branch (one time)
git clone --branch directory-live --single-branch \
  git@github.com:nicoechaniz/tribe-bridge.git ~/Projects/tribe-bridge-directory-live

cat > ~/.tribe-bridge/v1/directory-renewal.env <<'EOF'
TRIBE_V1_RENEWAL_HUB=debian@10.10.20.69
EOF

install -m 0644 templates/tribe-directory-renewal.{service,timer} \
  ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tribe-directory-renewal.timer

# check what it would do anytime:
~/.tribe-bridge/v1/venv/bin/python scripts/renew_directory_v1.py --dry-run
```

The renewal script signs with
`~/.tribe-bridge/v1-governance-offline/governance-root.json` (0600) — the same
working copy used by the manual ceremony. Audits land in
`~/.tribe-bridge/v1/renewals/<ts>/`; backups as `directory.json.bak-epoch<N>`.

## Remote client setup (eko@amapola, oliva@mac-mini, …)

```bash
cat > ~/.tribe-bridge/v1/directory-update.env <<'EOF'
TRIBE_V1_DIRECTORY_URL=https://raw.githubusercontent.com/nicoechaniz/tribe-bridge/directory-live/governance/directories/directory-current-signed.json
TRIBE_V1_DIRECTORY_STATE=/home/USERNAME/.tribe-bridge/v1/<agent>-directory-state.json
EOF

install -m 0644 templates/tribe-directory-update.{service,timer} \
  ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tribe-directory-update.timer

# first run / recovery from an expired directory (also works manually):
~/.tribe-bridge/v1/venv/bin/python scripts/update_directory_client_v1.py \
  --url "$TRIBE_V1_DIRECTORY_URL" --state "$TRIBE_V1_DIRECTORY_STATE"
```

The script prints a JSON summary on change or failure and stays silent when
already current (cron-friendly). A failed verification never mutates the
installed file, so an agent with an expired directory recovers by running it
manually once — no human relay needed anymore.
