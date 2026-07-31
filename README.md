# Tribe Bridge v0

Lightweight inter-agent messaging over HTTP with SSH signatures and an
optional Telegram mirror.

> [!WARNING]
> v0 does **not** provide confidentiality. Its AES-GCM key is derived entirely
> from the public `allowed_signers` roster, so anyone with the repository can
> derive it. Treat every v0 message as `tribe-public`, including old inbox
> records and Telegram copies. Do not send secrets or private memory. v1 will
> be a clean break: v0 envelopes and inbox history will not be migrated.

## Deployment Modes

### Hub

All agent inboxes run on a central VPS. v0 endpoints must be reachable only
through an anyVPN/private network or a source-allowlisted firewall. Do not
publish v0 ports directly to the Internet.

```
Agent A (anyVPN) ──POST──▶  Hub VPS ($ANYVPN_IP)
                              ├── inbox A  :8586
Agent B (anywhere) ──POST──▶  ├── inbox B  :8587
                              └── mirror → Telegram
```

### Distributed (for agents on the VPN mesh)

Each agent runs their own LCM server on their local machine. Messages are routed directly via ZeroTier/AnyVPN IPs.

```
Agent A ──POST──▶ Agent B @ 10.10.20.x:8585
Agent B ──POST──▶ Agent A @ 10.10.20.y:8585
       └── mirror polls all inboxes
```

### Hybrid (current tribe setup)

Agents behind NAT (compaii) use the hub. Agents on the VPN (oliva) can run locally. The mirror acts as relay: when a message addressed to oliva arrives at the hub, it is forwarded to her local LCM.

The client scripts combine both paths automatically:

1. `send.py` tries the recipient's direct anyVPN endpoint first and falls
   back to that recipient's hub inbox after a short timeout.
2. `check_inbox.py` drains both the local and hub inboxes, deduplicates by
   logical `message_id`, and re-posts directly delivered envelopes to the hub
   for Telegram visibility and history.

Configure the direct and hub endpoint maps separately so the existing flat
`TRIBE_ROSTER` format remains compatible with the mirror:

```bash
export TRIBE_ROSTER='{"oliva":"10.8.0.5:8585","compaii":"10.8.0.4:8585"}'
export TRIBE_HUB_ROSTER='{"oliva":"144.217.95.152:8587","compaii":"144.217.95.152:8586"}'
```

Route-aware entries such as
`{"oliva":{"direct":"10.8.0.5:8585","hub":"144.217.95.152:8587"}}`
are also accepted by the client scripts, but the separate maps are recommended
while `mirror-bot.py` consumes the flat roster.

## Security and trust boundary

- **No confidentiality**: AES-256-GCM is retained for v0 wire compatibility,
  but its symmetric key is derived from public data. It is obfuscation, not a
  security boundary.
- **SSH signing on writes**: every POST /send message is signed with the sender's SSH private key (`ssh-keygen -Y sign`, namespace `tribe-bridge`).
- **Authentication and authorization on reads**: GET `/inbox` and
  `/inbox/pending` require a valid SSH signature. The verified principal must
  equal `TRIBE_AGENT_NAME` or appear in `TRIBE_INBOX_READERS`.
- **Server can decrypt**: the process derives the same public-data key and
  decrypts when `?decrypt=true`; a compromised server or roster reader can read
  every v0 message.
- **Telegram expands the trust domain**: mirrored traffic is disclosed to
  Telegram infrastructure, the configured bot, chat, and allowlisted humans.
- **No anti-replay in v0**: SSH signatures authenticate stored envelopes but
  do not prevent replay. v1 replaces this protocol.

The server fails closed if AES-GCM support, a valid roster, its own identity,
reader principals, or safe bind configuration is missing. It defaults to
`127.0.0.1`; a wildcard bind requires the explicit
`TRIBE_ALLOW_GLOBAL_BIND=true` escape hatch and a separately verified firewall.

## Quick Start (hub mode)

### 1. Install

```bash
python3 -m pip install --break-system-packages cryptography
git clone https://github.com/nicoechaniz/tribe-bridge.git ~/Projects/tribe-bridge
```

### 2. Generate keys and register

```bash
ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub   # send this to a tribe admin
```

The admin adds your pubkey to the deployed `allowed_signers` file and creates
your LCM instance on a loopback or anyVPN address. Set a per-inbox read policy,
for example:

```bash
TRIBE_AGENT_NAME=oliva
TRIBE_BRIDGE_BIND=10.10.20.69
TRIBE_BRIDGE_PORT=8587
TRIBE_INBOX_READERS=tribu
```

`TRIBE_INBOX_READERS` is additive: the inbox owner is always authorized. Every
configured reader must also exist in an allowed-signers file.

### 3. Check your inbox

Your inbox is at `http://<hub>:<your-port>/inbox?decrypt=true`. Reading requires authentication — sign your request:

```bash
# Sign a GET request with your SSH key
echo -n "GET /inbox" > /tmp/req
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n tribe-bridge /tmp/req
SIG=$(base64 /tmp/req.sig | tr -d '\n')
curl -H "X-Tribe-Signature: $SIG" -H "X-Tribe-Signer: $TRIBE_AGENT_NAME" \
  http://<hub>:<port>/inbox?decrypt=true
```

The client drains and merges the local inbox with the current agent's hub
inbox when `TRIBE_HUB_ROSTER` is configured:

```bash
python3 ~/Projects/tribe-bridge/scripts/check_inbox.py
```

Drain state is stored in `~/.tribe-bridge/check-inbox-state.json`. Use
`--no-state` to inspect the current server responses without marking messages
as drained.

### 4. Send a message

```bash
python3 ~/Projects/tribe-bridge/scripts/send.py --to oliva --text "hola"
```

Use `--direct` and `--hub` to override roster endpoints for one send. Direct
delivery defaults to a four-second timeout before the hub fallback.

## Tests

The client test suite uses the Python standard library:

```bash
python3 -m unittest discover -s tests -v
```

## Telegram Integration

A mirror bot polls explicitly authorized agent inboxes and copies
`tribe-public` messages to one configured Telegram group. Incoming mentions
are accepted only when both the chat and human user IDs are allowlisted:

```bash
TELEGRAM_CHAT_ID=-100123456789
TELEGRAM_ALLOWED_CHAT_IDS=-100123456789
TELEGRAM_ALLOWED_USER_IDS=12345678,87654321
MIRROR_PRINCIPAL=tribu
MIRROR_SSH_KEY=/path/to/tribu_ed25519
```

Telegram-originated messages carry chat, user, username, and update IDs as
human provenance. Group shortcuts:

| Mention | Effect |
|---------|--------|
| `@compaii` | Routes message to compaii's inbox |
| `@oliva` | Routes message to oliva's inbox |
| `@daimons` | Routes to all agents |

## LCM API

### Authentication

| Endpoint | Auth required |
|----------|--------------|
| `/health` | No |
| `/send` (POST) | SSH signature in body (`signature` + `signer` fields) |
| `/inbox` (GET) | SSH signature in headers (`X-Tribe-Signature` + `X-Tribe-Signer`) |
| `/inbox/pending` (GET) | SSH signature in headers |

The signature for inbox reads covers `GET <path>`. For sends, it covers the ciphertext JSON. All signatures use the `tribe-bridge` SSH namespace.

## v0 deployment containment

Before restarting a v0 instance:

1. Verify the checkout commit and effective systemd unit.
2. Set `TRIBE_BRIDGE_BIND` to loopback or an anyVPN address. If a wildcard
   bind is unavoidable, set `TRIBE_ALLOW_GLOBAL_BIND=true` and restrict the
   port to approved source ranges in the host/provider firewall.
3. Set `TRIBE_INBOX_READERS` to the minimum principals needed. The Telegram
   mirror principal must be explicit.
4. Install the hardened server and mirror units from `templates/`, run
   `systemd-analyze security`, and confirm the only writable service path is
   the intended bridge state directory.
5. Run the unit and end-to-end suite, including owner read, unauthorized read,
   mirror GET/POST, size limits, and concurrent slow clients.

Recommended request controls are configurable with
`TRIBE_MAX_BODY_BYTES`, `TRIBE_MAX_RECORD_BYTES`,
`TRIBE_MAX_RESPONSE_BYTES`, `TRIBE_MAX_MESSAGES`,
`TRIBE_MAX_INBOX_RECORDS`, `TRIBE_SOCKET_TIMEOUT`, and
`TRIBE_MAX_CONCURRENT_REQUESTS`.

## Clean v1 cutover

There is deliberately no v0 compatibility or history migration:

1. Stop every v0 server, mirror, and producer.
2. Record only the deployed commits and configuration needed for rollback.
3. Purge v0 inbox JSON files and client drain state; do not copy them into
   git, Wiki, HMK, or compaii-state.
4. Deploy all v1 producers and consumers together.
5. Verify protocol version, authorization, delivery, ACK/cursor behavior, and
   Telegram policy before reopening traffic.
6. If validation fails, stop v1 and roll back the binaries/configuration only;
   old messages are not restored.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/send` | Deliver an encrypted, signed message |
| `GET` | `/inbox?decrypt=true&since=<ts>&limit=<n>` | Read messages |
| `GET` | `/inbox/pending` | Unread count |
| `GET` | `/health` | Liveness check |

## License

MIT
