# LCM Agent Bridge — Project Memory

## Status
- **Phase**: bootstrap (2026-07-29)
- **Branch**: main
- **Deployed**: not yet

## What
Lightweight Communication & Marshalling bridge for inter-agent messaging
over AnyVPN. Agents send structured messages to each other; a mirror bot
copies all traffic to a Telegram group where humans can observe and
participate.

## Architecture

```
┌──────────┐  POST /send   ┌──────────┐  POST /send   ┌──────────┐
│ CompAII  │ ────────────▶ │  Oliva   │ ◀──────────── │   Ani    │
│ :8585    │ ◀──────────── │  :8585   │ ────────────▶ │  :8585   │
└──────────┘               └──────────┘               └──────────┘
      │                          │                          │
      └──────────┬───────────────┴──────────┬───────────────┘
                 │                          │
                 ▼                          ▼
          mirror-bot.py              Telegram grupo
          (reads all inboxes)        "Tribu LCM"
```

Each agent runs `lcm-server.py` on its AnyVPN IP, port 8585. The server
exposes:
- `POST /send` — deliver a message to this agent
- `GET /inbox` — list messages for this agent (with `?since=` param)
- `GET /inbox/pending` — count of unread messages

Agents use the `send_to_agent` Hermes tool to dispatch messages. The tool
is gated: it never fires autonomously — only when the human explicitly
asks.

## Flow

1. Nico (CLI): "CompAII, preguntale a Oliva cómo va el render"
2. CompAII: POST /send → oliva-ip:8585
3. Oliva-agent processes, responds via POST /send → compaii-ip:8585
4. Nico: "¿respondió?"
5. CompAII: GET /inbox → "Oliva: 73% completado"

All messages are simultaneously mirrored to the Telegram group so humans
(Anii, Oliva, Nico) see everything in real time.

## Components

| File | Purpose |
|------|---------|
| src/lcm-server.py | HTTP server per agent (stdlib, no deps) |
| src/mirror-bot.py | Telegram bot mirror (needs python-telegram-bot) |
| templates/plugins/send-to-agent/ | Hermes plugin: `send_to_agent` tool |
| test/test_lcm.py | Integration tests |

## AnyVPN IPs

| Agent | IP | Port |
|-------|----|------|
| compaii | TBD | 8585 |
| oliva | TBD | 8585 |
| ani | TBD | 8585 |

## Telegram

- Group: "Tribu LCM" (to be created)
- Mirror bot: @tribu_lcm_bot (to be created)
- Token + chat_id: TBD

## Guards

- `send_to_agent` tool never fires autonomously (Minecraft lesson)
- Messages are HMAC-signed with a shared tribe secret
- Mirror bot only reads, never writes to LCM
- No agent-to-agent loops — request/response pattern only

## Git
- Remote: nicoechaniz/lcm-agent-bridge (to be created)
