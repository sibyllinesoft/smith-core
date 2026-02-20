---
description: Start the chat bridge daemon and platform gateway processes
---
# Start Chat Bridge

Run these read-only inspection commands to understand the current state:

```bash
# Verify config exists
test -f "${CHAT_BRIDGE_CONFIG:-config/chat-bridge.toml}" && echo "CONFIG_OK" || echo "NO_CONFIG"

# Check which platforms are configured
grep '^type = ' "${CHAT_BRIDGE_CONFIG:-config/chat-bridge.toml}" 2>/dev/null

# Check if daemon/gateways are already running
pgrep -f smith-chat-daemon && echo "DAEMON_RUNNING" || echo "DAEMON_NOT_RUNNING"
pgrep -af 'smith-.*-gateway' 2>/dev/null || echo "NO_GATEWAYS_RUNNING"
```

## What It Does

This skill starts the chat bridge daemon and the correct gateway binary for each configured platform adapter. The daemon handles inbound message routing, session management, and the admin/webhook API. Each gateway connects to its platform (Discord WebSocket, Telegram polling, etc.) and publishes messages to NATS for the daemon to consume.

## Start Sequence

### 1. Start the daemon

```bash
smith-chat-daemon
```

The daemon reads `CHAT_BRIDGE_CONFIG` (defaults to `config/chat-bridge.toml`) and starts the webhook server on `CHAT_BRIDGE_WEBHOOK_PORT` (defaults to 8092).

Start this in a separate terminal or background it with log redirection:

```bash
smith-chat-daemon 2>&1 | tee logs/chat-daemon.log &
```

### 2. Start gateway(s) for each configured platform

Parse the `type = ` values from the config and start the matching gateway binary:

| Config `type =` | Binary name | Required env vars |
|-----------------|-------------|-------------------|
| `discord` | `smith-discord-gateway` | `DISCORD_BOT_TOKEN` |
| `telegram` | `smith-telegram-gateway` | `TELEGRAM_BOT_TOKEN` |
| `slack` | `smith-slack-gateway` | `SLACK_APP_TOKEN`, `SLACK_BOT_TOKEN` |
| `teams` | `smith-teams-gateway` | `TEAMS_TENANT_ID`, `TEAMS_CLIENT_ID`, `TEAMS_CLIENT_SECRET` |
| `mattermost` | `smith-mattermost-gateway` | `MATTERMOST_TOKEN` |
| `whatsapp` | `smith-whatsapp-gateway` | `WHATSAPP_ACCESS_TOKEN` |
| `matrix` | `smith-matrix-gateway` | `MATRIX_ACCESS_TOKEN` |
| `signal` | `smith-signal-gateway` | `SIGNAL_RECIPIENT` |
| `google_chat` | `smith-google-chat-gateway` | `GOOGLE_CHAT_WEBHOOK_URL` |
| `imessage` | `smith-imessage-gateway` | (config-only) |

Start each gateway directly:

```bash
<binary-name>
```

For example, for Discord:

```bash
smith-discord-gateway 2>&1 | tee logs/discord-gateway.log &
```

Each gateway should run in its own terminal or backgrounded process.

## Prerequisites

- `config/chat-bridge.toml` exists and has at least one `[[adapters]]` stanza (run `setup-chat-bridge` first).
- Platform credentials set in `.env` for each configured adapter.
- Docker stack running (NATS and Redis required by daemon).
- smith-services installed (`npm install -g @sibyllinesoft/smith-services`) or built from source (`cargo build -p smith-chat`).

## Expected Output

- Daemon logs: `Starting chat bridge daemon` and `Starting webhook ingestion server`.
- Gateway logs: platform-specific ready message (e.g., `Discord bot is READY`).
- Processes visible via `pgrep -f smith-chat-daemon` and `pgrep -f gateway`.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `NO_CONFIG` | Config file missing | Run `setup-chat-bridge` skill first |
| `failed to read chat bridge config` | Wrong `CHAT_BRIDGE_CONFIG` path | Check `.env` value matches actual file location |
| `failed to connect to NATS` | NATS not running | `docker compose up -d nats` |
| `failed to connect to redis` | Redis not running | `docker compose up -d redis` |
| Gateway missing env var | Credential not set in `.env` | Run `setup-chat-bridge` to set credentials |
| Port 8092 already in use | Another daemon instance running | Kill existing process or change `CHAT_BRIDGE_WEBHOOK_PORT` |
| `could not determine which binary to run` | Missing `--bin` flag | Use full `--bin <name>` as shown above |

## Notes

Use separate terminal sessions so logs remain visible. For convenience, create a `logs/` directory first:

```bash
mkdir -p logs
```

To stop all chat bridge processes:

```bash
pkill -f smith-chat-daemon
pkill -f 'smith-.*-gateway'
```
