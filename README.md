# Smith Core

**An AI agent platform where security isn't an afterthought.**

Smith Core gives you a personal AI assistant across 10 chat platforms, backed by sandboxed execution, policy-based admission control, and an mTLS gateway. The agent can discover and use tools through a unified [MCP](https://modelcontextprotocol.io/) catalog, and every action flows through NATS JetStream with full audit visibility.

Run it on your own hardware. Talk to it on the channels you already use. Know exactly what it can and can't do.

## Why this exists

Most open-source agent platforms give you a powerful assistant that runs tools directly on your host with no isolation. That's fine for demos. It's less fine when the agent is processing untrusted input from group chats, or when you want to let other people talk to it.

Smith Core separates *thinking* from *doing*. The AI reasons about what to do; a separate sandboxed daemon (`agentd`) actually does it — inside Landlock + seccomp-bpf + cgroups on Linux, with OPA policies governing what's allowed. You get the full capability of an autonomous agent without handing it the keys to everything.

## Install

Requires **Node >= 22** and **Docker**.

```bash
npx @sibyllinesoft/smith-installer
```

The installer is an AI-guided setup agent. It detects your system, walks you through configuration, and gets the stack running. For headless/CI environments:

```bash
npx @sibyllinesoft/smith-installer --non-interactive
```

The installer emits non-blocking security warnings if it detects weak default
secrets or missing private-network hints (for example Cloudflare Tunnel or
Tailscale configuration).
On macOS, the installer also writes Gondolin VM defaults into `.env` so
persistent sandbox sessions are enabled out of the box.

### From source

```bash
git clone https://github.com/sibyllinesoft/smith-core.git
cd smith-core

# Generate local mTLS certs for Envoy (idempotent)
just generate-certs

# Start infrastructure (NATS, PostgreSQL, Redis, ClickHouse, Grafana, etc.)
just up

# Build all Rust services (workspace + agentd)
just build-all

# Install Node.js dependencies
just npm-install

# Start secure agentd baseline config
just run-agentd

# Run the agent
just run-agent
```

## Chat platforms

Smith Core connects to 10 messaging platforms through dedicated gateway binaries. Each gateway ingests messages and publishes them to NATS; the agent responds through the same channel.

| Platform | Gateway | Pattern |
|----------|---------|---------|
| Discord | `just run-discord-gateway` | WebSocket (Bot API) |
| Slack | `just run-slack-gateway` | WebSocket (Socket Mode) |
| Telegram | `just run-telegram-gateway` | Long-poll |
| Signal | `just run-signal-gateway` | Polling |
| Matrix | `just run-matrix-gateway` | Polling |
| Mattermost | `just run-mattermost-gateway` | WebSocket |
| Microsoft Teams | `just run-teams-gateway` | Graph API polling |
| WhatsApp | `just run-whatsapp-gateway` | Inbound webhook |
| Google Chat | `just run-google-chat-gateway` | Inbound webhook |
| iMessage | `just run-imessage-gateway` | Inbound webhook |

Gateways requiring inbound HTTP (WhatsApp, Google Chat, iMessage) need the `webhooks` feature flag.

The `smith-chat-daemon` also exposes a shared webhook ingress service (default
`CHAT_BRIDGE_WEBHOOK_PORT=8092`) including `/webhook/github`, which validates
`X-Hub-Signature-256` when `CHAT_BRIDGE_GITHUB_WEBHOOK_SECRET` is set and
publishes normalized orchestration events to `smith.orch.ingest.github`.
With `CHAT_BRIDGE_REQUIRE_SIGNED_WEBHOOKS=true` (default), unsigned webhook
requests are rejected.

## Architecture

```mermaid
graph TD
    Platforms["Discord · Telegram · Slack · Signal · Matrix · Teams<br/>Mattermost · WhatsApp · Google Chat · iMessage"]
    Platforms --> Gateways["Gateway Binaries"]
    Gateways --> NATS["NATS JetStream"]

    NATS <--> PiBridge["pi-bridge<br/>(AI reasoning)"]
    NATS --> Recorder["Session Recorder"]

    Recorder --> Postgres["PostgreSQL"]
    Recorder --> Observability["Grafana + ClickHouse"]

    PiBridge --> Index
    PiBridge --> Agentd

    subgraph OPA["OPA Policy Engine"]
        Index["MCP Index<br/>(tool catalog)"]
        Index --> Shims["MCP Sidecars"]
        Shims --> Tools["Tool Servers<br/>(postgres, users, cron, ...)"]

        subgraph Agentd["agentd — sandboxed execution"]
            direction LR
            Landlock ~~~ Seccomp["seccomp-bpf"] ~~~ Cgroups["cgroups v2"]
        end
    end

    style Platforms fill:#2d2d44,stroke:#888,color:#eee
    style OPA fill:#111122,stroke:#e9a545,stroke-width:2px,color:#eee
    style Agentd fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#eee
    style NATS fill:#1a1a2e,stroke:#0f3460,stroke-width:2px,color:#eee
```

**NATS JetStream** is the primary async backbone for sessions, telemetry, and orchestration. Control-plane discovery and capability execution still use explicit HTTP/gRPC gateway calls.

## Key components

### agentd — Sandboxed execution

The agent daemon executes capabilities in multi-layer isolation:

- **Landlock LSM** — filesystem access control (Linux 5.13+)
- **seccomp-bpf** — syscall filtering
- **cgroups v2** — CPU and memory limits
- **Process namespaces** — full process isolation

agentd has zero intelligence. It receives vetted intents, executes them inside the sandbox, and returns results. The AI reasoning happens elsewhere.

| Mode | Isolation | Platform |
|------|-----------|----------|
| Full sandbox | All layers | Linux 5.13+ |
| Partial sandbox | seccomp + cgroups | Older Linux |
| Demo mode | Policy-only | Any OS |

### MCP Sidecar — Tool bridge

Wraps any stdio-based MCP server in an HTTP API. Spawn a tool server, get an HTTP endpoint:

```bash
just run-mcp-sidecar -- npx @modelcontextprotocol/server-filesystem /data
```

Supports optional middleware transforms (TOML config) for input injection, output redaction, argument filtering, and more.

### MCP Index — Tool catalog

Aggregates tools from multiple MCP sidecar instances into a single searchable catalog. Agents query one endpoint to discover all available tools. Polls upstream sidecars at configurable intervals.

### Admission control

OPA policies are stored in PostgreSQL and synced to the OPA server. The admission service enforces policy before any capability executes — blocking, allowing, or quarantining intents based on configurable rules.

### Observability

The full stack ships with:

- **OpenTelemetry Collector** — traces and metrics pipeline
- **ClickHouse** — telemetry storage
- **Grafana** — pre-configured dashboards for agent activity, Envoy traffic, session exploration, and token usage
- **Envoy** — mTLS gateway with admin interface on `:9901`

## Infrastructure

`docker compose up` starts 14 services:

| Service | Purpose | Port |
|---------|---------|------|
| NATS | Message bus (JetStream) | 4222 |
| PostgreSQL | Primary database | 5432 |
| Redis | Cache | — |
| ClickHouse | Telemetry storage | — |
| OTEL Collector | Trace/metrics pipeline | — |
| Grafana | Dashboards | 3000 |
| OPA | Policy engine | — |
| Envoy | mTLS gateway | 6173 |
| Session Recorder | Chat session persistence | — |
| Smith Cron | Scheduled tasks | — |
| MCP Postgres | DB tools via MCP | — |
| MCP Users | User management tools | — |
| MCP Cron | Cron management tools | — |
| MCP Index | Unified tool catalog | 9200 |

## Development

```bash
just build            # Build Rust workspace
just build-agentd     # Build agentd (separate workspace)
just build-all        # Both
just test             # Run workspace tests
just test-agentd      # Run agentd tests
just test-all         # Both
just lint             # Clippy
just fmt              # Format
```

See the [justfile](justfile) for all available commands.
For release gates, use [`docs/release-readiness-checklist.md`](docs/release-readiness-checklist.md).
For Cloudflare/Tailscale tunnel setup and e2e checks, use
[`docs/private-network-tunnels.md`](docs/private-network-tunnels.md).

## Project structure

```
smith-core/
├── agent/
│   └── pi-bridge/       # AI reasoning bridge (TypeScript)
├── service/
│   ├── mcp-sidecar/        # MCP stdio-to-HTTP bridge
│   ├── mcp-index/       # Unified tool catalog
│   ├── smith-chat/      # Chat adapters + 10 gateway binaries
│   ├── admission/       # OPA policy sync
│   └── smith-cron/      # Cron scheduler
├── sidecar/
│   └── session-recorder/  # Chat session persistence
├── installer/           # AI-guided setup agent
├── infra/               # Config for NATS, Envoy, Grafana, OPA, OTEL, PostgreSQL
├── docker-compose.yaml  # Full infrastructure stack
├── Cargo.toml           # Rust workspace root
├── package.json         # npm workspace root
└── justfile             # Development commands
```

## Configuration

Services are configured through environment variables. Copy `.env.example` to `.env` and adjust:

```bash
# Core
NATS_URL=nats://localhost:4222
SMITH_DATABASE_URL=postgresql://smith:smith-dev@localhost:5432/smith
AGENTD_ROOT=../agentd  # path to agentd repo checkout
AGENTD_CONFIG=${AGENTD_ROOT}/config/agentd.toml
MCP_INDEX_API_TOKEN=replace-with-a-long-random-secret
MCP_SIDECAR_API_TOKEN=replace-with-a-long-random-secret
# Optional persistent VM overrides
SMITH_EXECUTOR_VM_POOL_ENABLED=true
SMITH_EXECUTOR_VM_METHOD=gondolin

# Chat (set tokens for platforms you use)
DISCORD_BOT_TOKEN=
TELEGRAM_BOT_TOKEN=
SLACK_BOT_TOKEN=
SLACK_APP_TOKEN=
```

For non-development deployments, rotate all default passwords in `.env` and set strong `MCP_INDEX_API_TOKEN` and `MCP_SIDECAR_API_TOKEN` values.
When `SMITH_EXECUTOR_VM_POOL_ENABLED=true` (or `executor.vm_pool.enabled=true` in `agentd.toml`), VM execution defaults to `gondolin` on macOS and `host` on other platforms (override with `SMITH_EXECUTOR_VM_METHOD`).

## Security defaults

Smith Core is designed for single-user, self-hosted deployments. Defaults are secure for that context:

- **DM pairing** — unknown senders on chat platforms are challenged before the agent processes their messages
- **Sandboxed execution** — capabilities run inside agentd's isolation layers, not on the host
- **Policy enforcement** — OPA policies govern what the agent can do
- **mTLS gateway** — Envoy terminates TLS and forwards only explicit routes
- **Loopback-bound host ports** — infrastructure ports bind to `127.0.0.1` by default
- **Token-enforced MCP APIs** — `mcp-index` and `mcp-sidecar` require API tokens by default (including `/health`; opt-out only via explicit `*_ALLOW_UNAUTHENTICATED=true`)
- **Signed webhook enforcement** — `smith-chat` webhook ingress rejects unsigned requests by default (`CHAT_BRIDGE_REQUIRE_SIGNED_WEBHOOKS=true`)
- **Config-backed agentd startup** — `just run-agentd` uses committed config; insecure fallback is now dev-only via `just run-agentd-dev`
- **No default policy bundles for multi-user** — that's a [paid offering](https://smithcore.dev)

## License

MIT
