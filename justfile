# Smith Core — development commands

set dotenv-load

# ── Infrastructure ────────────────────────────────────────────────────────

# Generate local mTLS certs for Envoy (idempotent unless SMITH_FORCE_CERTS=1)
generate-certs:
    bash infra/envoy/certs/generate-certs.sh

# Start all infrastructure (NATS, PostgreSQL, Redis, ClickHouse, Grafana, etc.)
up: generate-certs
    docker compose up -d

# Stop all infrastructure
down:
    docker compose down

# Show infrastructure status
status:
    docker compose ps

# View infrastructure logs
logs *args:
    docker compose logs {{args}}

# ── Private-Network Tunnels ──────────────────────────────────────────────

# Create/reuse a Cloudflare named tunnel and write token/hostname to .env
tunnel-cloudflare-create name hostname:
    bash scripts/cloudflare-named-tunnel.sh {{name}} {{hostname}}

# Start Cloudflare connector profile
tunnel-cloudflare-up:
    docker compose --profile tunnel-cloudflare up -d cloudflared

# Stop Cloudflare connector profile
tunnel-cloudflare-down:
    docker compose --profile tunnel-cloudflare stop cloudflared

# Tail Cloudflare connector logs
tunnel-cloudflare-logs:
    docker compose --profile tunnel-cloudflare logs -f cloudflared

# End-to-end tunnel smoke test (provider: cloudflare|tailscale)
tunnel-e2e provider:
    bash scripts/tunnel-e2e.sh {{provider}}

# Convenience wrapper for Cloudflare e2e
tunnel-cloudflare-e2e:
    bash scripts/tunnel-e2e.sh cloudflare

# Convenience wrapper for Tailscale e2e
tunnel-tailscale-e2e:
    bash scripts/tunnel-e2e.sh tailscale

# ── Rust Services ─────────────────────────────────────────────────────────

# Build all Rust workspace crates
build:
    cargo build --workspace

# Build in release mode
build-release:
    cargo build --workspace --release

# Build agentd (independent workspace)
build-agentd:
    cargo build --manifest-path agent/agentd/Cargo.toml

# Build agentd in release mode
build-agentd-release:
    cargo build --manifest-path agent/agentd/Cargo.toml --release

# Build everything (workspace + agentd)
build-all: build build-agentd

# Run all Rust tests
test:
    cargo test --workspace

# Run agentd tests
test-agentd:
    cargo test --manifest-path agent/agentd/Cargo.toml

# Run all tests (workspace + agentd)
test-all: test test-agentd

# Lint all Rust code
lint:
    cargo clippy --workspace -- -W clippy::all

# Format all Rust code
fmt:
    cargo fmt --all

# ── Node.js Services ─────────────────────────────────────────────────────

# Install all Node.js dependencies
npm-install:
    npm install

# ── Running Services ──────────────────────────────────────────────────────

# Run the MCP shim (pass MCP server command after --)
run-mcp-sidecar *args:
    cargo run -p mcp-sidecar -- {{args}}

# Run the MCP index
run-mcp-index:
    cargo run -p mcp-index

# Run agentd
run-agentd:
    cargo run --manifest-path agent/agentd/Cargo.toml --features grpc --bin agentd -- run --config ${AGENTD_CONFIG:-agent/agentd/config/agentd.toml} --capability-digest ${AGENTD_CAPABILITY_DIGEST:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}

# Run agentd with fallback config enabled (development-only)
run-agentd-dev:
    SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK=1 SMITH_ALLOW_ZERO_CAPABILITY_DIGEST=1 cargo run --manifest-path agent/agentd/Cargo.toml --features grpc --bin agentd -- run --config ${AGENTD_CONFIG:-agent/agentd/config/agentd.toml} --capability-digest ${AGENTD_CAPABILITY_DIGEST:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}

# Run the pi-bridge agent
run-agent:
    cd agent/pi-bridge && npm run dev

# Run the cron scheduler
run-cron:
    cd service/smith-cron && node cron.mjs

# Run the session recorder
run-session-recorder:
    cd sidecar/session-recorder && node recorder.mjs

# ── Chat Gateways ─────────────────────────────────────────────────────────

# Run Discord gateway
run-discord-gateway:
    cargo run -p smith-chat --bin smith-discord-gateway

# Run Telegram gateway
run-telegram-gateway:
    cargo run -p smith-chat --bin smith-telegram-gateway

# Run Slack gateway
run-slack-gateway:
    cargo run -p smith-chat --bin smith-slack-gateway

# Run Signal gateway
run-signal-gateway:
    cargo run -p smith-chat --bin smith-signal-gateway

# Run Matrix gateway
run-matrix-gateway:
    cargo run -p smith-chat --bin smith-matrix-gateway

# Run Mattermost gateway
run-mattermost-gateway:
    cargo run -p smith-chat --bin smith-mattermost-gateway

# Run Teams gateway
run-teams-gateway:
    cargo run -p smith-chat --bin smith-teams-gateway

# Run WhatsApp gateway (requires webhooks feature)
run-whatsapp-gateway:
    cargo run -p smith-chat --features webhooks --bin smith-whatsapp-gateway

# Run Google Chat gateway (requires webhooks feature)
run-google-chat-gateway:
    cargo run -p smith-chat --features webhooks --bin smith-google-chat-gateway

# Run iMessage gateway (requires webhooks feature)
run-imessage-gateway:
    cargo run -p smith-chat --features webhooks --bin smith-imessage-gateway

# ── Installer ─────────────────────────────────────────────────────────────

# Run the agentic installer
install *args:
    cd installer && npm run build && bash -lc 'set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; node dist/cli.js "$@"'

# ── Full Stack ────────────────────────────────────────────────────────────

# Complete development setup: start infra, build everything
dev: up build npm-install
    @echo "Smith Core is ready. Run 'just run-agent' to start the agent."
