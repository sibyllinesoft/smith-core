# Smith Core Release Readiness Checklist

Scope: single-user installation on a private network / VPN.

## Must Pass Before Tagging

- [ ] `cargo check --workspace`
- [ ] `cargo check --manifest-path agent/agentd/Cargo.toml --features grpc --bin agentd`
- [ ] `npm run build --workspaces --if-present`
- [ ] `npm run test --workspace installer`
- [ ] `docker compose config`
- [ ] Envoy config validates (`envoy --mode validate -c /etc/envoy/envoy.yaml`)
- [ ] `bash infra/envoy/certs/generate-certs.sh` succeeds
- [ ] `just run-agentd` starts with committed config (`agent/agentd/config/agentd.toml`)

## Security Baseline (Single-User Private Network)

- [ ] Keep host-exposed infrastructure ports loopback-bound (`127.0.0.1`)
- [ ] Set non-default values for:
  - [ ] `POSTGRES_PASSWORD`
  - [ ] `CLICKHOUSE_PASSWORD`
  - [ ] `GRAFANA_ADMIN_PASSWORD`
- [ ] Set `MCP_INDEX_API_TOKEN` to a long random secret
- [ ] Keep `CHAT_BRIDGE_DM_POLICY=pairing` unless explicitly accepting open DMs
- [ ] Use a private network path (VPN/tunnel) for remote access, such as Cloudflare Tunnel or Tailscale
- [ ] Do not use `SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK=1` in normal runtime
- [ ] Keep `strict_sandbox=true` in `agent/agentd/config/agentd.toml`
- [ ] Confirm `AGENTD_CAPABILITY_DIGEST` is intentionally chosen for your bundle policy
- [ ] Keep agentd metrics/health listeners on loopback only (`127.0.0.1`)

## Functionality / Self-Containment

- [ ] Installer non-interactive flow works: `npx @sibyllinesoft/smith-installer --non-interactive`
- [ ] Installer skill pack is packaged (`npm pack --dry-run --workspace installer`)
- [ ] Core services up in compose: `nats`, `postgres`, `envoy`, `mcp-index`
- [ ] If Cloudflare tunnel is configured: `just tunnel-cloudflare-e2e`
- [ ] If Tailscale path is configured: `just tunnel-tailscale-e2e`
- [ ] Planner demo crate is absent from this repo (kept in internal/other repo if needed)

## Explicitly Deferred (Known TODOs)

- [ ] Prompt injection mitigation on MCP sidecars
- [ ] Multi-user/open-network hardening controls (kept out of this OSS baseline)

## Release Artifacts

- [ ] `README.md` reflects actual runtime defaults and ports
- [ ] `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` present
- [ ] CI workflow passes on a clean checkout
