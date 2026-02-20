---
description: Collect preflight state for installer decision making
---
# Preflight

Run:

```bash
mkdir -p var/installer
ENV_SOURCE=".env"
if [ ! -f "$ENV_SOURCE" ]; then
  ENV_SOURCE=".env.example"
fi

read_env_value() {
  local key="$1"
  if [ ! -f "$ENV_SOURCE" ]; then
    echo ""
    return
  fi
  awk -F= -v k="$key" '$1 == k {sub(/^[ \t]+/, "", $2); print $2; exit}' "$ENV_SOURCE"
}

POSTGRES_PASSWORD="$(read_env_value POSTGRES_PASSWORD)"
MCP_INDEX_API_TOKEN="$(read_env_value MCP_INDEX_API_TOKEN)"
CLOUDFLARE_TUNNEL_TOKEN="$(read_env_value CLOUDFLARE_TUNNEL_TOKEN)"
TAILSCALE_AUTHKEY="$(read_env_value TAILSCALE_AUTHKEY)"

NODE_VERSION="$(node -v 2>/dev/null || echo missing)"
NODE_MAJOR="${NODE_VERSION#v}"
NODE_MAJOR="${NODE_MAJOR%%.*}"

cat > var/installer/preflight.json <<JSON
{
  "env_source": "'${ENV_SOURCE}'",
  "node": "'${NODE_VERSION}'",
  "node_major": "'${NODE_MAJOR}'",
  "node_22_ok": "'$( [ "${NODE_MAJOR}" -ge 22 ] 2>/dev/null && echo yes || echo no )'",
  "docker": "'$(docker --version 2>/dev/null || echo missing)'",
  "compose": "'$(docker compose version 2>/dev/null || echo missing)'",
  "cargo": "'$(cargo --version 2>/dev/null || echo missing)'",
  "postgres_password_default": "'$( [ "${POSTGRES_PASSWORD}" = "smith-dev" ] && echo yes || echo no )'",
  "mcp_index_token_set": "'$( [ -n "${MCP_INDEX_API_TOKEN}" ] && echo yes || echo no )'",
  "cloudflare_tunnel_hint": "'$( [ -n "${CLOUDFLARE_TUNNEL_TOKEN}" ] && echo yes || echo no )'",
  "tailscale_hint": "'$( [ -n "${TAILSCALE_AUTHKEY}" ] && echo yes || echo no )'"
}
JSON
cat var/installer/preflight.json
```

## What It Does

This skill creates a lightweight local preflight snapshot for the installer agent.

1. Creates `var/installer/` if needed.
2. Captures key runtime version information.
3. Writes a JSON state file the agent can reference.
4. Avoids repeated probing throughout the install session.

## Prerequisites

- Repository write access.
- Basic shell utilities.

## Expected Output

A JSON document exists at `var/installer/preflight.json` and includes:

- `env_source`
- `node` — full version string
- `node_major` — major version number
- `node_22_ok` — `yes` if Node >= 22 (recommended for runtime services)
- `docker`
- `compose`
- `cargo`
- `postgres_password_default`
- `mcp_index_token_set`
- `cloudflare_tunnel_hint`
- `tailscale_hint`

## Reading Results

- Any `missing` value is a hard blocker for full bootstrap.
- If `node_22_ok` is `no`, warn that runtime services (pi-bridge, smith-cron, session-recorder) require Node >= 22 for local development. Docker containers use Node 22 regardless, so this only affects running services outside Docker.
- If all values are present, continue with stack startup/build steps.
- If password defaults or missing private-network hints are detected, continue but emit loud warnings.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Cannot create `var/installer` | Permission issue | Fix directory permissions |
| Empty JSON values | Command substitution failed | Re-run with full shell output |
| `cat: ... no such file` | Preflight command not run | Re-run preflight block |
| Missing tunnel hints | VPN/tunnel env not configured yet | Continue with warning and recommend Cloudflare Tunnel or Tailscale |
