#!/usr/bin/env bash
# smith-check.sh — validate an existing smith-core installation.
#
# Exit 0 if all required checks pass, 1 if any required check fails.
# Optional checks report SKIP on failure and do not affect the exit code.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

passed=0
failed=0
skipped=0

pass() { echo "[PASS] $1"; ((passed++)); }
fail() { echo "[FAIL] $1"; ((failed++)); }
skip() { echo "[SKIP] $1"; ((skipped++)); }

# ── .env checks ──────────────────────────────────────────────────────────

if [[ -f .env ]]; then
  mcp_index_token=$(grep -E '^MCP_INDEX_API_TOKEN=' .env | head -1 | cut -d= -f2-)
  mcp_sidecar_token=$(grep -E '^MCP_SIDECAR_API_TOKEN=' .env | head -1 | cut -d= -f2-)

  env_ok=true
  for token_name in MCP_INDEX_API_TOKEN MCP_SIDECAR_API_TOKEN; do
    val=$(grep -E "^${token_name}=" .env | head -1 | cut -d= -f2-)
    val="${val//\"/}"
    val="${val//\'/}"
    if [[ -z "$val" || "$val" == change-me* || "$val" == changeme* || "$val" == replace-with-* || ${#val} -lt 24 ]]; then
      env_ok=false
    fi
  done

  if $env_ok; then
    pass ".env exists with non-placeholder MCP tokens"
  else
    fail ".env has missing or placeholder MCP_INDEX_API_TOKEN / MCP_SIDECAR_API_TOKEN"
  fi
else
  fail ".env file does not exist"
fi

# ── Docker daemon ────────────────────────────────────────────────────────

if docker info &>/dev/null; then
  pass "Docker daemon running"
else
  fail "Docker daemon not running"
fi

# ── Docker services healthy ──────────────────────────────────────────────

required_services=(nats postgres envoy mcp-index redis opa-management)
services_up=0
services_total=${#required_services[@]}

for svc in "${required_services[@]}"; do
  status=$(docker compose ps --format '{{.State}}' "$svc" 2>/dev/null)
  if [[ "$status" == "running" ]]; then
    ((services_up++))
  fi
done

if [[ $services_up -eq $services_total ]]; then
  pass "Core Docker services healthy (${services_up}/${services_total})"
else
  fail "Docker services: ${services_up}/${services_total} running (need: ${required_services[*]})"
fi

# ── Required ports responding ────────────────────────────────────────────

declare -A port_map=( [4222]="NATS" [5432]="PostgreSQL" [9200]="MCP Index" [6173]="Envoy" )
ports_ok=0
ports_total=${#port_map[@]}

for port in "${!port_map[@]}"; do
  if (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
    ((ports_ok++))
  else
    fail "Port $port not responding (${port_map[$port]})"
  fi
done

if [[ $ports_ok -eq $ports_total ]]; then
  pass "Required ports responding (${ports_ok}/${ports_total})"
fi

# ── Node.js version ─────────────────────────────────────────────────────

if command -v node &>/dev/null; then
  node_version=$(node -v | sed 's/^v//')
  node_major=${node_version%%.*}
  if [[ $node_major -ge 22 ]]; then
    pass "Node.js v${node_version} (>= 22)"
  elif [[ $node_major -ge 20 ]]; then
    pass "Node.js v${node_version} (>= 20, recommend >= 22)"
  else
    fail "Node.js v${node_version} — need >= 20 (recommend >= 22)"
  fi
else
  fail "Node.js not found in PATH"
fi

# ── Workspace build ──────────────────────────────────────────────────────

if npm run build --workspaces --if-present &>/dev/null; then
  pass "npm workspace build succeeds"
else
  fail "npm workspace build failed"
fi

# ── mTLS certificates ───────────────────────────────────────────────────

cert_dir="infra/envoy/certs/generated"
cert_files=(ca.crt ca.key server.crt server.key client.crt client.key)
certs_ok=true

for f in "${cert_files[@]}"; do
  if [[ ! -f "$cert_dir/$f" ]]; then
    certs_ok=false
    break
  fi
done

if $certs_ok; then
  pass "mTLS certs exist in ${cert_dir}/"
else
  fail "Missing mTLS certs in ${cert_dir}/ (run: bash infra/envoy/certs/generate-certs.sh)"
fi

# ── Optional: smith-chat-daemon ──────────────────────────────────────────

if command -v smith-chat-daemon &>/dev/null && smith-chat-daemon --help &>/dev/null; then
  pass "smith-chat-daemon available"
else
  skip "smith-chat-daemon not installed (non-fatal)"
fi

# ── Optional: agentd ─────────────────────────────────────────────────────

if command -v agentd &>/dev/null && agentd --version &>/dev/null; then
  pass "agentd available"
else
  skip "agentd not installed (non-fatal)"
fi

# ── Summary ──────────────────────────────────────────────────────────────

total=$((passed + failed + skipped))
echo ""
echo "── Summary: ${passed}/${total} passed, ${failed} failed, ${skipped} skipped ──"

if [[ $failed -gt 0 ]]; then
  exit 1
fi
exit 0
