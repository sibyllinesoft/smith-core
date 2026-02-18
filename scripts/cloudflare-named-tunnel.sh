#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/cloudflare-named-tunnel.sh <tunnel-name> <hostname>

Creates (or reuses) a Cloudflare named tunnel, routes DNS for the hostname,
retrieves a run token, and stores tunnel settings in .env.

Required:
  - cloudflared installed locally
  - `cloudflared tunnel login` completed for your account
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

upsert_env() {
  local key="$1"
  local value="$2"
  local file="$3"
  local tmp_file="${file}.tmp.$$"

  if [ ! -f "$file" ]; then
    printf '%s=%s\n' "$key" "$value" >"$file"
    return 0
  fi

  awk -v k="$key" -v v="$value" '
    BEGIN { replaced = 0 }
    $0 ~ ("^" k "=") {
      if (!replaced) {
        print k "=" v
        replaced = 1
      }
      next
    }
    { print }
    END {
      if (!replaced) {
        print k "=" v
      }
    }
  ' "$file" >"$tmp_file"

  mv "$tmp_file" "$file"
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  local tunnel_name="${1:-}"
  local hostname="${2:-}"
  local env_file="${SMITH_ENV_FILE:-.env}"
  local origin_cert="${CLOUDFLARED_ORIGIN_CERT:-$HOME/.cloudflared/cert.pem}"

  [ -n "$tunnel_name" ] || {
    usage
    fail "missing tunnel name"
  }
  [ -n "$hostname" ] || {
    usage
    fail "missing hostname"
  }

  require_cmd cloudflared

  if [ ! -f "$origin_cert" ]; then
    fail "Cloudflare origin cert not found at ${origin_cert}. Run: cloudflared tunnel login"
  fi

  echo "checking tunnel ${tunnel_name}..."
  if cloudflared tunnel info "$tunnel_name" >/dev/null 2>&1; then
    echo "tunnel already exists; reusing ${tunnel_name}"
  else
    echo "creating named tunnel ${tunnel_name}..."
    cloudflared tunnel create "$tunnel_name"
  fi

  echo "routing DNS ${hostname} -> ${tunnel_name}..."
  cloudflared tunnel route dns "$tunnel_name" "$hostname"

  echo "retrieving run token for ${tunnel_name}..."
  local token
  if ! token="$(cloudflared tunnel token "$tunnel_name" 2>/dev/null)"; then
    fail "failed to fetch tunnel token. Retrieve it in Cloudflare dashboard and set CLOUDFLARE_TUNNEL_TOKEN manually."
  fi
  token="$(printf '%s' "$token" | tr -d '\r\n')"
  [ -n "$token" ] || fail "cloudflared returned an empty tunnel token"

  upsert_env "CLOUDFLARE_TUNNEL_TOKEN" "$token" "$env_file"
  upsert_env "CLOUDFLARE_TUNNEL_HOSTNAME" "$hostname" "$env_file"
  upsert_env "CLOUDFLARE_TUNNEL_E2E_URL" "https://${hostname}/health" "$env_file"

  echo
  echo "updated ${env_file}:"
  echo "  CLOUDFLARE_TUNNEL_TOKEN=<redacted>"
  echo "  CLOUDFLARE_TUNNEL_HOSTNAME=${hostname}"
  echo "  CLOUDFLARE_TUNNEL_E2E_URL=https://${hostname}/health"
  echo
  echo "next:"
  echo "  1) Ensure your tunnel's public hostname forwards to http://mcp-index:9200"
  echo "  2) Start tunnel connector: docker compose --profile tunnel-cloudflare up -d cloudflared"
  echo "  3) Run E2E check: bash scripts/tunnel-e2e.sh cloudflare"
}

main "$@"
