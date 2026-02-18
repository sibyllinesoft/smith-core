#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/tunnel-e2e.sh <cloudflare|tailscale>

Runs a local-origin health check and a remote tunnel URL health check.

Environment:
  TUNNEL_LOCAL_HEALTH_URL      Local origin URL (default: http://127.0.0.1:9200/health)
  TUNNEL_E2E_ATTEMPTS          Retry attempts for remote URL (default: 20)
  TUNNEL_E2E_DELAY_SECONDS     Delay between retries (default: 3)
  CLOUDFLARE_TUNNEL_E2E_URL    Full Cloudflare URL for health endpoint
  CLOUDFLARE_TUNNEL_HOSTNAME   Fallback hostname (used as https://<hostname>/health)
  TAILSCALE_TUNNEL_E2E_URL     Full Tailscale URL for health endpoint
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

http_ok() {
  local url="$1"
  curl --silent --show-error --fail --max-time 10 "$url" >/dev/null
}

wait_for_url() {
  local label="$1"
  local url="$2"
  local attempts="${TUNNEL_E2E_ATTEMPTS:-20}"
  local delay="${TUNNEL_E2E_DELAY_SECONDS:-3}"

  local i
  for i in $(seq 1 "$attempts"); do
    if http_ok "$url"; then
      echo "ok: ${label} health check passed at ${url}"
      return 0
    fi
    sleep "$delay"
  done

  fail "${label} health check failed after ${attempts} attempts (${url})"
}

check_cloudflare() {
  local url="${CLOUDFLARE_TUNNEL_E2E_URL:-}"
  if [ -z "$url" ] && [ -n "${CLOUDFLARE_TUNNEL_HOSTNAME:-}" ]; then
    url="https://${CLOUDFLARE_TUNNEL_HOSTNAME}/health"
  fi
  [ -n "$url" ] || fail "set CLOUDFLARE_TUNNEL_E2E_URL or CLOUDFLARE_TUNNEL_HOSTNAME"

  if command -v docker >/dev/null 2>&1; then
    if ! docker compose ps --services --status=running 2>/dev/null | grep -qx "cloudflared"; then
      echo "warning: cloudflared connector is not currently running in compose profile tunnel-cloudflare"
    fi
  fi

  wait_for_url "cloudflare" "$url"
}

check_tailscale() {
  local url="${TAILSCALE_TUNNEL_E2E_URL:-}"
  [ -n "$url" ] || fail "set TAILSCALE_TUNNEL_E2E_URL"

  require_cmd tailscale
  if ! tailscale status >/dev/null 2>&1; then
    fail "tailscale status failed; authenticate this host first"
  fi

  wait_for_url "tailscale" "$url"
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  local provider="${1:-}"
  [ -n "$provider" ] || {
    usage
    fail "missing provider (cloudflare|tailscale)"
  }

  require_cmd curl

  local local_url="${TUNNEL_LOCAL_HEALTH_URL:-http://127.0.0.1:9200/health}"
  echo "checking local origin: ${local_url}"
  http_ok "$local_url" || fail "local origin is not healthy; start stack first (just up)"
  echo "ok: local origin healthy"

  case "$provider" in
    cloudflare)
      check_cloudflare
      ;;
    tailscale)
      check_tailscale
      ;;
    *)
      usage
      fail "unsupported provider: ${provider}"
      ;;
  esac
}

main "$@"
