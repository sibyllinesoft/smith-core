---
description: Configure environment and path defaults used by agentd and bridge components
---
# Configure Agentd

Run:

```bash
cp -n .env.example .env || true

if [ "$(uname -s)" = "Darwin" ]; then
  command -v gondolin >/dev/null
  grep -q '^SMITH_EXECUTOR_VM_POOL_ENABLED=' .env || echo 'SMITH_EXECUTOR_VM_POOL_ENABLED=true' >> .env
  grep -q '^SMITH_EXECUTOR_VM_METHOD=' .env || echo 'SMITH_EXECUTOR_VM_METHOD=gondolin' >> .env
  grep -q '^SMITH_EXECUTOR_GONDOLIN_COMMAND=' .env || echo 'SMITH_EXECUTOR_GONDOLIN_COMMAND=gondolin' >> .env
  grep -q '^SMITH_EXECUTOR_GONDOLIN_ARGS=' .env || echo 'SMITH_EXECUTOR_GONDOLIN_ARGS=exec,--' >> .env
fi
```

## What It Does

This skill establishes baseline environment configuration for local runs.

1. Creates `.env` from `.env.example` when missing.
2. Ensures key URLs and credentials are available for local services.
3. Makes bridge and stack configuration explicit and reproducible.
4. Avoids hidden machine-specific defaults.
5. On macOS, enables Gondolin-backed persistent VM sessions by default.

## Prerequisites

- Repository root writable.
- `.env.example` present.

## Expected Output

- `.env` exists at repository root.
- Variables for NATS/Postgres/Grafana/stack endpoints are present.
- On macOS, Gondolin VM defaults are present:
  - `SMITH_EXECUTOR_VM_POOL_ENABLED=true`
  - `SMITH_EXECUTOR_VM_METHOD=gondolin`
  - `SMITH_EXECUTOR_GONDOLIN_COMMAND=gondolin`
  - `SMITH_EXECUTOR_GONDOLIN_ARGS=exec,--`

## Reading Results

Review and customize at minimum:

- `POSTGRES_PASSWORD`
- `GRAFANA_ADMIN_PASSWORD`
- `MCP_INDEX_API_TOKEN`
- `AGENTD_CONFIG`
- `SMITH_NATS_URL`
- `SMITH_DATABASE_URL`
- `AGENTD_URL`
- `SMITH_EXECUTOR_VM_POOL_ENABLED` (set to `true` on macOS)
- `SMITH_EXECUTOR_VM_METHOD` (set to `gondolin` on macOS)

If this system is not isolated to a private network, set up a private access path
(for example Cloudflare Tunnel or Tailscale) before exposing services.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `.env` not created | Permission/path issue | Create file manually and retry |
| Service auth failures | Password mismatch with compose | Align `.env` values and restart stack |
| Bridge cannot reach agentd | Bad `AGENTD_URL` | Set reachable URL and rerun |
| Unexpected defaults used | Variable unset | Populate `.env` explicitly |
| `gondolin` not found on macOS | Gondolin missing from PATH | Install Gondolin and retry |

## Notes

There is no generated `agentd.toml` workflow in the current installer path.
