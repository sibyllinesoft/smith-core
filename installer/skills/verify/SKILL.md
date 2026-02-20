---
description: Verify the full Smith Core bootstrap state after install steps
---
# Verify

Run:

```bash
cargo check --workspace
npm run build --workspaces --if-present
docker compose ps
```

Then check agentd (optional, may not be installed):

```bash
agentd --version || echo "agentd not installed (non-fatal)"
```

## What It Does

This skill validates that core components are buildable and infrastructure is running.

1. Checks Rust root workspace.
2. Builds Node workspaces.
3. Confirms Docker services are active and healthy.
4. Optionally verifies agentd is installed (non-fatal if missing).

## Prerequisites

- Dependencies installed.
- Docker stack started.

## Expected Output

- All check/build commands exit with status 0.
- `docker compose ps` shows core services as `running` or `healthy`.

## Reading Results

Installation is considered healthy when:

- Rust checks pass.
- Node workspace build passes.
- Core services (`nats`, `postgres`, `envoy`, `mcp-index`) are running.

agentd is a supplementary component — its absence does not block the core stack.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Rust check failures | Code/toolchain mismatch | Fix compile issues and rerun |
| npm build failures | TS/dependency issue | Resolve workspace build errors |
| Containers not running | Compose/startup failure | Inspect compose logs and restart |
| Intermittent health failures | Service startup race | Wait and re-run verification |
| agentd --version fails | Platform binary not available | Non-fatal; build from source if needed |

## Notes

This is the final gate for local release-readiness confidence.
