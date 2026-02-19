---
description: Verify the full Smith Core bootstrap state after install steps
---
# Verify

Run:

```bash
cargo check --workspace
npm run build --workspaces --if-present
agentd --version
docker compose ps
```

## What It Does

This skill validates that core components are buildable and infrastructure is running.

1. Checks Rust root workspace.
2. Verifies agentd is installed.
3. Builds Node workspaces.
4. Confirms Docker services are active.

## Prerequisites

- Dependencies installed.
- Docker stack started.

## Expected Output

- All check/build commands exit with status 0.
- `docker compose ps` shows core services up.

## Reading Results

Installation is considered healthy when:

- Rust checks pass.
- Node workspace build passes.
- Core services (`nats`, `postgres`, `envoy`, `mcp-index`) are running.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Rust check failures | Code/toolchain mismatch | Fix compile issues and rerun |
| npm build failures | TS/dependency issue | Resolve workspace build errors |
| Containers not running | Compose/startup failure | Inspect compose logs and restart |
| Intermittent health failures | Service startup race | Wait and re-run verification |

## Notes

This is the final gate for local release-readiness confidence.
