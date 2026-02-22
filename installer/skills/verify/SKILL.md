---
description: Verify the full Smith Core bootstrap state after install steps
---
# Verify

Run:

```bash
npm run build --workspaces --if-present
docker compose ps
```

Then check pre-built binaries (optional, may not be installed):

```bash
smith-chat-daemon --help || echo "smith-services not installed (non-fatal)"
agentd --version || echo "agentd not installed (non-fatal)"
```

## What It Does

This skill validates that core components are installed and infrastructure is running.

1. Builds Node workspaces.
2. Confirms Docker services are active and healthy.
3. Optionally verifies smith-services binaries are installed (non-fatal if missing).
4. Optionally verifies agentd is installed (non-fatal if missing).

## Prerequisites

- Dependencies installed.
- Docker stack started.

## Expected Output

- All build commands exit with status 0.
- `docker compose ps` shows core services as `running` or `healthy`.

## Reading Results

Installation is considered healthy when:

- Node workspace build passes.
- Core services (`nats`, `postgres`, `envoy`, `mcp-index`) are running.

smith-services and agentd are supplementary components — their absence does not block the core stack.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| npm build failures | TS/dependency issue | Resolve workspace build errors |
| Containers not running | Compose/startup failure | Inspect compose logs and restart |
| Intermittent health failures | Service startup race | Wait and re-run verification |
| smith-chat-daemon --help fails | Platform binary not available | Non-fatal; build from source with cargo if needed |
| agentd --version fails | Platform binary not available | Non-fatal; build from source if needed |

## Notes

This is the final gate for local release-readiness confidence.

## Wrapup Output

After verification passes, display the following information to the user:

### MCP Index Access

```bash
# View the MCP Index API token
grep MCP_INDEX_API_TOKEN .env

# MCP Index endpoint
# http://localhost:9200

# Test MCP Index connectivity
curl -H "Authorization: Bearer $(grep MCP_INDEX_API_TOKEN .env | cut -d= -f2)" http://localhost:9200/tools
```

### Future Validation

To re-validate the installation at any time:

```bash
bash scripts/smith-check.sh
```
