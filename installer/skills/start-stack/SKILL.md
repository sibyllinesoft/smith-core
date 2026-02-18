---
description: Start the Smith Core infrastructure stack with Docker Compose
---
# Start Stack

Run:

```bash
bash infra/envoy/certs/generate-certs.sh
docker compose up -d
docker compose ps
```

## What It Does

This skill launches the local infrastructure dependencies.

1. Ensures local Envoy mTLS certs exist before container startup.
2. Starts NATS, Postgres, Redis, ClickHouse, Grafana, OPA, Envoy, and MCP services.
3. Ensures background containers are running.
4. Gives a service-level health snapshot via `docker compose ps`.
5. Establishes prerequisites for bridge and service processes.

## Prerequisites

- Docker and Compose available.
- Ports required by the stack are free.

## Expected Output

- Cert generation exits successfully (or reports existing certs).
- `docker compose up -d` exits successfully.
- `docker compose ps` shows core services as `running` or `healthy`.

## Reading Results

Focus on these critical services:

- `smith-nats`
- `smith-postgres`
- `smith-envoy`
- `smith-mcp-index`

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Container exits immediately | Bad env/config | Inspect `docker compose logs <service>` |
| Envoy fails with cert path errors | Certs not generated/mounted | Run `bash infra/envoy/certs/generate-certs.sh` and retry |
| Port bind error | Port already in use | Free the port or remap in compose |
| Image pull/build failure | Network or registry failure | Retry after network recovery |
| Healthcheck stuck | Dependency not ready | Check dependent service logs |

## Notes

Use `docker compose down` to stop the stack.
