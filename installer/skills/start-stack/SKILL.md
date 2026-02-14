---
description: Start the observability docker-compose stack
---
# Step 30: Start Stack

Run: `bash scripts/bootstrap/steps/30-start-stack.sh`

## What It Does

Starts the observability stack (NATS, Grafana, ClickHouse, Envoy gateway) via docker compose.

1. Copies `.env.example` to `.env` if `.env` doesn't exist
2. Creates the `smith-platform` Docker network if missing
3. Runs `compose up -d --build` in `observability/deploy/`
4. Polls the gateway health endpoint with mTLS (max 120 seconds)
5. Runs `make health` for additional service checks

## Prerequisites

- Step 00 (system profile with compose command)
- Step 10 (container runtime installed)
- Step 20 (certificates generated for mTLS health check)

## Environment Variables

| Variable | Effect |
|----------|--------|
| `SMITH_GATEWAY_PORT` | Override gateway port (default: 6173) |

## Expected Output

```
[INFO] Starting observability stack...
[INFO] Waiting for gateway to become healthy (max 120s)...
[INFO]   ...waiting (5/120s)
[INFO]   ...waiting (10/120s)
[ OK ] Gateway healthy at https://localhost:6173/health
[INFO] Running health checks...
[ OK ] All health checks passed
```

## Reading Results

The gateway is ready when the health poll succeeds. If it times out (120s), the stack may still be starting — check compose logs.

Key endpoints after stack is up:
- Gateway (mTLS): `https://localhost:6173/`
- Envoy admin: `http://localhost:9901/ready`
- OTLP gRPC: `localhost:7317`
- OTLP HTTP: `http://localhost:7318`

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "No compose command available" | No runtime installed | Run step 10 first |
| Gateway timeout (120s) | Slow build or port conflict | Check `cd observability/deploy && docker compose logs` |
| Network create fails | Permission issue or existing network | Check `docker network ls` / `podman network ls` |
| Port 6173 in use | Another service on that port | Set `SMITH_GATEWAY_PORT=6174` or stop the conflicting service |
| `.env` missing secrets | Default `.env.example` used | Edit `observability/deploy/.env` with real credentials if needed |
| Health check returns TLS error | Cert mismatch or wrong CA | Re-run step 20 with `SMITH_FORCE=1` |

## Platform Gotchas

- **Podman**: Compose invoked as `podman compose` (not `podman-compose`)
- **macOS**: Docker Desktop must be running; podman needs `podman machine start`
- **Fedora/SELinux**: Volume mounts may need `:Z` suffix — check compose logs for permission errors
- **WSL**: Ensure Docker Desktop WSL integration is enabled, or use podman from distro repos
- **First run**: Building images can take several minutes; subsequent runs are fast
