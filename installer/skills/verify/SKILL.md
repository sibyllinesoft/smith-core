---
description: Run health checks and print system status summary
---
# Step 90: Verify

Run: `bash scripts/bootstrap/steps/90-verify.sh`

## What It Does

Comprehensive health check that validates the entire Smith platform setup.

Checks:
1. **Certificates**: ca.crt, server.crt, client.crt exist
2. **Observability Stack** (via mTLS):
   - Gateway health endpoint
   - Grafana API health
   - NATS healthz
   - Envoy admin ready
   - `make health` aggregate check
3. **Agent Daemon**:
   - agentd binary on PATH
   - Metrics endpoint responding
   - systemd unit active (Linux only)

Prints a summary with pass/fail counts and all endpoint URLs.

## Prerequisites

- Step 00 (system profile)
- All other steps should have completed for a full pass

## Environment Variables

None specific. Uses profile values for compose command and gateway port.

## Expected Output

```
  Smith Platform Status
  =====================

  Certificates:
    CA cert                        OK
    Server cert                    OK
    Client cert                    OK

  Observability Stack:
    Gateway                        OK
    Grafana                        OK
    NATS                           OK
    Envoy admin                    OK
    Make health                    OK

  Agent Daemon:
    agentd binary                  OK
    Metrics endpoint               OK
    systemd unit                   OK

  ---------------------------------
  10/10 checks passed

  Endpoints:
    Gateway (mTLS):  https://localhost:6173/
    OTLP gRPC:       localhost:7317
    OTLP HTTP:       http://localhost:7318
    Envoy admin:     http://localhost:9901
    Agentd metrics:  http://localhost:9090/metrics
```

## Exit Code

Returns the number of failed checks. Exit code 0 means all checks passed.

## Reading Results

The output is self-explanatory — look for FAIL entries and investigate those specific components.

## Common Failures

| Check | Likely Cause | Fix |
|-------|-------------|-----|
| CA cert FAIL | Step 20 not run | Run step 20 |
| Gateway FAIL | Stack not running or certs wrong | Check `docker compose logs` in `observability/deploy/` |
| Grafana FAIL | Grafana container not ready | Wait and re-check, or check Grafana logs |
| NATS FAIL | NATS container not running | Check compose logs for NATS errors |
| agentd binary FAIL | Not installed or not in PATH | Run step 40 |
| Metrics FAIL | agentd not running | Run step 60 |
| systemd unit FAIL | Unit not installed or failed | Check `systemctl --user status agentd` |

## Platform Gotchas

- **macOS**: systemd unit check is skipped (no systemd)
- **No compose**: Observability stack checks are skipped with a SKIP label
