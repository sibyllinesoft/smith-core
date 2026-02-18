---
description: Start agentd with committed baseline config and verify process health
---
# Start Agentd

Run:

```bash
cargo run --manifest-path agent/agentd/Cargo.toml --features grpc --bin agentd -- run \
  --config ${AGENTD_CONFIG:-agent/agentd/config/agentd.toml} \
  --capability-digest ${AGENTD_CAPABILITY_DIGEST:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}
```

## What It Does

This skill launches `agentd` directly from source using the valid CLI shape.

1. Runs the explicit `agentd` bin target (multi-bin workspace-safe).
2. Enables gRPC feature for Envoy JSON transcoding compatibility.
3. Uses committed `agentd` config instead of insecure fallback parsing.
4. Supplies required `--capability-digest` argument.

## Prerequisites

- `agentd` build completed successfully.
- Required infrastructure services available if runtime depends on them.

## Expected Output

- Process starts without immediate panic.
- Startup logs indicate daemon initialization and gRPC listener startup.

## Reading Results

- Keep process attached while testing bridge/gateway flows.
- If process exits, inspect final error lines for missing config or dependency issues.
- On macOS, ensure `.env` includes `SMITH_EXECUTOR_VM_POOL_ENABLED=true` and
  `SMITH_EXECUTOR_VM_METHOD=gondolin` to use the Gondolin sandbox path.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `could not determine which binary to run` | Missing `--bin agentd` | Use full command shown above |
| `Failed to load config` | Wrong/missing config path | Set `AGENTD_CONFIG` to a valid agentd TOML |
| `Refusing all-zero capability digest` | Placeholder digest left at zero | Set real `AGENTD_CAPABILITY_DIGEST`, or opt in with `SMITH_ALLOW_ZERO_CAPABILITY_DIGEST=1` for local-only testing |
| `--capability-digest` required | Missing mandatory flag | Provide 64-char hex digest (env or inline) |
| Port already in use | Conflicting process | Stop conflicting process or change `AGENTD_GRPC_LISTEN` |
| Cannot connect to NATS/DB | Stack not running or wrong URL | Start stack and fix endpoint vars |
| TLS-related errors | Missing cert files for strict modes | Generate certs and verify mounts/env |

## Notes

Use a separate terminal session so logs remain visible during installer verification.  
For development-only fallback behavior, run the same command with `SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK=1 SMITH_ALLOW_ZERO_CAPABILITY_DIGEST=1`.
