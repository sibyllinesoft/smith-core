---
description: Start agentd with committed baseline config and verify process health
---
# Start Agentd

Run:

```bash
agentd run \
  --config ${AGENTD_CONFIG:-agentd.toml} \
  --capability-digest ${AGENTD_CAPABILITY_DIGEST:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}
```

## What It Does

This skill launches `agentd` using the globally installed binary.

1. Runs agentd with the specified config file.
2. Supplies required `--capability-digest` argument.

## Prerequisites

- `agentd` installed (`npm install -g @sibyllinesoft/agentd`).
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
| `agentd: command not found` | Not installed | Run `npm install -g @sibyllinesoft/agentd` |
| `Failed to load config` | Wrong/missing config path | Set `AGENTD_CONFIG` to a valid agentd TOML |
| `Refusing all-zero capability digest` | Placeholder digest left at zero | Set real `AGENTD_CAPABILITY_DIGEST`, or opt in with `SMITH_ALLOW_ZERO_CAPABILITY_DIGEST=1` for local-only testing |
| `--capability-digest` required | Missing mandatory flag | Provide 64-char hex digest (env or inline) |
| Port already in use | Conflicting process | Stop conflicting process or change `AGENTD_GRPC_LISTEN` |
| Cannot connect to NATS/DB | Stack not running or wrong URL | Start stack and fix endpoint vars |
| TLS-related errors | Missing cert files for strict modes | Generate certs and verify mounts/env |

## Notes

Use a separate terminal session so logs remain visible during installer verification.
For development-only fallback behavior, run the same command with `SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK=1 SMITH_ALLOW_ZERO_CAPABILITY_DIGEST=1`.

### macOS / non-Linux platforms

agentd auto-detects the platform at startup. On macOS (and other non-Linux hosts):
- `--isolation auto` (the default) resolves to `gondolin`
- Gondolin provides VM-level isolation; Linux kernel features (landlock, seccomp) are skipped
- No extra flags are needed

To override, pass `--isolation <backend>` explicitly (e.g. `--isolation host-direct` to skip Gondolin).
