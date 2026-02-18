---
description: Choose deployment profile for Smith Core installation
---
# Choose Deployment

Run:

```bash
export SMITH_DEPLOYMENT_MODE=local
```

## What It Does

This skill sets deployment intent for the installer session.

1. Selects local-first deployment for open-source Smith Core.
2. Keeps infrastructure on local Docker networking.
3. Avoids assumptions about external managed tunnel services.
4. Ensures follow-up commands target local endpoints.

## Prerequisites

- User decision on local vs externally exposed deployment.

## Expected Output

Environment reflects local mode:

```text
SMITH_DEPLOYMENT_MODE=local
```

## Reading Results

- `local` means services run via `docker compose` on this machine.
- Any external ingress should be configured separately after bootstrap.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Variable not visible in later commands | Exported in another shell | Export in the active shell/session |
| Confusion about cloud mode | Legacy docs mention tunnels | Use local mode for core OSS bootstrap |
| External access needed | Out-of-scope for default installer | Configure reverse proxy separately |

## Notes

Current installer implementation validates and bootstraps local development flows.
