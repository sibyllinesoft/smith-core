---
description: Choose deployment mode (local or cloud with Cloudflare tunnel)
---
# Step 05: Choose Deployment Mode

Run: `bash scripts/bootstrap/steps/05-choose-deployment.sh`

## What It Does

Selects whether the Smith platform runs in **local** or **cloud** deployment mode:

1. Reads `SMITH_DEPLOYMENT_MODE` from the environment (or prompts interactively)
2. For cloud mode: reads `SMITH_TUNNEL_TOKEN` (or prompts, or defaults to quick tunnel)
3. Writes `var/bootstrap/.deployment-mode` marker (`local` or `cloud`)
4. Writes `var/bootstrap/.tunnel-token` marker (cloud mode with token only, chmod 600)

Downstream steps read these markers:
- **Step 30** (`30-start-stack.sh`): passes `--profile pi-runner` (always) and `--profile cloud` (cloud mode), injects tunnel token into `.env`
- **Step 90** (`90-verify.sh`): checks pi-runner network isolation, gateway access, and cloudflared status

## Prerequisites

- None — this is the first bootstrap step (runs before system detection)

## Environment Variables

| Variable | Effect |
|----------|--------|
| `SMITH_DEPLOYMENT_MODE` | `local` (default) or `cloud` |
| `SMITH_TUNNEL_TOKEN` | Cloudflare tunnel token (cloud mode). Empty = quick tunnel |

## Agent Decision Point

Before running this step, **ask the user**:

> "How would you like to deploy Smith?"
>
> 1. **Local** (default) — the pi-runner container connects to the Envoy gateway on the internal Docker network. Access from this machine only.
> 2. **Cloud** — adds a Cloudflare tunnel so the gateway is reachable from the internet. Requires a free Cloudflare account.

If the user chooses cloud, ask:

> "Do you have a Cloudflare named tunnel token? If not, I'll use a quick tunnel (temporary URL that changes on restart)."

Set environment variables accordingly:
- Local: `SMITH_DEPLOYMENT_MODE=local`
- Cloud without token: `SMITH_DEPLOYMENT_MODE=cloud`
- Cloud with token: `SMITH_DEPLOYMENT_MODE=cloud SMITH_TUNNEL_TOKEN=<token>`

## Expected Output

Local mode:
```
[ OK ] Deployment mode: local
[INFO] Wrote deployment mode marker: var/bootstrap/.deployment-mode
```

Cloud mode with token:
```
[ OK ] Deployment mode: cloud
[ OK ] Tunnel token provided — cloudflared will use named tunnel
[INFO] Wrote deployment mode marker: var/bootstrap/.deployment-mode
[INFO] Wrote tunnel token marker: var/bootstrap/.tunnel-token
```

Cloud mode without token:
```
[ OK ] Deployment mode: cloud
[WARN] No tunnel token — cloudflared will start a quick tunnel
[WARN] Quick tunnels are ephemeral and change URL on restart
[INFO] Wrote deployment mode marker: var/bootstrap/.deployment-mode
```

## Reading Results

Check the marker:
```bash
cat var/bootstrap/.deployment-mode
# "local" or "cloud"
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Invalid SMITH_DEPLOYMENT_MODE" | Typo in env var | Use `local` or `cloud` exactly |
| No interactive prompt | Not running in a TTY | Set `SMITH_DEPLOYMENT_MODE` explicitly |
| Quick tunnel URL changes | No named tunnel configured | Create a Cloudflare tunnel and set `SMITH_TUNNEL_TOKEN` |

## Platform Gotchas

- **Quick tunnels** are free but ephemeral — the URL changes every time cloudflared restarts. For a stable URL, create a named tunnel in the Cloudflare dashboard.
- **Named tunnels** require a Cloudflare account and the `cloudflared` CLI to generate a token: `cloudflared tunnel create <name>` then `cloudflared tunnel token <name>`.
- The pi-runner container is always started (both modes) on the `pi-runner-isolated` network, which is `internal: true` — it cannot reach the internet or the host, only Envoy.
