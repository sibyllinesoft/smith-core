---
description: Optional ActivityWatch time tracking setup (opt-in)
---
# Step 35: Setup ActivityWatch

Run: `SMITH_ACTIVITYWATCH=1 bash scripts/bootstrap/steps/35-setup-activitywatch.sh`

## What It Does

This step is **opt-in** — it only runs when `SMITH_ACTIVITYWATCH=1` is set. Without this variable, the step exits immediately with a skip message.

When enabled:
1. Starts `aw-server-rust` via `compose --profile activitywatch`
2. Polls the health endpoint at `http://localhost:5600/api/0/info` (max 30s)
3. Writes a marker file at `var/bootstrap/.activitywatch-enabled` containing the AW URL
4. If agentd is already configured (`agentd.toml` exists), patches `allowed_destinations` to include the AW endpoint and restarts agentd
5. If agentd is not yet configured, step 50 reads the marker and injects AW settings automatically
6. Prints integration guidance: agentd sandbox config, MCP options, per-platform desktop watcher install

## Prerequisites

- Step 00 (system profile with compose command)
- Step 30 (compose stack running — ActivityWatch is added as a profile)
- Container runtime with compose support

## Environment Variables

| Variable | Effect |
|----------|--------|
| `SMITH_ACTIVITYWATCH` | Must be `1` to enable this step |
| `AW_SERVER_PORT` | Override ActivityWatch port (default: 5600) |

## Agent Decision Point

Before running this step, **ask the user**:

> "Would you like to enable ActivityWatch for time tracking? It tracks window focus and idle time for personal productivity insights. This is optional and can be enabled later."

If yes, set `SMITH_ACTIVITYWATCH=1` in the environment before running.

## Expected Output

When disabled:
```
[INFO] ActivityWatch disabled (set SMITH_ACTIVITYWATCH=1 to enable)
```

When enabled:
```
[INFO] Starting aw-server-rust via compose (activitywatch profile)...
[INFO] Waiting for ActivityWatch to become healthy (max 30s)...
[ OK ] ActivityWatch healthy at http://localhost:5600
[INFO] Wrote ActivityWatch marker for agentd configuration
[INFO] === Agentd <-> ActivityWatch Integration ===
[INFO] === MCP Integration (Optional) ===
[INFO] === Desktop Watcher Installation ===
```

## Reading Results

Check the marker file:
```bash
cat var/bootstrap/.activitywatch-enabled
# Should contain: http://localhost:5600
```

Verify the server is running:
```bash
curl -s http://localhost:5600/api/0/info | jq .
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "No compose command available" | Runtime not installed | Run step 10 first |
| Health timeout (30s) | AW container slow to start | Check compose logs: `docker compose --profile activitywatch logs activitywatch` |
| Patch fails on agentd.toml | Unexpected config format | Manually add `"http://localhost:5600"` to `allowed_destinations` |

## Desktop Watcher Installation

The server only collects data — desktop watchers report window focus and idle time:

| Platform | Install |
|----------|---------|
| Arch | `yay -S activitywatch-bin` (AUR) |
| Ubuntu/Debian | AppImage or .deb from GitHub releases |
| Fedora | Download from GitHub releases |
| macOS | `brew install --cask activitywatch` |
| NixOS | Add `activitywatch` to packages |

## Platform Gotchas

- **Network isolation**: If agentd's `network_isolation` is later enabled, it needs host network access to reach AW on localhost:5600
- **Port conflict**: If something else uses port 5600, set `AW_SERVER_PORT` to an alternative
