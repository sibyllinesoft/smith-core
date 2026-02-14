---
description: Start the agentd daemon and poll metrics endpoint
---
# Step 60: Start Agentd

Run: `bash scripts/bootstrap/steps/60-start-agentd.sh`

## What It Does

Starts the agentd daemon and verifies it's responding.

1. Checks that `agentd.toml` exists (fails if step 50 wasn't run)
2. Starts agentd using the platform-appropriate method:
   - **Linux + systemd**: `systemctl --user start agentd`
   - **macOS**: `launchctl load` + `launchctl start com.smith.agentd`
   - **Fallback**: `nohup agentd run --config ...` with PID file
3. Polls `http://localhost:9090/metrics` for up to 20 seconds

## Prerequisites

- Step 50 (agentd config and daemon unit installed)
- Step 40 (agentd binary on PATH)

## Environment Variables

None specific to this step. Metrics port (9090) is configured in step 50.

## Expected Output

```
[INFO] Starting agentd via systemctl --user...
[ OK ] agentd started (systemd --user)
[INFO] Waiting for agentd metrics at http://localhost:9090/metrics (max 20s)...
[ OK ] agentd metrics endpoint responding
```

## Reading Results

Verify agentd is running:
```bash
# systemd
systemctl --user status agentd

# Check metrics
curl -s http://localhost:9090/metrics | head -5

# Check logs
journalctl --user -u agentd -f
# or
cat ~/.local/state/agentd/logs/agentd.log
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "agentd config not found" | Step 50 not run | Run step 50 first |
| systemctl start fails | Unit not installed or broken | Check `systemctl --user status agentd`, re-run step 50 |
| Metrics timeout (20s) | agentd slow to start or crashed | Check logs: `journalctl --user -u agentd` |
| "Plist not found" (macOS) | Step 50 not run | Run step 50 first |
| PID file stale | Previous nohup agentd died | Remove PID file and re-run |
| Port 9090 in use | Another service on metrics port | Edit agentd.toml to change metrics port |

## Platform Gotchas

- **nohup fallback**: On systems without systemd/launchd, agentd runs as a background process with a PID file at `~/.local/state/agentd/agentd.pid`
- **Metrics may be disabled**: The 20s timeout warning is non-fatal — agentd may be running fine without metrics enabled
