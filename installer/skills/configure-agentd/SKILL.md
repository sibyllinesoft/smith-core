---
description: Create XDG directories, config file, and daemon unit for agentd
---
# Step 50: Configure Agentd

Run: `bash scripts/bootstrap/steps/50-configure-agentd.sh`

## What It Does

Sets up agentd's configuration and daemon management.

1. Creates XDG directories for agentd:
   - `~/.config/agentd/` — config
   - `~/.local/share/agentd/{work,state,audit}` — data
   - `~/.local/state/agentd/logs/` — logs
2. Generates `agentd.toml` from template (`scripts/bootstrap/templates/agentd.toml`)
   - Substitutes paths, UID/GID, sandbox settings
   - Injects ActivityWatch endpoint if step 35 wrote a marker
3. Installs a daemon unit:
   - **Linux + systemd**: installs `~/.config/systemd/user/agentd.service`, enables it
   - **macOS**: installs `~/Library/LaunchAgents/com.smith.agentd.plist`
   - **Fallback**: prints nohup command for manual start

## Prerequisites

- Step 00 (system profile)
- Step 40 (agentd binary installed)
- Templates must exist: `scripts/bootstrap/templates/agentd.toml` and daemon unit template

## Environment Variables

| Variable | Effect |
|----------|--------|
| `SMITH_FORCE` | `1` to regenerate config even if it exists |

## Sandbox Configuration

The config is auto-tuned based on system profile:

| Setting | Landlock-capable | No Landlock |
|---------|-----------------|-------------|
| `landlock_enabled` | `true` | `false` |
| `strict_sandbox` | `false` (dev default) | `false` |
| `network_isolation` | `false` (dev default) | `false` |

If ActivityWatch was enabled (step 35), `allowed_destinations` includes `["http://localhost:5600"]`.

## Expected Output

```
[INFO] Creating agentd directories...
[INFO] Generating config: ~/.config/agentd/agentd.toml
[ OK ] Config written to ~/.config/agentd/agentd.toml
[INFO] Installing systemd --user unit...
[ OK ] Systemd unit installed and enabled: ~/.config/systemd/user/agentd.service
```

## Reading Results

Check the generated config:
```bash
cat ~/.config/agentd/agentd.toml
```

Check the daemon unit:
```bash
# Linux
systemctl --user status agentd

# macOS
launchctl list com.smith.agentd
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Config template not found" | Missing template file | Ensure repo is fully cloned, check `scripts/bootstrap/templates/` |
| "Unit template not found" | Missing service/plist template | Same as above |
| systemctl daemon-reload fails | systemd --user not running | Enable lingering: `loginctl enable-linger $USER` |
| Config exists, not overwritten | Idempotency — existing config preserved | Use `SMITH_FORCE=1` to regenerate |

## Platform Gotchas

- **macOS**: No systemd — uses launchd plist instead
- **WSL without systemd**: Falls back to nohup documentation (manual start)
- **NixOS**: systemd --user works but paths may differ; verify XDG env vars
