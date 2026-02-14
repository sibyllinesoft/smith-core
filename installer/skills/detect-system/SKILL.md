---
description: Detect system capabilities (OS, arch, container runtime, kernel features)
---
# Step 00: Detect System

Run: `bash scripts/bootstrap/steps/00-detect-system.sh`

## What It Does

Probes the system and writes `var/bootstrap/system-profile.json` with:
- OS, architecture, distro, kernel version
- Landlock capability (Linux 5.13+)
- Container runtime (podman/docker) and compose command
- Package manager detection
- WSL detection
- systemd user session availability
- Tool availability (cargo, node, bun, jq)
- XDG paths, UID/GID, disk space

Also validates minimum requirements and exits non-zero if any are missing.

## Prerequisites

These must be installed before running:
- `curl`
- `openssl`
- `jq`
- At least one of `cargo` or `node` (for later agentd install)

## Reading Results

After running, read `var/bootstrap/system-profile.json` to understand the system.

Key fields to check:
- `landlock_capable`: `false` → warn about reduced sandbox isolation
- `container_runtime`: empty → step 10 will install one
- `is_wsl`: `true` → may need special systemd handling
- `disk_free_gb`: < 10 → warn about low disk space
- `has_cargo` / `has_node`: determines agentd install method (step 40)
- `has_bun`: preferred over npm for client build (step 25)
- `pkg_manager`: which package manager to use for installing missing tools

## Environment Variables

This step does not use any custom environment variables. It always regenerates the profile (system state can change between runs).

## Expected Output

On success:
```
[INFO] Detecting system profile...
[INFO] System: linux/amd64 (arch) kernel=6.x.x
[INFO] Runtime: podman | Pkg: pacman | Systemd: true
[INFO] Cargo: true | Node: true | Bun: false | Landlock: true
[ OK ] System profile written to var/bootstrap/system-profile.json
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "curl is required but not found" | curl not installed | Install: `pacman -S curl` / `apt install curl` / `brew install curl` |
| "openssl is required but not found" | openssl not installed | Install: `pacman -S openssl` / `apt install openssl` / `brew install openssl` |
| "jq is required but not found" | jq not installed | Install: `pacman -S jq` / `apt install jq` / `brew install jq` |
| "At least one of cargo or npm/node is required" | Neither Rust nor Node.js installed | Install Rust via `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` or Node via nvm |

## Platform Gotchas

- **macOS**: `disk_free_gb` uses GNU `df -BG` which may not be available; the script falls back to 0
- **NixOS**: Tools are available via devShell, ensure you're in `nix develop` first
- **WSL**: Landlock detection may show false results depending on the WSL kernel version
