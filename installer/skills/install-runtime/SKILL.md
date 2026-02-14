---
description: Install container runtime (podman preferred, docker fallback)
---
# Step 10: Install Container Runtime

Run: `bash scripts/bootstrap/steps/10-install-runtime.sh`

## What It Does

Installs a container runtime and compose tooling. Prefers podman (rootless), falls back to docker.

1. Checks if a runtime is already available and working
2. If not, installs the target runtime per distro
3. Verifies both the runtime and compose command work
4. On docker+Linux: warns about docker group membership

## Prerequisites

- Step 00 must have run (needs system profile)
- Internet access for package downloads
- `sudo` access for package installation

## Environment Variables

| Variable | Effect |
|----------|--------|
| `SMITH_CONTAINER_RUNTIME` | Force `podman` or `docker` (default: podman) |

## Expected Output

If runtime already exists:
```
[ OK ] Container runtime already available: podman
[ OK ] Compose available: podman compose
```

If installing:
```
[INFO] Installing container runtime: podman (distro: arch)
[INFO] Installing podman via pacman...
[ OK ] Container runtime: podman
[ OK ] Compose: podman compose
```

## Installation by Distro

| Distro | Podman | Docker |
|--------|--------|--------|
| Arch | `pacman -S podman` | `pacman -S docker docker-compose` |
| Ubuntu/Debian | `apt install podman` | Official Docker repo + `docker-ce` packages |
| Fedora | `dnf install podman` | `dnf install docker docker-compose-plugin` |
| macOS | `brew install podman` | `brew install --cask docker` |
| NixOS | System config: `virtualisation.podman.enable` | System config: `virtualisation.docker.enable` |

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Unsupported distro for podman install" | Unknown distro | Set `SMITH_CONTAINER_RUNTIME=docker` or install manually |
| "No container runtime available after install" | Install failed silently | Check package manager output, try manual install |
| "Compose not working" | Missing compose plugin | Install `docker-compose-plugin` or `podman-compose` |
| Docker permission denied | User not in docker group | Run `sudo usermod -aG docker $USER` then log out/in |

## Platform Gotchas

- **macOS Docker**: Requires Docker Desktop to be running after install
- **macOS Podman**: Needs `podman machine init && podman machine start` for VM setup
- **Ubuntu < 22.04**: podman may not be in repos; use Docker instead
- **NixOS**: Runtime install is a no-op; configure via system flake
- **Fedora + SELinux**: Compose volumes may need `:Z` label suffix
