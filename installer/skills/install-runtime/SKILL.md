---
description: Validate container runtime availability for Smith Core services
---
# Install Runtime

Run:

```bash
docker --version
docker compose version
```

## What It Does

This skill validates runtime prerequisites for the infrastructure stack.

1. Confirms Docker engine availability.
2. Confirms Compose plugin availability.
3. Blocks bootstrap early if runtime prerequisites are missing.
4. Keeps installer behavior deterministic.

## Prerequisites

- Docker installed on host.
- Active user has permission to run Docker commands.

## Expected Output

Both commands return version information without errors.

## Reading Results

- If both commands succeed, proceed to stack startup.
- If either command fails, runtime must be installed/configured first.
- On macOS, also ensure `gondolin` is installed before enabling persistent VM sessions.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `docker: command not found` | Docker not installed | Install Docker |
| `permission denied` on daemon socket | User not authorized | Add user to Docker group or use sudo |
| `docker compose` missing | Compose plugin not installed | Install Docker Compose plugin |
| Daemon not running | Docker service stopped | Start Docker daemon |
| `gondolin` missing on macOS | Gondolin not installed | Install Gondolin and confirm `gondolin help` succeeds |

## Notes

Installer does not perform OS-level package installation in this repo version.
