---
description: Detect local system capabilities required for Smith Core installation
---
# Detect System

Run:

```bash
uname -a
node -v
docker --version
docker compose version
cargo --version

if [ "$(uname -s)" = "Darwin" ]; then
  command -v gondolin
  gondolin help >/dev/null
fi
```

## What It Does

This skill gathers the minimum environment facts needed before bootstrap.

1. Confirms host OS/kernel information.
2. Confirms Node.js runtime availability.
3. Confirms Docker engine and Compose plugin availability.
4. Confirms Rust toolchain availability.
5. On macOS, confirms Gondolin is installed for persistent VM sandbox mode.
6. Establishes whether the machine can run the standard Smith Core flow.

## Prerequisites

- Shell access in the `smith-core` repository.
- `bash` available.

## Expected Output

Successful environment output includes:

```text
Linux ...
v22.x.x
Docker version ...
Docker Compose version ...
cargo 1.xx.x ...
/usr/bin/gondolin   # macOS only
```

## Reading Results

- Missing `node` means installer and Node workspaces cannot run.
- Missing `docker compose` means infrastructure cannot start.
- Missing `cargo` means Rust services cannot build from source.
- On macOS, missing `gondolin` means persistent VM sandbox sessions cannot start.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `node: command not found` | Node.js missing | Install Node 22+ |
| `docker: command not found` | Docker missing | Install Docker engine |
| `docker compose` unknown command | Compose plugin missing | Install Docker Compose plugin |
| `cargo: command not found` | Rust toolchain missing | Install Rust via rustup |
| `gondolin: command not found` (macOS) | Gondolin missing | Install Gondolin and verify `gondolin help` works |

## Notes

This skill is diagnostic only. It does not install packages automatically.
