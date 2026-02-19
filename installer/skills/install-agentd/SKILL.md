---
description: Install the agentd binary from npm
---
# Install Agentd

Run:

```bash
npm install -g @sibyllinesoft/agentd
```

## What It Does

This skill installs the pre-built `agentd` binary via npm.

1. Downloads the platform-appropriate binary from the `@sibyllinesoft/agentd` npm package.
2. Makes the `agentd` command available globally.
3. Validates installation by checking the binary is on PATH.

## Prerequisites

- Node.js >= 20 and npm installed.

## Expected Output

`agentd --version` prints a version string.

## Reading Results

- Install errors indicate npm/network issues.
- Successful install enables `agentd run ...`.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Permission denied | Global npm requires sudo or prefix config | Use `npm config set prefix ~/.npm-global` or run with sudo |
| Network failure | Registry unreachable | Retry when network is available |
| Platform not supported | No binary for this OS/arch | Build from source (see agentd repo) |

## Notes

Pre-built binaries are available for Linux x64 and macOS arm64. For other platforms, build from the agentd source repository.
