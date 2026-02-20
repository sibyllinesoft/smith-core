---
description: Install the agentd binary from npm
---
# Install Agentd

Run:

```bash
npm install -g @sibyllinesoft/agentd
```

Then verify:

```bash
agentd --version
```

## What It Does

This skill installs the pre-built `agentd` binary via npm.

1. Downloads the platform-appropriate binary from the `@sibyllinesoft/agentd` npm package.
2. Makes the `agentd` command available globally.
3. Validates installation by checking the binary is on PATH.

## Prerequisites

- Node.js >= 20 and npm installed.

## Supported Platforms

| Platform | Architecture | Package |
|----------|-------------|---------|
| Linux | x64 | `@sibyllinesoft/agentd-linux-x64` |
| macOS | arm64 (Apple Silicon) | `@sibyllinesoft/agentd-darwin-arm64` |

Other platforms must build from source (see the agentd repository).

## Expected Output

`agentd --version` prints a version string.

## Reading Results

- Install errors indicate npm/network issues or a missing platform package.
- If the install succeeds but `agentd --version` fails with "Could not find the agentd binary", the platform-specific package is not published yet.
- Successful install enables `agentd run ...`.
- **agentd installation failure is non-fatal** — infrastructure and build steps are unaffected.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Could not find the agentd binary for darwin-arm64" | Platform package not published to npm | Build from source (see agentd repo) |
| Permission denied | Global npm requires sudo or prefix config | Use `npm config set prefix ~/.npm-global` or run with sudo |
| npm 404 for platform package | Platform binary not yet released | Build from source or wait for package publish |
| Network failure | Registry unreachable | Retry when network is available |

## Notes

- agentd installation is non-fatal during bootstrap. The rest of the stack works without it.
- If the platform package is missing, you can still build agentd from source using the agentd repository.
- Pre-built binaries are available for Linux x64 and macOS arm64.
