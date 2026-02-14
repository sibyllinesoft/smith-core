# agentd

Agent daemon for secure capability execution with pluggable isolation backends.

## Overview

`agentd` is a security-focused execution engine that runs capabilities in isolated sandboxes. It implements defense-in-depth security through:

- **Landlock LSM** - Filesystem access control (Linux 5.13+)
- **seccomp-bpf** - System call filtering
- **cgroups v2** - Resource limits (CPU, memory)
- **Process namespaces** - Isolation

## Building

```bash
cargo build --release
```

## Running

```bash
# Start the daemon
./target/release/agentd

# With NATS connection
AGENTD_NATS_URL=nats://localhost:4222 ./target/release/agentd
```

## Configuration

Configuration is loaded from environment variables and TOML files:

- `AGENTD_NATS_URL` - NATS server URL
- `AGENTD_WORK_ROOT` - Sandbox working directory
- `AGENTD_LOG_LEVEL` - Log verbosity (trace, debug, info, warn, error)

## Capabilities

Current supported capabilities:

- `shell.exec.v1` - Execute shell commands with output capture

## Security Modes

| Mode | Isolation | Use Case |
|------|-----------|----------|
| Full Sandbox | All layers | Production (Linux 5.13+) |
| Partial Sandbox | seccomp + cgroups | Legacy Linux |
| Demo Mode | Policy only | Development |

## Project Structure

```
agentd/
├── src/              # Main daemon source
├── crates/           # Vendored dependencies
│   ├── smith-protocol/   # Message protocols
│   ├── smith-bus/        # NATS helpers
│   ├── smith-config/     # Configuration
│   ├── smith-attestation/# Cryptographic signing
│   ├── smith-logging/    # Structured logging
│   └── smith-jailer/     # Sandbox implementation
├── policy/           # Security policies
├── tests/            # Integration tests
└── examples/         # Usage examples
```

## License

MIT
