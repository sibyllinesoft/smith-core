---
description: Build and validate the agentd workspace from source
---
# Install Agentd

Run:

```bash
cargo build --manifest-path agent/agentd/Cargo.toml --features grpc --bin agentd
```

## What It Does

This skill prepares the `agentd` binary from source.

1. Compiles `agent/agentd` and internal crates.
2. Ensures gRPC support is included (`--features grpc`).
3. Produces a runnable `agentd` binary for Envoy transcoding flows.
4. Validates crate path wiring in the extracted repo.

## Prerequisites

- Rust toolchain installed.
- Cargo dependency resolution functional.

## Expected Output

`cargo build --manifest-path agent/agentd/Cargo.toml --features grpc --bin agentd` finishes successfully.

## Reading Results

- Compile errors indicate source/API drift in `agentd` components.
- Successful build enables `cargo run --manifest-path agent/agentd/Cargo.toml --features grpc --bin agentd -- run ...`.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Dependency fetch failures | Network issue | Retry when registry/network is available |
| Compile errors | Code mismatch | Fix code and re-run build |
| Toolchain mismatch | Old Rust version | Update to current stable toolchain |
| Linker errors | Missing system build deps | Install compiler/linker prerequisites |

## Notes

This is source-build based; no separate package installer is required.
