---
description: Install the agentd binary via cargo or npm
---
# Step 40: Install Agentd

Run: `bash scripts/bootstrap/steps/40-install-agentd.sh`

## What It Does

Installs the `agentd` binary — the secure capability execution engine.

1. Checks if agentd is already on PATH (and version matches if pinned)
2. Selects install method: cargo (preferred) or npm
3. Installs with retry (up to 3 attempts with exponential backoff)
4. Verifies the binary is on PATH after installation

## Prerequisites

- Step 00 (system profile with cargo/node detection)
- At least one of `cargo` or `npm` must be available
- Internet access for package download

## Environment Variables

| Variable | Effect |
|----------|--------|
| `SMITH_AGENTD_INSTALL_METHOD` | Force `cargo` or `npm` |
| `SMITH_AGENTD_VERSION` | Pin a specific version (e.g. `0.5.0`) |

## Agent Decision Point

If both cargo and node are available, **ask the user**:

> "Both cargo and npm are available. Would you like to install agentd via cargo (compiles from source, slower but native) or npm (prebuilt binary, faster)?"

Set `SMITH_AGENTD_INSTALL_METHOD=cargo` or `npm` accordingly.

## Expected Output

If already installed:
```
[ OK ] agentd already installed: agentd 0.5.0
```

If installing via cargo:
```
[INFO] Installing agentd via cargo...
[INFO] Compiling agentd v0.5.0
[ OK ] agentd installed: agentd 0.5.0
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "No install method available" | Neither cargo nor npm found | Install Rust (`rustup`) or Node.js 20+ |
| Cargo compile error | Missing system libraries | Install build deps: `build-essential` / `base-devel` / Xcode CLI tools |
| "agentd not found on PATH" | Cargo/npm bin dir not in PATH | Add `~/.cargo/bin` or npm global bin to PATH |
| Network timeout | Slow connection | Retry — the script retries 3 times automatically |
| Version mismatch | Pinned version not available | Check available versions: `cargo search agentd` or `npm view agentd versions` |

## Platform Gotchas

- **Cargo builds**: Can take several minutes on first install (compiles from source)
- **npm global**: May need `sudo` on some systems, or configure npm prefix
- **NixOS**: Cargo install may fail due to missing linker; use `nix develop` for proper build env
- **macOS**: Ensure Xcode CLI tools are installed for cargo builds: `xcode-select --install`
