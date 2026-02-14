---
description: Build the React SPA web client
---
# Step 25: Build Client

Run: `bash scripts/bootstrap/steps/25-build-client.sh`

## What It Does

Builds the Smith web client (React + TypeScript SPA) into `client/dist/`.

1. Checks if `client/dist/index.html` already exists (skip if so)
2. Installs npm dependencies if `node_modules/` is missing
3. Runs the build (`bun run build` or `npm run build`)
4. Verifies `client/dist/index.html` was produced

## Prerequisites

- Step 00 must have run (needs system profile for bun/npm detection)
- `bun` or `npm` must be available
- `client/` directory must exist in the repo

## Environment Variables

None specific to this step. Uses system profile to detect bun vs npm.

## Expected Output

If already built:
```
[ OK ] Client build exists at client/dist/index.html
```

If building:
```
[INFO] Building client SPA...
[INFO] Installing dependencies with bun...
[INFO] Building with bun...
[ OK ] Client built successfully
```

## Reading Results

Check that the dist output exists:
```bash
ls client/dist/index.html
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "No JS package manager available" | Neither bun nor npm installed | Install Node.js 20+ or bun |
| "Build completed but index.html not found" | Build script failed or output path changed | Check `client/package.json` for the build script and output config |
| npm peer dependency errors | Conflicting dependency versions | Use `--legacy-peer-deps` (the script does this automatically for npm) |
| Out of memory during build | Large TypeScript project | Set `NODE_OPTIONS=--max-old-space-size=4096` |

## Platform Gotchas

- **npm vs bun**: The script prefers bun when available (faster installs and builds)
- **npm**: Automatically uses `--legacy-peer-deps` to avoid peer dependency conflicts
- **NixOS**: Ensure you're in `nix develop` for node/bun availability
