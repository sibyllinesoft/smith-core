---
description: Build Node workspaces required by installer and bridge services
---
# Build Client

Run:

```bash
npm install
npm run build --workspaces --if-present
```

## What It Does

This skill builds TypeScript/Node workspace packages used by Smith Core.

1. Installs workspace dependencies.
2. Builds workspaces that expose a `build` script.
3. Verifies installer and bridge artifacts compile.
4. Ensures runtime JS entrypoints exist before launch.

## Prerequisites

- Node.js 22+.
- npm available.
- Internet access for package installation.

## Expected Output

- `npm install` completes without fatal errors.
- Build runs for `@smith/pi-bridge` and `@sibyllinesoft/smith-installer`.

## Reading Results

- TypeScript compile failures indicate code/config drift.
- Missing workspace build output blocks installer CLI execution.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| npm install fails | Network/auth/registry issues | Fix npm connectivity and retry |
| TypeScript errors in build | Source mismatch | Fix TS errors before bootstrap |
| Wrong Node version | Node < 22 | Upgrade Node runtime |
| Workspace not built | Missing `build` script | Add or correct workspace script |

## Notes

Use this before running installer commands that depend on `dist/` outputs.
