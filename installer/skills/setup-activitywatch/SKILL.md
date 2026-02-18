---
description: Configure optional ActivityWatch integration guidance for local installs
---
# Setup ActivityWatch

Run:

```bash
echo "ActivityWatch integration is optional in smith-core"
```

## What It Does

This skill captures optional guidance for ActivityWatch-related tooling.

1. Marks ActivityWatch as non-blocking for core installation.
2. Prevents installer flow from failing on optional telemetry extras.
3. Documents that ActivityWatch setup should be explicit and user-driven.
4. Keeps bootstrap focused on required services.

## Prerequisites

- None; this step can be skipped safely.

## Expected Output

A clear statement that ActivityWatch is optional and skipped by default.

## Reading Results

- If user requires ActivityWatch, configure it separately and then integrate endpoints.
- If not required, continue directly to build/start/verify steps.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| User expects ActivityWatch by default | Legacy installer assumptions | Clarify it is optional |
| Missing ActivityWatch MCP server | Not provisioned in repo stack | Add external server configuration |
| Agent tries to depend on ActivityWatch metrics | Over-eager automation | Keep optional path disabled unless requested |

## Notes

Core Smith Core install success does not depend on ActivityWatch.
