---
description: Inspect and configure OPA security policies for agentd intent evaluation and gateway authorization
---
# Configure Policy

Run these read-only inspection commands to understand the current policy state:

```bash
# Query opa_policies table for active policy records
docker compose exec -T postgres psql -U smith -d smith -c "SELECT id, name, updated_at FROM opa_policies ORDER BY updated_at DESC;"

# View tool-access policy data (most commonly edited artifact)
docker compose exec -T postgres psql -U smith -d smith -c "SELECT data FROM opa_policies WHERE name = 'tool_access';"

# Check OPA server health (Docker-internal only, port 8181 is not published to host)
docker compose exec -T opa-management wget -qO- http://localhost:8181/health

# List loaded OPA policies
docker compose exec -T opa-management wget -qO- http://localhost:8181/v1/policies

# Show executor.policy section from agentd config
grep -A 20 '^\[executor\.policy\]' ${AGENTD_ROOT}/config/agentd.toml || echo "No [executor.policy] section found"

# List Rego policy files
ls -la ${AGENTD_ROOT}/policy/*.rego 2>/dev/null || echo "No .rego files found"
```

## What It Does

This skill inspects and configures the OPA (Open Policy Agent) security policy system that governs agentd intent evaluation and gateway authorization.

### Security Profiles

Smith Core ships three security profiles:

1. **Permissive** (workstation) — broad tool access; suitable for local development.
2. **Strict** (server) — restricted tool set; requires explicit allowlisting.
3. **Paranoid** (max security) — minimal defaults; every tool must be individually approved.

### Architecture

- 10 Rego policy files live at `${AGENTD_ROOT}/policy/*.rego`.
- Policy data is stored in PostgreSQL (`opa_policies` table) and synced to the OPA management server.
- Sync flow: **PostgreSQL** -> **admission service** -> **OPA server (8181)** -> **Envoy ext_authz (9292)**.
- Separately, agentd evaluates policies in-process via the `regorus` embedded Rego engine using `[executor.policy]` config in `agentd.toml`.

### Important: OPA is Docker-internal only

OPA uses `expose: ["8181"]` in docker-compose (no `ports:` mapping), so `curl localhost:8181` will **not** work from the host. All OPA API commands must use `docker compose exec -T opa-management` to reach the OPA API.

## Mutation Commands

These commands modify policy state. Use them interactively after inspecting current state:

### Edit tool-access policy data

```bash
docker compose exec -T postgres psql -U smith -d smith -c "UPDATE opa_policies SET data = '<new-json>' WHERE name = 'tool_access';"
```

### Build policy bundle

```bash
bash ${AGENTD_ROOT}/scripts/build-policy-bundle.sh
```

### Validate Rego files (requires OPA CLI on host)

```bash
opa check ${AGENTD_ROOT}/policy/
```

### Force re-sync from PostgreSQL to OPA

```bash
docker compose restart opa-management
```

## Prerequisites

- Docker stack running (`docker compose ps` shows `postgres` and `opa-management` healthy).
- `opa_policies` table populated (happens during initial `start-stack` phase).
- `${AGENTD_ROOT}/config/agentd.toml` present.

## Expected Output

- `opa_policies` table lists active policy records with timestamps.
- OPA health endpoint returns `{"status": "ok"}` or similar.
- Rego files are listed at `${AGENTD_ROOT}/policy/*.rego`.
- `[executor.policy]` config section is visible in `agentd.toml`.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `psql` connection refused | Postgres container not running | `docker compose up -d postgres` |
| OPA health check fails | `opa-management` container not running | `docker compose up -d opa-management` |
| Empty `opa_policies` table | Policies not seeded | Re-run `start-stack` skill or seed manually |
| `regorus` evaluation errors in agentd logs | Rego syntax error in policy files | Run `opa check ${AGENTD_ROOT}/policy/` to validate |
| Changes not reflected in authorization | Sync lag or stale cache | `docker compose restart opa-management` |

## Notes

### Tool-Access Policy Data Structure

The `tool_access` policy record in `opa_policies` stores a JSON document with the following structure:

```json
{
  "default": "permissive",
  "exceptions": {
    "strict": {
      "allowed_tools": ["shell_exec", "file_read", "file_write"],
      "denied_tools": ["network_raw", "kernel_module"]
    },
    "paranoid": {
      "allowed_tools": ["file_read"],
      "denied_tools": ["*"]
    }
  },
  "source_restrictions": {
    "untrusted": {
      "untrusted_allowed_tools": ["file_read", "shell_exec"]
    }
  }
}
```

- **`default`**: The active security profile name (`permissive`, `strict`, or `paranoid`).
- **`exceptions`**: Per-profile overrides that define `allowed_tools` and `denied_tools` lists.
- **`source_restrictions`**: Controls which tools are available to untrusted request sources.
- **`untrusted_allowed_tools`**: Subset of tools that untrusted callers may invoke regardless of profile.

To change the active profile, update the `default` field. To customize tool access within a profile, modify the corresponding entry in `exceptions`.
