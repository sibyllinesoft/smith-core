---
description: Collect comprehensive system and project state into preflight.json
---
# Step 01: Preflight

Run: `bash scripts/bootstrap/steps/01-preflight.sh`

## What It Does

Collects comprehensive system and project state into `var/bootstrap/preflight.json`. This gives you (the installer agent) everything you need to know about the environment **without running manual discovery commands**.

Always re-runs (no idempotency gate) — preflight data should always be fresh.

## What It Collects

| Section | Fields | Purpose |
|---------|--------|---------|
| `bootstrap_state` | completed steps, deployment mode, tunnel/activitywatch flags | Know what's already done |
| `runtime_versions` | docker, compose, cargo, rustc, node, npm, bun, agentd versions | Know what's installed |
| `smith_containers` | running containers, networks, volumes | Know what's running |
| `ports` | 6173, 7222, 7317, 7318, 9901, 9200, 5600 availability | Know what's free |
| `certificates` | cert existence, expiry date, days remaining | Know cert status |
| `project_state` | git branch, dirty state, client built, env file, agentd dir | Know repo state |
| `system_resources` | RAM, CPU cores, disk free | Know hardware limits |
| `network` | internet reachable, DNS working | Know connectivity |

## How to Use the Data

**Instead of running manual commands, read the preflight JSON:**

```bash
# DON'T do this:
docker --version
docker ps
ss -tlnp | grep 6173

# DO this:
cat var/bootstrap/preflight.json | jq .
```

**Key decisions from preflight data:**

- `runtime_versions.docker_running == false` → need to start Docker or step 10 first
- `ports."6173" == "in-use"` → something is already on the gateway port
- `certificates.cert_days_remaining < 30` → certs need regeneration
- `project_state.client_built == false` → need step 25
- `project_state.agentd_dir_exists == true` → old agentd dir still present (stale)
- `system_resources.memory_total_gb < 4` → warn about low resources
- `network.internet_reachable == false` → offline install path needed

## Prerequisites

- `jq` (used internally to build JSON)
- No other dependencies — uses only shell builtins and standard tools

## Expected Output

```
[INFO] Collecting preflight state...
[INFO] Docker: Docker version 27.x.x (running=true)
[INFO] Cargo: cargo 1.82.0 | Node: v22.x.x
[INFO] Containers: 5 running
[INFO] Certs: exist=true | Client built: true
[INFO] Resources: 31.2GB RAM, 16 cores, 120GB free disk
[INFO] Network: internet=true dns=true
[ OK ] Preflight state written to var/bootstrap/preflight.json
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "jq: command not found" | jq not installed | Install jq first (or run step 00 which validates this) |
| Empty containers/networks/volumes | Docker not running | Expected if Docker isn't started yet |
| cert_days_remaining is null | No certs generated yet | Expected before step 20 |

## Environment Variables

This step does not use any custom environment variables. It always regenerates the preflight data.
