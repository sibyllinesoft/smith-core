---
description: Generate mTLS certificates for the observability gateway
---
# Step 20: Generate Certificates

Run: `bash scripts/bootstrap/steps/20-generate-certs.sh`

## What It Does

Generates mTLS certificates used by the Envoy gateway for secure communication between services. Delegates to `observability/deploy/certs/generate-certs.sh`.

Produces in `observability/deploy/certs/generated/`:
- `ca.crt` / `ca.key` — Certificate Authority
- `server.crt` / `server.key` — Server certificate (for Envoy)
- `client.crt` / `client.key` — Client certificate (for curl/services)

## Prerequisites

- `openssl` must be installed
- The certificate generation script must exist at `observability/deploy/certs/generate-certs.sh`

## Environment Variables

None specific to this step.

## Expected Output

If certs already exist:
```
[ OK ] Certificates already exist in observability/deploy/certs/generated
```

If generating:
```
[INFO] Generating mTLS certificates...
[ OK ] Certificates generated in observability/deploy/certs/generated
```

## Reading Results

After running, verify the cert files exist:
```bash
ls observability/deploy/certs/generated/
# Should show: ca.crt ca.key client.crt client.key server.crt server.key
```

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Certificate generation script not found" | Missing `generate-certs.sh` | Ensure the repo is fully cloned (not shallow) |
| "openssl is required" | openssl not installed | Install via package manager |
| "ca.crt not found" after generation | Script failed silently | Run `bash observability/deploy/certs/generate-certs.sh` manually and check output |

## Platform Gotchas

- **macOS**: LibreSSL (default) vs OpenSSL — the script should work with both, but if cert generation fails, install OpenSSL via `brew install openssl`
- **NixOS**: openssl is in the devShell
