---
description: Generate local mTLS certificates for the Envoy gateway
---
# Generate Certs

Run:

```bash
bash infra/envoy/certs/generate-certs.sh
```

## What It Does

This skill generates the mTLS certificate chain used by the local Envoy gateway.

1. Creates a self-signed local CA certificate.
2. Creates a server certificate for `smith-gateway` / `localhost`.
3. Creates a client certificate for bridge-side mTLS calls.
4. Writes outputs to `infra/envoy/certs/generated/`.

## Prerequisites

- `openssl` must be available on PATH.
- The repo must contain `infra/envoy/certs/generate-certs.sh`.

## Expected Output

The script reports generated artifacts and lists files in:

- `infra/envoy/certs/generated/ca.crt`
- `infra/envoy/certs/generated/ca.key`
- `infra/envoy/certs/generated/server.crt`
- `infra/envoy/certs/generated/server.key`
- `infra/envoy/certs/generated/client.crt`
- `infra/envoy/certs/generated/client.key`

## Reading Results

- If files already exist, the script exits successfully without rotating certs.
- Set `SMITH_FORCE_CERTS=1` to regenerate certificates intentionally.
- These certs are mounted into `envoy` by `docker-compose.yaml`.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `openssl: command not found` | OpenSSL missing | Install OpenSSL via package manager |
| `Permission denied` writing files | Directory ownership/permissions issue | Fix permissions for `infra/envoy/certs/generated` |
| Envoy TLS startup error after generation | Corrupted or partial cert set | Re-run with `SMITH_FORCE_CERTS=1` |
| Client handshake fails | Client cert paths not wired in runtime env | Set `CLIENT_CERT`, `CLIENT_KEY`, `CA_CERT` correctly |

## Notes

For local single-user deployments, generated certs are development trust material and should not be reused across public environments.
