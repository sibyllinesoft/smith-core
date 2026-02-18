# Private-Network Tunnels

Smith Core binds host-facing ports to loopback by default (`127.0.0.1`). Use a
private network path for remote access instead of publishing management ports
directly.

This repo now includes:

- Cloudflare named tunnel bootstrap + connector profile
- Provider-specific e2e tunnel smoke tests (`cloudflare`, `tailscale`)
- Installer `verify`/`all` steps run tunnel e2e checks automatically when
  tunnel e2e environment variables are present in `.env`

## Prerequisites

- `just up` completed successfully
- `.env` exists (`cp .env.example .env` if needed)
- For Cloudflare: local `cloudflared` CLI installed and authenticated
- For Tailscale: local `tailscale` CLI installed and authenticated

## Cloudflare Named Tunnel

1. Authenticate once with Cloudflare:

```bash
cloudflared tunnel login
```

2. Create (or reuse) a named tunnel, route DNS, and write token/hostname to `.env`:

```bash
just tunnel-cloudflare-create smith-core agent.example.com
```

3. In Cloudflare Zero Trust, ensure your tunnel has a public hostname forwarding
   to the local origin inside the Compose network (recommended: `http://mcp-index:9200`).

4. Start the connector:

```bash
just tunnel-cloudflare-up
```

5. Run an end-to-end health check:

```bash
just tunnel-cloudflare-e2e
```

6. Optional operations:

```bash
just tunnel-cloudflare-logs
just tunnel-cloudflare-down
```

## Tailscale Path

1. Bring the host onto your tailnet (if not already):

```bash
tailscale up --auth-key="${TAILSCALE_AUTHKEY}" --hostname="${TAILSCALE_HOSTNAME:-smith-core}"
```

2. Expose the local health endpoint over Tailscale Serve:

```bash
tailscale serve --service="svc:smith-core" --https=443 http://127.0.0.1:9200
```

3. Get the advertised URL and set it in `.env`:

```bash
tailscale serve status --json
# then set:
# TAILSCALE_TUNNEL_E2E_URL=https://<your-tailnet-url>/health
```

4. Run an end-to-end health check:

```bash
just tunnel-tailscale-e2e
```

## Generic E2E Runner

```bash
just tunnel-e2e cloudflare
just tunnel-e2e tailscale
```

Script defaults:

- Local origin check: `http://127.0.0.1:9200/health`
- Remote retries: `20` attempts, `3s` interval

Override with `TUNNEL_LOCAL_HEALTH_URL`, `TUNNEL_E2E_ATTEMPTS`, and
`TUNNEL_E2E_DELAY_SECONDS`.
