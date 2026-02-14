# agentd Infrastructure

This directory contains infrastructure configuration for running agentd with an API gateway.

## Architecture

```
                    ┌─────────────────┐
                    │   API Clients   │
                    └────────┬────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────┐
│              Envoy Gateway (:8080)                  │
│  • API key authentication                           │
│  • Rate limiting                                    │
│  • Request routing (gRPC/HTTP)                      │
└──────────────────────┬─────────────────────────────┘
                       │
           ┌───────────┴───────────┐
           │                       │
           ▼                       ▼
   ┌───────────────┐      ┌───────────────┐
   │      OPA      │      │    agentd     │
   │               │◄─────│               │
   │  • API auth   │      │  • gRPC :9500 │
   │  • Egress     │      │  • HTTP :8090 │
   │    policy     │      │               │
   └───────────────┘      └───────┬───────┘
           ▲                      │
           │                      │ http_fetch
           │                      ▼
           │         ┌────────────────────────┐
           │         │  Envoy Egress (:8443)  │
           └─────────│                        │
                     │  • Policy enforcement  │
                     │  • Credential inject   │
                     │  • Rate limiting       │
                     └───────────┬────────────┘
                                 │
                                 ▼
                     ┌────────────────────────┐
                     │    External APIs       │
                     │  • OpenAI              │
                     │  • Anthropic           │
                     │  • GitHub              │
                     │  • etc.                │
                     └────────────────────────┘
```

### Two Proxy Pattern

agentd uses two Envoy proxies with distinct responsibilities:

1. **Gateway Proxy** (port 8080): Authenticates API clients accessing agentd
2. **Egress Proxy** (port 8443): Controls agent access to external APIs

This separation provides:
- **Credential isolation**: Agents never see external API keys
- **Unified policy**: Single OPA instance governs both ingress and egress
- **Audit trail**: All external API calls are logged
- **Fine-grained control**: Per-sandbox, per-service access policies

## Directory Structure

```
infra/
├── compose/
│   ├── docker-compose.yaml              # Production stack (gateway + egress + agentd)
│   ├── docker-compose.monitoring.yaml   # Monitoring overlay (Grafana + Prometheus + Loki)
│   ├── docker-compose.dev.yaml          # Development (gateway only)
│   └── .env.example                     # Environment variables template
├── envoy/
│   ├── envoy.yaml               # Gateway Envoy config
│   ├── envoy-dev.yaml           # Development gateway config
│   └── envoy-egress.yaml        # Egress proxy config
├── grafana/
│   └── provisioning/
│       ├── datasources/datasources.yml  # Prometheus + Loki datasources
│       └── dashboards/
│           ├── dashboards.yml           # Dashboard provider config
│           └── json/envoy-overview.json # Envoy + agentd dashboard
├── loki/
│   └── loki.yml                 # Loki local storage config
├── prometheus/
│   └── prometheus.yml           # Scrape targets config
├── promtail/
│   └── promtail.yml             # Docker log discovery config
└── opa/
    └── opa.yaml                 # OPA configuration
```

## Quick Start

### Development Mode

Run the API gateway locally while developing agentd:

```bash
# 1. Build policy bundle
./scripts/build-policy-bundle.sh

# 2. Start Envoy + OPA
docker compose -f infra/compose/docker-compose.dev.yaml up -d

# 3. Run agentd on host
cargo run --release -- daemon

# 4. Test the API
curl -H "X-API-Key: dev-api-key-change-in-production" http://localhost:8080/health
```

### Production Mode

Run the full stack in containers:

```bash
# 1. Build policy bundle
./scripts/build-policy-bundle.sh

# 2. Build agentd container
docker build -t agentd .

# 3. Start full stack
docker compose -f infra/compose/docker-compose.yaml up -d

# 4. Test
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/status
```

## Components

### Envoy Gateway

The Envoy proxy provides:

- **Rate Limiting**: Local rate limiting with configurable token bucket
- **External Authorization**: Delegates auth decisions to OPA
- **Request Routing**: Routes gRPC and HTTP traffic to agentd
- **TLS Termination**: Optional HTTPS support
- **Access Logging**: JSON-formatted request logs

Configuration files:
- `envoy/envoy.yaml` - Production config (uses DNS resolution)
- `envoy/envoy-dev.yaml` - Development config (localhost)

### OPA (Open Policy Agent)

OPA provides unified policy management:

- **API Authentication**: Validates API keys
- **Path-based Authorization**: Controls access to endpoints
- **Rate Limit Tiers**: Returns metadata for per-key rate limiting
- **Policy Bundles**: Loads policies from tarball bundles

Configuration: `opa/opa.yaml`

Policy files: `policy/gateway.rego`

### Policy Bundles

Policies are packaged into OPA bundles:

```bash
# Build bundle
./scripts/build-policy-bundle.sh

# Output
build/bundles/
├── agentd-bundle.tar.gz    # Compressed bundle for OPA
└── agentd-bundle/          # Uncompressed for development
```

## Configuration

### API Keys

API keys are configured in `policy/data/gateway_config.json`:

```json
{
  "api_keys": [
    {
      "id": "key-1",
      "key": "your-secret-key",
      "enabled": true,
      "role": "admin",
      "rate_limit_tier": "unlimited"
    }
  ]
}
```

Rebuild the bundle after modifying:
```bash
./scripts/build-policy-bundle.sh
```

### Rate Limiting

Rate limit tiers are defined in `policy/data/gateway_config.json`:

```json
{
  "rate_limit_tiers": {
    "default": { "requests_per_minute": 60 },
    "standard": { "requests_per_minute": 120 },
    "premium": { "requests_per_minute": 600 },
    "unlimited": { "requests_per_minute": -1 }
  }
}
```

### TLS Configuration

To enable TLS:

1. Generate or obtain certificates
2. Uncomment the TLS listener in `envoy/envoy.yaml`
3. Mount certificates in docker-compose

## Ports

| Service | Port | Description |
|---------|------|-------------|
| Gateway Envoy | 8080 | API Gateway (main entry point) |
| Gateway Envoy | 9901 | Gateway Admin API |
| Egress Envoy | 8443 | Egress Proxy (external API access) |
| Egress Envoy | 9902 | Egress Admin API |
| OPA | 8181 | Policy REST API |
| OPA | 9191 | ext_authz gRPC (internal) |
| agentd | 9500 | gRPC API (internal) |
| agentd | 8090 | HTTP API (internal) |

## Egress Proxy (External API Access)

The egress proxy allows agents to access external APIs while:
- Enforcing policy on which APIs each sandbox can access
- Injecting credentials so agents never see API keys
- Rate limiting per sandbox/service combination
- Logging all external API calls

### How Agents Use the Egress Proxy

Agents make HTTP requests to the egress proxy using service names as hosts:

```bash
# Instead of calling OpenAI directly:
# curl https://api.openai.com/v1/chat/completions -H "Authorization: Bearer sk-..."

# Agents call the egress proxy:
curl http://egress-proxy:8443/v1/chat/completions \
  -H "Host: openai" \
  -H "X-Sandbox-ID: sandbox-123" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [...]}'

# The proxy:
# 1. Checks if sandbox-123 is allowed to access "openai"
# 2. Injects the OpenAI API key
# 3. Forwards to api.openai.com
# 4. Returns the response
```

### Configuring External Services

Services are defined in `policy/data/egress_config.json`:

```json
{
  "egress_services": {
    "openai": {
      "display_name": "OpenAI API",
      "base_url": "https://api.openai.com",
      "allowed_methods": ["POST"],
      "allowed_paths": ["/v1/chat/completions", "/v1/embeddings"]
    }
  }
}
```

### Policy Tiers

Sandboxes are assigned policy tiers that control API access:

| Tier | Allowed Services | Rate Limits |
|------|-----------------|-------------|
| `default` | None | N/A |
| `restricted` | httpbin (testing) | 10/min |
| `standard` | OpenAI, Anthropic, GitHub | 60/min |
| `premium` | All + Slack | 300/min |
| `admin` | All services | 1000/min |

### Setting Up Credentials

1. Copy the environment template:
   ```bash
   cp infra/compose/.env.example infra/compose/.env
   ```

2. Fill in your API keys:
   ```bash
   OPENAI_API_KEY=sk-your-key
   ANTHROPIC_API_KEY=sk-ant-your-key
   GITHUB_TOKEN=ghp_your-token
   ```

3. Generate the secrets file:
   ```bash
   source infra/compose/.env
   ./scripts/generate-egress-secrets.sh > policy/data/egress_secrets.json
   ```

4. Rebuild the policy bundle:
   ```bash
   ./scripts/build-policy-bundle.sh
   ```

### Security Notes

- **Never commit `.env` or `egress_secrets.json`** - they contain real credentials
- In production, use a secrets manager (Vault, AWS Secrets Manager)
- Credentials are injected by Envoy, not OPA (OPA only makes allow/deny decisions)
- The egress proxy strips sandbox headers before forwarding to prevent spoofing

## Monitoring

### Grafana Stack (Prometheus + Loki + Grafana)

A full observability stack is available as a compose overlay:

```bash
cd infra/compose

# Start core + monitoring
docker compose -f docker-compose.yaml -f docker-compose.monitoring.yaml up -d

# Stop monitoring only
docker compose -f docker-compose.yaml -f docker-compose.monitoring.yaml stop prometheus loki promtail grafana
```

| Service | URL | Description |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | Dashboards (admin/admin, anonymous access enabled) |
| Prometheus | http://localhost:9090 | Metrics explorer and target status |
| Loki | http://localhost:3100 | Log aggregation (query via Grafana) |

**Pre-provisioned:**
- Prometheus + Loki datasources (auto-configured)
- Envoy Overview dashboard with gateway/egress request rates, latency percentiles, agentd intent metrics, and log panels

**Useful Loki queries in Grafana Explore:**

```logql
# All gateway access logs
{compose_service="envoy-gateway"}

# Gateway errors
{compose_service="envoy-gateway"} | json | status >= 400

# Egress requests by method
{compose_service="envoy-egress"} | json | line_format "{{.method}} {{.path}} {{.status}}"

# agentd logs
{compose_service="agentd"}
```

### Envoy Stats (without monitoring stack)

```bash
# View stats
curl http://localhost:9901/stats

# Prometheus metrics
curl http://localhost:9901/stats/prometheus
```

### OPA Decision Logs

Decision logs are enabled in `opa/opa.yaml` and output to console.

View in docker:
```bash
docker logs agentd-opa -f
```

## Troubleshooting

### Authorization Failures

Check OPA decision logs:
```bash
docker logs agentd-opa 2>&1 | grep -i decision
```

Query OPA directly:
```bash
curl -X POST http://localhost:8181/v1/data/agentd/gateway/authz \
  -H "Content-Type: application/json" \
  -d '{"input": {"attributes": {"request": {"http": {"headers": {"x-api-key": "test"}}}}}}'
```

### Connection Issues

Verify services are healthy:
```bash
docker compose -f infra/compose/docker-compose.yaml ps
```

Check Envoy cluster health:
```bash
curl http://localhost:9901/clusters
```

### Policy Updates

After modifying policies:
```bash
# Rebuild bundle
./scripts/build-policy-bundle.sh

# Restart OPA to reload (or wait for polling)
docker restart agentd-opa
```
