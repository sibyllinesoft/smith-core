package smith.envoy.authz

import rego.v1

default allow := false

# Allow requests to known gateway routes
allow if { known_path }

# Also allow health check (belt-and-suspenders with Envoy per-route disable)
allow if { input.attributes.request.http.path == "/health" }

known_path if { startswith(input.attributes.request.http.path, "/agentd.v1.Agentd/") }
known_path if { startswith(input.attributes.request.http.path, "/mcp/index/") }
known_path if { startswith(input.attributes.request.http.path, "/grafana/") }
known_path if { startswith(input.attributes.request.http.path, "/otel/") }
known_path if { startswith(input.attributes.request.http.path, "/nats/") }

headers["x-authz-decision"] := "allow" if { allow }
headers["x-authz-path-match"] := "known" if { known_path }

deny_reasons contains "unknown_path" if { not known_path }
