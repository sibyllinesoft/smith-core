package smith.envoy.authz

import rego.v1

default allow := false

# ── Ingress rules (non-CONNECT requests) ────────────────────────────────
allow if {
	not is_connect
	known_path
}

allow if {
	not is_connect
	input.attributes.request.http.path == "/health"
}

# ── Egress rules (CONNECT requests via forward proxy) ───────────────────
allow if {
	is_connect
	egress_allowed
}

is_connect if { input.attributes.request.http.method == "CONNECT" }

# Extract the domain from the CONNECT authority (host:port → host)
connect_authority := input.attributes.request.http.host
connect_domain := domain if {
	contains(connect_authority, ":")
	domain := split(connect_authority, ":")[0]
}
connect_domain := connect_authority if {
	not contains(connect_authority, ":")
}

# Default-allow mode: permit unless domain is in denylist
egress_allowed if {
	data.smith.egress.default == "allow"
	not domain_denied
}

# Default-deny mode: permit only if domain is in allowlist
egress_allowed if {
	data.smith.egress.default == "deny"
	domain_allowed
}

domain_denied if { data.smith.egress.domain_denylist[connect_domain] }
domain_denied if { wildcard_match(data.smith.egress.domain_denylist) }

domain_allowed if { data.smith.egress.domain_allowlist[connect_domain] }
domain_allowed if { wildcard_match(data.smith.egress.domain_allowlist) }

# Check wildcard patterns (*.example.com matches sub.example.com)
wildcard_match(domain_set) if {
	some pattern in object.keys(domain_set)
	startswith(pattern, "*.")
	suffix := substring(pattern, 1, -1)
	endswith(connect_domain, suffix)
}

# ── Ingress path matching ───────────────────────────────────────────────
known_path if { startswith(input.attributes.request.http.path, "/agentd.v1.Agentd/") }
known_path if { startswith(input.attributes.request.http.path, "/mcp/index/") }
known_path if { startswith(input.attributes.request.http.path, "/grafana/") }
known_path if { startswith(input.attributes.request.http.path, "/otel/") }
known_path if { startswith(input.attributes.request.http.path, "/nats/") }

# ── Response headers ────────────────────────────────────────────────────
headers["x-authz-decision"] := "allow" if { allow }
headers["x-authz-path-match"] := "known" if { known_path }
headers["x-authz-egress"] := "allowed" if { is_connect; egress_allowed }

deny_reasons contains "unknown_path" if { not is_connect; not known_path }
deny_reasons contains "egress_denied" if { is_connect; not egress_allowed }
