# Agentd Network Policy
#
# Policy rules for network access capabilities:
# - http.fetch.v1 - Make HTTP requests
# - http.post.v1 - Make HTTP POST requests
# - dns.resolve.v1 - Resolve DNS names

package agentd.network

import future.keywords.in
import future.keywords.if
import future.keywords.contains

import data.agentd.base

# Network capabilities
network_capabilities := {
    "http.fetch.v1",
    "http.post.v1",
    "dns.resolve.v1"
}

# Check if this is a network capability
is_network_capability if {
    base.capability in network_capabilities
}

# Read-only network operations
read_only_network := {
    "http.fetch.v1",
    "dns.resolve.v1"
}

# Write network operations (POST, etc.)
write_network := {
    "http.post.v1"
}

is_read_only_network if {
    base.capability in read_only_network
}

is_write_network if {
    base.capability in write_network
}

# Parse URL components via regex
_url_parts := regex.find_all_string_submatch_n(`^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\/([^/:?#]+)(?::(\d+))?`, base.request_url, 1)[0] if {
    base.request_url
}

request_scheme := _url_parts[1] if { _url_parts }

request_host := _url_parts[2] if { _url_parts }

request_port := to_number(_url_parts[3]) if {
    _url_parts
    _url_parts[3] != ""
}

# Default port based on scheme
effective_port := request_port if { request_port }
effective_port := 443 if { not request_port; request_scheme == "https" }
effective_port := 80 if { not request_port; request_scheme == "http" }

# Always blocked hosts (sensitive internal/cloud metadata services)
always_blocked_hosts := {
    "169.254.169.254",           # AWS/GCP metadata
    "metadata.google.internal",   # GCP metadata
    "metadata.azure.internal",    # Azure metadata
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0"
}

# Always blocked host patterns
always_blocked_host_patterns := {
    "*.internal",
    "*.local",
    "10.*",
    "172.16.*",
    "172.17.*",
    "172.18.*",
    "172.19.*",
    "172.20.*",
    "172.21.*",
    "172.22.*",
    "172.23.*",
    "172.24.*",
    "172.25.*",
    "172.26.*",
    "172.27.*",
    "172.28.*",
    "172.29.*",
    "172.30.*",
    "172.31.*",
    "192.168.*"
}

# Check if host is always blocked
host_is_always_blocked if {
    request_host in always_blocked_hosts
}

host_is_always_blocked if {
    some pattern in always_blocked_host_patterns
    glob.match(pattern, [], request_host)
}

# Deny access to blocked hosts
deny contains "Access to internal/metadata services is blocked" if {
    is_network_capability
    host_is_always_blocked
}

# Workstation mode: Allow most external hosts
workstation_allowed_schemes := {"http", "https"}

# Server mode: HTTPS only, specific hosts
server_allowed_schemes := {"https"}
server_allowed_hosts := {
    "api.github.com",
    "api.openai.com",
    "api.anthropic.com",
    "registry.npmjs.org",
    "pypi.org",
    "crates.io"
}

# Paranoid mode: Only explicitly allowed hosts
paranoid_allowed_hosts := set()  # Empty by default, must be configured

# Get allowed configuration based on profile
allowed_schemes := workstation_allowed_schemes if { base.is_workstation }
allowed_schemes := server_allowed_schemes if { base.is_server }
allowed_schemes := server_allowed_schemes if { base.is_paranoid }

# Workstation mode: Allow all non-blocked external hosts
allow if {
    is_network_capability
    base.is_workstation
    request_scheme in allowed_schemes
    not host_is_always_blocked
}

# Server mode: Allow only specific hosts
allow if {
    is_network_capability
    base.is_server
    request_scheme in allowed_schemes
    not host_is_always_blocked
    request_host in server_allowed_hosts
}

# Server mode: Allow hosts from configuration
allow if {
    is_network_capability
    base.is_server
    request_scheme in allowed_schemes
    not host_is_always_blocked
    request_host in input.context.allowed_network_hosts
}

# Paranoid mode: Only explicitly configured hosts
allow if {
    is_network_capability
    base.is_paranoid
    request_scheme in allowed_schemes
    not host_is_always_blocked
    request_host in input.context.allowed_network_hosts
}

# Deny HTTP in server/paranoid mode
deny contains "HTTP (non-TLS) requests are not allowed in server/paranoid mode" if {
    is_network_capability
    not base.is_workstation
    request_scheme == "http"
}

# Deny unrecognized hosts in server mode
deny contains msg if {
    is_network_capability
    base.is_server
    not request_host in server_allowed_hosts
    not request_host in input.context.allowed_network_hosts
    msg := sprintf("Network access to host %s is not in the allowed list", [request_host])
}

# Deny all hosts in paranoid mode unless explicitly allowed
deny contains msg if {
    is_network_capability
    base.is_paranoid
    not request_host in input.context.allowed_network_hosts
    msg := sprintf("Network access to host %s requires explicit approval in paranoid mode", [request_host])
}

# Rate limiting for network requests
network_rate_limits := {
    "workstation": 100,  # requests per minute
    "server": 50,
    "paranoid": 10
}

current_rate_limit := network_rate_limits[base.sandbox_profile]

deny contains msg if {
    is_network_capability
    base.rate_limit_exceeded(current_rate_limit)
    msg := sprintf("Network rate limit exceeded: %d requests/minute allowed", [current_rate_limit])
}

# Request size limits
max_request_body_bytes := 10485760 if { base.is_workstation }  # 10MB
max_request_body_bytes := 1048576 if { base.is_server }        # 1MB
max_request_body_bytes := 102400 if { base.is_paranoid }       # 100KB

deny contains msg if {
    is_write_network
    input.intent.params.body_size > max_request_body_bytes
    msg := sprintf("Request body size %d exceeds maximum %d bytes", [input.intent.params.body_size, max_request_body_bytes])
}

# Audit information for network operations
network_audit_info := {
    "operation": base.capability,
    "host": request_host,
    "scheme": request_scheme,
    "port": effective_port,
    "is_write": is_write_network,
    "profile": base.sandbox_profile
}
