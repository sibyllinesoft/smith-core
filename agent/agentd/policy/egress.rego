# Egress Proxy Policy
#
# Controls which external APIs sandboxes can access and injects credentials.
# This policy is separate from authentication - it's about capability control.
#
# Input from Envoy ext_authz:
# - input.attributes.request.http.host: target service (e.g., "openai")
# - input.attributes.request.http.path: request path
# - input.attributes.request.http.method: HTTP method
# - input.attributes.request.http.headers["x-sandbox-id"]: sandbox making request
# - input.attributes.request.http.headers["x-sandbox-policy"]: policy tier
#
# Output:
# - allow: boolean
# - headers: map of headers to inject (including credentials)
# - response_headers: headers to add to response

package agentd.egress.authz

import rego.v1

default allow := false

# Main authorization decision
allow if {
    sandbox_id := get_sandbox_id
    target_service := get_target_service

    # Check if sandbox policy allows this service
    service_allowed(sandbox_id, target_service)

    # Check method is allowed for this service
    method_allowed(target_service)

    # Check path is allowed (some services may have path restrictions)
    path_allowed(target_service)
}

# Headers to inject (credentials)
headers["authorization"] := auth_header if {
    target_service := get_target_service
    creds := get_credentials(target_service)
    creds.type == "bearer"
    auth_header := sprintf("Bearer %s", [creds.token])
}

headers["x-api-key"] := api_key if {
    target_service := get_target_service
    creds := get_credentials(target_service)
    creds.type == "api_key"
    api_key := creds.token
}

headers["anthropic-version"] := "2024-01-01" if {
    get_target_service == "anthropic"
}

# Response headers for observability
response_headers["x-egress-allowed"] := "true" if { allow }
response_headers["x-egress-service"] := get_target_service

# ============================================================================
# Service Access Control
# ============================================================================

# Check if sandbox policy tier allows the service
service_allowed(sandbox_id, service) if {
    policy_tier := get_sandbox_policy(sandbox_id)
    allowed_services := data.egress_policies[policy_tier].allowed_services
    service in allowed_services
}

# Wildcard: if policy allows "*", all configured services are allowed
service_allowed(sandbox_id, service) if {
    policy_tier := get_sandbox_policy(sandbox_id)
    "*" in data.egress_policies[policy_tier].allowed_services
    # Still must be a known/configured service
    data.egress_services[service]
}

# Method restrictions per service
method_allowed(service) if {
    method := input.attributes.request.http.method
    allowed_methods := data.egress_services[service].allowed_methods
    method in allowed_methods
}

# Default: GET and POST allowed if not specified
method_allowed(service) if {
    method := input.attributes.request.http.method
    not data.egress_services[service].allowed_methods
    method in ["GET", "POST"]
}

# Path restrictions per service
path_allowed(service) if {
    path := input.attributes.request.http.path
    patterns := data.egress_services[service].allowed_paths
    some pattern in patterns
    glob.match(pattern, ["/"], path)
}

# Default: all paths allowed if not specified
path_allowed(service) if {
    not data.egress_services[service].allowed_paths
}

# ============================================================================
# Credential Management
# ============================================================================

# Get credentials for a service
get_credentials(service) := creds if {
    creds := data.egress_credentials[service]
}

# ============================================================================
# Helpers
# ============================================================================

# Extract sandbox ID from request headers
get_sandbox_id := sandbox_id if {
    sandbox_id := input.attributes.request.http.headers["x-sandbox-id"]
} else := "unknown"

# Get target service from Host header
get_target_service := service if {
    host := input.attributes.request.http.headers[":authority"]
    # Strip port if present
    service := split(host, ":")[0]
} else := service if {
    host := input.attributes.request.http.host
    service := split(host, ":")[0]
}

# Get sandbox policy tier (from header or lookup)
get_sandbox_policy(sandbox_id) := policy if {
    policy := input.attributes.request.http.headers["x-sandbox-policy"]
} else := policy if {
    # Look up in sandbox registry
    policy := data.sandbox_policies[sandbox_id]
} else := "default"

# ============================================================================
# Deny Reasons (for debugging)
# ============================================================================

deny_reasons contains reason if {
    not service_allowed(get_sandbox_id, get_target_service)
    reason := sprintf("sandbox '%s' not allowed to access service '%s'", [get_sandbox_id, get_target_service])
}

deny_reasons contains reason if {
    not method_allowed(get_target_service)
    reason := sprintf("method '%s' not allowed for service '%s'", [input.attributes.request.http.method, get_target_service])
}

deny_reasons contains reason if {
    not path_allowed(get_target_service)
    reason := sprintf("path '%s' not allowed for service '%s'", [input.attributes.request.http.path, get_target_service])
}

# ============================================================================
# Rate Limit Metadata
# ============================================================================

# Return rate limit tier for the sandbox/service combination
rate_limit_key := sprintf("%s:%s", [get_sandbox_id, get_target_service])

rate_limit_tokens := tokens if {
    policy := get_sandbox_policy(get_sandbox_id)
    service := get_target_service
    tokens := data.egress_policies[policy].rate_limits[service].tokens_per_minute
} else := 60  # Default: 60 requests per minute
