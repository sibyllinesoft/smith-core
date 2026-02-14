# Gateway Authorization Policy
#
# This policy handles API gateway authorization via Envoy ext_authz.
# It validates:
# - API key authentication
# - Request rate limiting metadata
# - Path-based access control
# - Method restrictions

package agentd.gateway.authz

import rego.v1

default allow := false

# Main authorization decision
allow if {
    valid_api_key
    allowed_path
    allowed_method
}

# Health and readiness endpoints are always allowed (handled by Envoy config, but double-check)
allow if {
    input.attributes.request.http.path in ["/health", "/ready"]
}

# API Key Validation
# Keys are passed in X-API-Key header or Authorization: Bearer header
valid_api_key if {
    api_key := input.attributes.request.http.headers["x-api-key"]
    valid_key(api_key)
}

valid_api_key if {
    auth_header := input.attributes.request.http.headers["authorization"]
    startswith(auth_header, "Bearer ")
    token := substring(auth_header, 7, -1)
    valid_key(token)
}

# Key validation - in production, this would query a key store
# For now, we check against a configurable set of keys
valid_key(key) if {
    key != ""
    # Check against configured API keys
    # Keys can be loaded from data.api_keys or environment
    data.api_keys[_].key == key
    data.api_keys[_].enabled == true
}

# Fallback: If no API keys configured, allow any non-empty key in development
valid_key(key) if {
    count(data.api_keys) == 0
    data.gateway_config.allow_any_key == true
    key != ""
}

# Path-based Access Control
allowed_path if {
    path := input.attributes.request.http.path

    # gRPC services
    startswith(path, "/agentd.v1.")
}

allowed_path if {
    path := input.attributes.request.http.path

    # REST API
    startswith(path, "/api/v1/")
}

allowed_path if {
    path := input.attributes.request.http.path

    # Admin API (requires additional validation)
    startswith(path, "/admin/")
    is_admin_key
}

# Method Restrictions
allowed_method if {
    method := input.attributes.request.http.method
    method in ["GET", "POST", "PUT", "DELETE", "PATCH"]
}

# Admin key validation
is_admin_key if {
    api_key := get_api_key
    key_data := data.api_keys[_]
    key_data.key == api_key
    key_data.role == "admin"
}

# Helper to extract API key from request
get_api_key := key if {
    key := input.attributes.request.http.headers["x-api-key"]
} else := key if {
    auth_header := input.attributes.request.http.headers["authorization"]
    startswith(auth_header, "Bearer ")
    key := substring(auth_header, 7, -1)
}

# Rate limiting metadata (returned to Envoy for dynamic rate limiting)
rate_limit_tier := tier if {
    api_key := get_api_key
    key_data := data.api_keys[_]
    key_data.key == api_key
    tier := key_data.rate_limit_tier
} else := "default"

# Response headers to add
headers["x-rate-limit-tier"] := rate_limit_tier
headers["x-authenticated-key-id"] := key_id if {
    api_key := get_api_key
    key_data := data.api_keys[_]
    key_data.key == api_key
    key_id := key_data.id
}

# Deny reasons for debugging
deny_reasons contains "missing_api_key" if {
    not valid_api_key
}

deny_reasons contains "invalid_path" if {
    not allowed_path
}

deny_reasons contains "invalid_method" if {
    not allowed_method
}
