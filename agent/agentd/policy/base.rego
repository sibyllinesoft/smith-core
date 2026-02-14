# Agentd Base Policy
#
# This package provides common policy rules and helper functions
# used across all policy bundles (permissive, strict, paranoid).
#
# Input structure:
# {
#   "intent": {
#     "capability": "fs.read.v1",
#     "params": {...},
#     "request_id": "..."
#   },
#   "identity": {
#     "subject": "user@example.com",
#     "auth_method": "jwt",
#     "roles": ["user", "admin"],
#     "claims": {...}
#   },
#   "context": {
#     "source_adapter": "grpc",
#     "sandbox_id": "...",
#     "timestamp": "..."
#   },
#   "sandbox": {
#     "capabilities": {...},
#     "profile": "workstation"
#   }
# }

package agentd.base

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Default deny - all requests must be explicitly allowed
default allow := false
default deny := false

# Main authorization decision
# Returns: { "allowed": bool, "reason": string, "policy": string }
authorization := result if {
    allow
    result := {
        "allowed": true,
        "reason": "Request allowed by policy",
        "policy": "agentd.base"
    }
}

authorization := result if {
    not allow
    deny
    result := {
        "allowed": false,
        "reason": deny_reasons[_],
        "policy": "agentd.base"
    }
}

authorization := result if {
    not allow
    not deny
    result := {
        "allowed": false,
        "reason": "No policy matched - default deny",
        "policy": "agentd.base"
    }
}

# Collect all deny reasons
deny_reasons contains reason if {
    deny
    reason := "Request explicitly denied by policy"
}

# Helper: Check if identity has a specific role
has_role(role) if {
    role in input.identity.roles
}

# Helper: Check if identity has any of the specified roles
has_any_role(roles) if {
    some role in roles
    has_role(role)
}

# Helper: Check if identity has all specified roles
has_all_roles(roles) if {
    every role in roles {
        has_role(role)
    }
}

# Helper: Get capability name from intent
capability := input.intent.capability

# Helper: Get parameters from intent
params := input.intent.params

# Helper: Get authentication method
auth_method := input.identity.auth_method

# Helper: Get source adapter
source_adapter := input.context.source_adapter

# Helper: Get sandbox profile
sandbox_profile := input.sandbox.profile

# Helper: Check if running in workstation mode
is_workstation if {
    sandbox_profile == "workstation"
}

# Helper: Check if running in server mode
is_server if {
    sandbox_profile == "server"
}

# Helper: Check if running in paranoid mode
is_paranoid if {
    sandbox_profile == "paranoid"
}

# Helper: Check if capability is in allowed list
capability_allowed(allowed_capabilities) if {
    capability in allowed_capabilities
}

# Helper: Extract file path from params (for fs capabilities)
file_path := input.intent.params.path if {
    input.intent.params.path
}

# Helper: Extract URL from params (for http capabilities)
request_url := input.intent.params.url if {
    input.intent.params.url
}

# Helper: Check if path starts with prefix
path_starts_with(path, prefix) if {
    startswith(path, prefix)
}

# Helper: Check if path is under allowed directory
path_allowed(path, allowed_dirs) if {
    some dir in allowed_dirs
    path_starts_with(path, dir)
}

# Helper: Check if path matches blocked pattern
path_blocked(path, blocked_patterns) if {
    some pattern in blocked_patterns
    glob.match(pattern, ["/"], path)
}

# Helper: Rate limiting support
# Input should include: context.rate_limit.requests_in_window, context.rate_limit.window_seconds
rate_limit_exceeded(max_requests) if {
    input.context.rate_limit.requests_in_window > max_requests
}

# Helper: Time-based restrictions
# Returns true if current time is within allowed hours (UTC)
within_allowed_hours(start_hour, end_hour) if {
    current_hour := time.clock(time.now_ns())[0]
    current_hour >= start_hour
    current_hour < end_hour
}

# Helper: Validate JSON schema (simplified)
params_has_required_fields(required) if {
    every field in required {
        input.intent.params[field]
    }
}

# Audit information to include in logs
audit_info := {
    "capability": capability,
    "subject": input.identity.subject,
    "auth_method": auth_method,
    "source_adapter": source_adapter,
    "sandbox_profile": sandbox_profile,
    "request_id": input.intent.request_id
}
