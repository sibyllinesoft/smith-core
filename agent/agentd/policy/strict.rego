# Agentd Strict Policy Bundle (Server Mode)
#
# This policy bundle is designed for server deployments where the agent
# handles requests from potentially untrusted sources. It provides:
#
# - Restricted filesystem access to designated directories only
# - Network access limited to approved hosts
# - Strong authentication requirements
# - Resource limits on all operations
# - Comprehensive audit logging
#
# Use this bundle for production server deployments.

package agentd.strict

import future.keywords.in
import future.keywords.if
import future.keywords.contains

import data.agentd.base
import data.agentd.filesystem
import data.agentd.network
import data.agentd.sandbox

# Main policy entry point
default allow := false

# Authentication is required for all operations
require_authentication if {
    base.auth_method != ""
    base.auth_method != "none"
    input.identity.subject != ""
}

# Aggregate allow rules from sub-policies (only if authenticated)
allow if {
    require_authentication
    filesystem.allow
}

allow if {
    require_authentication
    network.allow
}

allow if {
    require_authentication
    sandbox.allow
}

# Shell execution requires elevated privileges
allow if {
    base.capability == "shell.exec.v1"
    require_authentication
    base.has_any_role({"admin", "shell-user", "developer"})
    validated_command
}

# Shell command validation
validated_command if {
    # Check command is not in blocklist
    command := input.intent.params.command
    not command_is_blocked(command)
}

# Blocked shell commands
blocked_commands := {
    "rm -rf /",
    "rm -rf /*",
    "dd if=/dev/zero",
    ":(){ :|:& };:",  # Fork bomb
    "chmod 777",
    "sudo",
    "su -",
    "curl | bash",
    "wget | bash"
}

command_is_blocked(command) if {
    some blocked in blocked_commands
    contains(command, blocked)
}

# Aggregate deny rules from sub-policies
deny contains reason if {
    filesystem.deny[reason]
}

deny contains reason if {
    network.deny[reason]
}

deny contains reason if {
    sandbox.deny[reason]
}

# Strict-specific deny rules

# Require authentication for all operations
deny contains "Authentication required for all operations in server mode" if {
    not require_authentication
}

# Require TLS for gRPC connections
deny contains "TLS required for gRPC connections in server mode" if {
    base.source_adapter == "grpc"
    not input.context.tls_enabled
}

# Deny blocked shell commands
deny contains msg if {
    base.capability == "shell.exec.v1"
    command := input.intent.params.command
    command_is_blocked(command)
    msg := sprintf("Shell command '%s' is blocked in server mode", [command])
}

# Rate limiting
deny contains "Rate limit exceeded" if {
    input.context.rate_limit.requests_in_window > 100
}

# Request timeout limits
deny contains msg if {
    input.intent.params.timeout_seconds > 300
    msg := sprintf("Request timeout %d seconds exceeds maximum 300 seconds", [input.intent.params.timeout_seconds])
}

# Memory limit for operations
deny contains msg if {
    input.intent.params.max_memory_bytes > 1073741824  # 1GB
    msg := sprintf("Memory limit %d bytes exceeds maximum 1GB", [input.intent.params.max_memory_bytes])
}

# IP-based restrictions (only allow from known networks)
allowed_client_networks := {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8"
}

# Note: IP validation would be handled by the adapter, not in Rego
# This is a placeholder for configuration

# Final authorization decision
authorization := {
    "allowed": true,
    "deny_reasons": [],
    "policy_bundle": "strict",
    "audit_required": true
} if {
    allow
    count(deny) == 0
}

authorization := {
    "allowed": false,
    "deny_reasons": deny,
    "policy_bundle": "strict",
    "audit_required": true
} if {
    not allow
}

authorization := {
    "allowed": false,
    "deny_reasons": deny,
    "policy_bundle": "strict",
    "audit_required": true
} if {
    count(deny) > 0
}

# Server-specific configuration defaults
default_config := {
    "max_file_size_bytes": 10485760,       # 10MB
    "max_network_timeout_seconds": 60,      # 1 minute
    "max_shell_duration_seconds": 300,      # 5 minutes
    "allow_network_to_all_hosts": false,
    "allow_file_writes": false,
    "require_authentication": true,
    "require_tls": true,
    "audit_level": "comprehensive"
}

# Allowed capabilities in server mode
allowed_capabilities := {
    "fs.read.v1",
    "fs.list.v1",
    "fs.stat.v1",
    "http.fetch.v1",
    "shell.exec.v1",
    "sandbox.introspect.v1",
    "sandbox.list.v1"
}

# Restricted capabilities (require additional authorization)
restricted_capabilities := {
    "fs.write.v1",
    "fs.delete.v1",
    "http.post.v1",
    "sandbox.create.v1",
    "sandbox.terminate.v1"
}

# Check capability restrictions
deny contains msg if {
    base.capability in restricted_capabilities
    not base.has_any_role({"admin", "elevated-user"})
    msg := sprintf("Capability %s requires elevated privileges", [base.capability])
}

# Audit information (comprehensive for server mode)
audit := {
    "bundle": "strict",
    "timestamp": time.now_ns(),
    "allow": allow,
    "deny_count": count(deny),
    "deny_reasons": deny,
    "capability": base.capability,
    "subject": input.identity.subject,
    "auth_method": base.auth_method,
    "source_adapter": base.source_adapter,
    "request_id": input.intent.request_id,
    "client_id": input.context.client_id
}
