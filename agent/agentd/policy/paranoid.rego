# Agentd Paranoid Policy Bundle (Maximum Security Mode)
#
# This policy bundle is designed for maximum security environments where
# even the smallest risk is unacceptable. It provides:
#
# - Minimal filesystem access (sandbox directory only)
# - Network access only to explicitly configured hosts
# - mTLS authentication required
# - Fresh sandbox per request
# - Aggressive timeouts and resource limits
# - Complete audit logging with request/response capture
#
# Use this bundle for high-security environments or when running
# untrusted code.

package agentd.paranoid

import future.keywords.in
import future.keywords.if
import future.keywords.contains

import data.agentd.base
import data.agentd.filesystem
import data.agentd.network
import data.agentd.sandbox

# Main policy entry point
default allow := false

# mTLS authentication is required
require_mtls_authentication if {
    base.auth_method == "mtls"
    input.identity.subject != ""
    input.context.tls_verified == true
    input.context.client_cert_verified == true
}

# Only minimal capabilities are allowed
minimal_capabilities := {
    "fs.read.v1",
    "sandbox.introspect.v1"
}

# Capabilities that require explicit approval
approval_required_capabilities := {
    "fs.write.v1",
    "shell.exec.v1",
    "http.fetch.v1"
}

# Never allowed in paranoid mode
never_allowed_capabilities := {
    "fs.delete.v1",
    "http.post.v1",
    "sandbox.create.v1",
    "sandbox.terminate.v1",
    "env.get.v1",
    "process.list.v1"
}

# Allow minimal capabilities with mTLS
allow if {
    require_mtls_authentication
    base.capability in minimal_capabilities
    filesystem.allow
}

# Allow approved capabilities with explicit approval
allow if {
    require_mtls_authentication
    base.capability in approval_required_capabilities
    input.context.explicit_approval == true
    input.context.approval_token != ""
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

# Paranoid-specific deny rules

# Require mTLS authentication
deny contains "mTLS authentication required in paranoid mode" if {
    not require_mtls_authentication
}

# Deny never-allowed capabilities
deny contains msg if {
    base.capability in never_allowed_capabilities
    msg := sprintf("Capability %s is never allowed in paranoid mode", [base.capability])
}

# Deny capabilities requiring approval without approval token
deny contains msg if {
    base.capability in approval_required_capabilities
    not input.context.explicit_approval
    msg := sprintf("Capability %s requires explicit approval in paranoid mode", [base.capability])
}

# Strict timeout limits
deny contains msg if {
    input.intent.params.timeout_seconds > 30
    msg := sprintf("Timeout %d seconds exceeds paranoid mode limit of 30 seconds", [input.intent.params.timeout_seconds])
}

# Strict memory limits
deny contains msg if {
    input.intent.params.max_memory_bytes > 268435456  # 256MB
    msg := sprintf("Memory limit %d bytes exceeds paranoid mode limit of 256MB", [input.intent.params.max_memory_bytes])
}

# Require fresh sandbox for each request
deny contains "Fresh sandbox required for each request in paranoid mode" if {
    not input.context.fresh_sandbox
}

# Require sandbox to be isolated
deny contains "Sandbox must use full isolation in paranoid mode" if {
    not input.sandbox.capabilities.syscall_filter_active
}

deny contains "Sandbox must use network isolation in paranoid mode" if {
    input.sandbox.capabilities.has_network
    not input.context.network_explicitly_allowed
}

# Rate limiting (very aggressive)
deny contains "Rate limit exceeded in paranoid mode" if {
    input.context.rate_limit.requests_in_window > 10
}

# Request size limits
deny contains msg if {
    count(input.intent.params) > 1048576  # 1MB
    msg := "Request parameters exceed 1MB size limit"
}

# Deny if sandbox has been active too long
deny contains "Sandbox active time exceeded in paranoid mode" if {
    input.sandbox.active_duration_seconds > 60
}

# Client certificate must be from trusted CA
trusted_ca_subjects := {
    "CN=AgentD CA,O=Smith Platform"
}

deny contains "Client certificate not from trusted CA" if {
    require_mtls_authentication
    not input.context.client_cert_issuer in trusted_ca_subjects
}

# Require audit acknowledgment
deny contains "Audit acknowledgment required for paranoid mode" if {
    not input.context.audit_acknowledged
}

# Final authorization decision
authorization := {
    "allowed": true,
    "deny_reasons": [],
    "policy_bundle": "paranoid",
    "audit_required": true,
    "full_capture": true,
    "retention_days": 365
} if {
    allow
    count(deny) == 0
}

authorization := {
    "allowed": false,
    "deny_reasons": deny,
    "policy_bundle": "paranoid",
    "audit_required": true,
    "full_capture": true,
    "retention_days": 365
} if {
    not allow
}

authorization := {
    "allowed": false,
    "deny_reasons": deny,
    "policy_bundle": "paranoid",
    "audit_required": true,
    "full_capture": true,
    "retention_days": 365
} if {
    count(deny) > 0
}

# Paranoid-specific configuration defaults
default_config := {
    "max_file_size_bytes": 1048576,        # 1MB
    "max_network_timeout_seconds": 10,      # 10 seconds
    "max_shell_duration_seconds": 30,       # 30 seconds
    "allow_network_to_all_hosts": false,
    "allow_file_writes": false,
    "require_authentication": true,
    "require_mtls": true,
    "require_fresh_sandbox": true,
    "require_approval_for_writes": true,
    "audit_level": "full_capture",
    "audit_retention_days": 365
}

# Comprehensive audit information (full capture mode)
audit := {
    "bundle": "paranoid",
    "timestamp": time.now_ns(),
    "allow": allow,
    "deny_count": count(deny),
    "deny_reasons": deny,
    "capability": base.capability,
    "subject": input.identity.subject,
    "auth_method": base.auth_method,
    "source_adapter": base.source_adapter,
    "request_id": input.intent.request_id,
    "client_id": input.context.client_id,
    "client_cert_subject": input.context.client_cert_subject,
    "client_cert_issuer": input.context.client_cert_issuer,
    "tls_version": input.context.tls_version,
    "sandbox_id": input.sandbox.sandbox_id,
    "sandbox_profile": base.sandbox_profile,
    "request_params": input.intent.params,  # Full capture
    "approval_token": input.context.approval_token
}
