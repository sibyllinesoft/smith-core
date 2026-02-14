# Agentd Permissive Policy Bundle (Workstation Mode)
#
# This policy bundle is designed for workstation/development use where
# the agent is trusted and running under user supervision. It provides:
#
# - Broad filesystem access to user directories
# - Unrestricted network access (except cloud metadata)
# - Flexible sandbox management
# - Minimal authentication requirements
#
# Use this bundle when running agentd as a local development tool.

package agentd.permissive

import future.keywords.in
import future.keywords.if
import future.keywords.contains

import data.agentd.base
import data.agentd.filesystem
import data.agentd.network
import data.agentd.sandbox

# Main policy entry point
default allow := false

# Aggregate allow rules from sub-policies
allow if { filesystem.allow }
allow if { network.allow }
allow if { sandbox.allow }

# Additional permissive rules for workstation mode

# Allow shell execution for any authenticated user
allow if {
    base.capability == "shell.exec.v1"
    input.identity.subject != ""
}

# Allow shell execution even without authentication in development
allow if {
    base.capability == "shell.exec.v1"
    base.is_workstation
    input.context.development_mode == true
}

# Allow environment variable access
allow if {
    base.capability == "env.get.v1"
    base.is_workstation
}

# Allow process listing
allow if {
    base.capability == "process.list.v1"
    base.is_workstation
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

# Permissive-specific deny rules (very few)

# Still block access to truly sensitive paths
deny contains "Access to shadow file is never allowed" if {
    startswith(base.file_path, "/etc/shadow")
}

deny contains "Access to SSH private keys is never allowed" if {
    contains(base.file_path, "id_rsa")
    not contains(base.file_path, ".pub")
}

deny contains "Access to SSH private keys is never allowed" if {
    contains(base.file_path, "id_ed25519")
    not contains(base.file_path, ".pub")
}

# Final authorization decision
authorization := {
    "allowed": count(deny) == 0,
    "allow_matched": allow,
    "deny_reasons": deny,
    "policy_bundle": "permissive"
} if {
    allow
}

authorization := {
    "allowed": false,
    "allow_matched": false,
    "deny_reasons": deny,
    "policy_bundle": "permissive"
} if {
    not allow
}

# Workstation-specific configuration defaults
default_config := {
    "max_file_size_bytes": 104857600,      # 100MB
    "max_network_timeout_seconds": 300,     # 5 minutes
    "max_shell_duration_seconds": 3600,     # 1 hour
    "allow_network_to_all_hosts": true,
    "allow_file_writes": true,
    "require_authentication": false,
    "audit_level": "minimal"
}

# Audit information
audit := {
    "bundle": "permissive",
    "allow": allow,
    "deny_count": count(deny),
    "capability": base.capability,
    "subject": input.identity.subject
}
