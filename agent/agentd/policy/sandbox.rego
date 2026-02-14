# Agentd Sandbox Management Policy
#
# Policy rules for sandbox lifecycle management:
# - sandbox.create.v1 - Create new sandbox
# - sandbox.attach.v1 - Attach to existing sandbox
# - sandbox.detach.v1 - Detach from sandbox
# - sandbox.terminate.v1 - Terminate sandbox
# - sandbox.introspect.v1 - Query sandbox capabilities
# - sandbox.list.v1 - List available sandboxes

package agentd.sandbox

import future.keywords.in
import future.keywords.if
import future.keywords.contains

import data.agentd.base

# Sandbox management capabilities
sandbox_capabilities := {
    "sandbox.create.v1",
    "sandbox.attach.v1",
    "sandbox.detach.v1",
    "sandbox.terminate.v1",
    "sandbox.introspect.v1",
    "sandbox.list.v1"
}

# Check if this is a sandbox capability
is_sandbox_capability if {
    base.capability in sandbox_capabilities
}

# Read-only sandbox operations
read_only_sandbox := {
    "sandbox.introspect.v1",
    "sandbox.list.v1"
}

# Lifecycle sandbox operations
lifecycle_sandbox := {
    "sandbox.create.v1",
    "sandbox.attach.v1",
    "sandbox.detach.v1",
    "sandbox.terminate.v1"
}

is_read_only_sandbox if {
    base.capability in read_only_sandbox
}

is_lifecycle_sandbox if {
    base.capability in lifecycle_sandbox
}

# Roles that can manage sandboxes
sandbox_admin_roles := {"admin", "sandbox-admin"}
sandbox_user_roles := {"user", "sandbox-user", "admin", "sandbox-admin"}

# Check if identity can manage sandboxes (lifecycle operations)
can_manage_sandboxes if {
    base.has_any_role(sandbox_admin_roles)
}

# Check if identity can use sandboxes (read operations)
can_use_sandboxes if {
    base.has_any_role(sandbox_user_roles)
}

# Allow read-only operations for sandbox users
allow if {
    is_read_only_sandbox
    can_use_sandboxes
}

# Allow lifecycle operations for sandbox admins
allow if {
    is_lifecycle_sandbox
    can_manage_sandboxes
}

# Workstation mode: Allow all sandbox operations for any authenticated user
allow if {
    is_sandbox_capability
    base.is_workstation
    input.identity.subject != ""  # Any authenticated user
}

# Deny sandbox operations for unauthenticated users in server/paranoid mode
deny contains "Sandbox operations require authentication" if {
    is_sandbox_capability
    not base.is_workstation
    input.identity.subject == ""
}

# Deny lifecycle operations for non-admin users in server mode
deny contains "Sandbox lifecycle operations require admin role" if {
    is_lifecycle_sandbox
    base.is_server
    not can_manage_sandboxes
}

# Paranoid mode: Strict sandbox management
deny contains "Sandbox creation is restricted in paranoid mode" if {
    base.capability == "sandbox.create.v1"
    base.is_paranoid
    not input.context.explicit_sandbox_approval
}

# Sandbox resource limits based on profile
max_sandboxes_per_user := {
    "workstation": 10,
    "server": 5,
    "paranoid": 1
}

current_max_sandboxes := max_sandboxes_per_user[base.sandbox_profile]

deny contains msg if {
    base.capability == "sandbox.create.v1"
    input.context.user_sandbox_count >= current_max_sandboxes
    msg := sprintf("Maximum sandboxes per user (%d) exceeded", [current_max_sandboxes])
}

# Sandbox duration limits
max_sandbox_duration_seconds := {
    "workstation": 86400,   # 24 hours
    "server": 3600,         # 1 hour
    "paranoid": 300         # 5 minutes
}

current_max_duration := max_sandbox_duration_seconds[base.sandbox_profile]

deny contains msg if {
    base.capability == "sandbox.create.v1"
    input.intent.params.duration_seconds > current_max_duration
    msg := sprintf("Requested sandbox duration (%d seconds) exceeds maximum (%d seconds)", [input.intent.params.duration_seconds, current_max_duration])
}

# Sandbox memory limits
max_sandbox_memory_mb := {
    "workstation": 4096,    # 4GB
    "server": 1024,         # 1GB
    "paranoid": 256         # 256MB
}

current_max_memory := max_sandbox_memory_mb[base.sandbox_profile]

deny contains msg if {
    base.capability == "sandbox.create.v1"
    input.intent.params.memory_mb > current_max_memory
    msg := sprintf("Requested sandbox memory (%d MB) exceeds maximum (%d MB)", [input.intent.params.memory_mb, current_max_memory])
}

# Prevent termination of sandboxes owned by other users (except admins)
deny contains "Cannot terminate sandbox owned by another user" if {
    base.capability == "sandbox.terminate.v1"
    input.intent.params.sandbox_owner != input.identity.subject
    not can_manage_sandboxes
}

# Isolation profile restrictions
allowed_isolation_profiles := {"minimal", "standard"} if { base.is_workstation }
allowed_isolation_profiles := {"standard", "strict"} if { base.is_server }
allowed_isolation_profiles := {"strict", "paranoid"} if { base.is_paranoid }

deny contains msg if {
    base.capability == "sandbox.create.v1"
    requested_profile := input.intent.params.isolation_profile
    not requested_profile in allowed_isolation_profiles
    msg := sprintf("Isolation profile '%s' is not allowed in %s mode", [requested_profile, base.sandbox_profile])
}

# Audit information for sandbox operations
sandbox_audit_info := {
    "operation": base.capability,
    "sandbox_id": input.intent.params.sandbox_id,
    "is_lifecycle": is_lifecycle_sandbox,
    "profile": base.sandbox_profile,
    "user": input.identity.subject
}
