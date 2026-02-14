# Agentd Filesystem Policy
#
# Policy rules for filesystem access capabilities:
# - fs.read.v1 - Read file contents
# - fs.write.v1 - Write file contents
# - fs.list.v1 - List directory contents
# - fs.stat.v1 - Get file metadata
# - fs.delete.v1 - Delete files

package agentd.filesystem

import future.keywords.in
import future.keywords.if
import future.keywords.contains

import data.agentd.base

# Filesystem capabilities
fs_capabilities := {
    "fs.read.v1",
    "fs.write.v1",
    "fs.list.v1",
    "fs.stat.v1",
    "fs.delete.v1"
}

# Check if this is a filesystem capability
is_fs_capability if {
    base.capability in fs_capabilities
}

# Read-only capabilities (safer)
read_only_capabilities := {
    "fs.read.v1",
    "fs.list.v1",
    "fs.stat.v1"
}

# Write capabilities (more dangerous)
write_capabilities := {
    "fs.write.v1",
    "fs.delete.v1"
}

is_read_only if {
    base.capability in read_only_capabilities
}

is_write_operation if {
    base.capability in write_capabilities
}

# Always blocked paths (sensitive system files)
always_blocked_paths := {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/root/**",
    "/var/log/auth.log",
    "/var/log/secure",
    "**/.ssh/id_*",
    "**/.ssh/authorized_keys",
    "**/.gnupg/**",
    "**/.aws/credentials",
    "**/.config/gcloud/**",
    "**/credentials.json",
    "**/*.pem",
    "**/*.key"
}

# Check if path is always blocked
path_is_always_blocked if {
    some pattern in always_blocked_paths
    glob.match(pattern, ["/"], base.file_path)
}

# Deny access to always-blocked paths
deny contains "Access to sensitive system file is blocked" if {
    is_fs_capability
    path_is_always_blocked
}

# Workstation mode allowed directories (user's own directories)
workstation_allowed_read := {
    "/home",
    "/tmp",
    "/var/tmp",
    "/usr/share",
    "/usr/local",
    "/opt"
}

workstation_allowed_write := {
    "/home",
    "/tmp",
    "/var/tmp"
}

# Server mode allowed directories (more restricted)
server_allowed_read := {
    "/tmp/agentd",
    "/var/lib/agentd"
}

server_allowed_write := {
    "/tmp/agentd",
    "/var/lib/agentd/output"
}

# Paranoid mode allowed directories (minimal)
paranoid_allowed_read := {
    "/tmp/agentd/sandbox"
}

paranoid_allowed_write := {
    "/tmp/agentd/sandbox/output"
}

# Get allowed directories based on profile and operation
allowed_read_dirs := workstation_allowed_read if { base.is_workstation }
allowed_read_dirs := server_allowed_read if { base.is_server }
allowed_read_dirs := paranoid_allowed_read if { base.is_paranoid }

allowed_write_dirs := workstation_allowed_write if { base.is_workstation }
allowed_write_dirs := server_allowed_write if { base.is_server }
allowed_write_dirs := paranoid_allowed_write if { base.is_paranoid }

# Allow read operations in allowed directories
allow if {
    is_read_only
    not path_is_always_blocked
    base.path_allowed(base.file_path, allowed_read_dirs)
}

# Allow write operations in allowed directories (with additional checks)
allow if {
    is_write_operation
    not path_is_always_blocked
    base.path_allowed(base.file_path, allowed_write_dirs)
    not base.is_paranoid  # Paranoid mode requires explicit approval
}

# Deny writes in paranoid mode unless explicitly approved
deny contains "Write operations require explicit approval in paranoid mode" if {
    is_write_operation
    base.is_paranoid
    not input.context.explicit_write_approval
}

# Deny operations outside allowed directories
deny contains msg if {
    is_fs_capability
    is_read_only
    not base.path_allowed(base.file_path, allowed_read_dirs)
    msg := sprintf("Read access denied: path %s is outside allowed directories", [base.file_path])
}

deny contains msg if {
    is_fs_capability
    is_write_operation
    not base.path_allowed(base.file_path, allowed_write_dirs)
    msg := sprintf("Write access denied: path %s is outside allowed directories", [base.file_path])
}

# Size limits for read operations
max_read_size_bytes := 10485760 if { base.is_workstation }  # 10MB
max_read_size_bytes := 5242880 if { base.is_server }        # 5MB
max_read_size_bytes := 1048576 if { base.is_paranoid }      # 1MB

deny contains msg if {
    is_read_only
    input.intent.params.max_bytes > max_read_size_bytes
    msg := sprintf("Read size %d exceeds maximum allowed %d bytes", [input.intent.params.max_bytes, max_read_size_bytes])
}

# Audit information for filesystem operations
fs_audit_info := {
    "operation": base.capability,
    "path": base.file_path,
    "is_write": is_write_operation,
    "profile": base.sandbox_profile
}
