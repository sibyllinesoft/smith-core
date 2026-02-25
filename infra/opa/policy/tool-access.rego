package smith.tool_access

import rego.v1

import data.smith.tool_access.roles
import data.smith.tool_access.user_overrides
import data.smith.tool_access.source_restrictions
import data.smith.tool_access.untrusted_allowed_tools

default allow := false

# Untrusted agents: deny everything unless explicitly allowed
allow if {
  input.metadata.trusted == false
  untrusted_allowed_tools[input.tool]
}

# Role default=allow: allowed unless tool is in exceptions (deny list)
allow if {
  _is_trusted
  not _has_user_override
  not _source_denied
  cfg := roles[input.role]
  cfg["default"] == "allow"
  not cfg.exceptions[input.tool]
}

# Role default=deny: allowed only if tool is in exceptions (allow list)
allow if {
  _is_trusted
  not _has_user_override
  not _source_denied
  cfg := roles[input.role]
  cfg["default"] == "deny"
  cfg.exceptions[input.tool]
}

# User + specific tool override
allow if {
  _is_trusted
  not _source_denied
  override := user_overrides[input.user_id]
  override.tools[input.tool] == "allow"
}

# User + global default override (no specific tool rule)
allow if {
  _is_trusted
  not _has_user_tool_rule
  not _source_denied
  override := user_overrides[input.user_id]
  override["default"] == "allow"
}

# Trusted unless metadata.trusted is explicitly false
default _is_trusted := true

_is_trusted := false if {
  input.metadata.trusted == false
}

_has_user_tool_rule if {
  user_overrides[input.user_id].tools[input.tool]
}

_has_user_override if {
  user_overrides[input.user_id]
}

# Source-based restrictions: deny specific tools for specific sources/triggers
_source_denied if {
  source_restrictions[input.source][input.tool]
}
_source_denied if {
  source_restrictions[input.trigger][input.tool]
}
