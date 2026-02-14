use serde::{Deserialize, Serialize};

/// Policy update messages delivered over the control plane.
///
/// Updates are applied in-order by subscribers. `reset` clears previously
/// registered policies either globally or for a specific capability while
/// `remove` drops a single policy by identifier. `upsert` replaces or inserts a
/// policy definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PolicyUpdate {
    /// Insert or replace a policy definition.
    Upsert { policy: OpaPolicy },
    /// Remove a policy definition by id.
    Remove { policy_id: String },
    /// Clear all policies (or those scoped to a capability).
    Reset { capability: Option<String> },
}

/// Declarative OPA policy delivered to the executor.
///
/// Policies are grouped by capability and optionally scoped to a tenant. The
/// Rego entrypoint should return a structured object containing the fields the
/// executor expects (see `executor::policy::PolicyDecisionEnvelope`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpaPolicy {
    /// Stable policy identifier used for updates/removals.
    pub policy_id: String,
    /// Monotonic version number supplied by the control plane.
    pub version: u64,
    /// Capability string (e.g. `fs.read.v1`).
    pub capability: String,
    /// Optional tenant scoping. `None` means policy applies to all tenants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Lower numbers evaluate first. Defaults to `0` when omitted.
    #[serde(default)]
    pub priority: u32,
    /// Fully-qualified entrypoint rule (e.g. `data.smith.allow`).
    pub entrypoint: String,
    /// Rego module text.
    pub module: String,
    /// Optional static data block to load alongside the module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Optional execution limits override returned on allow decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<PolicyLimits>,
    /// Optional scope metadata forwarded on allow decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<serde_json::Value>,
    /// Arbitrary metadata for observability/debugging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Policy-defined execution limit overrides.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyLimits {
    pub cpu_ms_per_100ms: u32,
    pub mem_bytes: u64,
    pub io_bytes: u64,
    pub pids_max: u32,
    pub timeout_ms: u64,
}

impl From<PolicyLimits> for crate::ExecutionLimits {
    fn from(value: PolicyLimits) -> Self {
        Self {
            cpu_ms_per_100ms: value.cpu_ms_per_100ms,
            mem_bytes: value.mem_bytes,
            io_bytes: value.io_bytes,
            pids_max: value.pids_max,
            timeout_ms: value.timeout_ms,
        }
    }
}
