//! # Smith Protocol Library
//!
//! This crate defines the core message protocols and data structures used throughout
//! the Smith AI-powered execution platform. It provides:
//!
//! - **Intent System**: Structured requests for capability execution with security signatures
//! - **Result System**: Standardized responses with execution metadata and audit trails  
//! - **Event System**: Real-time communication protocols for service coordination
//! - **Capability Definitions**: Type-safe capability specifications and parameter schemas
//! - **Security Context**: Comprehensive audit trails and sandbox isolation metadata
//!
//! ## Architecture Overview
//!
//! Smith follows a strict separation between intelligence (AI agents) and execution (secure runners).
//! All communication flows through NATS JetStream using the protocols defined in this crate:
//!
//! ```text
//! AI Agent → Intent → NATS → Policy Validation → Secure Executor → Result → AI Agent
//! ```
//!
//! ## Key Design Principles
//!
//! - **Zero-Trust Security**: All intents are cryptographically signed and policy-validated
//! - **Comprehensive Auditing**: Every action produces detailed audit trails for compliance
//! - **Capability-Based Model**: Fine-grained permissions using versioned capability strings
//! - **Type Safety**: Strongly typed parameters and results with JSON Schema validation
//! - **Time-Based Ordering**: UUIDv7 identifiers provide distributed ordering guarantees
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use smith_protocol::{Intent, Capability, IntentResult, RunnerMetadata};
//! use serde_json::json;
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! // Create a file read intent
//! let intent = Intent::new(
//!     Capability::FsReadV1,
//!     "production".to_string(),
//!     json!({"path": "/etc/hostname", "max_bytes": 1024}),
//!     30000, // 30 second TTL
//!     "client-public-key".to_string(),
//! );
//!
//! // Results include comprehensive execution metadata
//! let start_time_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
//! let end_time_ns = start_time_ns + 1_000_000; // 1ms later
//! let runner_metadata = RunnerMetadata::empty();
//!
//! let result = IntentResult::success(
//!     intent.id.clone(),
//!     json!({"content": "server.example.com\n"}),
//!     start_time_ns,
//!     end_time_ns,
//!     runner_metadata,
//!     "audit-12345".to_string(),
//! );
//! ```
//!
//! ## Security Model
//!
//! The protocol implements a multi-layer security model:
//!
//! 1. **Cryptographic Signatures**: All intents are signed with Ed25519 keys
//! 2. **Policy Validation**: CUE-based policies validate intents before execution  
//! 3. **Sandbox Isolation**: Multiple isolation layers (Landlock, seccomp, cgroups)
//! 4. **Resource Limits**: CPU, memory, and I/O constraints enforced per capability
//! 5. **Audit Trails**: Complete execution history for compliance and forensics
//!
//! For implementation details, see the specific capability modules and the executor documentation.

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use uuid::Uuid;

#[cfg(feature = "typescript")]
use ts_rs::TS;

/// Protocol version for capability negotiation and compatibility checking.
///
/// This version is incremented when breaking changes are made to the protocol.
/// Clients and servers use this for compatibility verification during handshake.
pub const PROTOCOL_VERSION: u32 = 0;

pub mod benchmark;
pub mod client;
pub mod idempotency;
pub mod negotiation;
pub mod policy;
pub mod policy_abi;
pub mod reasoning;
pub mod result_schema;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
#[serde(tag = "type", content = "data")]
/// Command sent to the core service
pub enum Command {
    /// Initialize service with client capabilities
    Handshake {
        version: u32,
        capabilities: Vec<String>,
    },
    /// Plan execution request
    Plan {
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        request_id: Uuid,
        goal: String,
        context: HashMap<String, String>,
    },
    /// Execute a tool call
    ToolCall {
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        request_id: Uuid,
        tool: String,
        #[cfg_attr(feature = "typescript", ts(type = "unknown"))]
        args: serde_json::Value,
        timeout_ms: Option<u64>,
    },
    /// Load hook configuration
    HookLoad {
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        request_id: Uuid,
        hook_type: String,
        script: String,
    },
    /// Shell command execution
    ShellExec {
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        request_id: Uuid,
        command: String,
        shell: Option<String>,
        cwd: Option<String>,
        env: HashMap<String, String>,
        timeout_ms: Option<u64>,
    },
    /// Request service shutdown
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
#[serde(tag = "type", content = "data")]
/// Event emitted by the core service
pub enum Event {
    /// Service ready with capabilities
    Ready {
        version: u32,
        capabilities: Vec<String>,
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        service_id: Uuid,
    },
    /// State change notification
    StateChange {
        #[cfg_attr(feature = "typescript", ts(type = "string | undefined"))]
        request_id: Option<Uuid>,
        state: ServiceState,
        #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
        timestamp: u64,
    },
    /// Log message
    Log {
        level: LogLevel,
        message: String,
        #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
        timestamp: u64,
        #[cfg_attr(feature = "typescript", ts(type = "string | undefined"))]
        request_id: Option<Uuid>,
    },
    /// Token usage tracking
    TokenUsage {
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        request_id: Uuid,
        #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
        tokens_used: u64,
        #[cfg_attr(feature = "typescript", ts(type = "bigint | undefined"))]
        tokens_remaining: Option<u64>,
    },
    /// Shell command output
    ShellOutput {
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        request_id: Uuid,
        stdout: Option<String>,
        stderr: Option<String>,
        exit_code: Option<i32>,
        finished: bool,
    },
    /// Tool call result
    ToolResult {
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        request_id: Uuid,
        success: bool,
        #[cfg_attr(feature = "typescript", ts(type = "unknown"))]
        result: serde_json::Value,
        error: Option<String>,
    },
    /// Hook execution result
    HookResult {
        #[cfg_attr(feature = "typescript", ts(type = "string"))]
        request_id: Uuid,
        action: HookAction,
    },
    /// Graph/DAG state delta
    GraphDelta {
        #[cfg_attr(feature = "typescript", ts(type = "string | undefined"))]
        request_id: Option<Uuid>,
        nodes_added: Vec<GraphNode>,
        edges_added: Vec<GraphEdge>,
        #[cfg_attr(feature = "typescript", ts(type = "string[]"))]
        nodes_removed: Vec<Uuid>,
        #[cfg_attr(feature = "typescript", ts(type = "string[]"))]
        edges_removed: Vec<Uuid>,
    },
    /// Service error
    Error {
        #[cfg_attr(feature = "typescript", ts(type = "string | undefined"))]
        request_id: Option<Uuid>,
        error_code: String,
        message: String,
        #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Service operational state
pub enum ServiceState {
    Starting,
    Ready,
    Processing,
    Error,
    Shutting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Log levels matching standard conventions
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
#[serde(tag = "type", content = "data")]
/// Hook action result from script execution
pub enum HookAction {
    Allow(serde_json::Value),
    Block { reason: String },
    Transform(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Graph node for DAG visualization
pub struct GraphNode {
    #[cfg_attr(feature = "typescript", ts(type = "string"))]
    pub id: Uuid,
    pub label: String,
    pub node_type: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Graph edge for DAG visualization
pub struct GraphEdge {
    #[cfg_attr(feature = "typescript", ts(type = "string"))]
    pub id: Uuid,
    #[cfg_attr(feature = "typescript", ts(type = "string"))]
    pub from: Uuid,
    #[cfg_attr(feature = "typescript", ts(type = "string"))]
    pub to: Uuid,
    pub label: Option<String>,
    pub edge_type: String,
}

/// Capability strings for handshake negotiation
pub mod capabilities {
    pub const SHELL_EXEC: &str = "shell_exec";
    pub const HOOKS_JS: &str = "hooks_js";
    pub const HOOKS_RUST: &str = "hooks_rust";
    pub const REPLAY: &str = "replay";
    pub const NATS: &str = "nats";
    pub const TRACING: &str = "tracing";
}

// JetStream-native protocol definitions for Smith executor platform

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
#[serde(rename_all = "snake_case")]
/// Intent capabilities enum for JetStream execution
pub enum Capability {
    #[serde(rename = "fs.read.v1")]
    FsReadV1,
    #[serde(rename = "http.fetch.v1")]
    HttpFetchV1,
    #[serde(rename = "fs.write.v1")]
    FsWriteV1,
    #[serde(rename = "git.clone.v1")]
    GitCloneV1,
    #[serde(rename = "archive.read.v1")]
    ArchiveReadV1,
    #[serde(rename = "sqlite.query.v1")]
    SqliteQueryV1,
    #[serde(rename = "bench.report.v1")]
    BenchReportV1,
    #[serde(rename = "shell.exec.v1")]
    ShellExec,
    /// Alias for HttpFetchV1 (for test compatibility)
    HttpFetch,
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Capability::FsReadV1 => write!(f, "fs.read.v1"),
            Capability::HttpFetchV1 => write!(f, "http.fetch.v1"),
            Capability::FsWriteV1 => write!(f, "fs.write.v1"),
            Capability::GitCloneV1 => write!(f, "git.clone.v1"),
            Capability::ArchiveReadV1 => write!(f, "archive.read.v1"),
            Capability::SqliteQueryV1 => write!(f, "sqlite.query.v1"),
            Capability::BenchReportV1 => write!(f, "bench.report.v1"),
            Capability::ShellExec => write!(f, "shell.exec.v1"),
            Capability::HttpFetch => write!(f, "http.fetch.v1"),
        }
    }
}

impl std::str::FromStr for Capability {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_capability_string(s)
    }
}

impl Capability {
    /// Parse a capability string into a Capability enum
    fn parse_capability_string(s: &str) -> Result<Self, anyhow::Error> {
        match s {
            "fs.read.v1" => Ok(Capability::FsReadV1),
            "http.fetch.v1" => Ok(Capability::HttpFetchV1),
            "fs.write.v1" => Ok(Capability::FsWriteV1),
            "git.clone.v1" => Ok(Capability::GitCloneV1),
            "archive.read.v1" => Ok(Capability::ArchiveReadV1),
            "sqlite.query.v1" => Ok(Capability::SqliteQueryV1),
            "bench.report.v1" => Ok(Capability::BenchReportV1),
            "shell.exec.v1" => Ok(Capability::ShellExec),
            "http.fetch" => Ok(Capability::HttpFetch), // For test compatibility
            _ => Err(anyhow::anyhow!("Unknown capability: {}", s)),
        }
    }

    /// Get all available capabilities as strings
    pub fn all_capabilities() -> Vec<&'static str> {
        vec![
            "fs.read.v1",
            "http.fetch.v1",
            "fs.write.v1",
            "git.clone.v1",
            "archive.read.v1",
            "sqlite.query.v1",
            "bench.report.v1",
            "shell.exec.v1",
        ]
    }

    /// Check if a capability string is valid
    pub fn is_valid_capability(s: &str) -> bool {
        Self::all_capabilities().contains(&s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Intent sent to executors via JetStream
pub struct Intent {
    /// Unique intent identifier (UUIDv7 for time ordering)
    pub id: String,
    /// Capability being requested
    pub capability: Capability,
    /// Routing domain/shard
    pub domain: String,
    /// Capability-specific parameters
    #[cfg_attr(feature = "typescript", ts(type = "unknown"))]
    pub params: serde_json::Value,
    /// Creation timestamp in nanoseconds
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub created_at_ns: u128,
    /// Time-to-live in milliseconds
    pub ttl_ms: u32,
    /// Nonce for deduplication and replay defense
    pub nonce: String,
    /// Public key of the signer (base64)
    pub signer: String,
    /// Detached signature of canonical intent body (base64)
    pub signature_b64: String,
    /// Additional metadata for the intent
    #[cfg_attr(feature = "typescript", ts(type = "Record<string, unknown>"))]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

impl Intent {
    /// Verify the signature of this intent using the embedded signer public key.
    pub fn verify_signature(&self) -> anyhow::Result<bool> {
        if self.signature_b64.trim().is_empty() {
            return Ok(false);
        }

        let signer_bytes = BASE64
            .decode(self.signer.trim())
            .context("Failed to decode signer public key from base64")?;

        let signer_array: [u8; PUBLIC_KEY_LENGTH] = signer_bytes.try_into().map_err(|_| {
            anyhow::anyhow!("Signer public key must be {PUBLIC_KEY_LENGTH} bytes after decoding")
        })?;

        let verifying_key = VerifyingKey::from_bytes(&signer_array)
            .map_err(|err| anyhow::anyhow!("Invalid signer public key: {err}"))?;

        self.verify_with_key(&verifying_key)
    }

    /// Verify the signature of this intent with a supplied verifying key.
    pub fn verify_with_key(&self, verifying_key: &VerifyingKey) -> anyhow::Result<bool> {
        if self.signature_b64.trim().is_empty() {
            return Ok(false);
        }

        let signature_bytes = BASE64
            .decode(self.signature_b64.trim())
            .context("Failed to decode intent signature from base64")?;

        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|err| anyhow::anyhow!("Invalid signature format: {err}"))?;

        let canonical_json = self.canonical_json()?;

        match verifying_key.verify(canonical_json.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Result of intent execution
pub struct IntentResult {
    /// ID of the original intent
    pub intent_id: String,
    /// Execution status
    pub status: ExecutionStatus,
    /// Success output (if status is Ok)
    #[cfg_attr(feature = "typescript", ts(type = "unknown | undefined"))]
    pub output: Option<serde_json::Value>,
    /// Error details (if status is Error/Denied/Timeout/Killed)
    pub error: Option<ExecutionError>,
    /// When execution started (nanoseconds)
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub started_at_ns: u128,
    /// When execution finished (nanoseconds)
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub finished_at_ns: u128,
    /// Runtime metadata from the executor
    pub runner_meta: RunnerMetadata,
    /// Reference to audit log entry
    pub audit_ref: AuditRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Reference to an audit log entry
pub struct AuditRef {
    /// Audit log entry ID
    pub id: String,
    /// Timestamp of the audit entry
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub timestamp: u64,
    /// Audit trail hash for integrity verification
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
#[serde(rename_all = "lowercase")]
/// Execution status enum
pub enum ExecutionStatus {
    Ok,
    Error,
    Denied,
    Timeout,
    Killed,
    /// Alias for Ok (for test compatibility)
    Success,
    /// Alias for Error (for test compatibility)
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Error details for failed executions
pub struct ExecutionError {
    /// Error code
    pub code: String,
    /// Human-readable error message
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Runtime metadata from executor
pub struct RunnerMetadata {
    /// Process ID of the runner
    pub pid: u32,
    /// CPU time used in milliseconds
    pub cpu_ms: u32,
    /// Maximum RSS in kilobytes
    pub max_rss_kb: u32,
    /// Capability digest used for bundle enforcement (optional for compatibility)
    pub capability_digest: Option<String>,
}

impl RunnerMetadata {
    /// Create empty metadata (used for denied/failed executions)
    pub fn empty() -> Self {
        Self {
            pid: 0,
            cpu_ms: 0,
            max_rss_kb: 0,
            capability_digest: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Audit log entry for compliance and debugging
pub struct AuditEntry {
    /// Intent that was processed
    pub intent_id: String,
    /// Execution result summary
    pub result_status: ExecutionStatus,
    /// Timestamp when audit was created
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub timestamp_ns: u128,
    /// Executor instance that processed this intent
    pub executor_id: String,
    /// Policy decisions made during admission
    pub policy_decisions: Vec<PolicyDecision>,
    /// Security context
    pub security_context: SecurityContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Policy decision made during admission
pub struct PolicyDecision {
    /// Policy rule that was evaluated
    pub rule_name: String,
    /// Result of the policy evaluation
    pub decision: PolicyResult,
    /// Human-readable reason for the decision
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
#[serde(rename_all = "lowercase")]
/// Policy evaluation result
pub enum PolicyResult {
    Allow,
    Deny,
    Transform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Security context for audit trail
pub struct SecurityContext {
    /// Sandbox mode used for execution
    pub sandbox_mode: Option<SandboxMode>,
    /// User namespace ID
    pub user_ns: Option<u32>,
    /// Mount namespace ID
    pub mount_ns: Option<u32>,
    /// PID namespace ID
    pub pid_ns: Option<u32>,
    /// Network namespace ID
    pub net_ns: Option<u32>,
    /// Cgroup path
    pub cgroup_path: Option<String>,
    /// Landlock restrictions applied
    pub landlock_enabled: bool,
    /// Seccomp filter applied
    pub seccomp_enabled: bool,
    /// Allow-list entries accessed during execution
    pub allowlist_hits: Option<Vec<AllowlistHit>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
#[serde(rename_all = "lowercase")]
/// Sandbox execution modes
pub enum SandboxMode {
    /// Full sandbox with all security features enabled
    Full,
    /// Partial sandbox with limited features (development/testing)
    Demo,
    /// No sandboxing (unsafe, for compatibility only)
    Unsafe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(
    feature = "typescript",
    ts(export, export_to = "client/src/lib/smith-protocol/generated.ts")
)]
/// Allow-list access record
pub struct AllowlistHit {
    /// Type of resource accessed
    pub resource_type: String,
    /// Resource identifier (path, URL, etc.)
    pub resource_id: String,
    /// Access operation (read, write, execute, etc.)
    pub operation: String,
    /// Timestamp of access
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub timestamp_ns: u128,
}

/// Resource usage metrics for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Peak memory usage in KB
    pub peak_memory_kb: u32,
    /// CPU time consumed in milliseconds
    pub cpu_time_ms: u32,
    /// Wall clock time for execution in milliseconds
    pub wall_time_ms: u32,
    /// Number of file descriptors used
    pub fd_count: u32,
    /// Number of bytes read from disk
    pub disk_read_bytes: u64,
    /// Number of bytes written to disk
    pub disk_write_bytes: u64,
    /// Number of bytes sent over network
    pub network_tx_bytes: u64,
    /// Number of bytes received over network
    pub network_rx_bytes: u64,
}

/// Capability specification for discovery and documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct CapabilitySpec {
    /// Capability name (e.g., "fs.read.v1")
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// JSON schema for parameter validation
    pub params_schema: serde_json::Value,
    /// Example parameters
    pub example_params: serde_json::Value,
    /// Resource requirements and limits
    pub resource_requirements: ResourceRequirements,
    /// Security implications and recommendations
    pub security_notes: Vec<String>,
}

/// Resource requirements for a capability
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct ResourceRequirements {
    /// Typical CPU time required (ms)
    pub cpu_ms_typical: u32,
    /// Maximum memory usage (KB)
    pub memory_kb_max: u32,
    /// Network access required
    pub network_access: bool,
    /// File system access required
    pub filesystem_access: bool,
    /// External command execution required
    pub external_commands: bool,
}

/// Resource limits enforced during intent execution
///
/// These limits provide defense-in-depth resource isolation and are enforced
/// by the secure executor's jailer. Violations result in execution termination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct ExecutionLimits {
    /// CPU time limit per 100ms interval
    pub cpu_ms_per_100ms: u32,
    /// Memory limit in bytes
    pub mem_bytes: u64,
    /// I/O limit in bytes
    pub io_bytes: u64,
    /// Maximum number of processes
    pub pids_max: u32,
    /// Total timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            cpu_ms_per_100ms: 50,         // 50% CPU usage
            mem_bytes: 128 * 1024 * 1024, // 128MB
            io_bytes: 10 * 1024 * 1024,   // 10MB
            pids_max: 10,
            timeout_ms: 30000, // 30 seconds
        }
    }
}

/// Enhanced audit event (replaces AuditEntry for better compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Intent that was processed
    pub intent_id: String,
    /// Execution result summary
    pub result_status: ExecutionStatus,
    /// Timestamp when audit was created
    pub timestamp_ns: u128,
    /// Executor instance that processed this intent
    pub executor_id: String,
    /// Policy decisions made during admission
    pub policy_decisions: Vec<PolicyDecision>,
    /// Security context
    pub security_context: SecurityContext,
    /// Resource usage metrics
    pub resource_usage: Option<ResourceUsage>,
}

/// Capability-specific parameter types
pub mod params {
    use super::*;

    /// Parameters for fs.read.v1 capability
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
    pub struct FsReadV1 {
        /// File path to read
        pub path: String,
        /// Maximum bytes to read (optional)
        pub max_bytes: Option<u64>,
        /// Whether to follow symlinks
        pub follow_symlinks: Option<bool>,
    }

    /// Parameters for http.fetch.v1 capability
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
    pub struct HttpFetchV1 {
        /// URL to fetch
        pub url: String,
        /// HTTP method (default: GET)
        pub method: Option<String>,
        /// HTTP headers
        pub headers: Option<HashMap<String, String>>,
        /// Request body (for POST/PUT)
        pub body: Option<String>,
        /// Timeout in milliseconds
        pub timeout_ms: Option<u32>,
    }

    /// Parameters for archive.read.v1 capability
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
    pub struct ArchiveReadV1 {
        /// Archive file path to read
        pub path: String,
        /// Whether to extract file contents (default: false, metadata only)
        pub extract_content: Option<bool>,
    }

    /// Parameters for sqlite.query.v1 capability
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
    pub struct SqliteQueryV1 {
        /// SQLite database file path
        pub database_path: String,
        /// SQL query to execute (read-only)
        pub query: String,
        /// Query parameters for prepared statements
        pub params: Option<Vec<serde_json::Value>>,
        /// Maximum rows to return (default: 1000)
        pub max_rows: Option<u32>,
        /// Query timeout in milliseconds (default: 30000)
        pub timeout_ms: Option<u32>,
    }

    /// Parameters for bench.report.v1 capability
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
    pub struct BenchReportV1 {
        /// Benchmark name/identifier
        pub benchmark_name: String,
        /// Performance metrics to report
        pub metrics: HashMap<String, f64>,
        /// Benchmark metadata
        pub metadata: Option<HashMap<String, serde_json::Value>>,
        /// Historical data retention days (default: 30)
        pub retention_days: Option<u32>,
    }

    /// Parameters for shell.exec.v1 capability
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
    pub struct ShellExecV1 {
        /// Command to execute
        pub command: String,
        /// Command arguments
        pub args: Option<Vec<String>>,
        /// Environment variables
        pub env: Option<HashMap<String, String>>,
        /// Working directory
        pub cwd: Option<String>,
        /// Timeout in milliseconds (default: 30000, max: 600000)
        pub timeout_ms: Option<u32>,
        /// Data to write to stdin
        pub stdin: Option<String>,
    }
}

/// Intent creation and signing utilities
impl Intent {
    /// Create a new intent with the given parameters
    pub fn new(
        capability: Capability,
        domain: String,
        params: serde_json::Value,
        ttl_ms: u32,
        signer: String,
    ) -> Self {
        let id = Self::generate_intent_id();
        let nonce = Self::generate_nonce();
        let created_at_ns = Self::current_timestamp_ns();

        Self {
            id,
            capability,
            domain,
            params,
            created_at_ns,
            ttl_ms,
            nonce,
            signer,
            signature_b64: String::new(), // Will be set by signing process
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Generate a time-ordered intent ID using UUIDv7
    fn generate_intent_id() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    /// Generate a random nonce for deduplication
    fn generate_nonce() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Get current timestamp in nanoseconds since epoch
    fn current_timestamp_ns() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    /// Get canonical JSON representation for signing
    pub fn canonical_json(&self) -> anyhow::Result<String> {
        let canonical = self.create_unsigned_copy();
        let sorted_json = Self::sort_json_keys(canonical)?;
        Ok(serde_json::to_string(&sorted_json)?)
    }

    /// Create a copy of the intent without signature for canonical form
    fn create_unsigned_copy(&self) -> Self {
        let mut canonical = self.clone();
        canonical.signature_b64 = String::new();
        canonical
    }

    /// Sort JSON keys for deterministic output
    fn sort_json_keys(value: impl Serialize) -> anyhow::Result<serde_json::Value> {
        let mut json = serde_json::to_value(value)?;
        if let serde_json::Value::Object(ref mut map) = json {
            // Remove signature_b64 field completely for canonical form
            map.remove("signature_b64");

            let sorted: BTreeMap<_, _> = map.iter().collect();
            *map = sorted
                .into_iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
        }
        Ok(json)
    }

    /// Check if intent has expired based on current time
    pub fn is_expired(&self) -> bool {
        let now_ns = Self::current_timestamp_ns();
        let expiry_ns = self.created_at_ns + self.ttl_as_nanoseconds();
        now_ns > expiry_ns
    }

    /// Convert TTL from milliseconds to nanoseconds
    fn ttl_as_nanoseconds(&self) -> u128 {
        (self.ttl_ms as u128) * 1_000_000
    }

    /// Get the subject pattern for this intent
    pub fn subject(&self) -> String {
        smith_bus::builders::IntentSubject::with_domain(&self.capability.to_string(), &self.domain)
    }

    /// Get the result subject for this intent
    pub fn result_subject(&self) -> String {
        smith_bus::builders::ResultSubject::for_intent(&self.id)
    }
}

impl IntentResult {
    /// Create a successful result
    pub fn success(
        intent_id: String,
        output: serde_json::Value,
        started_at_ns: u128,
        finished_at_ns: u128,
        runner_meta: RunnerMetadata,
        audit_ref: String,
    ) -> Self {
        Self::create_result(
            intent_id,
            ExecutionStatus::Ok,
            Some(output),
            None,
            started_at_ns,
            finished_at_ns,
            runner_meta,
            audit_ref,
        )
    }

    /// Create an error result
    pub fn error(
        intent_id: String,
        error_code: String,
        error_message: String,
        started_at_ns: u128,
        finished_at_ns: u128,
        runner_meta: RunnerMetadata,
        audit_ref: String,
    ) -> Self {
        let error = Some(ExecutionError {
            code: error_code,
            message: error_message,
        });

        Self::create_result(
            intent_id,
            ExecutionStatus::Error,
            None,
            error,
            started_at_ns,
            finished_at_ns,
            runner_meta,
            audit_ref,
        )
    }

    /// Create a denied result
    pub fn denied(intent_id: String, reason: String, audit_ref: String) -> Self {
        let now_ns = Intent::current_timestamp_ns();
        let error = Some(ExecutionError {
            code: "POLICY_DENIED".to_string(),
            message: reason,
        });
        let empty_metadata = RunnerMetadata::empty();

        Self::create_result(
            intent_id,
            ExecutionStatus::Denied,
            None,
            error,
            now_ns,
            now_ns,
            empty_metadata,
            audit_ref,
        )
    }

    /// Create a result with the given parameters
    #[allow(clippy::too_many_arguments)]
    fn create_result(
        intent_id: String,
        status: ExecutionStatus,
        output: Option<serde_json::Value>,
        error: Option<ExecutionError>,
        started_at_ns: u128,
        finished_at_ns: u128,
        runner_meta: RunnerMetadata,
        audit_ref: String,
    ) -> Self {
        Self {
            intent_id,
            status,
            output,
            error,
            started_at_ns,
            finished_at_ns,
            runner_meta,
            audit_ref: AuditRef {
                id: audit_ref,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                hash: "placeholder".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use serde_json::json;

    #[test]
    fn test_capability_serialization() {
        let cap = Capability::FsReadV1;
        let serialized = serde_json::to_string(&cap).unwrap();
        assert_eq!(serialized, r#""fs.read.v1""#);

        let deserialized: Capability = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, cap);
    }

    #[test]
    fn test_capability_from_str() {
        assert_eq!(
            "fs.read.v1".parse::<Capability>().unwrap(),
            Capability::FsReadV1
        );
        assert_eq!(
            "http.fetch.v1".parse::<Capability>().unwrap(),
            Capability::HttpFetchV1
        );
        assert!("invalid".parse::<Capability>().is_err());
    }

    #[test]
    fn test_intent_creation() {
        let intent = Intent::new(
            Capability::FsReadV1,
            "test".to_string(),
            json!({"path": "/etc/hostname"}),
            30000,
            "test-signer".to_string(),
        );

        assert!(!intent.id.is_empty());
        assert_eq!(intent.capability, Capability::FsReadV1);
        assert_eq!(intent.domain, "test");
        assert_eq!(intent.ttl_ms, 30000);
        assert!(!intent.nonce.is_empty());
        assert_eq!(intent.signer, "test-signer");
    }

    #[test]
    fn test_intent_subjects() {
        let intent = Intent::new(
            Capability::HttpFetchV1,
            "web".to_string(),
            json!({"url": "https://example.com"}),
            10000,
            "test-signer".to_string(),
        );

        assert_eq!(intent.subject(), "smith.intents.http.fetch.v1.web");
        assert_eq!(
            intent.result_subject(),
            format!("smith.results.{}", intent.id)
        );
    }

    #[test]
    fn test_intent_expiration() {
        let mut intent = Intent::new(
            Capability::FsReadV1,
            "test".to_string(),
            json!({"path": "/tmp/test"}),
            100, // 100ms TTL
            "test-signer".to_string(),
        );

        // Should not be expired immediately
        assert!(!intent.is_expired());

        // Simulate expired intent by setting old timestamp
        intent.created_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            - 200_000_000; // 200ms ago

        assert!(intent.is_expired());
    }

    #[test]
    fn test_intent_canonical_json() {
        let intent = Intent::new(
            Capability::FsReadV1,
            "test".to_string(),
            json!({"path": "/etc/hostname", "max_bytes": 1024}),
            30000,
            "test-signer".to_string(),
        );

        let canonical = intent.canonical_json().unwrap();

        // Should be valid JSON
        let _: serde_json::Value = serde_json::from_str(&canonical).unwrap();

        // Should not contain signature
        assert!(!canonical.contains("signature_b64"));
    }

    #[test]
    fn test_intent_signature_verification() {
        use ed25519_dalek::SigningKey;

        let signing_bytes = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&signing_bytes);
        let verifying_key = signing_key.verifying_key();

        let mut intent = Intent::new(
            Capability::FsReadV1,
            "test".to_string(),
            json!({"path": "/etc/hostname"}),
            30_000,
            BASE64.encode(verifying_key.to_bytes()),
        );

        let canonical = intent.canonical_json().unwrap();
        let signature = signing_key.sign(canonical.as_bytes());
        intent.signature_b64 = BASE64.encode(signature.to_bytes());

        assert!(intent.verify_signature().unwrap());

        let mut invalid_signature = signature.to_bytes();
        invalid_signature[0] ^= 0xFF;
        intent.signature_b64 = BASE64.encode(invalid_signature);
        assert!(!intent.verify_signature().unwrap());
    }

    #[test]
    fn test_intent_result_creation() {
        let intent_id = "test-intent-123".to_string();
        let audit_ref = "audit-ref-456".to_string();
        let runner_meta = RunnerMetadata {
            pid: 1234,
            cpu_ms: 500,
            max_rss_kb: 2048,
            capability_digest: Some("test-capability-digest".to_string()),
        };

        // Test successful result
        let success_result = IntentResult::success(
            intent_id.clone(),
            json!({"content": "file contents"}),
            1640995200000000000,
            1640995201000000000,
            runner_meta.clone(),
            audit_ref.clone(),
        );

        assert_eq!(success_result.intent_id, intent_id);
        assert!(matches!(success_result.status, ExecutionStatus::Ok));
        assert!(success_result.output.is_some());
        assert!(success_result.error.is_none());

        // Test error result
        let error_result = IntentResult::error(
            intent_id.clone(),
            "FILE_NOT_FOUND".to_string(),
            "File does not exist".to_string(),
            1640995200000000000,
            1640995201000000000,
            runner_meta.clone(),
            audit_ref.clone(),
        );

        assert_eq!(error_result.intent_id, intent_id);
        assert!(matches!(error_result.status, ExecutionStatus::Error));
        assert!(error_result.output.is_none());
        assert!(error_result.error.is_some());
        assert_eq!(error_result.error.as_ref().unwrap().code, "FILE_NOT_FOUND");

        // Test denied result
        let denied_result = IntentResult::denied(
            intent_id.clone(),
            "Policy violation: unauthorized path".to_string(),
            audit_ref.clone(),
        );

        assert_eq!(denied_result.intent_id, intent_id);
        assert!(matches!(denied_result.status, ExecutionStatus::Denied));
        assert!(denied_result.error.is_some());
        assert_eq!(denied_result.error.as_ref().unwrap().code, "POLICY_DENIED");
    }

    #[test]
    fn test_fs_read_params() {
        let params = params::FsReadV1 {
            path: "/etc/hostname".to_string(),
            max_bytes: Some(1024),
            follow_symlinks: Some(false),
        };

        let json = serde_json::to_value(&params).unwrap();
        let deserialized: params::FsReadV1 = serde_json::from_value(json).unwrap();

        assert_eq!(deserialized.path, "/etc/hostname");
        assert_eq!(deserialized.max_bytes, Some(1024));
        assert_eq!(deserialized.follow_symlinks, Some(false));
    }

    #[test]
    fn test_http_fetch_params() {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Smith/1.0".to_string());

        let params = params::HttpFetchV1 {
            url: "https://api.example.com/data".to_string(),
            method: Some("POST".to_string()),
            headers: Some(headers.clone()),
            body: Some(r#"{"key":"value"}"#.to_string()),
            timeout_ms: Some(5000),
        };

        let json = serde_json::to_value(&params).unwrap();
        let deserialized: params::HttpFetchV1 = serde_json::from_value(json).unwrap();

        assert_eq!(deserialized.url, "https://api.example.com/data");
        assert_eq!(deserialized.method, Some("POST".to_string()));
        assert_eq!(deserialized.headers, Some(headers));
        assert_eq!(deserialized.timeout_ms, Some(5000));
    }

    #[test]
    fn test_audit_entry_structure() {
        let policy_decision = PolicyDecision {
            rule_name: "path_allowlist".to_string(),
            decision: PolicyResult::Allow,
            reason: "Path is in allowed list".to_string(),
        };

        let security_context = SecurityContext {
            sandbox_mode: Some(SandboxMode::Full),
            user_ns: Some(1001),
            mount_ns: Some(2002),
            pid_ns: Some(3003),
            net_ns: Some(4004),
            cgroup_path: Some("/sys/fs/cgroup/smith/executor-123".to_string()),
            landlock_enabled: true,
            seccomp_enabled: true,
            allowlist_hits: None,
        };

        let audit_entry = AuditEntry {
            intent_id: "intent-123".to_string(),
            result_status: ExecutionStatus::Ok,
            timestamp_ns: 1640995200000000000,
            executor_id: "executor-001".to_string(),
            policy_decisions: vec![policy_decision],
            security_context,
        };

        // Test serialization roundtrip
        let json = serde_json::to_string(&audit_entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.intent_id, "intent-123");
        assert_eq!(deserialized.executor_id, "executor-001");
        assert_eq!(deserialized.policy_decisions.len(), 1);
        assert!(deserialized.security_context.landlock_enabled);
    }

    #[test]
    fn test_all_capability_variants() {
        // Test that all capability variants can be created and have proper string representations
        let capabilities = vec![
            (Capability::FsReadV1, "fs.read.v1"),
            (Capability::HttpFetchV1, "http.fetch.v1"),
            (Capability::FsWriteV1, "fs.write.v1"),
            (Capability::GitCloneV1, "git.clone.v1"),
            (Capability::ArchiveReadV1, "archive.read.v1"),
            (Capability::SqliteQueryV1, "sqlite.query.v1"),
            (Capability::BenchReportV1, "bench.report.v1"),
        ];

        for (capability, expected_string) in capabilities {
            // Test Display trait
            assert_eq!(capability.to_string(), expected_string);

            // Test FromStr trait
            let parsed: Capability = expected_string.parse().unwrap();
            assert_eq!(parsed, capability);

            // Test serialization roundtrip
            let serialized = serde_json::to_string(&capability).unwrap();
            let deserialized: Capability = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, capability);
        }
    }

    #[test]
    fn test_capability_all_capabilities() {
        let all_caps = Capability::all_capabilities();
        assert_eq!(all_caps.len(), 8);

        // Verify all expected capabilities are present
        assert!(all_caps.contains(&"fs.read.v1"));
        assert!(all_caps.contains(&"http.fetch.v1"));
        assert!(all_caps.contains(&"fs.write.v1"));
        assert!(all_caps.contains(&"git.clone.v1"));
        assert!(all_caps.contains(&"archive.read.v1"));
        assert!(all_caps.contains(&"sqlite.query.v1"));
        assert!(all_caps.contains(&"bench.report.v1"));
        assert!(all_caps.contains(&"shell.exec.v1"));
    }

    #[test]
    fn test_capability_is_valid_capability() {
        // Test valid capabilities
        assert!(Capability::is_valid_capability("fs.read.v1"));
        assert!(Capability::is_valid_capability("http.fetch.v1"));
        assert!(Capability::is_valid_capability("sqlite.query.v1"));

        // Test invalid capabilities
        assert!(!Capability::is_valid_capability("invalid.capability"));
        assert!(!Capability::is_valid_capability(""));
        assert!(!Capability::is_valid_capability("fs.read.v2")); // Wrong version
    }

    #[test]
    fn test_execution_status_variants() {
        let statuses = vec![
            ExecutionStatus::Ok,
            ExecutionStatus::Error,
            ExecutionStatus::Denied,
            ExecutionStatus::Timeout,
            ExecutionStatus::Killed,
        ];

        for status in statuses {
            // Test serialization roundtrip
            let serialized = serde_json::to_string(&status).unwrap();
            let deserialized: ExecutionStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, status);

            // Test Debug trait
            let debug_str = format!("{:?}", status);
            assert!(!debug_str.is_empty());
        }
    }

    #[test]
    fn test_execution_error_structure() {
        let error = ExecutionError {
            code: "FILE_NOT_FOUND".to_string(),
            message: "The specified file could not be found".to_string(),
        };

        // Test serialization
        let json = serde_json::to_string(&error).unwrap();
        let deserialized: ExecutionError = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.code, "FILE_NOT_FOUND");
        assert_eq!(
            deserialized.message,
            "The specified file could not be found"
        );

        // Test Clone trait
        let cloned = error.clone();
        assert_eq!(cloned.code, error.code);
        assert_eq!(cloned.message, error.message);
    }

    #[test]
    fn test_runner_metadata() {
        let metadata = RunnerMetadata {
            pid: 12345,
            cpu_ms: 1500,
            max_rss_kb: 8192,
            capability_digest: Some("sha256:abcd1234".to_string()),
        };

        // Test serialization roundtrip
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: RunnerMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.pid, 12345);
        assert_eq!(deserialized.cpu_ms, 1500);
        assert_eq!(deserialized.max_rss_kb, 8192);
        assert_eq!(
            deserialized.capability_digest,
            Some("sha256:abcd1234".to_string())
        );

        // Test empty metadata
        let empty = RunnerMetadata::empty();
        assert_eq!(empty.pid, 0);
        assert_eq!(empty.cpu_ms, 0);
        assert_eq!(empty.max_rss_kb, 0);
        assert_eq!(empty.capability_digest, None);
    }

    #[test]
    fn test_sandbox_mode_variants() {
        let modes = vec![
            (SandboxMode::Full, "full"),
            (SandboxMode::Demo, "demo"),
            (SandboxMode::Unsafe, "unsafe"),
        ];

        for (mode, expected_string) in modes {
            // Test serialization
            let serialized = serde_json::to_string(&mode).unwrap();
            assert_eq!(serialized, format!("\"{}\"", expected_string));

            // Test deserialization
            let deserialized: SandboxMode = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, mode);
        }
    }

    #[test]
    fn test_policy_result_variants() {
        let results = vec![
            (PolicyResult::Allow, "allow"),
            (PolicyResult::Deny, "deny"),
            (PolicyResult::Transform, "transform"),
        ];

        for (result, expected_string) in results {
            // Test serialization
            let serialized = serde_json::to_string(&result).unwrap();
            assert_eq!(serialized, format!("\"{}\"", expected_string));

            // Test deserialization
            let deserialized: PolicyResult = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, result);
        }
    }

    #[test]
    fn test_policy_decision_structure() {
        let decision = PolicyDecision {
            rule_name: "file_access_check".to_string(),
            decision: PolicyResult::Allow,
            reason: "File is within allowed directory".to_string(),
        };

        // Test serialization roundtrip
        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: PolicyDecision = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.rule_name, "file_access_check");
        assert_eq!(deserialized.decision, PolicyResult::Allow);
        assert_eq!(deserialized.reason, "File is within allowed directory");
    }

    #[test]
    fn test_security_context_comprehensive() {
        // Test full security context
        let full_context = SecurityContext {
            sandbox_mode: Some(SandboxMode::Full),
            user_ns: Some(1001),
            mount_ns: Some(2002),
            pid_ns: Some(3003),
            net_ns: Some(4004),
            cgroup_path: Some("/sys/fs/cgroup/smith/test-123".to_string()),
            landlock_enabled: true,
            seccomp_enabled: true,
            allowlist_hits: Some(vec![AllowlistHit {
                resource_type: "file".to_string(),
                resource_id: "/etc/hostname".to_string(),
                operation: "read".to_string(),
                timestamp_ns: 1640995200000000000,
            }]),
        };

        // Test serialization roundtrip
        let json = serde_json::to_string(&full_context).unwrap();
        let deserialized: SecurityContext = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.sandbox_mode, Some(SandboxMode::Full));
        assert_eq!(deserialized.user_ns, Some(1001));
        assert!(deserialized.landlock_enabled);
        assert_eq!(deserialized.allowlist_hits.as_ref().unwrap().len(), 1);

        // Test minimal security context
        let minimal_context = SecurityContext {
            sandbox_mode: None,
            user_ns: None,
            mount_ns: None,
            pid_ns: None,
            net_ns: None,
            cgroup_path: None,
            landlock_enabled: false,
            seccomp_enabled: false,
            allowlist_hits: None,
        };

        let minimal_json = serde_json::to_string(&minimal_context).unwrap();
        let minimal_deserialized: SecurityContext = serde_json::from_str(&minimal_json).unwrap();

        assert_eq!(minimal_deserialized.sandbox_mode, None);
        assert!(!minimal_deserialized.landlock_enabled);
        assert_eq!(minimal_deserialized.allowlist_hits, None);
    }

    #[test]
    fn test_intent_result_timeout_and_killed() {
        let intent_id = "timeout-test-123".to_string();
        let audit_ref = "audit-timeout-456".to_string();
        let runner_meta = RunnerMetadata::empty();

        // Test timeout result creation (utility function)
        let start_time = 1640995200000000000;
        let end_time = 1640995230000000000; // 30 seconds later

        let timeout_result = IntentResult::create_result(
            intent_id.clone(),
            ExecutionStatus::Timeout,
            None,
            Some(ExecutionError {
                code: "EXECUTION_TIMEOUT".to_string(),
                message: "Execution exceeded maximum allowed time".to_string(),
            }),
            start_time,
            end_time,
            runner_meta.clone(),
            audit_ref.clone(),
        );

        assert_eq!(timeout_result.status, ExecutionStatus::Timeout);
        assert!(timeout_result.error.is_some());
        assert_eq!(
            timeout_result.error.as_ref().unwrap().code,
            "EXECUTION_TIMEOUT"
        );

        // Test killed result creation (utility function)
        let killed_result = IntentResult::create_result(
            intent_id.clone(),
            ExecutionStatus::Killed,
            None,
            Some(ExecutionError {
                code: "PROCESS_KILLED".to_string(),
                message: "Process was terminated by signal".to_string(),
            }),
            start_time,
            end_time,
            runner_meta.clone(),
            audit_ref.clone(),
        );

        assert_eq!(killed_result.status, ExecutionStatus::Killed);
        assert!(killed_result.error.is_some());
        assert_eq!(killed_result.error.as_ref().unwrap().code, "PROCESS_KILLED");
    }
}
