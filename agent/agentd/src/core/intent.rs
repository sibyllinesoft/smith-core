//! Generic intent types for cross-adapter compatibility
//!
//! This module defines the core intent request and response types that
//! work across all ingest adapters. These are adapter-agnostic and can
//! be serialized to/from various wire formats (protobuf, JSON, etc.)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

/// A command to execute inside a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    /// Program to execute
    pub program: String,

    /// Command arguments
    pub args: Vec<String>,

    /// Working directory (relative to sandbox workdir)
    pub workdir: Option<PathBuf>,

    /// Environment variables
    pub env: HashMap<String, String>,

    /// Whether to inherit parent environment
    pub inherit_env: bool,

    /// Stdin to pipe to the process
    pub stdin: Option<Vec<u8>>,

    /// Execution timeout
    pub timeout: Option<Duration>,
}

impl Command {
    /// Create a simple command with program and args
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_string(),
            args: vec![],
            workdir: None,
            env: HashMap::new(),
            inherit_env: true,
            stdin: None,
            timeout: None,
        }
    }

    /// Add arguments
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args
            .extend(args.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Set working directory
    pub fn workdir(mut self, dir: PathBuf) -> Self {
        self.workdir = Some(dir);
        self
    }

    /// Add environment variable
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set stdin
    pub fn stdin(mut self, input: Vec<u8>) -> Self {
        self.stdin = Some(input);
        self
    }
}

/// Request to execute an intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentRequest {
    /// Unique request identifier
    pub id: Uuid,

    /// Capability to invoke (e.g., "fs.read.v1", "shell.exec.v1")
    pub capability: String,

    /// Version of the capability schema
    pub version: u32,

    /// Capability-specific parameters
    pub params: serde_json::Value,

    /// Resource constraints
    pub constraints: RequestConstraints,

    /// Request metadata
    pub metadata: RequestMetadata,

    /// Sandbox preferences
    pub sandbox_prefs: SandboxPreferences,
}

impl IntentRequest {
    /// Create a new intent request
    pub fn new(capability: &str, params: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            capability: capability.to_string(),
            version: 1,
            params,
            constraints: RequestConstraints::default(),
            metadata: RequestMetadata::default(),
            sandbox_prefs: SandboxPreferences::default(),
        }
    }

    /// Set the request ID
    pub fn with_id(mut self, id: Uuid) -> Self {
        self.id = id;
        self
    }

    /// Set constraints
    pub fn with_constraints(mut self, constraints: RequestConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    /// Set sandbox preferences
    pub fn with_sandbox_prefs(mut self, prefs: SandboxPreferences) -> Self {
        self.sandbox_prefs = prefs;
        self
    }
}

/// Constraints on request execution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestConstraints {
    /// Maximum execution time in milliseconds
    pub max_duration_ms: Option<u64>,

    /// Maximum output size in bytes
    pub max_output_bytes: Option<u64>,

    /// Maximum memory usage in bytes
    pub max_memory_bytes: Option<u64>,

    /// Whether to allow network access
    pub allow_network: Option<bool>,

    /// Whether to allow filesystem writes
    pub allow_writes: Option<bool>,
}

/// Request metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Trace ID for distributed tracing
    pub trace_id: Option<String>,

    /// Span ID for distributed tracing
    pub span_id: Option<String>,

    /// Request timestamp (Unix epoch milliseconds)
    pub timestamp_ms: Option<u64>,

    /// Client-provided idempotency key
    pub idempotency_key: Option<String>,

    /// Priority (0 = lowest, 10 = highest)
    pub priority: Option<u8>,

    /// Custom metadata fields
    pub custom: HashMap<String, String>,
}

/// Preferences for sandbox selection/creation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxPreferences {
    /// Prefer a specific sandbox by ID
    pub sandbox_id: Option<String>,

    /// Create a new sandbox (don't reuse)
    pub require_fresh: bool,

    /// Requested isolation profile
    pub profile: Option<String>,

    /// Whether to keep the sandbox after execution
    pub persist: bool,

    /// Preferred isolation backend
    pub backend: Option<String>,

    /// Custom sandbox labels
    pub labels: HashMap<String, String>,
}

/// Response from intent execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResponse {
    /// Request ID this responds to
    pub request_id: Uuid,

    /// Execution status
    pub status: IntentStatus,

    /// Status code string (e.g., "OK", "DENIED", "ERROR")
    pub code: String,

    /// Human-readable message
    pub message: String,

    /// Execution result (if successful)
    pub result: Option<ExecutionResult>,

    /// Error details (if failed)
    pub error: Option<ErrorDetails>,

    /// Execution timing
    pub timing: ResponseTiming,

    /// Sandbox information
    pub sandbox_info: Option<SandboxInfo>,
}

impl IntentResponse {
    /// Create a successful response
    pub fn success(request_id: Uuid, result: ExecutionResult) -> Self {
        Self {
            request_id,
            status: IntentStatus::Ok,
            code: "OK".to_string(),
            message: "Execution completed successfully".to_string(),
            result: Some(result),
            error: None,
            timing: ResponseTiming::default(),
            sandbox_info: None,
        }
    }

    /// Create an error response
    pub fn error(request_id: Uuid, code: &str, message: &str) -> Self {
        Self {
            request_id,
            status: IntentStatus::Error,
            code: code.to_string(),
            message: message.to_string(),
            result: None,
            error: Some(ErrorDetails {
                code: code.to_string(),
                message: message.to_string(),
                details: None,
                retryable: false,
                retry_after_ms: None,
            }),
            timing: ResponseTiming::default(),
            sandbox_info: None,
        }
    }

    /// Create a denied response
    pub fn denied(request_id: Uuid, reason: &str) -> Self {
        Self {
            request_id,
            status: IntentStatus::Denied,
            code: "DENIED".to_string(),
            message: reason.to_string(),
            result: None,
            error: None,
            timing: ResponseTiming::default(),
            sandbox_info: None,
        }
    }
}

/// Execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IntentStatus {
    /// Execution completed successfully
    Ok,
    /// Request was denied by policy
    Denied,
    /// Execution failed with error
    Error,
    /// Request expired before execution
    Expired,
    /// Execution was cancelled
    Cancelled,
    /// Execution is still in progress (for polling)
    Pending,
}

impl IntentStatus {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, IntentStatus::Pending)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, IntentStatus::Ok)
    }
}

/// Successful execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Exit code (0 = success)
    pub exit_code: i32,

    /// Standard output
    pub stdout: Option<String>,

    /// Standard output as bytes (for binary data)
    pub stdout_bytes: Option<Vec<u8>>,

    /// Standard error
    pub stderr: Option<String>,

    /// Structured output (capability-specific)
    pub output: Option<serde_json::Value>,

    /// Generated artifacts
    pub artifacts: Vec<Artifact>,

    /// Resource usage statistics
    pub resource_usage: Option<ResourceUsageStats>,
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self {
            exit_code: 0,
            stdout: None,
            stdout_bytes: None,
            stderr: None,
            output: None,
            artifacts: vec![],
            resource_usage: None,
        }
    }
}

/// Generated artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Artifact name
    pub name: String,

    /// Content type
    pub content_type: String,

    /// Size in bytes
    pub size: u64,

    /// SHA-256 hash
    pub sha256: String,

    /// Storage URI (for retrieval)
    pub uri: Option<String>,

    /// Inline content (for small artifacts)
    pub content: Option<Vec<u8>>,
}

/// Resource usage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsageStats {
    /// Peak memory usage in bytes
    pub peak_memory_bytes: u64,

    /// CPU time used in milliseconds
    pub cpu_time_ms: u64,

    /// Wall clock time in milliseconds
    pub wall_time_ms: u64,

    /// Bytes written to disk
    pub disk_write_bytes: u64,

    /// Bytes read from disk
    pub disk_read_bytes: u64,

    /// Network bytes sent
    pub network_tx_bytes: u64,

    /// Network bytes received
    pub network_rx_bytes: u64,
}

/// Error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetails {
    /// Error code
    pub code: String,

    /// Error message
    pub message: String,

    /// Additional details
    pub details: Option<serde_json::Value>,

    /// Whether the error is retryable
    pub retryable: bool,

    /// Suggested retry delay in milliseconds
    pub retry_after_ms: Option<u64>,
}

/// Response timing information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseTiming {
    /// When the request was received (Unix epoch ms)
    pub received_at_ms: u64,

    /// When execution started (Unix epoch ms)
    pub started_at_ms: u64,

    /// When execution completed (Unix epoch ms)
    pub completed_at_ms: u64,

    /// Queue wait time in milliseconds
    pub queue_time_ms: u64,

    /// Sandbox setup time in milliseconds
    pub setup_time_ms: u64,

    /// Actual execution time in milliseconds
    pub exec_time_ms: u64,

    /// Total time in milliseconds
    pub total_time_ms: u64,
}

/// Information about the sandbox used for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    /// Sandbox identifier
    pub sandbox_id: String,

    /// Isolation backend used
    pub backend: String,

    /// Isolation profile applied
    pub profile: String,

    /// Whether this was a newly created sandbox
    pub newly_created: bool,

    /// Sandbox capabilities (what the sandbox can do)
    pub capabilities: SandboxCapabilitiesInfo,
}

/// Summarized sandbox capabilities for client awareness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCapabilitiesInfo {
    /// Whether filesystem writes are allowed
    pub can_write: bool,

    /// Whether network access is allowed
    pub has_network: bool,

    /// Readable paths
    pub readable_paths: Vec<String>,

    /// Writable paths
    pub writable_paths: Vec<String>,

    /// Resource limits applied
    pub limits: ResourceLimitsInfo,
}

/// Summarized resource limits
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceLimitsInfo {
    /// Maximum memory in bytes
    pub max_memory_bytes: Option<u64>,

    /// Maximum CPU time in milliseconds
    pub max_cpu_ms: Option<u64>,

    /// Maximum wall time in milliseconds
    pub max_wall_ms: Option<u64>,

    /// Maximum output size in bytes
    pub max_output_bytes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ===== Command Tests =====

    #[test]
    fn test_command_new() {
        let cmd = Command::new("ls");
        assert_eq!(cmd.program, "ls");
        assert!(cmd.args.is_empty());
        assert!(cmd.workdir.is_none());
        assert!(cmd.env.is_empty());
        assert!(cmd.inherit_env);
        assert!(cmd.stdin.is_none());
        assert!(cmd.timeout.is_none());
    }

    #[test]
    fn test_command_args() {
        let cmd = Command::new("ls").args(["-la", "/tmp"]);
        assert_eq!(cmd.args, vec!["-la", "/tmp"]);
    }

    #[test]
    fn test_command_workdir() {
        let cmd = Command::new("ls").workdir(PathBuf::from("/home/user"));
        assert_eq!(cmd.workdir, Some(PathBuf::from("/home/user")));
    }

    #[test]
    fn test_command_env() {
        let cmd = Command::new("bash")
            .env("PATH", "/usr/bin")
            .env("HOME", "/home/user");
        assert_eq!(cmd.env.get("PATH"), Some(&"/usr/bin".to_string()));
        assert_eq!(cmd.env.get("HOME"), Some(&"/home/user".to_string()));
    }

    #[test]
    fn test_command_timeout() {
        let cmd = Command::new("sleep").timeout(Duration::from_secs(30));
        assert_eq!(cmd.timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_command_stdin() {
        let cmd = Command::new("cat").stdin(b"hello world".to_vec());
        assert_eq!(cmd.stdin, Some(b"hello world".to_vec()));
    }

    #[test]
    fn test_command_builder_chain() {
        let cmd = Command::new("python")
            .args(["script.py", "--verbose"])
            .workdir(PathBuf::from("/app"))
            .env("PYTHONPATH", "/lib")
            .timeout(Duration::from_secs(60))
            .stdin(b"input data".to_vec());

        assert_eq!(cmd.program, "python");
        assert_eq!(cmd.args.len(), 2);
        assert_eq!(cmd.workdir, Some(PathBuf::from("/app")));
        assert_eq!(cmd.env.get("PYTHONPATH"), Some(&"/lib".to_string()));
        assert_eq!(cmd.timeout, Some(Duration::from_secs(60)));
        assert!(cmd.stdin.is_some());
    }

    // ===== IntentRequest Tests =====

    #[test]
    fn test_intent_request_new() {
        let params = serde_json::json!({"path": "/etc/passwd"});
        let req = IntentRequest::new("fs.read.v1", params.clone());

        assert_eq!(req.capability, "fs.read.v1");
        assert_eq!(req.version, 1);
        assert_eq!(req.params, params);
    }

    #[test]
    fn test_intent_request_with_id() {
        let id = Uuid::new_v4();
        let req = IntentRequest::new("fs.read.v1", serde_json::json!({})).with_id(id);
        assert_eq!(req.id, id);
    }

    #[test]
    fn test_intent_request_with_constraints() {
        let constraints = RequestConstraints {
            max_duration_ms: Some(5000),
            max_output_bytes: Some(1024),
            max_memory_bytes: Some(1024 * 1024),
            allow_network: Some(false),
            allow_writes: Some(true),
        };

        let req = IntentRequest::new("shell.exec.v1", serde_json::json!({}))
            .with_constraints(constraints);

        assert_eq!(req.constraints.max_duration_ms, Some(5000));
        assert_eq!(req.constraints.max_output_bytes, Some(1024));
        assert_eq!(req.constraints.allow_network, Some(false));
    }

    #[test]
    fn test_intent_request_with_sandbox_prefs() {
        let prefs = SandboxPreferences {
            sandbox_id: Some("sb-123".to_string()),
            require_fresh: true,
            profile: Some("high-security".to_string()),
            persist: false,
            backend: Some("landlock".to_string()),
            labels: HashMap::new(),
        };

        let req = IntentRequest::new("fs.read.v1", serde_json::json!({})).with_sandbox_prefs(prefs);

        assert_eq!(req.sandbox_prefs.sandbox_id, Some("sb-123".to_string()));
        assert!(req.sandbox_prefs.require_fresh);
    }

    // ===== RequestConstraints Tests =====

    #[test]
    fn test_request_constraints_default() {
        let constraints = RequestConstraints::default();
        assert!(constraints.max_duration_ms.is_none());
        assert!(constraints.max_output_bytes.is_none());
        assert!(constraints.max_memory_bytes.is_none());
        assert!(constraints.allow_network.is_none());
        assert!(constraints.allow_writes.is_none());
    }

    // ===== RequestMetadata Tests =====

    #[test]
    fn test_request_metadata_default() {
        let metadata = RequestMetadata::default();
        assert!(metadata.trace_id.is_none());
        assert!(metadata.span_id.is_none());
        assert!(metadata.timestamp_ms.is_none());
        assert!(metadata.idempotency_key.is_none());
        assert!(metadata.priority.is_none());
        assert!(metadata.custom.is_empty());
    }

    #[test]
    fn test_request_metadata_with_values() {
        let metadata = RequestMetadata {
            trace_id: Some("trace-123".to_string()),
            span_id: Some("span-456".to_string()),
            timestamp_ms: Some(1234567890),
            idempotency_key: Some("idem-key".to_string()),
            priority: Some(5),
            custom: HashMap::from([("env".to_string(), "prod".to_string())]),
        };

        assert_eq!(metadata.trace_id, Some("trace-123".to_string()));
        assert_eq!(metadata.priority, Some(5));
    }

    // ===== SandboxPreferences Tests =====

    #[test]
    fn test_sandbox_preferences_default() {
        let prefs = SandboxPreferences::default();
        assert!(prefs.sandbox_id.is_none());
        assert!(!prefs.require_fresh);
        assert!(prefs.profile.is_none());
        assert!(!prefs.persist);
        assert!(prefs.backend.is_none());
        assert!(prefs.labels.is_empty());
    }

    // ===== IntentResponse Tests =====

    #[test]
    fn test_intent_response_success() {
        let id = Uuid::new_v4();
        let result = ExecutionResult {
            exit_code: 0,
            stdout: Some("output".to_string()),
            ..Default::default()
        };

        let response = IntentResponse::success(id, result);

        assert_eq!(response.request_id, id);
        assert_eq!(response.status, IntentStatus::Ok);
        assert_eq!(response.code, "OK");
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_intent_response_error() {
        let id = Uuid::new_v4();
        let response = IntentResponse::error(id, "EXEC_FAILED", "Command failed");

        assert_eq!(response.request_id, id);
        assert_eq!(response.status, IntentStatus::Error);
        assert_eq!(response.code, "EXEC_FAILED");
        assert_eq!(response.message, "Command failed");
        assert!(response.result.is_none());
        assert!(response.error.is_some());

        let error = response.error.unwrap();
        assert_eq!(error.code, "EXEC_FAILED");
        assert!(!error.retryable);
    }

    #[test]
    fn test_intent_response_denied() {
        let id = Uuid::new_v4();
        let response = IntentResponse::denied(id, "Policy violation");

        assert_eq!(response.request_id, id);
        assert_eq!(response.status, IntentStatus::Denied);
        assert_eq!(response.code, "DENIED");
        assert_eq!(response.message, "Policy violation");
    }

    // ===== IntentStatus Tests =====

    #[test]
    fn test_intent_status_is_terminal() {
        assert!(IntentStatus::Ok.is_terminal());
        assert!(IntentStatus::Denied.is_terminal());
        assert!(IntentStatus::Error.is_terminal());
        assert!(IntentStatus::Expired.is_terminal());
        assert!(IntentStatus::Cancelled.is_terminal());
        assert!(!IntentStatus::Pending.is_terminal());
    }

    #[test]
    fn test_intent_status_is_success() {
        assert!(IntentStatus::Ok.is_success());
        assert!(!IntentStatus::Denied.is_success());
        assert!(!IntentStatus::Error.is_success());
        assert!(!IntentStatus::Expired.is_success());
        assert!(!IntentStatus::Cancelled.is_success());
        assert!(!IntentStatus::Pending.is_success());
    }

    // ===== ExecutionResult Tests =====

    #[test]
    fn test_execution_result_default() {
        let result = ExecutionResult::default();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_none());
        assert!(result.stdout_bytes.is_none());
        assert!(result.stderr.is_none());
        assert!(result.output.is_none());
        assert!(result.artifacts.is_empty());
        assert!(result.resource_usage.is_none());
    }

    #[test]
    fn test_execution_result_with_values() {
        let result = ExecutionResult {
            exit_code: 1,
            stdout: Some("output".to_string()),
            stderr: Some("error".to_string()),
            output: Some(serde_json::json!({"key": "value"})),
            artifacts: vec![Artifact {
                name: "output.txt".to_string(),
                content_type: "text/plain".to_string(),
                size: 100,
                sha256: "abc123".to_string(),
                uri: None,
                content: Some(b"content".to_vec()),
            }],
            ..Default::default()
        };

        assert_eq!(result.exit_code, 1);
        assert_eq!(result.stdout, Some("output".to_string()));
        assert_eq!(result.artifacts.len(), 1);
    }

    // ===== Artifact Tests =====

    #[test]
    fn test_artifact_creation() {
        let artifact = Artifact {
            name: "report.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            size: 1024,
            sha256: "sha256hash".to_string(),
            uri: Some("s3://bucket/report.pdf".to_string()),
            content: None,
        };

        assert_eq!(artifact.name, "report.pdf");
        assert_eq!(artifact.content_type, "application/pdf");
        assert_eq!(artifact.size, 1024);
        assert!(artifact.uri.is_some());
        assert!(artifact.content.is_none());
    }

    // ===== ResourceUsageStats Tests =====

    #[test]
    fn test_resource_usage_stats_default() {
        let stats = ResourceUsageStats::default();
        assert_eq!(stats.peak_memory_bytes, 0);
        assert_eq!(stats.cpu_time_ms, 0);
        assert_eq!(stats.wall_time_ms, 0);
        assert_eq!(stats.disk_write_bytes, 0);
        assert_eq!(stats.disk_read_bytes, 0);
        assert_eq!(stats.network_tx_bytes, 0);
        assert_eq!(stats.network_rx_bytes, 0);
    }

    // ===== ErrorDetails Tests =====

    #[test]
    fn test_error_details_creation() {
        let error = ErrorDetails {
            code: "TIMEOUT".to_string(),
            message: "Execution timed out".to_string(),
            details: Some(serde_json::json!({"timeout_ms": 5000})),
            retryable: true,
            retry_after_ms: Some(1000),
        };

        assert_eq!(error.code, "TIMEOUT");
        assert!(error.retryable);
        assert_eq!(error.retry_after_ms, Some(1000));
    }

    // ===== ResponseTiming Tests =====

    #[test]
    fn test_response_timing_default() {
        let timing = ResponseTiming::default();
        assert_eq!(timing.received_at_ms, 0);
        assert_eq!(timing.started_at_ms, 0);
        assert_eq!(timing.completed_at_ms, 0);
        assert_eq!(timing.queue_time_ms, 0);
        assert_eq!(timing.setup_time_ms, 0);
        assert_eq!(timing.exec_time_ms, 0);
        assert_eq!(timing.total_time_ms, 0);
    }

    // ===== SandboxInfo Tests =====

    #[test]
    fn test_sandbox_info_creation() {
        let info = SandboxInfo {
            sandbox_id: "sb-123".to_string(),
            backend: "landlock".to_string(),
            profile: "standard".to_string(),
            newly_created: true,
            capabilities: SandboxCapabilitiesInfo {
                can_write: false,
                has_network: false,
                readable_paths: vec!["/etc".to_string()],
                writable_paths: vec![],
                limits: ResourceLimitsInfo::default(),
            },
        };

        assert_eq!(info.sandbox_id, "sb-123");
        assert!(info.newly_created);
        assert!(!info.capabilities.can_write);
    }

    // ===== Serialization Tests =====

    #[test]
    fn test_command_serialization() {
        let cmd = Command::new("ls").args(["-la"]).env("PATH", "/usr/bin");

        let json = serde_json::to_string(&cmd).unwrap();
        let deserialized: Command = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.program, "ls");
        assert_eq!(deserialized.args, vec!["-la"]);
    }

    #[test]
    fn test_intent_request_serialization() {
        let req = IntentRequest::new("fs.read.v1", serde_json::json!({"path": "/tmp"}));

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: IntentRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.capability, "fs.read.v1");
    }

    #[test]
    fn test_intent_response_serialization() {
        let id = Uuid::new_v4();
        let response = IntentResponse::error(id, "ERROR", "Test error");

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: IntentResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.request_id, id);
        assert_eq!(deserialized.status, IntentStatus::Error);
    }

    #[test]
    fn test_intent_status_serialization() {
        let status = IntentStatus::Pending;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pending\"");

        let deserialized: IntentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, IntentStatus::Pending);
    }

    #[test]
    fn test_all_intent_statuses_serialization() {
        let statuses = vec![
            IntentStatus::Ok,
            IntentStatus::Denied,
            IntentStatus::Error,
            IntentStatus::Expired,
            IntentStatus::Cancelled,
            IntentStatus::Pending,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: IntentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }
}
