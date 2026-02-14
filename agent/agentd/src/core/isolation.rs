//! Isolation backend traits for pluggable sandboxing
//!
//! This module defines the core traits for isolation backends that provide
//! secure execution environments. Implementations include:
//! - `LinuxNativeBackend`: Uses Landlock, seccomp-bpf, cgroups, namespaces
//! - `MacosNativeBackend`: Uses sandbox-exec (seatbelt)
//! - `ContainerBackend`: Uses Docker/Podman via bollard
//! - `HostDirectBackend`: No isolation, just policy guards (workstation mode)

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use super::intent::Command;
use super::sandbox::SandboxId;

/// Capabilities that an isolation backend can provide
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Backend name (e.g., "linux-native", "docker", "none")
    pub name: String,

    /// Whether filesystem isolation is supported
    pub filesystem_isolation: bool,

    /// Whether network isolation is supported
    pub network_isolation: bool,

    /// Whether process isolation (PID namespace) is supported
    pub process_isolation: bool,

    /// Whether resource limits (cgroups) are supported
    pub resource_limits: bool,

    /// Whether syscall filtering (seccomp) is supported
    pub syscall_filtering: bool,

    /// Whether the backend supports persistent sandboxes
    pub persistent_sandboxes: bool,

    /// Whether the backend supports sandbox snapshots
    pub snapshots: bool,

    /// Maximum number of concurrent sandboxes (None = unlimited)
    pub max_concurrent_sandboxes: Option<u32>,

    /// Available isolation profiles
    pub available_profiles: Vec<String>,

    /// Platform-specific capabilities
    pub platform_features: Vec<String>,
}

impl BackendCapabilities {
    /// Check if this backend provides full isolation
    pub fn is_fully_isolated(&self) -> bool {
        self.filesystem_isolation
            && self.network_isolation
            && self.process_isolation
            && self.syscall_filtering
    }

    /// Check if this is a "soft" isolation (policy only, no kernel enforcement)
    pub fn is_soft_isolation(&self) -> bool {
        !self.filesystem_isolation && !self.syscall_filtering
    }
}

/// A bind mount specification mapping a host path to a container path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindMount {
    /// Source path on the host
    pub source: PathBuf,
    /// Target path inside the container
    pub target: PathBuf,
    /// Whether the mount is read-only
    pub readonly: bool,
}

/// Specification for creating a new sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    /// Requested isolation profile (e.g., "strict", "permissive", "custom")
    pub profile: String,

    /// Working directory inside the sandbox
    pub workdir: PathBuf,

    /// Allowed filesystem paths (read-only)
    pub allowed_paths_ro: Vec<PathBuf>,

    /// Allowed filesystem paths (read-write)
    pub allowed_paths_rw: Vec<PathBuf>,

    /// Custom bind mounts with explicit source->target mapping
    /// These take precedence over allowed_paths_* for path mapping
    pub bind_mounts: Vec<BindMount>,

    /// Allowed network destinations (host:port or CIDR)
    pub allowed_network: Vec<String>,

    /// Environment variables to set
    pub environment: Vec<(String, String)>,

    /// Resource limits
    pub limits: ResourceLimits,

    /// Whether to enable network access
    pub network_enabled: bool,

    /// Custom seccomp profile (if supported)
    pub seccomp_profile: Option<String>,

    /// Timeout for sandbox creation
    pub creation_timeout: Duration,

    /// Labels for tracking/identification
    pub labels: Vec<(String, String)>,
}

impl Default for SandboxSpec {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            workdir: PathBuf::from("/workspace"),
            allowed_paths_ro: vec![],
            allowed_paths_rw: vec![],
            bind_mounts: vec![],
            allowed_network: vec![],
            environment: vec![],
            limits: ResourceLimits::default(),
            network_enabled: false,
            seccomp_profile: None,
            creation_timeout: Duration::from_secs(30),
            labels: vec![],
        }
    }
}

/// Resource limits for sandbox execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory in bytes
    pub max_memory_bytes: Option<u64>,

    /// Maximum CPU time in milliseconds
    pub max_cpu_time_ms: Option<u64>,

    /// Maximum wall-clock time in milliseconds
    pub max_wall_time_ms: Option<u64>,

    /// Maximum number of processes/threads
    pub max_processes: Option<u32>,

    /// Maximum open file descriptors
    pub max_open_files: Option<u32>,

    /// Maximum output size in bytes (stdout + stderr)
    pub max_output_bytes: Option<u64>,

    /// Maximum file write size in bytes
    pub max_write_bytes: Option<u64>,

    /// CPU weight (for cgroups, 1-10000)
    pub cpu_weight: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: Some(512 * 1024 * 1024), // 512 MB
            max_cpu_time_ms: Some(60_000),             // 60 seconds
            max_wall_time_ms: Some(120_000),           // 2 minutes
            max_processes: Some(64),
            max_open_files: Some(256),
            max_output_bytes: Some(10 * 1024 * 1024), // 10 MB
            max_write_bytes: Some(100 * 1024 * 1024), // 100 MB
            cpu_weight: Some(100),
        }
    }
}

/// Capabilities that a specific sandbox instance provides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCapabilities {
    /// Unique identifier for this sandbox
    pub sandbox_id: String,

    /// Backend that created this sandbox
    pub backend: String,

    /// Profile used to create this sandbox
    pub profile: String,

    /// Whether the sandbox has filesystem write access
    pub can_write_filesystem: bool,

    /// Paths the sandbox can read
    pub readable_paths: Vec<PathBuf>,

    /// Paths the sandbox can write
    pub writable_paths: Vec<PathBuf>,

    /// Whether the sandbox has network access
    pub has_network: bool,

    /// Allowed network destinations (if network enabled)
    pub allowed_destinations: Vec<String>,

    /// Applied resource limits
    pub limits: ResourceLimits,

    /// Whether syscall filtering is active
    pub syscall_filter_active: bool,

    /// Blocked syscall categories (informational)
    pub blocked_syscall_categories: Vec<String>,

    /// Whether this is a persistent sandbox (survives restart)
    pub is_persistent: bool,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Time remaining until timeout (if applicable)
    pub time_remaining_ms: Option<u64>,
}

/// Output from command execution
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// Exit code (0 = success)
    pub exit_code: i32,

    /// Standard output bytes
    pub stdout: Vec<u8>,

    /// Standard error bytes
    pub stderr: Vec<u8>,

    /// Execution duration
    pub duration: Duration,

    /// Whether the command was killed due to timeout
    pub timed_out: bool,

    /// Whether the command was killed due to resource limits
    pub resource_limited: bool,

    /// Resource usage statistics
    pub resource_usage: Option<ResourceUsage>,
}

/// Resource usage statistics from execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Peak memory usage in bytes
    pub peak_memory_bytes: u64,

    /// CPU time used in milliseconds
    pub cpu_time_ms: u64,

    /// Wall clock time in milliseconds
    pub wall_time_ms: u64,

    /// Number of bytes written to disk
    pub bytes_written: u64,

    /// Number of bytes read from disk
    pub bytes_read: u64,
}

/// Streaming output chunk sent via channel
#[derive(Debug, Clone)]
pub enum StreamOutput {
    /// Stdout data
    Stdout(Vec<u8>),
    /// Stderr data
    Stderr(Vec<u8>),
    /// Process has exited
    Exit { code: i32 },
}

/// Execution context passed to sandbox
#[derive(Debug, Clone)]
pub struct ExecContext {
    /// Trace ID for distributed tracing
    pub trace_id: String,

    /// Request ID for correlation
    pub request_id: String,

    /// Working directory override (within sandbox constraints)
    pub workdir: Option<PathBuf>,

    /// Additional environment variables
    pub extra_env: Vec<(String, String)>,

    /// Timeout override (within sandbox limits)
    pub timeout: Option<Duration>,

    /// Whether to capture stdout
    pub capture_stdout: bool,

    /// Whether to capture stderr
    pub capture_stderr: bool,

    /// Stream output in chunks (for real-time streaming)
    pub stream_output: bool,
}

impl Default for ExecContext {
    fn default() -> Self {
        Self {
            trace_id: String::new(),
            request_id: String::new(),
            workdir: None,
            extra_env: vec![],
            timeout: None,
            capture_stdout: true,
            capture_stderr: true,
            stream_output: false,
        }
    }
}

/// Trait for isolation backends that create sandboxes
#[async_trait]
pub trait IsolationBackend: Send + Sync {
    /// Get the name of this backend
    fn name(&self) -> &str;

    /// Probe the system to determine available capabilities
    /// This should be called at startup to detect what isolation features are available
    async fn probe(&self) -> Result<BackendCapabilities>;

    /// Create a new sandbox with the given specification
    async fn create_sandbox(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>>;

    /// List all active sandboxes managed by this backend
    async fn list_sandboxes(&self) -> Result<Vec<SandboxId>>;

    /// Get a reference to an existing sandbox by ID
    async fn get_sandbox(&self, id: &SandboxId) -> Result<Option<Box<dyn Sandbox>>>;

    /// Destroy all sandboxes (cleanup on shutdown)
    async fn destroy_all(&self) -> Result<()>;

    /// Health check for the backend
    async fn health_check(&self) -> Result<BackendHealth>;
}

/// Health status of an isolation backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHealth {
    /// Whether the backend is operational
    pub healthy: bool,

    /// Number of active sandboxes
    pub active_sandboxes: u32,

    /// Resource utilization (0.0 - 1.0)
    pub resource_utilization: f32,

    /// Any warnings or degraded features
    pub warnings: Vec<String>,

    /// Last successful sandbox creation timestamp
    pub last_sandbox_created: Option<chrono::DateTime<chrono::Utc>>,
}

/// Trait for individual sandbox instances
#[async_trait]
pub trait Sandbox: Send + Sync {
    /// Get the unique identifier for this sandbox
    fn id(&self) -> &SandboxId;

    /// Get the capabilities of this sandbox
    fn capabilities(&self) -> &SandboxCapabilities;

    /// Execute a command inside the sandbox
    async fn exec(&self, cmd: &Command, ctx: &ExecContext) -> Result<ExecOutput>;

    /// Execute a command with streaming output via channels
    ///
    /// Output is sent to the provided channel sender. The caller is responsible
    /// for receiving and processing the output chunks.
    async fn exec_streaming(
        &self,
        cmd: &Command,
        ctx: &ExecContext,
        output_tx: tokio::sync::mpsc::Sender<StreamOutput>,
    ) -> Result<ExecOutput>;

    /// Check if the sandbox is still alive and responsive
    async fn is_alive(&self) -> bool;

    /// Suspend the sandbox (if supported)
    async fn suspend(&self) -> Result<()>;

    /// Resume a suspended sandbox
    async fn resume(&self) -> Result<()>;

    /// Create a snapshot of the sandbox state (if supported)
    async fn snapshot(&self, name: &str) -> Result<String>;

    /// Restore sandbox from a snapshot
    async fn restore(&self, snapshot_id: &str) -> Result<()>;

    /// Destroy the sandbox, releasing all resources
    async fn destroy(&self) -> Result<()>;

    /// Get current resource usage
    async fn resource_usage(&self) -> Result<ResourceUsage>;
}
