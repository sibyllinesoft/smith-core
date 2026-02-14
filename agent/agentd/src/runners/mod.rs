use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub mod analysis_performance;
pub mod analysis_system;
pub mod fs_read;
pub mod fs_write;
// TODO: Fix git_clone module after refactoring is complete
// pub mod git_clone;
pub mod http_fetch;
pub mod implementation_execute;
pub mod planner_exec;
pub mod shell_exec;
pub mod test_simulation;
pub mod validation_test;

use crate::vm::MicroVmManager;
use smith_protocol::{ExecutionLimits, ExecutionStatus};

/// Execution context for runners
#[derive(Debug, Clone)]
pub struct ExecContext {
    pub workdir: std::path::PathBuf,
    pub limits: ExecutionLimits,
    pub scope: Scope,
    pub creds: Option<EphemeralCreds>,
    pub netns: Option<NetNamespaceHandle>,
    pub trace_id: String,
    pub session: Option<SessionContext>,
}

/// Metadata about the reasoning session associated with this execution.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: Uuid,
    pub domain: Option<String>,
    pub vm_profile: Option<String>,
}

/// Type alias for compatibility with main.rs
pub type ExecutionContext = ExecContext;

/// Execution scope (allowed paths, URLs, etc.)
#[derive(Debug, Clone)]
pub struct Scope {
    pub paths: Vec<String>,
    pub urls: Vec<String>,
}

/// Ephemeral credentials for execution
#[derive(Debug, Clone)]
pub struct EphemeralCreds {
    pub access_token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Network namespace handle
#[derive(Debug, Clone)]
pub struct NetNamespaceHandle {
    pub fd: i32, // File descriptor for netns
}

/// Output sink for streaming logs and results
pub trait OutputSink: Send + Sync {
    /// Write stdout data
    fn write_stdout(&mut self, data: &[u8]) -> Result<()>;

    /// Write stderr data  
    fn write_stderr(&mut self, data: &[u8]) -> Result<()>;

    /// Write log message
    fn write_log(&mut self, level: &str, message: &str) -> Result<()>;
}

/// Simple in-memory output sink for testing
pub struct MemoryOutputSink {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub logs: Vec<String>,
}

impl MemoryOutputSink {
    pub fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            logs: Vec::new(),
        }
    }
}

impl OutputSink for MemoryOutputSink {
    fn write_stdout(&mut self, data: &[u8]) -> Result<()> {
        self.stdout.extend_from_slice(data);
        Ok(())
    }

    fn write_stderr(&mut self, data: &[u8]) -> Result<()> {
        self.stderr.extend_from_slice(data);
        Ok(())
    }

    fn write_log(&mut self, level: &str, message: &str) -> Result<()> {
        self.logs.push(format!("[{}] {}", level, message));
        Ok(())
    }
}

/// Result of intent execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub artifacts: Vec<Artifact>,
    pub duration_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

/// Execution artifact
#[derive(Debug, Clone)]
pub struct Artifact {
    pub name: String,
    pub path: std::path::PathBuf,
    pub size: u64,
    pub sha256: String,
}

/// Runner trait for capability-specific execution
#[async_trait]
pub trait Runner: Send + Sync {
    /// Get runner digest (version hash)
    fn digest(&self) -> String;

    /// Validate parameters before execution
    fn validate_params(&self, params: &Value) -> Result<()>;

    /// Execute the intent in the given context
    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult>;
}

/// Runner registry for capability dispatch
pub struct RunnerRegistry {
    runners: std::collections::HashMap<String, Box<dyn Runner>>,
}

impl RunnerRegistry {
    /// Create new runner registry with built-in runners
    pub fn new(vm_manager: Option<Arc<MicroVmManager>>) -> Self {
        let mut registry = Self {
            runners: std::collections::HashMap::new(),
        };

        // Register built-in runners
        registry.register("fs.read", Box::new(fs_read::FsReadRunner::new()));
        registry.register("fs.read.v1", Box::new(fs_read::FsReadRunner::new()));
        // TODO: Restore fs.write after refactoring is complete
        // registry.register("fs.write", Box::new(fs_write::FsWriteRunner::new()));
        registry.register("http.fetch", Box::new(http_fetch::HttpFetchRunner::new()));
        // TODO: Restore git.clone after refactoring is complete
        // registry.register("git.clone", Box::new(git_clone::GitCloneRunner::new()));
        registry.register(
            "planner.exec",
            Box::new(planner_exec::PlannerExecRunner::new()),
        );
        registry.register(
            "analysis.system.v1",
            Box::new(analysis_system::AnalysisSystemRunner::new()),
        );
        registry.register(
            "analysis.performance.v1",
            Box::new(analysis_performance::AnalysisPerformanceRunner::new()),
        );
        registry.register(
            "analysis.security.v1",
            Box::new(test_simulation::NoopSuccessRunner::new(
                "analysis-security-runner-v1",
                "Security analysis complete",
            )),
        );
        registry.register(
            "analysis.concurrent.v1",
            Box::new(test_simulation::NoopSuccessRunner::new(
                "analysis-concurrent-runner-v1",
                "Concurrent analysis completed",
            )),
        );
        registry.register(
            "implementation.execute.v1",
            Box::new(implementation_execute::ImplementationExecuteRunner::new()),
        );
        registry.register(
            "implementation.prepare.v1",
            Box::new(test_simulation::NoopSuccessRunner::new(
                "implementation-prepare-runner-v1",
                "Implementation preparation complete",
            )),
        );
        registry.register(
            "validation.test.v1",
            Box::new(validation_test::ValidationTestRunner::new()),
        );
        registry.register(
            "validation.functional.v1",
            Box::new(test_simulation::NoopSuccessRunner::new(
                "validation-functional-runner-v1",
                "Functional validation complete",
            )),
        );
        registry.register(
            "validation.performance.v1",
            Box::new(test_simulation::NoopSuccessRunner::new(
                "validation-performance-runner-v1",
                "Performance validation complete",
            )),
        );
        registry.register(
            "validation.final.v1",
            Box::new(test_simulation::NoopSuccessRunner::new(
                "validation-final-runner-v1",
                "Final validation successful",
            )),
        );
        registry.register(
            "test.failure.v1",
            Box::new(test_simulation::RandomFailureRunner::new()),
        );
        registry.register(
            "test.always_fail.v1",
            Box::new(test_simulation::AlwaysFailRunner::new()),
        );
        let shell_runner = Box::new(shell_exec::ShellExecRunner::new(vm_manager.clone()));
        registry.register("shell.exec", shell_runner);
        registry.register(
            "shell.exec.v1",
            Box::new(shell_exec::ShellExecRunner::new(vm_manager)),
        );

        info!(
            "Runner registry initialized with {} runners",
            registry.runners.len()
        );
        registry
    }

    /// Register a runner for a capability
    pub fn register(&mut self, capability: &str, runner: Box<dyn Runner>) {
        self.runners.insert(capability.to_string(), runner);
        info!("Registered runner for capability: {}", capability);
    }

    /// Get runner for capability
    pub fn get_runner(&self, capability: &str) -> Option<&dyn Runner> {
        self.runners.get(capability).map(|r| r.as_ref())
    }

    /// List supported capabilities
    pub fn capabilities(&self) -> Vec<String> {
        self.runners.keys().cloned().collect()
    }
}

/// Generate ephemeral credentials for secure execution context
fn generate_ephemeral_credentials() -> Option<EphemeralCreds> {
    // Generate a secure random access token
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let access_token = format!("exec-{}", Uuid::new_v4());

    // Set expiration to 1 hour from now for security
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    debug!(
        "Generated ephemeral credentials, expires at: {}",
        expires_at
    );

    Some(EphemeralCreds {
        access_token,
        expires_at,
    })
}

/// Create a network namespace for isolated network execution
fn create_network_namespace() -> Option<NetNamespaceHandle> {
    let current_uid = unsafe { libc::geteuid() };
    if current_uid != 0 {
        debug!(
            current_uid,
            "Skipping network namespace creation (requires root capabilities)"
        );
        return None;
    }

    // For now, network namespace creation is platform-specific and requires elevated privileges
    // In a production environment, this would:
    // 1. Check if running on Linux with proper capabilities
    // 2. Create a new network namespace using unshare() or clone()
    // 3. Return the file descriptor for the namespace

    // This is a simplified implementation that would need platform-specific code
    #[cfg(target_os = "linux")]
    {
        match create_netns_linux() {
            Ok(fd) => {
                debug!("Created network namespace with fd: {}", fd);
                Some(NetNamespaceHandle { fd })
            }
            Err(e) => {
                warn!("Failed to create network namespace: {}", e);
                None
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        debug!("Network namespace creation not supported on this platform");
        None
    }
}

#[cfg(target_os = "linux")]
fn create_netns_linux() -> Result<i32> {
    use nix::sched::{unshare, CloneFlags};
    use std::os::unix::io::AsRawFd;

    // Create new network namespace
    unshare(CloneFlags::CLONE_NEWNET)
        .map_err(|e| anyhow::anyhow!("Failed to create network namespace: {}", e))?;

    // Open the current network namespace file descriptor
    // In a real implementation, we'd want to keep this FD open
    // For now, return a placeholder value
    let ns_fd = std::fs::File::open("/proc/self/ns/net")
        .map_err(|e| anyhow::anyhow!("Failed to open network namespace: {}", e))?;

    Ok(ns_fd.as_raw_fd())
}

/// Create execution context for intent
pub fn create_exec_context(
    workdir: &Path,
    limits: ExecutionLimits,
    scope: Scope,
    trace_id: String,
) -> ExecContext {
    ExecContext {
        workdir: workdir.to_path_buf(),
        limits,
        scope,
        creds: generate_ephemeral_credentials(),
        netns: create_network_namespace(),
        trace_id,
        session: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ===== RunnerRegistry Tests =====

    #[test]
    fn test_runner_registry() {
        let registry = RunnerRegistry::new(None);

        assert!(registry.get_runner("fs.read").is_some());
        assert!(registry.get_runner("http.fetch").is_some());
        assert!(registry.get_runner("nonexistent").is_none());

        // These runners are currently commented out during refactoring
        // TODO: Re-enable these tests when runners are restored
        // assert!(registry.get_runner("fs.write").is_some());
        // assert!(registry.get_runner("git.clone").is_some());

        let capabilities = registry.capabilities();
        assert!(capabilities.contains(&"fs.read".to_string()));
        assert!(capabilities.contains(&"http.fetch".to_string()));

        // These capabilities are currently disabled during refactoring
        // TODO: Re-enable these tests when runners are restored
        // assert!(capabilities.contains(&"fs.write".to_string()));
        // assert!(capabilities.contains(&"git.clone".to_string()));
    }

    #[test]
    fn test_runner_registry_v1_runners() {
        let registry = RunnerRegistry::new(None);

        // Check v1 capability variants
        assert!(registry.get_runner("fs.read.v1").is_some());
        assert!(registry.get_runner("shell.exec.v1").is_some());
        assert!(registry.get_runner("analysis.system.v1").is_some());
        assert!(registry.get_runner("analysis.performance.v1").is_some());
        assert!(registry.get_runner("analysis.security.v1").is_some());
        assert!(registry.get_runner("implementation.execute.v1").is_some());
        assert!(registry.get_runner("validation.test.v1").is_some());
    }

    #[test]
    fn test_runner_registry_test_runners() {
        let registry = RunnerRegistry::new(None);

        // Test simulation runners
        assert!(registry.get_runner("test.failure.v1").is_some());
        assert!(registry.get_runner("test.always_fail.v1").is_some());
    }

    #[test]
    fn test_runner_registry_shell_exec() {
        let registry = RunnerRegistry::new(None);

        // Both shell.exec and shell.exec.v1 should exist
        assert!(registry.get_runner("shell.exec").is_some());
        assert!(registry.get_runner("shell.exec.v1").is_some());
    }

    #[test]
    fn test_runner_registry_capabilities_count() {
        let registry = RunnerRegistry::new(None);
        let capabilities = registry.capabilities();

        // Should have many registered runners
        assert!(
            capabilities.len() >= 10,
            "Expected at least 10 registered capabilities, got {}",
            capabilities.len()
        );
    }

    // ===== MemoryOutputSink Tests =====

    #[test]
    fn test_memory_output_sink() {
        let mut sink = MemoryOutputSink::new();

        sink.write_stdout(b"hello").unwrap();
        sink.write_stderr(b"error").unwrap();
        sink.write_log("INFO", "test message").unwrap();

        assert_eq!(sink.stdout, b"hello");
        assert_eq!(sink.stderr, b"error");
        assert_eq!(sink.logs, vec!["[INFO] test message"]);
    }

    #[test]
    fn test_memory_output_sink_new() {
        let sink = MemoryOutputSink::new();
        assert!(sink.stdout.is_empty());
        assert!(sink.stderr.is_empty());
        assert!(sink.logs.is_empty());
    }

    #[test]
    fn test_memory_output_sink_multiple_writes() {
        let mut sink = MemoryOutputSink::new();

        sink.write_stdout(b"hello ").unwrap();
        sink.write_stdout(b"world").unwrap();

        assert_eq!(sink.stdout, b"hello world");
    }

    #[test]
    fn test_memory_output_sink_multiple_logs() {
        let mut sink = MemoryOutputSink::new();

        sink.write_log("INFO", "message 1").unwrap();
        sink.write_log("ERROR", "message 2").unwrap();
        sink.write_log("DEBUG", "message 3").unwrap();

        assert_eq!(sink.logs.len(), 3);
        assert_eq!(sink.logs[0], "[INFO] message 1");
        assert_eq!(sink.logs[1], "[ERROR] message 2");
        assert_eq!(sink.logs[2], "[DEBUG] message 3");
    }

    #[test]
    fn test_memory_output_sink_binary_data() {
        let mut sink = MemoryOutputSink::new();
        let binary_data: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE];

        sink.write_stdout(&binary_data).unwrap();
        assert_eq!(sink.stdout, binary_data);
    }

    // ===== ExecContext Tests =====

    #[test]
    fn test_exec_context_creation() {
        let ctx = ExecContext {
            workdir: PathBuf::from("/tmp/test"),
            limits: ExecutionLimits::default(),
            scope: Scope {
                paths: vec!["/allowed".to_string()],
                urls: vec!["https://example.com".to_string()],
            },
            creds: None,
            netns: None,
            trace_id: "trace-123".to_string(),
            session: None,
        };

        assert_eq!(ctx.workdir, PathBuf::from("/tmp/test"));
        assert_eq!(ctx.trace_id, "trace-123");
        assert!(ctx.creds.is_none());
        assert!(ctx.netns.is_none());
        assert!(ctx.session.is_none());
    }

    #[test]
    fn test_exec_context_with_session() {
        let session = SessionContext {
            session_id: Uuid::new_v4(),
            domain: Some("test-domain".to_string()),
            vm_profile: Some("standard".to_string()),
        };

        let ctx = ExecContext {
            workdir: PathBuf::from("/tmp"),
            limits: ExecutionLimits::default(),
            scope: Scope {
                paths: vec![],
                urls: vec![],
            },
            creds: None,
            netns: None,
            trace_id: "trace-456".to_string(),
            session: Some(session.clone()),
        };

        assert!(ctx.session.is_some());
        let s = ctx.session.unwrap();
        assert_eq!(s.domain, Some("test-domain".to_string()));
        assert_eq!(s.vm_profile, Some("standard".to_string()));
    }

    // ===== SessionContext Tests =====

    #[test]
    fn test_session_context_creation() {
        let session_id = Uuid::new_v4();
        let session = SessionContext {
            session_id,
            domain: Some("my-domain".to_string()),
            vm_profile: None,
        };

        assert_eq!(session.session_id, session_id);
        assert_eq!(session.domain, Some("my-domain".to_string()));
        assert!(session.vm_profile.is_none());
    }

    #[test]
    fn test_session_context_clone() {
        let session = SessionContext {
            session_id: Uuid::new_v4(),
            domain: Some("domain".to_string()),
            vm_profile: Some("profile".to_string()),
        };

        let cloned = session.clone();
        assert_eq!(cloned.session_id, session.session_id);
        assert_eq!(cloned.domain, session.domain);
        assert_eq!(cloned.vm_profile, session.vm_profile);
    }

    // ===== Scope Tests =====

    #[test]
    fn test_scope_creation() {
        let scope = Scope {
            paths: vec!["/etc".to_string(), "/var/log".to_string()],
            urls: vec!["https://api.example.com".to_string()],
        };

        assert_eq!(scope.paths.len(), 2);
        assert_eq!(scope.urls.len(), 1);
    }

    #[test]
    fn test_scope_empty() {
        let scope = Scope {
            paths: vec![],
            urls: vec![],
        };

        assert!(scope.paths.is_empty());
        assert!(scope.urls.is_empty());
    }

    // ===== EphemeralCreds Tests =====

    #[test]
    fn test_ephemeral_creds_creation() {
        let creds = EphemeralCreds {
            access_token: "token-123".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };

        assert_eq!(creds.access_token, "token-123");
        assert!(creds.expires_at > Utc::now());
    }

    // ===== NetNamespaceHandle Tests =====

    #[test]
    fn test_net_namespace_handle_creation() {
        let handle = NetNamespaceHandle { fd: 42 };
        assert_eq!(handle.fd, 42);
    }

    // ===== ExecutionResult Tests =====

    #[test]
    fn test_execution_result_creation() {
        let result = ExecutionResult {
            status: ExecutionStatus::Ok,
            exit_code: Some(0),
            artifacts: vec![],
            duration_ms: 100,
            stdout_bytes: 50,
            stderr_bytes: 0,
        };

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.artifacts.is_empty());
        assert_eq!(result.duration_ms, 100);
    }

    #[test]
    fn test_execution_result_with_error() {
        let result = ExecutionResult {
            status: ExecutionStatus::Error,
            exit_code: Some(1),
            artifacts: vec![],
            duration_ms: 50,
            stdout_bytes: 0,
            stderr_bytes: 100,
        };

        assert_eq!(result.status, ExecutionStatus::Error);
        assert_eq!(result.exit_code, Some(1));
    }

    #[test]
    fn test_execution_result_timeout() {
        let result = ExecutionResult {
            status: ExecutionStatus::Timeout,
            exit_code: None,
            artifacts: vec![],
            duration_ms: 30000,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };

        assert_eq!(result.status, ExecutionStatus::Timeout);
        assert!(result.exit_code.is_none());
    }

    // ===== Artifact Tests =====

    #[test]
    fn test_artifact_creation() {
        let artifact = Artifact {
            name: "output.txt".to_string(),
            path: PathBuf::from("/tmp/output.txt"),
            size: 1024,
            sha256: "abc123".to_string(),
        };

        assert_eq!(artifact.name, "output.txt");
        assert_eq!(artifact.size, 1024);
    }

    // ===== create_exec_context Tests =====

    #[test]
    fn test_create_exec_context() {
        let temp_dir = TempDir::new().unwrap();
        let limits = ExecutionLimits::default();
        let scope = Scope {
            paths: vec!["/etc".to_string()],
            urls: vec![],
        };

        let ctx = create_exec_context(temp_dir.path(), limits, scope, "trace-999".to_string());

        assert_eq!(ctx.workdir, temp_dir.path());
        assert_eq!(ctx.trace_id, "trace-999");
        assert_eq!(ctx.scope.paths, vec!["/etc".to_string()]);
        // Credentials should be generated
        assert!(ctx.creds.is_some());
        // Session should be None by default
        assert!(ctx.session.is_none());
    }

    #[test]
    fn test_create_exec_context_generates_creds() {
        let temp_dir = TempDir::new().unwrap();
        let ctx = create_exec_context(
            temp_dir.path(),
            ExecutionLimits::default(),
            Scope {
                paths: vec![],
                urls: vec![],
            },
            "trace".to_string(),
        );

        let creds = ctx.creds.unwrap();
        assert!(creds.access_token.starts_with("exec-"));
        assert!(creds.expires_at > Utc::now());
    }

    // ===== generate_ephemeral_credentials Tests =====

    #[test]
    fn test_generate_ephemeral_credentials() {
        let creds = generate_ephemeral_credentials();
        assert!(creds.is_some());

        let creds = creds.unwrap();
        assert!(creds.access_token.starts_with("exec-"));
        // Should expire in about an hour
        let one_hour = chrono::Duration::hours(1);
        let expected_expiry = Utc::now() + one_hour;
        // Allow some tolerance
        assert!(creds.expires_at > Utc::now());
        assert!(creds.expires_at < expected_expiry + chrono::Duration::minutes(1));
    }

    #[test]
    fn test_generate_ephemeral_credentials_unique() {
        let creds1 = generate_ephemeral_credentials().unwrap();
        let creds2 = generate_ephemeral_credentials().unwrap();

        // Each call should generate unique tokens
        assert_ne!(creds1.access_token, creds2.access_token);
    }
}

// Comprehensive capability testing module
#[cfg(test)]
mod capability_tests;
