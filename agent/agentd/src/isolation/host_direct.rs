//! Host-direct isolation backend (workstation mode)
//!
//! This backend provides no kernel-level isolation, running commands directly
//! on the host. It's intended for workstation use where:
//! - The user trusts the agent
//! - Full system access is needed
//! - Sandbox overhead is undesirable
//!
//! Security relies entirely on policy guards and soft limits (nice, ulimit).

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command as TokioCommand;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::core::intent::Command;
use crate::core::isolation::{
    BackendCapabilities, BackendHealth, ExecContext, ExecOutput, IsolationBackend, ResourceLimits,
    ResourceUsage, Sandbox, SandboxCapabilities, SandboxSpec, StreamOutput,
};
use crate::core::sandbox::SandboxId;

/// Host-direct backend for workstation mode
///
/// This backend runs commands directly on the host without isolation.
/// It's suitable for development and trusted agent scenarios.
pub struct HostDirectBackend {
    work_root: PathBuf,
    sandboxes: RwLock<HashMap<SandboxId, HostDirectSandbox>>,
}

impl HostDirectBackend {
    /// Create a new host-direct backend
    pub fn new(work_root: &Path) -> Self {
        info!(
            work_root = %work_root.display(),
            "HostDirectBackend initialized (workstation mode - no isolation)"
        );

        Self {
            work_root: work_root.to_path_buf(),
            sandboxes: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl IsolationBackend for HostDirectBackend {
    fn name(&self) -> &str {
        "host-direct"
    }

    async fn probe(&self) -> Result<BackendCapabilities> {
        Ok(BackendCapabilities {
            name: self.name().to_string(),
            filesystem_isolation: false,
            network_isolation: false,
            process_isolation: false,
            resource_limits: false, // Only soft limits via nice/ulimit
            syscall_filtering: false,
            persistent_sandboxes: true, // Working directories persist
            snapshots: false,
            max_concurrent_sandboxes: None, // Unlimited
            available_profiles: vec!["workstation".to_string(), "permissive".to_string()],
            platform_features: vec!["soft-limits".to_string(), "policy-only".to_string()],
        })
    }

    async fn create_sandbox(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>> {
        let sandbox_id = SandboxId::new();

        // Create working directory
        let workdir = self.work_root.join(sandbox_id.as_str());
        tokio::fs::create_dir_all(&workdir)
            .await
            .context("Failed to create sandbox workdir")?;

        // For host-direct, we have full access to the filesystem
        let capabilities = SandboxCapabilities {
            sandbox_id: sandbox_id.as_str().to_string(),
            backend: self.name().to_string(),
            profile: spec.profile.clone(),
            can_write_filesystem: true,
            readable_paths: vec![PathBuf::from("/")], // Full read access
            writable_paths: spec.allowed_paths_rw.clone(),
            has_network: true, // Full network access
            allowed_destinations: vec!["*".to_string()],
            limits: spec.limits.clone(),
            syscall_filter_active: false,
            blocked_syscall_categories: vec![], // Nothing blocked
            is_persistent: true,
            created_at: chrono::Utc::now(),
            time_remaining_ms: spec.limits.max_wall_time_ms,
        };

        let sandbox = HostDirectSandbox {
            id: sandbox_id.clone(),
            workdir,
            spec: spec.clone(),
            capabilities,
            created_at: std::time::Instant::now(),
        };

        // Store reference
        {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.insert(sandbox_id, sandbox.clone());
        }

        Ok(Box::new(sandbox))
    }

    async fn list_sandboxes(&self) -> Result<Vec<SandboxId>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes.keys().cloned().collect())
    }

    async fn get_sandbox(&self, id: &SandboxId) -> Result<Option<Box<dyn Sandbox>>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes
            .get(id)
            .map(|s| Box::new(s.clone()) as Box<dyn Sandbox>))
    }

    async fn destroy_all(&self) -> Result<()> {
        let sandboxes: Vec<_> = {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.drain().collect()
        };

        for (_, sandbox) in sandboxes {
            if let Err(e) = sandbox.destroy().await {
                warn!(sandbox_id = %sandbox.id, error = %e, "Failed to destroy sandbox");
            }
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<BackendHealth> {
        let sandboxes = self.sandboxes.read().await;

        Ok(BackendHealth {
            healthy: true,
            active_sandboxes: sandboxes.len() as u32,
            resource_utilization: 0.0, // No isolation means no resource tracking
            warnings: vec!["Running in workstation mode - no kernel isolation".to_string()],
            last_sandbox_created: None,
        })
    }
}

/// A host-direct sandbox (no isolation)
#[derive(Clone)]
pub struct HostDirectSandbox {
    id: SandboxId,
    workdir: PathBuf,
    spec: SandboxSpec,
    capabilities: SandboxCapabilities,
    created_at: std::time::Instant,
}

#[async_trait]
impl Sandbox for HostDirectSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &SandboxCapabilities {
        &self.capabilities
    }

    async fn exec(&self, cmd: &Command, ctx: &ExecContext) -> Result<ExecOutput> {
        // Create a channel but we don't need to read from it for non-streaming exec
        let (tx, mut rx) = tokio::sync::mpsc::channel::<StreamOutput>(100);

        // Spawn a task to drain the channel (we don't need the streaming output)
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        self.exec_streaming(cmd, ctx, tx).await
    }

    async fn exec_streaming(
        &self,
        cmd: &Command,
        ctx: &ExecContext,
        output_tx: tokio::sync::mpsc::Sender<StreamOutput>,
    ) -> Result<ExecOutput> {
        let start = std::time::Instant::now();

        // Determine working directory - prefer explicit workdir, fall back to sandbox workdir
        let workdir = ctx
            .workdir
            .clone()
            .or(cmd.workdir.clone())
            .unwrap_or_else(|| self.workdir.clone());

        // Build environment
        let mut env: HashMap<String, String> = HashMap::new();
        if cmd.inherit_env {
            env.extend(std::env::vars());
        }
        env.extend(cmd.env.clone());
        env.extend(ctx.extra_env.iter().cloned());

        // Set informational env vars (not enforced)
        env.insert(
            "AGENTD_SANDBOX_ID".to_string(),
            self.id.as_str().to_string(),
        );
        env.insert("AGENTD_SANDBOX_MODE".to_string(), "host-direct".to_string());

        // Build command
        let mut process = TokioCommand::new(&cmd.program);
        process
            .args(&cmd.args)
            .current_dir(&workdir)
            .envs(env)
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Spawn process
        let mut child = process.spawn().context("Failed to spawn command")?;

        // Write stdin if provided
        if let Some(stdin_data) = &cmd.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(stdin_data).await?;
            }
        }

        // Determine timeout (use command timeout, context timeout, or spec limit)
        let timeout = ctx
            .timeout
            .or(cmd.timeout)
            .or(self.spec.limits.max_wall_time_ms.map(Duration::from_millis))
            .unwrap_or(Duration::from_secs(300)); // Default 5 minutes for workstation

        // Stream stdout and stderr via channels
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let stdout_tx = output_tx.clone();
        let stderr_tx = output_tx.clone();

        let stdout_handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut stdout) = stdout {
                let mut chunk = vec![0u8; 4096];
                loop {
                    match stdout.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = chunk[..n].to_vec();
                            buf.extend_from_slice(&data);
                            let _ = stdout_tx.send(StreamOutput::Stdout(data)).await;
                        }
                        Err(_) => break,
                    }
                }
            }
            buf
        });

        let stderr_handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut stderr) = stderr {
                let mut chunk = vec![0u8; 4096];
                loop {
                    match stderr.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = chunk[..n].to_vec();
                            buf.extend_from_slice(&data);
                            let _ = stderr_tx.send(StreamOutput::Stderr(data)).await;
                        }
                        Err(_) => break,
                    }
                }
            }
            buf
        });

        // Wait for process with timeout
        let result = tokio::time::timeout(timeout, async {
            let status = child.wait().await?;
            let stdout_data = stdout_handle.await.unwrap_or_default();
            let stderr_data = stderr_handle.await.unwrap_or_default();
            Ok::<_, anyhow::Error>((status, stdout_data, stderr_data))
        })
        .await;

        let duration = start.elapsed();

        match result {
            Ok(Ok((status, stdout_data, stderr_data))) => {
                let exit_code = status.code().unwrap_or(-1);
                let _ = output_tx.send(StreamOutput::Exit { code: exit_code }).await;

                Ok(ExecOutput {
                    exit_code,
                    stdout: stdout_data,
                    stderr: stderr_data,
                    duration,
                    timed_out: false,
                    resource_limited: false,
                    resource_usage: Some(ResourceUsage {
                        peak_memory_bytes: 0,
                        cpu_time_ms: duration.as_millis() as u64,
                        wall_time_ms: duration.as_millis() as u64,
                        bytes_written: 0,
                        bytes_read: 0,
                    }),
                })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout - kill the process
                let _ = child.kill().await;
                let _ = output_tx.send(StreamOutput::Exit { code: -1 }).await;

                Ok(ExecOutput {
                    exit_code: -1,
                    stdout: vec![],
                    stderr: b"Process timed out".to_vec(),
                    duration,
                    timed_out: true,
                    resource_limited: false,
                    resource_usage: None,
                })
            }
        }
    }

    async fn is_alive(&self) -> bool {
        // Host-direct sandboxes are always "alive" as long as workdir exists
        self.workdir.exists()
    }

    async fn suspend(&self) -> Result<()> {
        // Host-direct sandboxes don't support suspension
        // In the future, we could implement SIGSTOP for child processes
        warn!("Suspend not implemented for host-direct sandboxes");
        Ok(())
    }

    async fn resume(&self) -> Result<()> {
        warn!("Resume not implemented for host-direct sandboxes");
        Ok(())
    }

    async fn snapshot(&self, name: &str) -> Result<String> {
        // Could implement via filesystem snapshots (btrfs, zfs) in the future
        anyhow::bail!("Snapshots not supported by HostDirectBackend")
    }

    async fn restore(&self, _snapshot_id: &str) -> Result<()> {
        anyhow::bail!("Restore not supported by HostDirectBackend")
    }

    async fn destroy(&self) -> Result<()> {
        // Optionally remove workdir
        // In workstation mode, we might want to keep it for debugging
        if self.workdir.exists() {
            debug!(
                workdir = %self.workdir.display(),
                "Host-direct sandbox workdir preserved (can be manually removed)"
            );
        }
        Ok(())
    }

    async fn resource_usage(&self) -> Result<ResourceUsage> {
        // No resource tracking in host-direct mode
        Ok(ResourceUsage {
            peak_memory_bytes: 0,
            cpu_time_ms: self.created_at.elapsed().as_millis() as u64,
            wall_time_ms: self.created_at.elapsed().as_millis() as u64,
            bytes_written: 0,
            bytes_read: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_spec(profile: &str) -> SandboxSpec {
        SandboxSpec {
            profile: profile.to_string(),
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

    fn create_test_exec_context() -> ExecContext {
        ExecContext {
            trace_id: "test-trace".to_string(),
            request_id: "test-request".to_string(),
            workdir: None,
            extra_env: vec![],
            timeout: Some(Duration::from_secs(5)),
            capture_stdout: true,
            capture_stderr: true,
            stream_output: false,
        }
    }

    // ===== HostDirectBackend Tests =====

    #[test]
    fn test_host_direct_backend_new() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());
        assert_eq!(backend.work_root, temp_dir.path());
    }

    #[test]
    fn test_host_direct_backend_name() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());
        assert_eq!(backend.name(), "host-direct");
    }

    #[tokio::test]
    async fn test_host_direct_probe() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let caps = backend.probe().await.unwrap();

        assert_eq!(caps.name, "host-direct");
        // Host-direct has no kernel isolation
        assert!(!caps.filesystem_isolation);
        assert!(!caps.network_isolation);
        assert!(!caps.process_isolation);
        assert!(!caps.resource_limits);
        assert!(!caps.syscall_filtering);
        // But supports persistent sandboxes
        assert!(caps.persistent_sandboxes);
        assert!(!caps.snapshots);
        // Unlimited sandboxes
        assert!(caps.max_concurrent_sandboxes.is_none());
        // Available profiles
        assert!(caps.available_profiles.contains(&"workstation".to_string()));
        assert!(caps.available_profiles.contains(&"permissive".to_string()));
        // Platform features
        assert!(caps.platform_features.contains(&"soft-limits".to_string()));
        assert!(caps.platform_features.contains(&"policy-only".to_string()));
    }

    #[tokio::test]
    async fn test_host_direct_create_sandbox() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let spec = create_test_spec("workstation");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();

        // Verify sandbox was created
        let caps = sandbox.capabilities();
        assert_eq!(caps.backend, "host-direct");
        assert_eq!(caps.profile, "workstation");
        assert!(caps.can_write_filesystem);
        assert!(caps.has_network);
        assert!(!caps.syscall_filter_active);
        assert!(caps.is_persistent);
    }

    #[tokio::test]
    async fn test_host_direct_list_sandboxes() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        // Initially empty
        let sandboxes = backend.list_sandboxes().await.unwrap();
        assert!(sandboxes.is_empty());

        // Create a sandbox
        let spec = create_test_spec("test");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();
        let sandbox_id = sandbox.id().clone();

        // Should now have one sandbox
        let sandboxes = backend.list_sandboxes().await.unwrap();
        assert_eq!(sandboxes.len(), 1);
        assert!(sandboxes.contains(&sandbox_id));
    }

    #[tokio::test]
    async fn test_host_direct_get_sandbox() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let spec = create_test_spec("test");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();
        let sandbox_id = sandbox.id().clone();

        // Get by ID
        let retrieved = backend.get_sandbox(&sandbox_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id(), &sandbox_id);

        // Non-existent ID
        let fake_id = SandboxId::new();
        let retrieved = backend.get_sandbox(&fake_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_host_direct_destroy_all() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        // Create multiple sandboxes
        for _ in 0..3 {
            let spec = create_test_spec("test");
            let _ = backend.create_sandbox(&spec).await.unwrap();
        }

        let sandboxes = backend.list_sandboxes().await.unwrap();
        assert_eq!(sandboxes.len(), 3);

        // Destroy all
        backend.destroy_all().await.unwrap();

        let sandboxes = backend.list_sandboxes().await.unwrap();
        assert!(sandboxes.is_empty());
    }

    #[tokio::test]
    async fn test_host_direct_health_check() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let health = backend.health_check().await.unwrap();

        assert!(health.healthy);
        assert_eq!(health.active_sandboxes, 0);
        assert!(!health.warnings.is_empty());
        assert!(health.warnings[0].contains("workstation mode"));
    }

    // ===== HostDirectSandbox Tests =====

    #[tokio::test]
    async fn test_sandbox_exec_simple_command() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let spec = create_test_spec("test");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();

        let cmd = Command::new("echo").args(["hello", "world"]);
        let ctx = create_test_exec_context();
        let result = sandbox.exec(&cmd, &ctx).await.unwrap();

        assert_eq!(result.exit_code, 0);
        assert!(!result.timed_out);
        let stdout_str = String::from_utf8_lossy(&result.stdout);
        assert!(stdout_str.contains("hello world"));
    }

    #[tokio::test]
    async fn test_sandbox_exec_with_exit_code() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let spec = create_test_spec("test");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();

        let cmd = Command::new("sh").args(["-c", "exit 42"]);
        let ctx = create_test_exec_context();
        let result = sandbox.exec(&cmd, &ctx).await.unwrap();

        assert_eq!(result.exit_code, 42);
    }

    #[tokio::test]
    async fn test_sandbox_is_alive() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let spec = create_test_spec("test");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();

        // Sandbox should be alive
        assert!(sandbox.is_alive().await);
    }

    #[tokio::test]
    async fn test_sandbox_suspend_resume() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let spec = create_test_spec("test");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();

        // These are no-ops for host-direct, but should not error
        sandbox.suspend().await.unwrap();
        sandbox.resume().await.unwrap();
    }

    #[tokio::test]
    async fn test_sandbox_snapshot_not_supported() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let spec = create_test_spec("test");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();

        // Snapshots are not supported
        let result = sandbox.snapshot("test-snapshot").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sandbox_resource_usage() {
        let temp_dir = TempDir::new().unwrap();
        let backend = HostDirectBackend::new(temp_dir.path());

        let spec = create_test_spec("test");
        let sandbox = backend.create_sandbox(&spec).await.unwrap();

        // Wait a bit for wall time to accumulate
        tokio::time::sleep(Duration::from_millis(10)).await;

        let usage = sandbox.resource_usage().await.unwrap();

        // In host-direct mode, only time is tracked
        assert_eq!(usage.peak_memory_bytes, 0);
        assert!(usage.wall_time_ms >= 10);
    }
}
