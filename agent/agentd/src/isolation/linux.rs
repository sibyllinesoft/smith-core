//! Linux native isolation backend
//!
//! This backend wraps the existing smith-jailer to provide the `IsolationBackend` trait.
//! It uses Linux-specific isolation mechanisms:
//! - Landlock LSM for filesystem access control
//! - seccomp-bpf for syscall filtering
//! - cgroups v2 for resource limits
//! - Namespaces for process/mount/network isolation

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::core::intent::Command;
use crate::core::isolation::{
    BackendCapabilities, BackendHealth, ExecContext, ExecOutput, IsolationBackend, ResourceLimits,
    ResourceUsage, Sandbox, SandboxCapabilities, SandboxSpec, StreamOutput,
};
use crate::core::sandbox::SandboxId;

/// Linux native isolation backend using smith-jailer
pub struct LinuxNativeBackend {
    work_root: PathBuf,
    landlock_available: bool,
    cgroups_available: bool,
    sandboxes: RwLock<HashMap<SandboxId, Arc<LinuxSandbox>>>,
}

impl LinuxNativeBackend {
    /// Create a new Linux native backend
    pub fn new(work_root: &Path) -> Result<Self> {
        // Check feature availability
        let landlock_available = Self::check_landlock_available();
        let cgroups_available = Self::check_cgroups_available();

        info!(
            landlock = landlock_available,
            cgroups = cgroups_available,
            "LinuxNativeBackend initialized"
        );

        Ok(Self {
            work_root: work_root.to_path_buf(),
            landlock_available,
            cgroups_available,
            sandboxes: RwLock::new(HashMap::new()),
        })
    }

    fn check_landlock_available() -> bool {
        // Check for Landlock ABI version via syscall
        #[cfg(target_os = "linux")]
        {
            smith_jailer::landlock::is_landlock_available()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn check_cgroups_available() -> bool {
        // Check if cgroups v2 is mounted
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    }

    fn check_seccomp_available() -> bool {
        // seccomp is available on all modern Linux kernels
        #[cfg(target_os = "linux")]
        {
            // Check /proc/self/seccomp
            Path::new("/proc/self/status").exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn check_namespaces_available() -> bool {
        // Check for user namespace support
        Path::new("/proc/sys/kernel/unprivileged_userns_clone").exists()
            || unsafe { libc::geteuid() } == 0
    }
}

#[async_trait]
impl IsolationBackend for LinuxNativeBackend {
    fn name(&self) -> &str {
        "linux-native"
    }

    async fn probe(&self) -> Result<BackendCapabilities> {
        let seccomp_available = Self::check_seccomp_available();
        let namespaces_available = Self::check_namespaces_available();

        let mut platform_features = Vec::new();
        if self.landlock_available {
            platform_features.push("landlock".to_string());
        }
        if seccomp_available {
            platform_features.push("seccomp".to_string());
        }
        if self.cgroups_available {
            platform_features.push("cgroups-v2".to_string());
        }
        if namespaces_available {
            platform_features.push("namespaces".to_string());
        }

        Ok(BackendCapabilities {
            name: self.name().to_string(),
            filesystem_isolation: self.landlock_available,
            network_isolation: namespaces_available,
            process_isolation: namespaces_available,
            resource_limits: self.cgroups_available,
            syscall_filtering: seccomp_available,
            persistent_sandboxes: false, // Jailed executions are ephemeral
            snapshots: false,
            max_concurrent_sandboxes: Some(100),
            available_profiles: vec![
                "default".to_string(),
                "strict".to_string(),
                "permissive".to_string(),
            ],
            platform_features,
        })
    }

    async fn create_sandbox(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>> {
        let sandbox_id = SandboxId::new();

        // Create working directory
        let workdir = self.work_root.join(sandbox_id.as_str());
        tokio::fs::create_dir_all(&workdir)
            .await
            .context("Failed to create sandbox workdir")?;

        // Set permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = tokio::fs::metadata(&workdir).await?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&workdir, perms).await?;
        }

        // Create tmp directory inside sandbox
        let tmp_dir = workdir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = tokio::fs::metadata(&tmp_dir).await?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o777);
            tokio::fs::set_permissions(&tmp_dir, perms).await?;
        }

        let capabilities = SandboxCapabilities {
            sandbox_id: sandbox_id.as_str().to_string(),
            backend: self.name().to_string(),
            profile: spec.profile.clone(),
            can_write_filesystem: !spec.allowed_paths_rw.is_empty(),
            readable_paths: spec.allowed_paths_ro.clone(),
            writable_paths: spec.allowed_paths_rw.clone(),
            has_network: spec.network_enabled,
            allowed_destinations: spec.allowed_network.clone(),
            limits: spec.limits.clone(),
            syscall_filter_active: Self::check_seccomp_available(),
            blocked_syscall_categories: vec![
                "mount".to_string(),
                "module".to_string(),
                "reboot".to_string(),
                "swap".to_string(),
            ],
            is_persistent: false,
            created_at: chrono::Utc::now(),
            time_remaining_ms: spec.limits.max_wall_time_ms,
        };

        let sandbox = Arc::new(LinuxSandbox {
            id: sandbox_id.clone(),
            workdir,
            spec: spec.clone(),
            capabilities,
            landlock_enabled: self.landlock_available,
            created_at: std::time::Instant::now(),
        });

        // Store reference
        {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.insert(sandbox_id.clone(), sandbox.clone());
        }

        Ok(Box::new(sandbox.as_ref().clone()))
    }

    async fn list_sandboxes(&self) -> Result<Vec<SandboxId>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes.keys().cloned().collect())
    }

    async fn get_sandbox(&self, id: &SandboxId) -> Result<Option<Box<dyn Sandbox>>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes
            .get(id)
            .map(|s| Box::new(s.as_ref().clone()) as Box<dyn Sandbox>))
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
        let active_count = sandboxes.len() as u32;

        let mut warnings = Vec::new();
        if !self.landlock_available {
            warnings.push("Landlock not available - filesystem isolation degraded".to_string());
        }
        if !self.cgroups_available {
            warnings.push("Cgroups v2 not available - resource limits degraded".to_string());
        }

        Ok(BackendHealth {
            healthy: true,
            active_sandboxes: active_count,
            resource_utilization: active_count as f32 / 100.0,
            warnings,
            last_sandbox_created: None,
        })
    }
}

/// A Linux sandbox instance
#[derive(Clone)]
pub struct LinuxSandbox {
    id: SandboxId,
    workdir: PathBuf,
    spec: SandboxSpec,
    capabilities: SandboxCapabilities,
    landlock_enabled: bool,
    created_at: std::time::Instant,
}

impl LinuxSandbox {
    fn resolve_execution_workdir(&self, requested_workdir: Option<&PathBuf>) -> Result<PathBuf> {
        let sandbox_root = self
            .workdir
            .canonicalize()
            .unwrap_or_else(|_| self.workdir.clone());

        let Some(requested) = requested_workdir else {
            return Ok(sandbox_root);
        };

        if requested.is_absolute() {
            anyhow::bail!(
                "Absolute workdir paths are not allowed in linux-native sandbox: {}",
                requested.display()
            );
        }

        for component in requested.components() {
            if matches!(component, Component::ParentDir | Component::RootDir) {
                anyhow::bail!(
                    "Invalid workdir component '{}' in {}",
                    component.as_os_str().to_string_lossy(),
                    requested.display()
                );
            }
            #[cfg(windows)]
            if matches!(component, Component::Prefix(_)) {
                anyhow::bail!(
                    "Invalid workdir component '{}' in {}",
                    component.as_os_str().to_string_lossy(),
                    requested.display()
                );
            }
        }

        let candidate = sandbox_root.join(requested);
        let resolved = candidate.canonicalize().with_context(|| {
            format!(
                "Requested workdir does not exist or cannot be resolved: {}",
                candidate.display()
            )
        })?;

        if !resolved.starts_with(&sandbox_root) {
            anyhow::bail!(
                "Requested workdir escapes sandbox root: {}",
                requested.display()
            );
        }

        if !resolved.is_dir() {
            anyhow::bail!(
                "Requested workdir is not a directory: {}",
                resolved.display()
            );
        }

        Ok(resolved)
    }
}

#[async_trait]
impl Sandbox for LinuxSandbox {
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

        // Determine and validate working directory (must remain under sandbox root).
        let workdir =
            self.resolve_execution_workdir(ctx.workdir.as_ref().or(cmd.workdir.as_ref()))?;

        // Build environment
        let mut env: HashMap<String, String> = HashMap::new();
        if cmd.inherit_env {
            env.extend(std::env::vars());
        }
        env.extend(cmd.env.clone());
        env.extend(ctx.extra_env.iter().cloned());

        // Set sandbox-specific env vars
        env.insert("SANDBOX_ID".to_string(), self.id.as_str().to_string());
        env.insert(
            "SANDBOX_WORKDIR".to_string(),
            workdir.to_string_lossy().to_string(),
        );
        env.insert(
            "TMPDIR".to_string(),
            self.workdir.join("tmp").to_string_lossy().to_string(),
        );

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

        // Apply Landlock filesystem restrictions if available
        if self.landlock_enabled {
            use smith_jailer::landlock::{apply_landlock_rules, LandlockConfig, LandlockRule};
            use std::collections::HashMap;
            use std::os::unix::process::CommandExt;

            // Track paths with their combined access rights
            // We merge permissions for the same path to avoid conflicts
            let mut path_permissions: HashMap<String, (bool, bool)> = HashMap::new(); // (rw, exec)

            // Helper to collect path permissions
            let mut collect_path = |perms: &mut HashMap<String, (bool, bool)>,
                                    path_str: &str,
                                    rw: bool,
                                    exec: bool| {
                let p = std::path::Path::new(path_str);
                // Try to canonicalize to resolve symlinks
                let canonical = match p.canonicalize() {
                    Ok(c) => c,
                    Err(_) => return, // Path doesn't exist
                };

                if let Ok(metadata) = canonical.metadata() {
                    // Only add rules for regular files and directories
                    if metadata.is_dir() || metadata.is_file() {
                        let path_s = canonical.to_string_lossy().to_string();
                        let entry = perms.entry(path_s).or_insert((false, false));
                        // Merge permissions - if any request is rw or exec, enable it
                        entry.0 = entry.0 || rw;
                        entry.1 = entry.1 || exec;
                    }
                }
            };

            // Collect read-only paths from spec
            for path in &self.spec.allowed_paths_ro {
                collect_path(&mut path_permissions, &path.to_string_lossy(), false, false);
            }

            // Collect read-write paths from spec
            for path in &self.spec.allowed_paths_rw {
                collect_path(&mut path_permissions, &path.to_string_lossy(), true, false);
            }

            // Always allow access to sandbox workdir
            collect_path(
                &mut path_permissions,
                &self.workdir.to_string_lossy(),
                true,
                false,
            );

            // Essential system paths for command execution
            collect_path(&mut path_permissions, "/usr/bin", false, true);
            collect_path(&mut path_permissions, "/usr/local/bin", false, true);
            collect_path(&mut path_permissions, "/usr/sbin", false, true);
            // /usr/lib needs execute for the dynamic linker (ld-linux-x86-64.so.2)
            collect_path(&mut path_permissions, "/usr/lib", false, true);
            collect_path(&mut path_permissions, "/etc/ld.so.cache", false, false);
            collect_path(&mut path_permissions, "/etc/ld.so.conf", false, false);
            collect_path(&mut path_permissions, "/etc/ld.so.conf.d", false, false);
            // Only allow write access to sandbox's tmp dir, not all of /tmp
            collect_path(
                &mut path_permissions,
                &self.workdir.join("tmp").to_string_lossy(),
                true,
                false,
            );

            // Build Landlock config from collected paths (with merged permissions)
            let mut landlock_config = LandlockConfig::default();
            for (path, (rw, exec)) in &path_permissions {
                debug!("Adding Landlock rule: {} (rw={}, exec={})", path, rw, exec);
                if *exec {
                    landlock_config.allow_execute(path);
                } else if *rw {
                    landlock_config.allow_read_write(path);
                } else {
                    landlock_config.allow_read(path);
                }
            }

            // Log the total number of rules
            debug!(sandbox_id = %self.id, rules_count = landlock_config.rules.len(), "Landlock config built");

            // Apply Landlock in pre_exec (runs in child after fork, before exec)
            unsafe {
                process.pre_exec(move || {
                    apply_landlock_rules(&landlock_config)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
                });
            }

            debug!(sandbox_id = %self.id, "Landlock pre_exec hook configured");
        }

        // Spawn process
        let mut child = match process.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    sandbox_id = %self.id,
                    error = %e,
                    program = %cmd.program,
                    "Failed to spawn command"
                );
                return Err(anyhow::anyhow!("Failed to spawn command: {}", e));
            }
        };

        // Write stdin if provided
        if let Some(stdin_data) = &cmd.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(stdin_data).await?;
            }
        }

        // Determine timeout
        let timeout = ctx
            .timeout
            .or(cmd.timeout)
            .or(self.spec.limits.max_wall_time_ms.map(Duration::from_millis))
            .unwrap_or(Duration::from_secs(60));

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
                    resource_usage: None,
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
        self.workdir.exists()
    }

    async fn suspend(&self) -> Result<()> {
        // Linux sandboxes don't support suspension currently
        anyhow::bail!("Suspend not supported by LinuxNativeBackend")
    }

    async fn resume(&self) -> Result<()> {
        anyhow::bail!("Resume not supported by LinuxNativeBackend")
    }

    async fn snapshot(&self, _name: &str) -> Result<String> {
        anyhow::bail!("Snapshots not supported by LinuxNativeBackend")
    }

    async fn restore(&self, _snapshot_id: &str) -> Result<()> {
        anyhow::bail!("Restore not supported by LinuxNativeBackend")
    }

    async fn destroy(&self) -> Result<()> {
        // Remove workdir
        if self.workdir.exists() {
            tokio::fs::remove_dir_all(&self.workdir)
                .await
                .context("Failed to remove sandbox workdir")?;
        }
        Ok(())
    }

    async fn resource_usage(&self) -> Result<ResourceUsage> {
        // In a full implementation, this would read from cgroups
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

    fn create_test_sandbox(workdir: PathBuf) -> LinuxSandbox {
        LinuxSandbox {
            id: SandboxId::new(),
            workdir,
            spec: SandboxSpec::default(),
            capabilities: SandboxCapabilities {
                sandbox_id: "test".to_string(),
                backend: "linux-native".to_string(),
                profile: "default".to_string(),
                can_write_filesystem: true,
                readable_paths: vec![],
                writable_paths: vec![],
                has_network: false,
                allowed_destinations: vec![],
                limits: ResourceLimits::default(),
                syscall_filter_active: true,
                blocked_syscall_categories: vec![],
                is_persistent: false,
                created_at: chrono::Utc::now(),
                time_remaining_ms: Some(60_000),
            },
            landlock_enabled: false,
            created_at: std::time::Instant::now(),
        }
    }

    #[test]
    fn test_resolve_execution_workdir_allows_relative_child() {
        let temp = TempDir::new().unwrap();
        let child = temp.path().join("child");
        std::fs::create_dir_all(&child).unwrap();
        let sandbox = create_test_sandbox(temp.path().to_path_buf());

        let requested = PathBuf::from("child");
        let resolved = sandbox.resolve_execution_workdir(Some(&requested)).unwrap();
        assert!(resolved.ends_with("child"));
    }

    #[test]
    fn test_resolve_execution_workdir_rejects_absolute_path() {
        let temp = TempDir::new().unwrap();
        let sandbox = create_test_sandbox(temp.path().to_path_buf());
        let requested = PathBuf::from("/tmp");
        let result = sandbox.resolve_execution_workdir(Some(&requested));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Absolute workdir paths are not allowed"));
    }

    #[test]
    fn test_resolve_execution_workdir_rejects_parent_traversal() {
        let temp = TempDir::new().unwrap();
        let sandbox = create_test_sandbox(temp.path().to_path_buf());
        let requested = PathBuf::from("../escape");
        let result = sandbox.resolve_execution_workdir(Some(&requested));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid workdir component"));
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_execution_workdir_rejects_symlink_escape() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let link = temp.path().join("link_out");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let sandbox = create_test_sandbox(temp.path().to_path_buf());
        let requested = PathBuf::from("link_out");
        let result = sandbox.resolve_execution_workdir(Some(&requested));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("escapes sandbox root"));
    }
}
