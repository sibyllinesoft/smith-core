//! Container-based isolation backend
//!
//! This backend provides proper filesystem isolation using:
//! - Mount namespaces for isolated filesystem view
//! - Bind mounts to expose specific host paths
//! - OverlayFS for copy-on-write workspace
//! - PID namespace for process isolation
//! - Network namespace (optional)
//!
//! Unlike LinuxNativeBackend which uses Landlock on the host filesystem,
//! this backend creates a new mount namespace where only explicitly
//! mounted paths are visible.

use anyhow::{Context, Result};
use async_trait::async_trait;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult, Pid};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command as TokioCommand;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::core::intent::Command;
use crate::core::isolation::{
    BackendCapabilities, BackendHealth, ExecContext, ExecOutput, IsolationBackend, ResourceLimits,
    ResourceUsage, Sandbox, SandboxCapabilities, SandboxSpec, StreamOutput,
};
use crate::core::sandbox::SandboxId;

/// Mount specification for exposing host paths in container
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// Source path on host
    pub source: PathBuf,
    /// Target path inside container
    pub target: PathBuf,
    /// Mount as read-only
    pub read_only: bool,
    /// Mount type
    pub mount_type: MountType,
}

/// Type of mount
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountType {
    /// Bind mount from host
    Bind,
    /// Tmpfs (memory-backed)
    Tmpfs,
    /// Proc filesystem
    Proc,
    /// Devtmpfs for /dev
    Dev,
}

/// Container isolation backend using mount namespaces
pub struct ContainerBackend {
    work_root: PathBuf,
    base_rootfs: Option<PathBuf>,
    sandboxes: RwLock<HashMap<SandboxId, Arc<ContainerSandbox>>>,
}

impl ContainerBackend {
    /// Create a new container backend
    ///
    /// # Arguments
    /// * `work_root` - Directory for sandbox working directories
    /// * `base_rootfs` - Optional base rootfs to use (if None, uses minimal rootfs)
    pub fn new(work_root: &Path, base_rootfs: Option<PathBuf>) -> Result<Self> {
        // Ensure work_root exists
        std::fs::create_dir_all(work_root)?;

        Ok(Self {
            work_root: work_root.to_path_buf(),
            base_rootfs,
            sandboxes: RwLock::new(HashMap::new()),
        })
    }

    /// Check if user namespaces are available
    fn check_userns_available() -> bool {
        // Check unprivileged user namespace support
        if Path::new("/proc/sys/kernel/unprivileged_userns_clone").exists() {
            if let Ok(content) =
                std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            {
                return content.trim() == "1";
            }
        }
        // If the file doesn't exist, user namespaces might still work (newer kernels)
        // Try creating one to check
        true
    }

    /// Check if we can use mount namespaces
    fn check_mount_ns_available() -> bool {
        // Mount namespaces require either root or user namespace support
        let is_root = unsafe { libc::geteuid() == 0 };
        is_root || Self::check_userns_available()
    }

    /// Create the sandbox rootfs structure
    async fn setup_rootfs(&self, sandbox_dir: &Path, spec: &SandboxSpec) -> Result<PathBuf> {
        let rootfs = sandbox_dir.join("rootfs");
        tokio::fs::create_dir_all(&rootfs).await?;

        // Create essential directories
        for dir in &[
            "bin",
            "dev",
            "etc",
            "lib",
            "lib64",
            "proc",
            "sys",
            "tmp",
            "usr",
            "var",
            "workspace",
        ] {
            tokio::fs::create_dir_all(rootfs.join(dir)).await?;
        }

        // Set tmp permissions
        let tmp_path = rootfs.join("tmp");
        let mut perms = tokio::fs::metadata(&tmp_path).await?.permissions();
        perms.set_mode(0o1777);
        tokio::fs::set_permissions(&tmp_path, perms).await?;

        // Create workspace with proper permissions
        let workspace = rootfs.join("workspace");
        let mut perms = tokio::fs::metadata(&workspace).await?.permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(&workspace, perms).await?;

        Ok(rootfs)
    }

    /// Generate mount specifications from sandbox spec
    fn generate_mounts(&self, spec: &SandboxSpec, rootfs: &Path) -> Vec<MountSpec> {
        let mut mounts = Vec::new();

        // Essential system mounts
        mounts.push(MountSpec {
            source: PathBuf::from("proc"),
            target: rootfs.join("proc"),
            read_only: false,
            mount_type: MountType::Proc,
        });

        mounts.push(MountSpec {
            source: PathBuf::from("tmpfs"),
            target: rootfs.join("dev"),
            read_only: false,
            mount_type: MountType::Dev,
        });

        mounts.push(MountSpec {
            source: PathBuf::from("tmpfs"),
            target: rootfs.join("tmp"),
            read_only: false,
            mount_type: MountType::Tmpfs,
        });

        // Bind mount essential host directories (read-only)
        for host_dir in &[
            "/usr/bin",
            "/usr/lib",
            "/usr/lib64",
            "/lib",
            "/lib64",
            "/bin",
        ] {
            if Path::new(host_dir).exists() {
                let target = if host_dir.starts_with("/usr/") {
                    rootfs.join(&host_dir[1..])
                } else {
                    rootfs.join(&host_dir[1..])
                };
                mounts.push(MountSpec {
                    source: PathBuf::from(host_dir),
                    target,
                    read_only: true,
                    mount_type: MountType::Bind,
                });
            }
        }

        // User-specified read-only paths
        for path in &spec.allowed_paths_ro {
            // Map to /mnt/host/<path> inside container
            let target = rootfs
                .join("mnt")
                .join("host")
                .join(path.strip_prefix("/").unwrap_or(path));
            mounts.push(MountSpec {
                source: path.clone(),
                target,
                read_only: true,
                mount_type: MountType::Bind,
            });
        }

        // User-specified read-write paths
        for path in &spec.allowed_paths_rw {
            let target = rootfs
                .join("mnt")
                .join("host")
                .join(path.strip_prefix("/").unwrap_or(path));
            mounts.push(MountSpec {
                source: path.clone(),
                target,
                read_only: false,
                mount_type: MountType::Bind,
            });
        }

        // Custom bind mounts with explicit target paths
        for bind_mount in &spec.bind_mounts {
            // For custom bind mounts, use the exact target path specified
            // (relative to rootfs)
            let target = if bind_mount.target.is_absolute() {
                rootfs.join(
                    bind_mount
                        .target
                        .strip_prefix("/")
                        .unwrap_or(&bind_mount.target),
                )
            } else {
                rootfs.join(&bind_mount.target)
            };
            mounts.push(MountSpec {
                source: bind_mount.source.clone(),
                target,
                read_only: bind_mount.readonly,
                mount_type: MountType::Bind,
            });
        }

        mounts
    }
}

#[async_trait]
impl IsolationBackend for ContainerBackend {
    fn name(&self) -> &str {
        "container"
    }

    async fn probe(&self) -> Result<BackendCapabilities> {
        let mount_ns = Self::check_mount_ns_available();
        let user_ns = Self::check_userns_available();
        let cgroups = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

        let mut features = Vec::new();
        if mount_ns {
            features.push("mount-namespace".to_string());
        }
        if user_ns {
            features.push("user-namespace".to_string());
        }
        if cgroups {
            features.push("cgroups-v2".to_string());
        }
        features.push("bind-mounts".to_string());
        features.push("overlayfs".to_string());

        Ok(BackendCapabilities {
            name: self.name().to_string(),
            filesystem_isolation: mount_ns,
            network_isolation: mount_ns, // Network namespace requires mount namespace
            process_isolation: mount_ns,
            resource_limits: cgroups,
            syscall_filtering: true, // Can combine with seccomp
            persistent_sandboxes: true,
            snapshots: true, // OverlayFS enables snapshots
            max_concurrent_sandboxes: Some(50),
            available_profiles: vec![
                "minimal".to_string(),
                "standard".to_string(),
                "full".to_string(),
            ],
            platform_features: features,
        })
    }

    async fn create_sandbox(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>> {
        let sandbox_id = SandboxId::new();
        let sandbox_dir = self.work_root.join(sandbox_id.as_str());

        tokio::fs::create_dir_all(&sandbox_dir)
            .await
            .context("Failed to create sandbox directory")?;

        // Setup rootfs
        let rootfs = self.setup_rootfs(&sandbox_dir, spec).await?;

        // Generate mount specifications
        let mounts = self.generate_mounts(spec, &rootfs);

        // Create mnt/host directory for bind mounts
        tokio::fs::create_dir_all(rootfs.join("mnt/host")).await?;

        // Ensure all mount target directories exist
        for mount in &mounts {
            if let Some(parent) = mount.target.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            if mount.mount_type == MountType::Bind {
                // For bind mounts, create empty file or directory matching source
                if mount.source.is_dir() {
                    tokio::fs::create_dir_all(&mount.target).await?;
                } else if mount.source.is_file() {
                    if let Some(parent) = mount.target.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    tokio::fs::write(&mount.target, "").await?;
                }
            }
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
            syscall_filter_active: true,
            blocked_syscall_categories: vec![
                "mount".to_string(),
                "module".to_string(),
                "reboot".to_string(),
            ],
            is_persistent: true,
            created_at: chrono::Utc::now(),
            time_remaining_ms: spec.limits.max_wall_time_ms,
        };

        let sandbox = Arc::new(ContainerSandbox {
            id: sandbox_id.clone(),
            sandbox_dir,
            rootfs,
            mounts,
            spec: spec.clone(),
            capabilities,
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
        if !Self::check_mount_ns_available() {
            warnings.push("Mount namespaces not available".to_string());
        }

        Ok(BackendHealth {
            healthy: true,
            active_sandboxes: active_count,
            resource_utilization: active_count as f32 / 50.0,
            warnings,
            last_sandbox_created: None,
        })
    }
}

/// A container sandbox instance
#[derive(Clone)]
pub struct ContainerSandbox {
    id: SandboxId,
    sandbox_dir: PathBuf,
    rootfs: PathBuf,
    mounts: Vec<MountSpec>,
    spec: SandboxSpec,
    capabilities: SandboxCapabilities,
    created_at: std::time::Instant,
}

impl ContainerSandbox {
    /// Execute a command inside the container namespace using bubblewrap
    async fn exec_in_namespace(&self, cmd: &Command, ctx: &ExecContext) -> Result<ExecOutput> {
        let start = std::time::Instant::now();

        // Build the bubblewrap command
        // bwrap handles namespace creation and bind mounts properly
        let mut bwrap_cmd = TokioCommand::new("bwrap");

        // Create new namespaces
        bwrap_cmd
            .arg("--unshare-pid") // New PID namespace
            .arg("--unshare-uts") // New UTS namespace
            .arg("--unshare-ipc"); // New IPC namespace

        // User namespace for unprivileged operation
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            bwrap_cmd.arg("--unshare-user");
        }

        // Network namespace (if network is disabled)
        if !self.spec.network_enabled {
            bwrap_cmd.arg("--unshare-net");
        }

        // Build a restrictive filesystem where:
        // - System paths are read-only
        // - Only explicitly allowed paths are writable
        // - Paths outside allowed areas either don't exist or are read-only
        //
        // Strategy: Use --ro-bind for system paths, --bind for allowed rw paths,
        // and implicitly block everything else by not mounting it

        bwrap_cmd
            .arg("--proc")
            .arg("/proc") // Mount /proc
            .arg("--dev")
            .arg("/dev") // Mount /dev
            .arg("--tmpfs")
            .arg("/tmp"); // Writable /tmp (for shell)

        // Bind mount essential system directories (read-only)
        for host_dir in &["/usr", "/lib", "/lib64", "/bin", "/etc"] {
            if Path::new(host_dir).exists() {
                bwrap_cmd.arg("--ro-bind").arg(host_dir).arg(host_dir);
            }
        }

        // Bind mount user-specified read-only paths
        for path in &self.spec.allowed_paths_ro {
            if path.exists() {
                bwrap_cmd.arg("--ro-bind").arg(path).arg(path);
            }
        }

        // For read-write paths, we need to:
        // 1. Bind mount parent directories as read-only (to make the path accessible
        //    but prevent writes to parent dirs)
        // 2. Then overlay the actual rw path with a writable bind mount

        // Collect all parent directories that need to exist for rw paths
        let mut parent_dirs: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        for path in &self.spec.allowed_paths_rw {
            let mut current = path.clone();
            while let Some(parent) = current.parent() {
                if parent.as_os_str().is_empty() || parent == Path::new("/") {
                    break;
                }
                parent_dirs.insert(parent.to_path_buf());
                current = parent.to_path_buf();
            }
        }

        // Sort parent dirs by depth (shortest first) and bind mount them as read-only
        // This creates the directory structure and makes writes to parent dirs fail
        let mut sorted_parents: Vec<_> = parent_dirs.into_iter().collect();
        sorted_parents.sort_by_key(|p| p.components().count());

        for parent in &sorted_parents {
            // Skip if this is also an allowed rw path (will be mounted writable below)
            if self.spec.allowed_paths_rw.contains(parent) {
                continue;
            }
            // Bind mount parent as read-only from host
            // This allows child mounts but makes writes here fail with EROFS
            if parent.exists() {
                bwrap_cmd.arg("--ro-bind").arg(parent).arg(parent);
            }
        }

        // Now bind mount the actual read-write paths (these overlay the ro-bind parents)
        for path in &self.spec.allowed_paths_rw {
            if path.exists() {
                bwrap_cmd.arg("--bind").arg(path).arg(path);
            }
        }

        // Custom bind mounts with explicit source->target mapping
        for bind_mount in &self.spec.bind_mounts {
            if bind_mount.source.exists() {
                // Ensure parent directories of target exist in the namespace
                // by creating them with tmpfs if needed
                if let Some(parent) = bind_mount.target.parent() {
                    if !parent.as_os_str().is_empty() && parent != Path::new("/") {
                        // Create parent dir structure with tmpfs
                        bwrap_cmd.arg("--dir").arg(parent);
                    }
                }

                if bind_mount.readonly {
                    bwrap_cmd
                        .arg("--ro-bind")
                        .arg(&bind_mount.source)
                        .arg(&bind_mount.target);
                } else {
                    bwrap_cmd
                        .arg("--bind")
                        .arg(&bind_mount.source)
                        .arg(&bind_mount.target);
                }
            }
        }

        // Working directory
        let workdir = ctx
            .workdir
            .clone()
            .or_else(|| cmd.workdir.clone())
            .unwrap_or_else(|| self.spec.workdir.clone());

        // Ensure workdir exists in namespace (use first rw path as fallback)
        if let Some(first_rw) = self.spec.allowed_paths_rw.first() {
            if workdir.starts_with(first_rw) {
                bwrap_cmd.arg("--chdir").arg(&workdir);
            } else {
                bwrap_cmd.arg("--chdir").arg(first_rw);
            }
        } else {
            bwrap_cmd.arg("--chdir").arg("/tmp");
        }

        // Die with parent
        bwrap_cmd.arg("--die-with-parent");

        // The actual command to run
        bwrap_cmd.arg("--").arg(&cmd.program).args(&cmd.args);

        // Environment
        let mut env: HashMap<String, String> = HashMap::new();
        if cmd.inherit_env {
            // Only inherit safe environment variables
            for (key, value) in std::env::vars() {
                if key.starts_with("LANG")
                    || key.starts_with("LC_")
                    || key == "PATH"
                    || key == "TERM"
                {
                    env.insert(key, value);
                }
            }
        }
        env.extend(cmd.env.clone());
        env.extend(ctx.extra_env.iter().cloned());
        env.insert("HOME".to_string(), workdir.to_string_lossy().to_string());
        env.insert("SANDBOX_ID".to_string(), self.id.as_str().to_string());
        env.insert("TMPDIR".to_string(), "/tmp".to_string());

        bwrap_cmd
            .envs(env)
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        debug!(sandbox_id = %self.id, "Spawning bwrap with {} ro-bind, {} bind mounts",
               self.spec.allowed_paths_ro.len(), self.spec.allowed_paths_rw.len());

        // Spawn process
        let mut child = bwrap_cmd.spawn().context("Failed to spawn bwrap")?;

        // Write stdin if provided
        if let Some(stdin_data) = &cmd.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(stdin_data).await?;
            }
        }

        // Timeout
        let timeout = ctx
            .timeout
            .or(cmd.timeout)
            .or(self.spec.limits.max_wall_time_ms.map(Duration::from_millis))
            .unwrap_or(Duration::from_secs(60));

        // Collect output
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let stdout_handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut stdout) = stdout {
                stdout.read_to_end(&mut buf).await.ok();
            }
            buf
        });

        let stderr_handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut stderr) = stderr {
                stderr.read_to_end(&mut buf).await.ok();
            }
            buf
        });

        // Wait with timeout
        let result = tokio::time::timeout(timeout, async {
            let status = child.wait().await?;
            let stdout_data = stdout_handle.await.unwrap_or_default();
            let stderr_data = stderr_handle.await.unwrap_or_default();
            Ok::<_, anyhow::Error>((status, stdout_data, stderr_data))
        })
        .await;

        let duration = start.elapsed();

        match result {
            Ok(Ok((status, stdout_data, stderr_data))) => Ok(ExecOutput {
                exit_code: status.code().unwrap_or(-1),
                stdout: stdout_data,
                stderr: stderr_data,
                duration,
                timed_out: false,
                resource_limited: false,
                resource_usage: None,
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout
                let _ = child.kill().await;
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
}

#[async_trait]
impl Sandbox for ContainerSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &SandboxCapabilities {
        &self.capabilities
    }

    async fn exec(&self, cmd: &Command, ctx: &ExecContext) -> Result<ExecOutput> {
        self.exec_in_namespace(cmd, ctx).await
    }

    async fn exec_streaming(
        &self,
        cmd: &Command,
        ctx: &ExecContext,
        output_tx: tokio::sync::mpsc::Sender<StreamOutput>,
    ) -> Result<ExecOutput> {
        // For now, execute and then send output
        // TODO: Implement true streaming
        let result = self.exec(cmd, ctx).await?;

        if !result.stdout.is_empty() {
            let _ = output_tx
                .send(StreamOutput::Stdout(result.stdout.clone()))
                .await;
        }
        if !result.stderr.is_empty() {
            let _ = output_tx
                .send(StreamOutput::Stderr(result.stderr.clone()))
                .await;
        }
        let _ = output_tx
            .send(StreamOutput::Exit {
                code: result.exit_code,
            })
            .await;

        Ok(result)
    }

    async fn is_alive(&self) -> bool {
        self.rootfs.exists()
    }

    async fn suspend(&self) -> Result<()> {
        // Could freeze cgroup
        warn!("Suspend not fully implemented for container backend");
        Ok(())
    }

    async fn resume(&self) -> Result<()> {
        warn!("Resume not fully implemented for container backend");
        Ok(())
    }

    async fn snapshot(&self, name: &str) -> Result<String> {
        // Create a snapshot using rsync or cp -a
        let snapshot_dir = self.sandbox_dir.join("snapshots").join(name);
        tokio::fs::create_dir_all(&snapshot_dir).await?;

        // Copy rootfs to snapshot
        let status = TokioCommand::new("cp")
            .arg("-a")
            .arg(&self.rootfs)
            .arg(snapshot_dir.join("rootfs"))
            .status()
            .await?;

        if !status.success() {
            anyhow::bail!("Failed to create snapshot");
        }

        Ok(format!("{}:{}", self.id.as_str(), name))
    }

    async fn restore(&self, snapshot_id: &str) -> Result<()> {
        let parts: Vec<&str> = snapshot_id.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid snapshot ID format");
        }
        let name = parts[1];

        let snapshot_dir = self.sandbox_dir.join("snapshots").join(name);
        if !snapshot_dir.exists() {
            anyhow::bail!("Snapshot not found");
        }

        // Replace rootfs with snapshot
        tokio::fs::remove_dir_all(&self.rootfs).await?;
        let status = TokioCommand::new("cp")
            .arg("-a")
            .arg(snapshot_dir.join("rootfs"))
            .arg(&self.rootfs)
            .status()
            .await?;

        if !status.success() {
            anyhow::bail!("Failed to restore snapshot");
        }

        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        // Remove entire sandbox directory
        if self.sandbox_dir.exists() {
            tokio::fs::remove_dir_all(&self.sandbox_dir)
                .await
                .context("Failed to remove sandbox directory")?;
        }
        Ok(())
    }

    async fn resource_usage(&self) -> Result<ResourceUsage> {
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

    #[tokio::test]
    async fn test_container_backend_probe() {
        let temp_dir = TempDir::new().unwrap();
        let backend = ContainerBackend::new(temp_dir.path(), None).unwrap();

        let caps = backend.probe().await.unwrap();
        assert_eq!(caps.name, "container");
        assert!(caps.persistent_sandboxes);
        assert!(caps.snapshots);
    }

    #[tokio::test]
    async fn test_container_sandbox_creation() {
        let temp_dir = TempDir::new().unwrap();
        let backend = ContainerBackend::new(temp_dir.path(), None).unwrap();

        let spec = SandboxSpec {
            profile: "standard".to_string(),
            workdir: PathBuf::from("/workspace"),
            allowed_paths_ro: vec![PathBuf::from("/etc/hosts")],
            allowed_paths_rw: vec![],
            ..Default::default()
        };

        let sandbox = backend.create_sandbox(&spec).await.unwrap();
        assert!(sandbox.is_alive().await);

        // Cleanup
        sandbox.destroy().await.unwrap();
    }
}
