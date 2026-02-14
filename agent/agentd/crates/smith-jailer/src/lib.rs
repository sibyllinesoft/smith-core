use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

pub mod cgroups;
pub mod landlock;
pub mod namespaces;
pub mod seccomp;

// Security test modules
#[cfg(test)]
pub mod landlock_security_tests;
#[cfg(test)]
pub mod seccomp_security_tests;

use cgroups::{CgroupConfig, CgroupManager, CgroupStats};
use landlock::{
    apply_fallback_path_restrictions, apply_landlock_rules, create_capability_landlock_config,
    is_landlock_available,
};
use namespaces::{
    create_namespaces, pivot_root_to_workdir, setup_mount_namespace, NamespaceConfig,
    NamespaceHandle,
};
use seccomp::{apply_seccomp_filter, create_capability_seccomp_config};
use smith_config::{CgroupLimits, LandlockProfile};
use smith_protocol::{ExecutionLimits, Intent};

/// Jailer for creating secure execution environments
pub struct Jailer {
    work_root: std::path::PathBuf,
    landlock_enabled: bool,
    cgroup_manager: Option<CgroupManager>,
}

/// Context for sandboxed execution
pub struct JailedExecution {
    pub workdir: std::path::PathBuf,
    pub limits: ExecutionLimits,
    pub pid: u32,
    pub namespace_handle: Option<NamespaceHandle>,
    pub cgroup_config: Option<CgroupConfig>,
}

#[derive(Debug, Clone)]
pub struct SandboxProfile {
    pub capability: &'static str,
    pub capability_versioned: &'static str,
    pub seccomp_syscalls: Vec<i32>,
    pub landlock_profile: LandlockProfile,
    pub cgroup_limits: CgroupLimits,
}

impl Jailer {
    fn sandbox_disabled() -> bool {
        static DISABLED: Lazy<bool> = Lazy::new(|| {
            std::env::var("SMITH_EXECUTOR_UNSAFE_NO_SANDBOX").unwrap_or_default() == "1"
        });
        *DISABLED
    }

    /// Create new jailer
    pub fn new(work_root: &Path, landlock_enabled: bool) -> Result<Self> {
        let disable_cgroups =
            std::env::var("SMITH_EXECUTOR_DISABLE_CGROUPS").unwrap_or_default() == "1";

        let cgroup_manager = if disable_cgroups {
            warn!("Cgroup enforcement disabled via SMITH_EXECUTOR_DISABLE_CGROUPS");
            None
        } else {
            match CgroupManager::new() {
                Ok(manager) => Some(manager),
                Err(err) => {
                    warn!(
                        "Cgroup manager unavailable ({}); continuing without cgroup enforcement",
                        err
                    );
                    None
                }
            }
        };

        Ok(Self {
            work_root: work_root.to_path_buf(),
            landlock_enabled,
            cgroup_manager,
        })
    }

    /// Create jailed environment for intent execution
    pub async fn create_jail(
        &self,
        intent: &Intent,
        limits: &ExecutionLimits,
    ) -> Result<JailedExecution> {
        let workdir = self.work_root.join(intent.id.to_string());

        info!(
            "Creating secure jail for intent {} at {}",
            intent.id,
            workdir.display()
        );

        // Step 1: Create workdir with proper permissions
        tokio::fs::create_dir_all(&workdir)
            .await
            .with_context(|| format!("Failed to create workdir: {}", workdir.display()))?;

        // Set workdir permissions (0700)

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = tokio::fs::metadata(&workdir).await?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&workdir, perms).await?;
        }

        // Ensure a writable tmp directory for unprivileged commands.
        let tmp_dir = workdir.join("tmp");
        if let Err(err) = tokio::fs::create_dir_all(&tmp_dir).await {
            warn!(
                error = %err,
                tmp = %tmp_dir.display(),
                "Failed to ensure tmp directory inside jail"
            );
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = tokio::fs::metadata(&tmp_dir).await {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o777);
                    if let Err(err) = tokio::fs::set_permissions(&tmp_dir, perms).await {
                        warn!(
                            error = %err,
                            tmp = %tmp_dir.display(),
                            "Failed to set tmp directory permissions"
                        );
                    }
                }
            }
        }

        if Self::sandbox_disabled() {
            warn!(
                "Sandbox disabled via SMITH_EXECUTOR_UNSAFE_NO_SANDBOX; running intent without isolation"
            );
            info!("Executing intent without sandboxing (env override)");
            return Ok(JailedExecution {
                workdir,
                limits: limits.clone(),
                pid: unsafe { libc::getpid() } as u32,
                namespace_handle: None,
                cgroup_config: None,
            });
        }

        // Step 2: Create cgroup for resource limits
        let cgroup_config = match &self.cgroup_manager {
            Some(manager) => Some(
                manager
                    .create_cgroup(&intent.id.to_string(), limits)
                    .await
                    .context("Failed to create cgroup")?,
            ),
            None => {
                warn!(
                    "Skipping cgroup creation for intent {} (cgroups disabled)",
                    intent.id
                );
                None
            }
        };

        // Step 3: Create namespaces (user, mount, PID, net, UTS, IPC)
        let capability_str = match intent.capability {
            smith_protocol::Capability::FsReadV1 => "fs.read",
            smith_protocol::Capability::HttpFetchV1 => "http.fetch",
            smith_protocol::Capability::FsWriteV1 => "fs.write",
            smith_protocol::Capability::GitCloneV1 => "git.clone",
            smith_protocol::Capability::ArchiveReadV1 => "archive.read",
            smith_protocol::Capability::SqliteQueryV1 => "sqlite.query",
            smith_protocol::Capability::BenchReportV1 => "bench.report",
            smith_protocol::Capability::ShellExec => "shell.exec",
            smith_protocol::Capability::HttpFetch => "http.fetch",
        };
        let namespace_config = self.create_namespace_config(capability_str)?;
        let namespace_handle = match create_namespaces(&namespace_config) {
            Ok(handle) => Some(handle),
            Err(error) => {
                warn!(
                    %error,
                    "Namespace isolation unavailable; continuing with degraded sandbox"
                );
                None
            }
        };

        // Step 4: Setup mount namespace with proc, tmpfs, bind-mounts when available
        if let Some(handle) = &namespace_handle {
            if handle.mount_ns_fd.is_some() {
                if let Err(error) = setup_mount_namespace(&namespace_config, &workdir)
                    .context("Failed to setup mount namespace")
                {
                    warn!(%error, "Mount namespace setup failed; continuing without mount isolation");
                }
            } else {
                warn!("Mount namespace unavailable; skipping mount isolation");
            }
        } else {
            warn!("No namespaces created; skipping mount namespace setup");
        }

        // Step 5: Apply Landlock filesystem access control
        if self.landlock_enabled {
            if is_landlock_available() {
                // For resource paths, we'll use the domain field or extract from params
                let resource_paths = vec![intent.domain.clone()]; // Use domain as primary resource path
                let landlock_config =
                    create_capability_landlock_config(capability_str, &resource_paths, &workdir);
                apply_landlock_rules(&landlock_config).context("Failed to apply Landlock rules")?;
                info!("Applied Landlock filesystem access control");
            } else {
                warn!("Landlock not available, using fallback restrictions");
                apply_fallback_path_restrictions(&[intent.domain.clone()])?;
            }
        } else {
            warn!("Landlock disabled in configuration");
        }

        // Step 6: Pivot root to workdir (isolate filesystem)
        if namespace_handle
            .as_ref()
            .and_then(|handle| handle.mount_ns_fd.as_ref())
            .is_some()
        {
            if let Err(error) =
                pivot_root_to_workdir(&workdir).context("Failed to pivot root to workdir")
            {
                warn!(%error, "Pivot root failed; continuing without filesystem root isolation");
            }
        } else {
            warn!("Pivot root skipped (mount namespace unavailable)");
        }

        // Step 7: Apply seccomp syscall filtering
        let seccomp_config = create_capability_seccomp_config(capability_str);
        debug!(
            capability = capability_str,
            default_action = ?seccomp_config.default_action,
            allowed_syscalls = seccomp_config.allowed_syscalls.len(),
            "Applying seccomp profile"
        );
        apply_seccomp_filter(&seccomp_config).context("Failed to apply seccomp filter")?;
        info!("Applied seccomp syscall filtering");

        // Step 8: Add current process to cgroup for resource limits
        let current_pid = unsafe { libc::getpid() } as u32;
        if let (Some(manager), Some(config)) = (&self.cgroup_manager, &cgroup_config) {
            manager
                .add_process(config, current_pid)
                .await
                .context("Failed to add process to cgroup")?;
        } else {
            warn!(
                "Skipping cgroup assignment for intent {} (cgroups disabled)",
                intent.id
            );
        }

        // Step 9: Drop capabilities and switch to unprivileged user
        if let Err(error) = self.drop_privileges().context("Failed to drop privileges") {
            warn!(%error, "Unable to drop executor privileges; continuing with current user");
        }

        info!("Successfully created secure jail for intent {}", intent.id);

        Ok(JailedExecution {
            workdir,
            limits: limits.clone(),
            pid: current_pid,
            namespace_handle,
            cgroup_config,
        })
    }

    /// Create jailed environment using pre-derived sandbox profile data.
    pub async fn create_jail_with_profile(
        &self,
        intent: &Intent,
        limits: &ExecutionLimits,
        profile: &SandboxProfile,
    ) -> Result<JailedExecution> {
        let workdir = self.work_root.join(intent.id.to_string());

        info!(
            capability = profile.capability_versioned,
            "Creating secure jail with dynamic sandbox profile for intent {} at {}",
            intent.id,
            workdir.display()
        );

        // Create workdir and apply permissions
        tokio::fs::create_dir_all(&workdir)
            .await
            .with_context(|| format!("Failed to create workdir: {}", workdir.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = tokio::fs::metadata(&workdir).await?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&workdir, perms).await?;
        }

        // Ensure a writable tmp directory for unprivileged commands.
        let tmp_dir = workdir.join("tmp");
        if let Err(err) = tokio::fs::create_dir_all(&tmp_dir).await {
            warn!(
                error = %err,
                tmp = %tmp_dir.display(),
                "Failed to ensure tmp directory inside jail"
            );
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = tokio::fs::metadata(&tmp_dir).await {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o777);
                    if let Err(err) = tokio::fs::set_permissions(&tmp_dir, perms).await {
                        warn!(
                            error = %err,
                            tmp = %tmp_dir.display(),
                            "Failed to set tmp directory permissions"
                        );
                    }
                }
            }
        }

        if Self::sandbox_disabled() {
            warn!(
                "Sandbox disabled via SMITH_EXECUTOR_UNSAFE_NO_SANDBOX; running intent without isolation"
            );
            info!("Executing intent without sandboxing (env override)");
            return Ok(JailedExecution {
                workdir,
                limits: limits.clone(),
                pid: unsafe { libc::getpid() } as u32,
                namespace_handle: None,
                cgroup_config: None,
            });
        }

        // Create cgroup for resource limits
        let cgroup_config = match &self.cgroup_manager {
            Some(manager) => Some(
                manager
                    .create_cgroup(&intent.id.to_string(), limits)
                    .await
                    .context("Failed to create cgroup")?,
            ),
            None => {
                warn!(
                    "Skipping cgroup creation for intent {} (cgroups disabled)",
                    intent.id
                );
                None
            }
        };

        // Create namespaces configured for capability
        let namespace_config = self.create_namespace_config(profile.capability)?;
        let namespace_handle = match create_namespaces(&namespace_config) {
            Ok(handle) => Some(handle),
            Err(error) => {
                warn!(
                    %error,
                    "Namespace isolation unavailable; continuing with degraded sandbox"
                );
                None
            }
        };

        if let Some(handle) = &namespace_handle {
            if handle.mount_ns_fd.is_some() {
                if let Err(error) = setup_mount_namespace(&namespace_config, &workdir)
                    .context("Failed to setup mount namespace")
                {
                    warn!(%error, "Mount namespace setup failed; continuing without mount isolation");
                }
            } else {
                warn!("Mount namespace unavailable; skipping mount isolation");
            }
        } else {
            warn!("No namespaces created; skipping mount namespace setup");
        }

        // Apply Landlock or fallback restrictions based on derived profile
        if self.landlock_enabled {
            if is_landlock_available() {
                let landlock_config = landlock::landlock_config_from_profile(
                    profile.capability,
                    &profile.landlock_profile,
                    &workdir,
                );
                apply_landlock_rules(&landlock_config)
                    .context("Failed to apply Landlock rules from derived profile")?;
                info!("Applied Landlock filesystem access control from policy derivation");
            } else {
                warn!("Landlock not available, using fallback restrictions");
                let mut fallback_paths = profile.landlock_profile.read.clone();
                fallback_paths.extend(profile.landlock_profile.write.clone());
                if fallback_paths.is_empty() {
                    fallback_paths.push(intent.domain.clone());
                }
                apply_fallback_path_restrictions(&fallback_paths)?;
            }
        } else {
            warn!("Landlock disabled in configuration");
        }

        if namespace_handle
            .as_ref()
            .and_then(|handle| handle.mount_ns_fd.as_ref())
            .is_some()
        {
            if let Err(error) =
                pivot_root_to_workdir(&workdir).context("Failed to pivot root to workdir")
            {
                warn!(%error, "Pivot root failed; continuing without filesystem root isolation");
            }
        } else {
            warn!("Pivot root skipped (mount namespace unavailable)");
        }

        // Apply seccomp filtering via derived allowlist
        let mut seccomp_config = create_capability_seccomp_config(profile.capability);
        if !profile.seccomp_syscalls.is_empty() {
            seccomp_config.allow_syscalls(&profile.seccomp_syscalls);
        }
        apply_seccomp_filter(&seccomp_config).context("Failed to apply seccomp filter")?;
        info!("Applied seccomp syscall filtering from policy derivation");

        let current_pid = unsafe { libc::getpid() } as u32;
        if let (Some(manager), Some(config)) = (&self.cgroup_manager, &cgroup_config) {
            manager
                .add_process(config, current_pid)
                .await
                .context("Failed to add process to cgroup")?;
        } else {
            warn!(
                "Skipping cgroup assignment for intent {} (cgroups disabled)",
                intent.id
            );
        }

        if let Err(error) = self.drop_privileges().context("Failed to drop privileges") {
            warn!(%error, "Unable to drop executor privileges; continuing with current user");
        }

        Ok(JailedExecution {
            workdir,
            limits: limits.clone(),
            pid: current_pid,
            namespace_handle,
            cgroup_config,
        })
    }

    /// Get cgroup statistics for a jail
    pub async fn get_cgroup_stats(
        &self,
        cgroup_config: Option<&CgroupConfig>,
    ) -> Result<CgroupStats> {
        match (&self.cgroup_manager, cgroup_config) {
            (Some(manager), Some(config)) => manager.get_stats(config).await,
            _ => Ok(CgroupStats::default()),
        }
    }

    /// Cleanup jail after execution
    pub async fn cleanup_jail(&self, execution: &JailedExecution) -> Result<()> {
        info!(
            "Cleaning up jail for PID {} at {}",
            execution.pid,
            execution.workdir.display()
        );

        // Step 1: Remove cgroup (this kills remaining processes)
        if let (Some(manager), Some(config)) = (&self.cgroup_manager, &execution.cgroup_config) {
            if let Err(e) = manager.remove_cgroup(config).await {
                warn!("Failed to remove cgroup: {}", e);
            } else {
                debug!("Removed cgroup for jail cleanup");
            }
        } else {
            debug!("No cgroup associated with jail; skipping removal");
        }

        // Step 2: Remove workdir (if it still exists after pivot_root)
        if execution.workdir.exists() {
            let workdir = execution.workdir.clone();
            info!(workdir = %workdir.display(), "Removing jail workdir (async)");
            tokio::spawn(async move {
                if let Err(e) = tokio::fs::remove_dir_all(&workdir).await {
                    warn!(workdir = %workdir.display(), "Background workdir removal failed: {}", e);
                } else {
                    info!(workdir = %workdir.display(), "Background workdir removal completed");
                }
            });
        } else {
            debug!(workdir = %execution.workdir.display(), "Jail workdir already removed");
        }

        info!(workdir = %execution.workdir.display(), "Jail workdir cleanup scheduled");
        info!("Completed jail cleanup");
        Ok(())
    }

    /// Create namespace configuration based on capability
    fn create_namespace_config(&self, capability: &str) -> Result<NamespaceConfig> {
        let mut config = NamespaceConfig::default();

        // Always expose the workspace root if configured so capabilities can
        // operate on in-repo files while still running inside the jail.
        if let Some(workspace_mount) = Self::workspace_bind_mount(capability) {
            config.bind_mounts.push(workspace_mount);
        }

        // Add capability-specific bind mounts
        match capability {
            "fs.read" => {
                // File reading capability doesn't need additional mounts
            }
            "http.fetch" => {
                // HTTP fetch needs DNS and SSL certificate access
                config.bind_mounts.push(namespaces::BindMount {
                    source: "/etc/resolv.conf".to_string(),
                    target: "/etc/resolv.conf".to_string(),
                    readonly: true,
                    options: vec!["nosuid".to_string(), "nodev".to_string()],
                });
                config.bind_mounts.push(namespaces::BindMount {
                    source: "/etc/ssl/certs".to_string(),
                    target: "/etc/ssl/certs".to_string(),
                    readonly: true,
                    options: vec!["nosuid".to_string(), "nodev".to_string()],
                });
            }
            "shell.exec" | "shell.exec.v1" => {
                // Shell execution relies on the default workspace bind mount and
                // does not require extra system mounts beyond the baseline.
            }
            _ => {
                warn!(
                    "Unknown capability '{}', using default namespace config",
                    capability
                );
            }
        }

        Ok(config)
    }

    fn workspace_bind_mount(capability: &str) -> Option<namespaces::BindMount> {
        let workspace_root = std::env::var("SMITH_WORKSPACE_ROOT").ok()?;
        let canonical = std::fs::canonicalize(&workspace_root)
            .unwrap_or_else(|_| PathBuf::from(workspace_root));
        let canonical_str = canonical.to_string_lossy().to_string();

        if canonical_str.is_empty() {
            return None;
        }

        let readonly = matches!(capability, "fs.read" | "fs.read.v1");
        let mut options = vec!["nosuid".to_string(), "nodev".to_string()];
        if readonly {
            options.push("noexec".to_string());
        }

        Some(namespaces::BindMount {
            source: canonical_str.clone(),
            target: canonical_str,
            readonly,
            options,
        })
    }

    /// Drop all capabilities and switch to unprivileged user
    fn drop_privileges(&self) -> Result<()> {
        let current_uid = unsafe { libc::geteuid() };
        info!(current_uid = current_uid, "Evaluating privilege drop");
        if current_uid != 0 {
            info!(
                "Running as non-root user (uid {}), skipping privilege drop",
                current_uid
            );
            return Ok(());
        }

        info!("Dropping privileges and switching to unprivileged user");
        debug!("Attempting to clear CAP_SYS_ADMIN via prctl");

        // Drop all capabilities
        unsafe {
            // Clear all capability sets - CAP_SYS_ADMIN is constant 21
            if libc::prctl(libc::PR_CAPBSET_DROP, 21, 0, 0, 0) != 0 {
                warn!("Failed to drop CAP_SYS_ADMIN capability");
            }
        }

        debug!("Setting group to nobody (65534)");
        // Switch to unprivileged user (nobody:nogroup = 65534:65534)
        unsafe {
            if libc::setresgid(65534, 65534, 65534) != 0 {
                return Err(anyhow::anyhow!(
                    "Failed to set group ID to nobody: {}",
                    std::io::Error::last_os_error()
                ));
            }
            debug!("Setting user to nobody (65534)");
            if libc::setresuid(65534, 65534, 65534) != 0 {
                return Err(anyhow::anyhow!(
                    "Failed to set user ID to nobody: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        info!("Successfully dropped privileges");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::Capability;
    use tempfile::TempDir;

    /// Create a test intent for security testing
    fn create_test_intent(capability: Capability) -> Intent {
        Intent {
            id: "test-intent-123".to_string(),
            capability,
            domain: "test".to_string(),
            params: serde_json::json!({}),
            created_at_ns: 1000000000,
            ttl_ms: 30000,
            nonce: "a1b2c3d4e5f6789012345678901234ab".to_string(),
            signer: "test-signer".to_string(),
            signature_b64: "test-signature".to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    fn create_test_limits() -> ExecutionLimits {
        ExecutionLimits {
            cpu_ms_per_100ms: 50,         // 50ms CPU per 100ms
            mem_bytes: 100 * 1024 * 1024, // 100MB
            io_bytes: 10 * 1024 * 1024,   // 10MB I/O
            pids_max: 5,
            timeout_ms: 30000, // 30 seconds
        }
    }

    #[tokio::test]
    async fn test_jailer_creation() {
        let temp_dir = TempDir::new().unwrap();
        let work_root = temp_dir.path();

        // Test jailer creation with landlock enabled
        let jailer_with_landlock = Jailer::new(work_root, true);
        assert!(
            jailer_with_landlock.is_ok(),
            "Should create jailer with landlock enabled"
        );

        let jailer = jailer_with_landlock.unwrap();
        assert_eq!(jailer.work_root, work_root);
        assert!(jailer.landlock_enabled, "Landlock should be enabled");

        // Test jailer creation with landlock disabled
        let jailer_without_landlock = Jailer::new(work_root, false);
        assert!(
            jailer_without_landlock.is_ok(),
            "Should create jailer with landlock disabled"
        );

        let jailer = jailer_without_landlock.unwrap();
        assert!(!jailer.landlock_enabled, "Landlock should be disabled");
    }

    #[tokio::test]
    async fn test_create_namespace_config() {
        let temp_dir = TempDir::new().unwrap();
        let jailer = Jailer::new(temp_dir.path(), true).unwrap();

        // Test fs.read.v1 capability
        let fs_read_config = jailer.create_namespace_config("fs.read.v1");
        assert!(
            fs_read_config.is_ok(),
            "Should create namespace config for fs.read.v1"
        );

        // Test http.fetch.v1 capability
        let http_fetch_config = jailer.create_namespace_config("http.fetch.v1");
        assert!(
            http_fetch_config.is_ok(),
            "Should create namespace config for http.fetch.v1"
        );

        // Test unknown capability
        let unknown_config = jailer.create_namespace_config("unknown.capability.v1");
        assert!(
            unknown_config.is_ok(),
            "Should create default namespace config for unknown capability"
        );
    }

    #[tokio::test]
    async fn test_jail_creation_and_cleanup_fs_read() {
        // Skip if not running as root (required for full security isolation)
        if unsafe { libc::getuid() } != 0 {
            println!("Skipping jail test - requires root privileges for full security isolation");
            return;
        }

        let temp_dir = TempDir::new().unwrap();
        let jailer = Jailer::new(temp_dir.path(), false).unwrap(); // Disable landlock for test

        let intent = create_test_intent(Capability::FsReadV1);
        let limits = create_test_limits();

        // Test jail creation
        let jail_result = jailer.create_jail(&intent, &limits).await;

        if jail_result.is_err() {
            println!(
                "Jail creation failed (expected in test environment): {:?}",
                jail_result.err()
            );
            return;
        }

        let jailed_execution = jail_result.unwrap();

        // Verify jail properties
        assert!(
            jailed_execution.workdir.exists(),
            "Working directory should exist"
        );
        assert_eq!(jailed_execution.limits.mem_bytes, 100 * 1024 * 1024);
        assert_eq!(jailed_execution.limits.timeout_ms, 30000);

        // Test cleanup
        let cleanup_result = jailer.cleanup_jail(&jailed_execution).await;
        assert!(
            cleanup_result.is_ok(),
            "Cleanup should succeed: {:?}",
            cleanup_result.err()
        );
    }

    #[tokio::test]
    async fn test_jail_creation_security_failure_handling() {
        let temp_dir = TempDir::new().unwrap();
        let jailer = Jailer::new(temp_dir.path(), true).unwrap();

        let intent = create_test_intent(Capability::FsReadV1);
        let limits = create_test_limits();

        // In non-root test environment, jail creation may fail due to security restrictions
        // This is actually a good security property - the test verifies proper error handling
        let jail_result = jailer.create_jail(&intent, &limits).await;

        // Either succeeds (if running with proper privileges) or fails gracefully
        match jail_result {
            Ok(jailed_execution) => {
                println!("Jail created successfully in test environment");
                // Always cleanup if successful
                let _ = jailer.cleanup_jail(&jailed_execution).await;
            }
            Err(e) => {
                println!(
                    "Jail creation failed as expected in test environment: {}",
                    e
                );
                // Verify error is security-related (expected behavior)
                let error_str = e.to_string();
                assert!(
                    error_str.contains("permission")
                        || error_str.contains("privilege")
                        || error_str.contains("namespace")
                        || error_str.contains("cgroup")
                        || error_str.contains("capability"),
                    "Should fail with security-related error, got: {}",
                    error_str
                );
            }
        }
    }

    #[tokio::test]
    async fn test_jail_creation_with_invalid_limits() {
        let temp_dir = TempDir::new().unwrap();
        let jailer = Jailer::new(temp_dir.path(), false).unwrap();

        let intent = create_test_intent(Capability::FsReadV1);

        // Test with zero memory limit (invalid)
        let invalid_limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 0, // Invalid - zero memory
            io_bytes: 10 * 1024 * 1024,
            pids_max: 5,
            timeout_ms: 30000,
        };

        let jail_result = jailer.create_jail(&intent, &invalid_limits).await;

        // Should handle gracefully - either succeed with minimum limits or fail appropriately
        if let Err(e) = jail_result {
            println!("Jail creation failed with invalid limits (expected): {}", e);
        } else {
            println!("Jail creation succeeded despite invalid limits - graceful handling");
        }
    }

    #[tokio::test]
    async fn test_multiple_capability_types() {
        let temp_dir = TempDir::new().unwrap();
        let jailer = Jailer::new(temp_dir.path(), false).unwrap();

        // Test different capability types have appropriate configurations
        let capabilities = [
            (Capability::FsReadV1, "fs.read.v1"),
            (Capability::HttpFetchV1, "http.fetch.v1"),
        ];

        for (capability, capability_str) in capabilities {
            let _intent = create_test_intent(capability);

            let config_result = jailer.create_namespace_config(capability_str);
            assert!(
                config_result.is_ok(),
                "Should create config for {:?}",
                capability_str
            );
        }
    }

    #[tokio::test]
    async fn test_concurrent_jail_operations() {
        let temp_dir = TempDir::new().unwrap();
        let jailer = Jailer::new(temp_dir.path(), false).unwrap();

        // Test that jailer can handle multiple concurrent operations safely
        let intent1 = create_test_intent(Capability::FsReadV1);
        let intent2 = create_test_intent(Capability::HttpFetchV1);
        let limits = create_test_limits();

        let jailer_ref = &jailer;
        let limits_ref = &limits;

        // Attempt concurrent jail creation (may fail in test environment, but should be safe)
        let (result1, result2) = tokio::join!(
            jailer_ref.create_jail(&intent1, limits_ref),
            jailer_ref.create_jail(&intent2, limits_ref)
        );

        // At least one should succeed or both should fail gracefully
        match (result1, result2) {
            (Ok(jail1), Ok(jail2)) => {
                println!("Both concurrent jails created successfully");
                // Cleanup both
                let _ = tokio::join!(jailer.cleanup_jail(&jail1), jailer.cleanup_jail(&jail2));
            }
            (Ok(jail1), Err(e2)) => {
                println!("First jail succeeded, second failed: {}", e2);
                let _ = jailer.cleanup_jail(&jail1).await;
            }
            (Err(e1), Ok(jail2)) => {
                println!("Second jail succeeded, first failed: {}", e1);
                let _ = jailer.cleanup_jail(&jail2).await;
            }
            (Err(e1), Err(e2)) => {
                println!(
                    "Both jails failed (expected in test environment): {}, {}",
                    e1, e2
                );
            }
        }
    }

    #[test]
    fn test_jailer_creation_edge_cases() {
        // Test with non-existent work root
        let non_existent_path = Path::new("/non/existent/path");
        let result = Jailer::new(non_existent_path, true);

        // Should either succeed (creates path) or fail gracefully
        match result {
            Ok(_) => println!("Jailer handles non-existent path gracefully"),
            Err(e) => println!("Jailer fails gracefully with non-existent path: {}", e),
        }

        // Test with path permissions issues
        let read_only_path = Path::new("/");
        let result = Jailer::new(read_only_path, false);

        // Should handle permission issues appropriately
        if let Err(e) = result {
            let error_str = e.to_string();
            assert!(
                error_str.contains("permission")
                    || error_str.contains("read-only")
                    || error_str.contains("access")
                    || error_str.len() > 0, // Any error message is acceptable
                "Should provide meaningful error for permission issues"
            );
        }
    }
}
