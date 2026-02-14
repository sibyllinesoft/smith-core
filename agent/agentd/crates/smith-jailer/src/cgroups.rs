use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use smith_protocol::ExecutionLimits;

/// cgroup v2 manager for resource limits
pub struct CgroupManager {
    cgroup_root: PathBuf,
}

/// cgroup configuration for a specific execution
pub struct CgroupConfig {
    pub name: String,
    pub limits: ExecutionLimits,
    pub path: PathBuf,
}

impl CgroupManager {
    /// Create new cgroup manager
    pub fn new() -> Result<Self> {
        // Detect cgroup v2 mount point
        let cgroup_root = Self::detect_cgroup_root()?;

        info!(
            "cgroup manager initialized with root: {}",
            cgroup_root.display()
        );
        Ok(Self { cgroup_root })
    }

    /// Create cgroup for intent execution
    pub async fn create_cgroup(
        &self,
        intent_id: &str,
        limits: &ExecutionLimits,
    ) -> Result<CgroupConfig> {
        let cgroup_name = format!("smith-executor-{}", intent_id);
        let cgroup_path = self.cgroup_root.join("smith").join(&cgroup_name);

        // Create cgroup directory
        fs::create_dir_all(&cgroup_path).await.with_context(|| {
            format!(
                "Failed to create cgroup directory: {}",
                cgroup_path.display()
            )
        })?;

        let config = CgroupConfig {
            name: cgroup_name,
            limits: limits.clone(),
            path: cgroup_path,
        };

        // Apply limits
        self.apply_limits(&config).await?;

        info!("Created cgroup: {}", config.name);
        Ok(config)
    }

    /// Apply resource limits to cgroup
    async fn apply_limits(&self, config: &CgroupConfig) -> Result<()> {
        // CPU limits
        if config.limits.cpu_ms_per_100ms > 0 {
            let cpu_max = format!("{} 100000", config.limits.cpu_ms_per_100ms * 1000); // Convert to microseconds
            self.write_cgroup_file(&config.path, "cpu.max", &cpu_max)
                .await
                .context("Failed to set CPU limit")?;
        }

        // Memory limits
        if config.limits.mem_bytes > 0 {
            self.write_cgroup_file(
                &config.path,
                "memory.max",
                &config.limits.mem_bytes.to_string(),
            )
            .await
            .context("Failed to set memory limit")?;
        }

        // PID limits
        if config.limits.pids_max > 0 {
            self.write_cgroup_file(
                &config.path,
                "pids.max",
                &config.limits.pids_max.to_string(),
            )
            .await
            .context("Failed to set PID limit")?;
        }

        // I/O limits (if supported)
        if config.limits.io_bytes > 0 {
            // This is more complex as it requires device identification
            warn!("I/O limits not yet implemented");
        }

        info!("Applied resource limits to cgroup: {}", config.name);
        Ok(())
    }

    /// Add process to cgroup
    pub async fn add_process(&self, config: &CgroupConfig, pid: u32) -> Result<()> {
        self.write_cgroup_file(&config.path, "cgroup.procs", &pid.to_string())
            .await
            .with_context(|| format!("Failed to add process {} to cgroup {}", pid, config.name))
    }

    /// Remove cgroup (cleanup)
    pub async fn remove_cgroup(&self, config: &CgroupConfig) -> Result<()> {
        // Kill any remaining processes
        self.kill_processes(config).await?;

        // Remove cgroup directory
        fs::remove_dir(&config.path)
            .await
            .with_context(|| format!("Failed to remove cgroup: {}", config.path.display()))?;

        info!("Removed cgroup: {}", config.name);
        Ok(())
    }

    /// Kill all processes in cgroup
    async fn kill_processes(&self, config: &CgroupConfig) -> Result<()> {
        // Read processes in cgroup
        let procs_path = config.path.join("cgroup.procs");

        if let Ok(contents) = fs::read_to_string(&procs_path).await {
            for line in contents.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    if pid > 0 {
                        // Send SIGTERM first
                        unsafe {
                            libc::kill(pid, libc::SIGTERM);
                        }
                    }
                }
            }

            // Wait a bit, then SIGKILL if needed
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            for line in contents.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    if pid > 0 {
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get cgroup statistics
    pub async fn get_stats(&self, config: &CgroupConfig) -> Result<CgroupStats> {
        let mut stats = CgroupStats::default();

        // Read memory stats
        if let Ok(memory_current) = self.read_cgroup_file(&config.path, "memory.current").await {
            stats.memory_usage_bytes = memory_current.trim().parse().unwrap_or(0);
        }

        // Read CPU stats
        if let Ok(cpu_stat) = self.read_cgroup_file(&config.path, "cpu.stat").await {
            for line in cpu_stat.lines() {
                if let Some(usage_str) = line.strip_prefix("usage_usec ") {
                    stats.cpu_usage_usec = usage_str.trim().parse().unwrap_or(0);
                }
            }
        }

        // Read PID stats
        if let Ok(pids_current) = self.read_cgroup_file(&config.path, "pids.current").await {
            stats.pids_current = pids_current.trim().parse().unwrap_or(0);
        }

        Ok(stats)
    }

    /// Write to cgroup file
    async fn write_cgroup_file(
        &self,
        cgroup_path: &Path,
        filename: &str,
        content: &str,
    ) -> Result<()> {
        let file_path = cgroup_path.join(filename);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file_path)
            .await
            .with_context(|| format!("Failed to open cgroup file: {}", file_path.display()))?;

        file.write_all(content.as_bytes())
            .await
            .with_context(|| format!("Failed to write to cgroup file: {}", file_path.display()))?;

        file.flush().await.context("Failed to flush cgroup file")?;

        Ok(())
    }

    /// Read from cgroup file
    async fn read_cgroup_file(&self, cgroup_path: &Path, filename: &str) -> Result<String> {
        let file_path = cgroup_path.join(filename);
        fs::read_to_string(&file_path)
            .await
            .with_context(|| format!("Failed to read cgroup file: {}", file_path.display()))
    }

    /// Detect cgroup v2 mount point
    fn detect_cgroup_root() -> Result<PathBuf> {
        // Try common cgroup v2 mount points
        let candidates = ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"];

        for candidate in &candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                // Check if it's cgroup v2 by looking for cgroup.controllers
                if path.join("cgroup.controllers").exists() {
                    return Ok(path);
                }
            }
        }

        Err(anyhow::anyhow!("Could not find cgroup v2 mount point"))
    }
}

/// cgroup statistics
#[derive(Debug, Default)]
pub struct CgroupStats {
    pub memory_usage_bytes: u64,
    pub cpu_usage_usec: u64,
    pub pids_current: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_cgroup_manager_creation() {
        // This test requires cgroup v2 to be available
        if std::env::var("TEST_CGROUPS").is_ok() {
            let manager = CgroupManager::new();
            assert!(manager.is_ok(), "CgroupManager creation should succeed");
        }
    }

    #[tokio::test]
    async fn test_cgroup_creation() {
        if std::env::var("TEST_CGROUPS").is_ok() {
            let manager = CgroupManager::new().unwrap();
            let intent_id = Uuid::new_v4().to_string();

            let limits = ExecutionLimits {
                cpu_ms_per_100ms: 50,
                mem_bytes: 100_000_000, // 100MB
                io_bytes: 10_000_000,   // 10MB
                pids_max: 10,
                timeout_ms: 30_000,
            };

            let config = manager.create_cgroup(&intent_id, &limits).await;
            assert!(config.is_ok(), "cgroup creation should succeed");

            if let Ok(config) = config {
                // Cleanup
                let _ = manager.remove_cgroup(&config).await;
            }
        }
    }
}
