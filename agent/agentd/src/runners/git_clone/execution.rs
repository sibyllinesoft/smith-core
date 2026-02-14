//! Git Clone Execution Module
//!
//! Contains the core execution logic for git clone operations including process management,
//! timeout handling, and output monitoring.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::fs::create_dir_all;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use super::super::{OutputSink, Artifact};

/// Git clone execution engine
pub struct GitExecutor;

impl GitExecutor {
    /// Execute git clone operation with all safety and monitoring features
    pub async fn execute_git_clone(
        repo_url: &str,
        dest_path: &Path,
        branch: &str,
        depth: u32,
        recursive: bool,
        timeout_secs: u64,
        max_size_mb: u64,
        out: &mut dyn OutputSink,
    ) -> Result<()> {
        Self::prepare_destination(dest_path).await?;
        let command = Self::build_git_command(repo_url, dest_path, branch, depth, recursive, out)?;
        Self::execute_with_monitoring(command, timeout_secs, max_size_mb, out).await?;
        Self::verify_clone_result(dest_path).await?;
        
        Ok(())
    }

    /// Calculate directory size recursively
    pub async fn get_directory_size(dir: &Path) -> Result<u64> {
        let mut total_size = 0u64;
        let mut entries = tokio::fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                total_size += metadata.len();
            } else if metadata.is_dir() {
                total_size += Self::get_directory_size(&entry.path()).await?;
            }
        }

        Ok(total_size)
    }

    /// Create artifacts from cloned repository
    pub async fn create_artifacts(repo_path: &Path) -> Result<Vec<Artifact>> {
        let mut artifacts = Vec::new();

        // Basic repository structure artifact
        artifacts.push(Artifact {
            name: "repository_info".to_string(),
            content_type: "text/plain".to_string(),
            data: format!("Cloned repository to: {}", repo_path.display()).into_bytes(),
        });

        // Repository size information
        if let Ok(size) = Self::get_directory_size(repo_path).await {
            artifacts.push(Artifact {
                name: "repository_size".to_string(),
                content_type: "application/json".to_string(),
                data: serde_json::json!({
                    "size_bytes": size,
                    "size_mb": size / (1024 * 1024),
                    "path": repo_path.display().to_string()
                })
                .to_string()
                .into_bytes(),
            });
        }

        // Git log summary (last 10 commits)
        if let Ok(log_content) = Self::get_git_log_summary(repo_path).await {
            artifacts.push(Artifact {
                name: "git_log_summary".to_string(),
                content_type: "text/plain".to_string(),
                data: log_content.into_bytes(),
            });
        }

        Ok(artifacts)
    }

    /// Prepare destination directory
    async fn prepare_destination(dest_path: &Path) -> Result<()> {
        if let Some(parent) = dest_path.parent() {
            create_dir_all(parent).await.with_context(|| {
                format!("Failed to create parent directory: {}", parent.display())
            })?;
        }
        Ok(())
    }

    /// Build git clone command with all specified options
    fn build_git_command(
        repo_url: &str,
        dest_path: &Path,
        branch: &str,
        depth: u32,
        recursive: bool,
        out: &mut dyn OutputSink,
    ) -> Result<Command> {
        let mut cmd = Command::new("git");
        cmd.arg("clone")
            .arg("--branch")
            .arg(branch)
            .arg("--single-branch")
            .arg("--depth")
            .arg(depth.to_string())
            .arg(repo_url)
            .arg(dest_path);

        // Add recursive flag if requested (but warn about security implications)
        if recursive {
            cmd.arg("--recursive");
            out.write_log(
                "WARN",
                "Recursive clone enabled - submodules will be cloned",
            )?;
        }

        // Set up process execution with limits
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        out.write_log(
            "INFO",
            &format!(
                "Executing git clone: {} -> {}",
                repo_url,
                dest_path.display()
            ),
        )?;

        Ok(cmd)
    }

    /// Execute command with timeout and output monitoring
    async fn execute_with_monitoring(
        mut cmd: Command,
        timeout_secs: u64,
        max_size_mb: u64,
        out: &mut dyn OutputSink,
    ) -> Result<()> {
        let mut child = cmd.spawn().context("Failed to spawn git clone process")?;

        // Monitor process with timeout
        let clone_timeout = Duration::from_secs(timeout_secs);
        let result = timeout(clone_timeout, async {
            Self::monitor_process_output(&mut child, max_size_mb, out).await
        }).await;

        match result {
            Ok(process_result) => process_result,
            Err(_) => {
                // Kill the process if it times out
                let _ = child.kill().await;
                Err(anyhow::anyhow!(
                    "Git clone operation timed out after {} seconds",
                    timeout_secs
                ))
            }
        }
    }

    /// Monitor process output with size limits
    async fn monitor_process_output(
        child: &mut tokio::process::Child,
        max_size_mb: u64,
        out: &mut dyn OutputSink,
    ) -> Result<()> {
        // Read stdout and stderr
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        // Spawn tasks to read stdout and stderr
        let stdout_task = tokio::spawn(async move {
            let mut reader = stdout;
            let mut buffer = vec![0; 4096];
            while let Ok(n) = reader.read(&mut buffer).await {
                if n == 0 {
                    break;
                }
                stdout_buf.extend_from_slice(&buffer[..n]);
                // Check size limit
                if stdout_buf.len() > (max_size_mb as usize * 1024 * 1024) {
                    warn!("Git clone output exceeded size limit");
                    break;
                }
            }
            stdout_buf
        });

        let stderr_task = tokio::spawn(async move {
            let mut reader = stderr;
            let mut buffer = vec![0; 4096];
            while let Ok(n) = reader.read(&mut buffer).await {
                if n == 0 {
                    break;
                }
                stderr_buf.extend_from_slice(&buffer[..n]);
            }
            stderr_buf
        });

        // Wait for process completion
        let exit_status = child.wait().await?;

        let stdout_data = stdout_task.await.unwrap_or_default();
        let stderr_data = stderr_task.await.unwrap_or_default();

        // Log output
        if !stdout_data.is_empty() {
            out.write_log("INFO", &format!("STDOUT: {}", String::from_utf8_lossy(&stdout_data)))?;
        }
        if !stderr_data.is_empty() {
            out.write_log("INFO", &format!("STDERR: {}", String::from_utf8_lossy(&stderr_data)))?;
        }

        // Check exit status
        if !exit_status.success() {
            return Err(anyhow::anyhow!(
                "Git clone failed with exit code: {}",
                exit_status.code().unwrap_or(-1)
            ));
        }

        info!("Git clone completed successfully");
        Ok(())
    }

    /// Verify clone operation was successful
    async fn verify_clone_result(dest_path: &Path) -> Result<()> {
        // Check if destination directory exists and contains .git
        if !dest_path.exists() {
            return Err(anyhow::anyhow!(
                "Clone destination directory does not exist: {}",
                dest_path.display()
            ));
        }

        let git_dir = dest_path.join(".git");
        if !git_dir.exists() {
            return Err(anyhow::anyhow!(
                "Cloned directory does not contain .git folder: {}",
                dest_path.display()
            ));
        }

        debug!("Clone verification successful for: {}", dest_path.display());
        Ok(())
    }

    /// Get git log summary for artifacts
    async fn get_git_log_summary(repo_path: &Path) -> Result<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .arg("log")
            .arg("--oneline")
            .arg("-10")
            .output()
            .await?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(anyhow::anyhow!("Failed to get git log"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    struct TestOutputSink {
        logs: Vec<String>,
    }

    impl TestOutputSink {
        fn new() -> Self {
            Self { logs: Vec::new() }
        }
    }

    impl OutputSink for TestOutputSink {
        fn write_log(&mut self, level: &str, message: &str) -> Result<()> {
            self.logs.push(format!("{}: {}", level, message));
            Ok(())
        }

        fn write_output(&mut self, data: &[u8]) -> Result<()> {
            self.logs.push(format!("OUTPUT: {}", String::from_utf8_lossy(data)));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_prepare_destination() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_path = temp_dir.path().join("subdir").join("repo");
        
        GitExecutor::prepare_destination(&dest_path).await.unwrap();
        
        assert!(dest_path.parent().unwrap().exists());
    }

    #[test]
    fn test_build_git_command() {
        let mut sink = TestOutputSink::new();
        let dest_path = std::path::Path::new("/tmp/test");
        
        let mut cmd = GitExecutor::build_git_command(
            "https://github.com/test/repo.git",
            dest_path,
            "main",
            1,
            false,
            &mut sink,
        ).unwrap();

        // Verify command was built correctly
        let program = cmd.as_std().get_program();
        assert_eq!(program, "git");
    }
}