use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use smith_protocol::ExecutionStatus;

/// File system read runner for fs.read capability
pub struct FsReadRunner {
    version: String,
}

impl FsReadRunner {
    /// Create new fs.read runner
    pub fn new() -> Self {
        Self {
            version: "fs-read-v1".to_string(),
        }
    }

    /// Validate file path is within allowed scope
    fn validate_path(&self, path: &Path, scope_paths: &[String]) -> Result<()> {
        // Convert to absolute path - handle nonexistent files
        let abs_path = if path.exists() {
            path.canonicalize()
                .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?
        } else {
            // For nonexistent files, resolve the parent directory and append the filename
            if let Some(parent) = path.parent() {
                if let Some(filename) = path.file_name() {
                    parent
                        .canonicalize()
                        .with_context(|| {
                            format!("Failed to canonicalize parent path: {}", parent.display())
                        })?
                        .join(filename)
                } else {
                    return Err(anyhow::anyhow!("Invalid path: {}", path.display()));
                }
            } else {
                return Err(anyhow::anyhow!("Path has no parent: {}", path.display()));
            }
        };

        // Check against allowed paths
        for allowed_prefix in scope_paths {
            let allowed_path_buf = Path::new(allowed_prefix);
            let allowed_path = if allowed_path_buf.exists() {
                allowed_path_buf.canonicalize().with_context(|| {
                    format!("Failed to canonicalize allowed path: {}", allowed_prefix)
                })?
            } else {
                // For nonexistent allowed paths, resolve parent and append filename
                if let Some(parent) = allowed_path_buf.parent() {
                    if let Some(filename) = allowed_path_buf.file_name() {
                        parent
                            .canonicalize()
                            .with_context(|| {
                                format!(
                                    "Failed to canonicalize allowed parent path: {}",
                                    parent.display()
                                )
                            })?
                            .join(filename)
                    } else {
                        return Err(anyhow::anyhow!("Invalid allowed path: {}", allowed_prefix));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "Allowed path has no parent: {}",
                        allowed_prefix
                    ));
                }
            };

            if abs_path.starts_with(&allowed_path) {
                debug!(
                    "Path {} is within allowed prefix {}",
                    abs_path.display(),
                    allowed_path.display()
                );
                return Ok(());
            }
        }

        Err(anyhow::anyhow!(
            "Path {} is not within any allowed path prefix",
            abs_path.display()
        ))
    }

    /// Read file content with offset and length
    async fn read_file_slice(&self, path: &Path, offset: u64, length: usize) -> Result<Vec<u8>> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut file = std::fs::File::open(&path)
                .with_context(|| format!("Failed to open file: {}", path.display()))?;

            if offset > 0 {
                file.seek(SeekFrom::Start(offset)).with_context(|| {
                    format!(
                        "Failed to seek to offset {} in file: {}",
                        offset,
                        path.display()
                    )
                })?;
            }

            let mut buffer = vec![0u8; length];
            let bytes_read = file
                .read(&mut buffer)
                .with_context(|| format!("Failed to read from file: {}", path.display()))?;
            buffer.truncate(bytes_read);

            info!(
                "Read {} bytes from {} (offset: {}, requested: {})",
                bytes_read,
                path.display(),
                offset,
                length
            );

            Ok(buffer)
        })
        .await
        .context("File read task panicked")?
    }
}

#[async_trait]
impl Runner for FsReadRunner {
    fn digest(&self) -> String {
        self.version.clone()
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        // Validate mandatory path parameter
        let path_value = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("path parameter is required"))?;

        if path_value.trim().is_empty() {
            return Err(anyhow::anyhow!("path must not be empty"));
        }

        // Validate offset parameter
        if let Some(offset) = params.get("offset") {
            if !offset.is_u64() {
                return Err(anyhow::anyhow!("offset must be a non-negative integer"));
            }
        }

        // Validate len parameter (required)
        let len = params
            .get("len")
            .ok_or_else(|| anyhow::anyhow!("len parameter is required"))?;

        if !len.is_u64() {
            return Err(anyhow::anyhow!("len must be a non-negative integer"));
        }

        let len_val = len.as_u64().unwrap();
        if len_val == 0 {
            return Err(anyhow::anyhow!("len must be greater than 0"));
        }

        if len_val > 1_048_576 {
            return Err(anyhow::anyhow!("len cannot exceed 1MB (1048576 bytes)"));
        }

        Ok(())
    }

    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start_time = std::time::Instant::now();

        tracing::info!(
            trace_id = ctx.trace_id,
            ?ctx.scope.paths,
            "fs.read runner invoked"
        );

        out.write_log("INFO", "Starting fs.read execution")?;

        // Extract parameters
        let requested_path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("path parameter is required"))?;
        let resource_path = PathBuf::from(if Path::new(requested_path).is_absolute() {
            requested_path.to_string()
        } else {
            ctx.workdir
                .join(requested_path)
                .to_string_lossy()
                .to_string()
        });

        tracing::info!(
            path = %resource_path.display(),
            scope_paths = ?ctx.scope.paths,
            "fs.read parameters"
        );

        if ctx.scope.paths.is_empty() {
            out.write_log("ERROR", "No allowed scope paths provided for fs.read")?;
            return Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(1),
                artifacts: vec![],
                duration_ms: start_time.elapsed().as_millis() as u64,
                stdout_bytes: 0,
                stderr_bytes: 0,
            });
        }

        let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);

        let len = params
            .get("len")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("len parameter is required"))?;

        // Enforce I/O limits - requested length cannot exceed the I/O limit
        if len > ctx.limits.io_bytes {
            out.write_log(
                "ERROR",
                &format!(
                    "Requested length {} exceeds I/O limit {}",
                    len, ctx.limits.io_bytes
                ),
            )?;
            return Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(1),
                artifacts: vec![],
                duration_ms: start_time.elapsed().as_millis() as u64,
                stdout_bytes: 0,
                stderr_bytes: 0,
            });
        }

        out.write_log(
            "INFO",
            &format!(
                "Reading {} bytes from {} (offset: {})",
                len,
                resource_path.display(),
                offset
            ),
        )?;

        // Validate path is within scope
        if let Err(e) = self.validate_path(&resource_path, &ctx.scope.paths) {
            let error_msg = format!("Path validation failed: {}", e);
            out.write_log("ERROR", &error_msg)?;
            out.write_stderr(error_msg.as_bytes())?;
            return Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(1),
                artifacts: vec![],
                duration_ms: start_time.elapsed().as_millis() as u64,
                stdout_bytes: 0,
                stderr_bytes: error_msg.len() as u64,
            });
        }

        // Check file exists and is readable
        if !resource_path.exists() {
            let error_msg = format!("File does not exist: {}", resource_path.display());
            out.write_log("ERROR", &error_msg)?;
            out.write_stderr(error_msg.as_bytes())?;

            return Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(2),
                artifacts: vec![],
                duration_ms: start_time.elapsed().as_millis() as u64,
                stdout_bytes: 0,
                stderr_bytes: error_msg.len() as u64,
            });
        }

        if !resource_path.is_file() {
            let error_msg = format!("Path is not a file: {}", resource_path.display());
            out.write_log("ERROR", &error_msg)?;
            out.write_stderr(error_msg.as_bytes())?;

            return Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(3),
                artifacts: vec![],
                duration_ms: start_time.elapsed().as_millis() as u64,
                stdout_bytes: 0,
                stderr_bytes: error_msg.len() as u64,
            });
        }

        // Apply I/O limit to the actual read length
        let effective_len = std::cmp::min(len, ctx.limits.io_bytes) as usize;

        // Read file content
        match self
            .read_file_slice(&resource_path, offset, effective_len)
            .await
        {
            Ok(content) => {
                // Ensure we don't exceed I/O limits in output
                let content_to_output = if content.len() as u64 > ctx.limits.io_bytes {
                    content[..(ctx.limits.io_bytes as usize)].to_vec()
                } else {
                    content
                };

                // Write content to stdout
                out.write_stdout(&content_to_output)?;
                out.write_log(
                    "INFO",
                    &format!("Successfully read {} bytes", content_to_output.len()),
                )?;

                let stdout_bytes = content_to_output.len() as u64;
                let execution_time_ms = start_time.elapsed().as_millis().max(1) as u64;

                Ok(ExecutionResult {
                    status: ExecutionStatus::Ok,
                    exit_code: Some(0),
                    artifacts: vec![],
                    duration_ms: execution_time_ms,
                    stdout_bytes,
                    stderr_bytes: 0,
                })
            }
            Err(e) => {
                let error_msg = format!("Failed to read file: {}", e);
                out.write_log("ERROR", &error_msg)?;
                out.write_stderr(error_msg.as_bytes())?;
                let execution_time_ms = start_time.elapsed().as_millis().max(1) as u64;

                Ok(ExecutionResult {
                    status: ExecutionStatus::Error,
                    exit_code: Some(4),
                    artifacts: vec![],
                    duration_ms: execution_time_ms,
                    stdout_bytes: 0,
                    stderr_bytes: error_msg.len() as u64,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::{create_exec_context, MemoryOutputSink, Scope};
    use serde_json::json;
    use smith_protocol::ExecutionLimits;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    #[tokio::test]
    async fn test_fs_read_runner() {
        let runner = FsReadRunner::new();
        assert_eq!(runner.digest(), "fs-read-v1");
    }

    #[tokio::test]
    async fn test_validate_params() {
        let runner = FsReadRunner::new();

        // Valid parameters
        let valid_params = json!({
            "path": "/tmp/test.txt",
            "offset": 0,
            "len": 1024
        });
        assert!(runner.validate_params(&valid_params).is_ok());

        // Missing len parameter
        let missing_len = json!({"path": "/tmp/test.txt", "offset": 0});
        assert!(runner.validate_params(&missing_len).is_err());

        // Invalid len type
        let invalid_len = json!({"path": "/tmp/test.txt", "len": "not_a_number"});
        assert!(runner.validate_params(&invalid_len).is_err());

        // Len too large
        let large_len = json!({"path": "/tmp/test.txt", "len": 2_000_000});
        assert!(runner.validate_params(&large_len).is_err());

        // Zero len
        let zero_len = json!({"path": "/tmp/test.txt", "len": 0});
        assert!(runner.validate_params(&zero_len).is_err());

        // Negative len
        let negative_len = json!({"path": "/tmp/test.txt", "len": -1});
        assert!(runner.validate_params(&negative_len).is_err());

        // Missing path parameter
        let missing_path = json!({"len": 100});
        assert!(runner.validate_params(&missing_path).is_err());
    }

    #[tokio::test]
    async fn test_fs_read_execution() {
        let temp_dir = tempdir().unwrap();
        let mut temp_file = NamedTempFile::new_in(temp_dir.path()).unwrap();

        // Write test content
        let test_content = b"Hello, World! This is a test file for fs.read runner.";
        temp_file.write_all(test_content).unwrap();
        temp_file.flush().unwrap();

        // Create execution context
        let limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 100_000_000,
            io_bytes: 10_000_000,
            pids_max: 10,
            timeout_ms: 30_000,
        };

        let scope = Scope {
            paths: vec![temp_dir.path().to_string_lossy().to_string()],
            urls: vec![],
        };

        let ctx = create_exec_context(temp_dir.path(), limits, scope, "test-trace-id".to_string());

        // Test parameters
        let path_value = temp_file.path().to_string_lossy().to_string();
        let params = json!({
            "path": path_value,
            "offset": 0,
            "len": test_content.len()
        });

        // Override the scope to use the actual file path
        let mut test_ctx = ctx;
        test_ctx.scope.paths = vec![path_value.clone()];

        let runner = FsReadRunner::new();
        let mut output = MemoryOutputSink::new();

        let result = runner
            .execute(&test_ctx, params, &mut output)
            .await
            .unwrap();

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(output.stdout, test_content);
        assert_eq!(result.stdout_bytes, test_content.len() as u64);
    }

    #[tokio::test]
    async fn test_fs_read_nonexistent_file() {
        let temp_dir = tempdir().unwrap();

        let limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 100_000_000,
            io_bytes: 10_000_000,
            pids_max: 10,
            timeout_ms: 30_000,
        };

        let scope = Scope {
            paths: vec![temp_dir
                .path()
                .join("nonexistent.txt")
                .to_string_lossy()
                .to_string()],
            urls: vec![],
        };

        let ctx = create_exec_context(temp_dir.path(), limits, scope, "test-trace-id".to_string());

        let params = json!({
            "path": temp_dir
                .path()
                .join("nonexistent.txt")
                .to_string_lossy()
                .to_string(),
            "offset": 0,
            "len": 1024
        });

        let runner = FsReadRunner::new();
        let mut output = MemoryOutputSink::new();

        let result = runner.execute(&ctx, params, &mut output).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Error);
        assert_eq!(result.exit_code, Some(2));
        assert!(output.stderr.len() > 0);
    }

    #[tokio::test]
    async fn test_fs_read_partial_content() {
        let temp_dir = tempdir().unwrap();
        let mut temp_file = NamedTempFile::new_in(temp_dir.path()).unwrap();

        // Write test content
        let test_content = b"0123456789abcdefghijklmnopqrstuvwxyz";
        temp_file.write_all(test_content).unwrap();
        temp_file.flush().unwrap();

        let limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 100_000_000,
            io_bytes: 10_000_000,
            pids_max: 10,
            timeout_ms: 30_000,
        };

        let scope = Scope {
            paths: vec![temp_dir.path().to_string_lossy().to_string()],
            urls: vec![],
        };

        let mut ctx =
            create_exec_context(temp_dir.path(), limits, scope, "test-trace-id".to_string());

        let path_value = temp_file.path().to_string_lossy().to_string();
        ctx.scope.paths = vec![path_value.clone()];

        // Read 10 bytes starting from offset 5
        let params = json!({
            "path": path_value,
            "offset": 5,
            "len": 10
        });

        let runner = FsReadRunner::new();
        let mut output = MemoryOutputSink::new();

        let result = runner.execute(&ctx, params, &mut output).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(output.stdout, b"56789abcde");
        assert_eq!(result.stdout_bytes, 10);
    }
}
