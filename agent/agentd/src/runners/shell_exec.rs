use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use smith_protocol::ExecutionStatus;
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::time::{self, Duration, MissedTickBehavior};
use tracing::{debug, info, warn};

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use crate::vm::MicroVmManager;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug)]
pub struct ShellExecRunner {
    vm_manager: Option<Arc<MicroVmManager>>,
}

#[derive(Debug, Deserialize)]
struct ShellExecParams {
    command: String,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl ShellExecRunner {
    pub fn new(vm_manager: Option<Arc<MicroVmManager>>) -> Self {
        Self { vm_manager }
    }

    fn parse_params(&self, params: Value) -> Result<ShellExecParams> {
        serde_json::from_value(params).context("Failed to parse shell.exec parameters")
    }

    async fn try_execute_in_vm(
        &self,
        ctx: &ExecContext,
        parsed: &ShellExecParams,
        timeout_ms: u64,
        out: &mut dyn OutputSink,
    ) -> Result<Option<ExecutionResult>> {
        let (manager, session) = match (&self.vm_manager, &ctx.session) {
            (Some(manager), Some(session)) => (manager.clone(), session.clone()),
            _ => return Ok(None),
        };

        let guard = match manager.acquire(session.session_id).await {
            Ok(guard) => guard,
            Err(err) => {
                warn!(
                    session_id = %session.session_id,
                    error = %err,
                    "Failed to acquire micro-VM; falling back to ephemeral sandbox"
                );
                return Ok(None);
            }
        };

        info!(
            session_id = %session.session_id,
            domain = session.domain.as_deref().unwrap_or("unknown"),
            command = %parsed.command,
            "Executing shell command inside persistent VM"
        );

        let mut command = Command::new(guard.shell_path());
        for arg in guard.shell_args() {
            command.arg(arg);
        }
        command.arg(&parsed.command);
        command.current_dir(guard.workdir());
        command.kill_on_drop(true);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        for (key, value) in guard.environment() {
            command.env(key, value);
        }
        command.env("SMITH_TRACE_ID", ctx.trace_id.clone());

        let result = self
            .spawn_and_collect(
                command,
                &parsed.command,
                timeout_ms,
                guard.workdir(),
                ctx,
                out,
            )
            .await?;

        Ok(Some(result))
    }

    async fn execute_on_host(
        &self,
        ctx: &ExecContext,
        parsed: &ShellExecParams,
        timeout_ms: u64,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let workdir = &ctx.workdir;
        let mut command = Command::new("bash");
        command.arg("-lc").arg(&parsed.command);
        command.current_dir(workdir);
        command.kill_on_drop(true);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.env("SMITH_TRACE_ID", ctx.trace_id.clone());

        self.spawn_and_collect(command, &parsed.command, timeout_ms, workdir, ctx, out)
            .await
    }

    async fn spawn_and_collect(
        &self,
        mut command: Command,
        command_label: &str,
        timeout_ms: u64,
        workdir: &Path,
        ctx: &ExecContext,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        debug!(
            command = %command_label,
            timeout_ms,
            workdir = %workdir.display(),
            trace_id = %ctx.trace_id,
            "Starting shell.exec runner"
        );

        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        let heartbeat_interval = Duration::from_secs(5);

        let spawn_start = Instant::now();
        debug!(
            command = %command_label,
            timeout_ms,
            workdir = %workdir.display(),
            "Spawning shell command"
        );
        let child = match command.spawn() {
            Ok(child) => {
                debug!(
                    command = %command_label,
                    workdir = %workdir.display(),
                    "Shell command spawn returned Ok"
                );
                child
            }
            Err(err) => {
                let raw_os_error = err.raw_os_error();
                warn!(
                    command = %command_label,
                    workdir = %workdir.display(),
                    error = %err,
                    raw_os_error,
                    "Failed to spawn shell command"
                );
                return Err(err).context("Failed to spawn shell command");
            }
        };
        let child_pid = child.id();
        debug!(
            command = %command_label,
            workdir = %workdir.display(),
            child_pid = ?child_pid,
            "Shell command pid acquired"
        );
        info!(
            command = %command_label,
            child_pid = ?child_pid,
            workdir = %workdir.display(),
            spawn_ms = spawn_start.elapsed().as_millis() as u64,
            "Shell command spawned"
        );

        let (output_tx, output_rx) = oneshot::channel();
        let command_label_cloned = command_label.to_string();
        tokio::spawn(async move {
            let result = child.wait_with_output().await;
            match output_tx.send(result) {
                Ok(()) => {
                    debug!(command = %command_label_cloned, "Shell command wait task signaled completion");
                }
                Err(_) => {
                    debug!(command = %command_label_cloned, "Shell command wait task dropped before signaling completion");
                }
            }
        });

        debug!(
            command = %command_label,
            child_pid = ?child_pid,
            "Shell exec wait loop initialized"
        );

        let mut timeout_future = time::sleep(timeout);
        tokio::pin!(timeout_future);
        let mut output_rx = output_rx;
        tokio::pin!(output_rx);

        let mut heartbeat = time::interval(heartbeat_interval);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut timed_out = false;
        let mut command_output: Option<Output> = None;

        loop {
            tokio::select! {
                result = &mut output_rx => {
                    match result {
                        Ok(Ok(output)) => {
                            debug!(
                                command = %command_label,
                                child_pid = ?child_pid,
                                elapsed_ms = start.elapsed().as_millis() as u64,
                                "Shell command wait_with_output completed"
                            );
                            command_output = Some(output);
                        }
                        Ok(Err(err)) => {
                            warn!(
                                command = %command_label,
                                child_pid = ?child_pid,
                                error = %err,
                                "Failed to collect shell command output"
                            );
                            return Err(err).context("Failed to collect shell command output");
                        }
                        Err(_) => {
                            return Err(anyhow!(
                                "Shell command wait task was cancelled before completion"
                            ));
                        }
                    }
                    break;
                }
                _ = &mut timeout_future => {
                    debug!(
                        command = %command_label,
                        child_pid = ?child_pid,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "Shell exec timeout reached"
                    );
                    timed_out = true;
                    break;
                }
                _ = heartbeat.tick() => {
                    info!(
                        command = %command_label,
                        child_pid = ?child_pid,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "Shell command still running"
                    );
                }
            }
        }

        debug!(
            command = %command_label,
            child_pid = ?child_pid,
            timed_out,
            has_output = command_output.is_some(),
            "Shell exec wait loop exiting"
        );

        if timed_out {
            if command_output.is_some() {
                debug!(
                    command = %command_label,
                    child_pid = ?child_pid,
                    "Shell exec timeout fired but output already captured"
                );
                timed_out = false;
            } else {
                out.write_log("error", "Shell command timed out")?;
                warn!(
                    command = %command_label,
                    child_pid = ?child_pid,
                    timeout_ms,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    "Shell command timed out; attempting to terminate"
                );

                #[cfg(target_os = "linux")]
                {
                    if let Some(pid) = child_pid {
                        let raw_pid = pid as i32;
                        let signal_result = unsafe { libc::kill(raw_pid, libc::SIGKILL) };
                        if signal_result != 0 {
                            let err = std::io::Error::last_os_error();
                            warn!(
                                command = %command_label,
                                child_pid = ?child_pid,
                                error = %err,
                                "Failed to send SIGKILL to shell command"
                            );
                        } else {
                            debug!(
                                command = %command_label,
                                child_pid = ?child_pid,
                                "Sent SIGKILL to shell command after timeout"
                            );
                        }
                    } else {
                        warn!(
                            command = %command_label,
                            "Shell command PID unavailable; unable to signal process"
                        );
                    }
                }

                #[cfg(not(target_os = "linux"))]
                {
                    warn!(
                        command = %command_label,
                        "Shell command timeout handling is not supported on this platform"
                    );
                }

                debug!(
                    command = %command_label,
                    child_pid = ?child_pid,
                    "Awaiting shell command termination after timeout"
                );
                match output_rx.as_mut().await {
                    Ok(Ok(output)) => {
                        debug!(
                            command = %command_label,
                            child_pid = ?child_pid,
                            "Shell exec collected output after timeout"
                        );
                        command_output = Some(output);
                    }
                    Ok(Err(err)) => {
                        warn!(
                            command = %command_label,
                            child_pid = ?child_pid,
                            error = %err,
                            "Failed to collect shell command output after timeout"
                        );
                        return Err(err)
                            .context("Failed to collect shell command output after timeout");
                    }
                    Err(_) => {
                        return Err(anyhow!(
                            "Shell command wait task was cancelled after timeout"
                        ));
                    }
                }
            }
        }

        let output = command_output
            .ok_or_else(|| anyhow!("Shell command finished without producing output"))?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let exit_code = output.status.code();
        let stdout = output.stdout;
        let stderr = output.stderr;
        let stdout_bytes = stdout.len() as u64;
        let stderr_bytes = stderr.len() as u64;

        out.write_stdout(&stdout)?;
        out.write_stderr(&stderr)?;
        if !stderr.is_empty() {
            if let Ok(stderr_str) = std::str::from_utf8(&stderr) {
                out.write_log("warn", stderr_str.trim_end())?;
            }
        }

        if timed_out {
            return Ok(ExecutionResult {
                status: ExecutionStatus::Timeout,
                exit_code,
                artifacts: Vec::new(),
                duration_ms,
                stdout_bytes,
                stderr_bytes,
            });
        }

        info!(
            command = %command_label,
            child_pid = ?child_pid,
            timeout_ms,
            workdir = %workdir.display(),
            exit_code,
            exited_successfully = output.status.success(),
            duration_ms,
            "Shell command completed"
        );

        let exec_status = if output.status.success() {
            ExecutionStatus::Ok
        } else {
            ExecutionStatus::Error
        };

        Ok(ExecutionResult {
            status: exec_status,
            exit_code,
            artifacts: Vec::new(),
            duration_ms,
            stdout_bytes,
            stderr_bytes,
        })
    }
}

#[async_trait]
impl Runner for ShellExecRunner {
    fn digest(&self) -> String {
        format!("shell-exec-runner-{}", env!("CARGO_PKG_VERSION"))
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        let parsed = self.parse_params(params.clone())?;
        if parsed.command.trim().is_empty() {
            return Err(anyhow!("Shell command must not be empty"));
        }
        Ok(())
    }

    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let parsed = self.parse_params(params)?;
        if parsed.command.trim().is_empty() {
            return Err(anyhow!("Shell command must not be empty"));
        }

        out.write_log(
            "info",
            &format!("Executing shell command: {}", parsed.command),
        )?;
        let timeout_ms = parsed.timeout_ms.max(1);

        if let Some(vm_result) = self
            .try_execute_in_vm(ctx, &parsed, timeout_ms, out)
            .await?
        {
            return Ok(vm_result);
        }

        self.execute_on_host(ctx, &parsed, timeout_ms, out).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::{MemoryOutputSink, Scope};
    use serde_json::json;
    use smith_protocol::ExecutionLimits;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ===== ShellExecRunner Creation Tests =====

    #[test]
    fn test_shell_exec_runner_new_without_vm() {
        let runner = ShellExecRunner::new(None);
        assert!(runner.vm_manager.is_none());
    }

    // ===== Parameter Parsing Tests =====

    #[test]
    fn test_parse_params_valid() {
        let runner = ShellExecRunner::new(None);
        let params = json!({
            "command": "echo hello"
        });

        let parsed = runner.parse_params(params).unwrap();
        assert_eq!(parsed.command, "echo hello");
        assert_eq!(parsed.timeout_ms, DEFAULT_TIMEOUT_MS);
    }

    #[test]
    fn test_parse_params_with_timeout() {
        let runner = ShellExecRunner::new(None);
        let params = json!({
            "command": "sleep 5",
            "timeout_ms": 60000
        });

        let parsed = runner.parse_params(params).unwrap();
        assert_eq!(parsed.command, "sleep 5");
        assert_eq!(parsed.timeout_ms, 60000);
    }

    #[test]
    fn test_parse_params_missing_command() {
        let runner = ShellExecRunner::new(None);
        let params = json!({});

        let result = runner.parse_params(params);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_params_invalid_type() {
        let runner = ShellExecRunner::new(None);
        let params = json!({
            "command": 12345
        });

        let result = runner.parse_params(params);
        assert!(result.is_err());
    }

    // ===== Validation Tests =====

    #[test]
    fn test_validate_params_valid() {
        let runner = ShellExecRunner::new(None);
        let params = json!({
            "command": "ls -la"
        });

        assert!(runner.validate_params(&params).is_ok());
    }

    #[test]
    fn test_validate_params_empty_command() {
        let runner = ShellExecRunner::new(None);
        let params = json!({
            "command": ""
        });

        let result = runner.validate_params(&params);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_validate_params_whitespace_only() {
        let runner = ShellExecRunner::new(None);
        let params = json!({
            "command": "   \t\n   "
        });

        let result = runner.validate_params(&params);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_params_missing_command() {
        let runner = ShellExecRunner::new(None);
        let params = json!({
            "timeout_ms": 5000
        });

        let result = runner.validate_params(&params);
        assert!(result.is_err());
    }

    // ===== Digest Tests =====

    #[test]
    fn test_digest_format() {
        let runner = ShellExecRunner::new(None);
        let digest = runner.digest();

        assert!(digest.starts_with("shell-exec-runner-"));
        assert!(digest.contains(env!("CARGO_PKG_VERSION")));
    }

    // ===== Default Timeout Tests =====

    #[test]
    fn test_default_timeout_ms() {
        assert_eq!(default_timeout_ms(), DEFAULT_TIMEOUT_MS);
        assert_eq!(DEFAULT_TIMEOUT_MS, 30_000);
    }

    // ===== Integration Tests (require async runtime) =====

    fn create_test_context(workdir: &Path) -> ExecContext {
        ExecContext {
            workdir: workdir.to_path_buf(),
            limits: ExecutionLimits::default(),
            scope: Scope {
                paths: vec![],
                urls: vec![],
            },
            creds: None,
            netns: None,
            trace_id: "test-trace-123".to_string(),
            session: None,
        }
    }

    #[tokio::test]
    async fn test_execute_simple_command() {
        let runner = ShellExecRunner::new(None);
        let temp_dir = TempDir::new().unwrap();
        let ctx = create_test_context(temp_dir.path());
        let mut output = MemoryOutputSink::new();

        let params = json!({
            "command": "echo hello",
            "timeout_ms": 5000
        });

        let result = runner.execute(&ctx, params, &mut output).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout_bytes > 0);
    }

    #[tokio::test]
    async fn test_execute_command_with_exit_code() {
        let runner = ShellExecRunner::new(None);
        let temp_dir = TempDir::new().unwrap();
        let ctx = create_test_context(temp_dir.path());
        let mut output = MemoryOutputSink::new();

        let params = json!({
            "command": "exit 42",
            "timeout_ms": 5000
        });

        let result = runner.execute(&ctx, params, &mut output).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Error);
        assert_eq!(result.exit_code, Some(42));
    }

    #[tokio::test]
    async fn test_execute_command_stderr() {
        let runner = ShellExecRunner::new(None);
        let temp_dir = TempDir::new().unwrap();
        let ctx = create_test_context(temp_dir.path());
        let mut output = MemoryOutputSink::new();

        let params = json!({
            "command": "echo error >&2",
            "timeout_ms": 5000
        });

        let result = runner.execute(&ctx, params, &mut output).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert!(result.stderr_bytes > 0);
    }

    #[tokio::test]
    async fn test_execute_empty_command_fails() {
        let runner = ShellExecRunner::new(None);
        let temp_dir = TempDir::new().unwrap();
        let ctx = create_test_context(temp_dir.path());
        let mut output = MemoryOutputSink::new();

        let params = json!({
            "command": ""
        });

        let result = runner.execute(&ctx, params, &mut output).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_outputs_logs() {
        let runner = ShellExecRunner::new(None);
        let temp_dir = TempDir::new().unwrap();
        let ctx = create_test_context(temp_dir.path());
        let mut output = MemoryOutputSink::new();

        let params = json!({
            "command": "echo test",
            "timeout_ms": 5000
        });

        runner.execute(&ctx, params, &mut output).await.unwrap();

        // Should have info log about executing command
        assert!(!output.logs.is_empty());
        assert!(output
            .logs
            .iter()
            .any(|l| l.contains("Executing shell command")));
    }

    #[tokio::test]
    async fn test_execute_in_workdir() {
        let runner = ShellExecRunner::new(None);
        let temp_dir = TempDir::new().unwrap();

        // Create a file in the temp directory
        std::fs::write(temp_dir.path().join("test.txt"), "content").unwrap();

        let ctx = create_test_context(temp_dir.path());
        let mut output = MemoryOutputSink::new();

        let params = json!({
            "command": "ls test.txt",
            "timeout_ms": 5000
        });

        let result = runner.execute(&ctx, params, &mut output).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Ok);
        // stdout should contain "test.txt"
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        assert!(stdout_str.contains("test.txt"));
    }

    #[tokio::test]
    async fn test_execute_timeout() {
        let runner = ShellExecRunner::new(None);
        let temp_dir = TempDir::new().unwrap();
        let ctx = create_test_context(temp_dir.path());
        let mut output = MemoryOutputSink::new();

        // Command that will definitely timeout (100ms timeout, 10 second sleep)
        let params = json!({
            "command": "sleep 10",
            "timeout_ms": 100
        });

        let result = runner.execute(&ctx, params, &mut output).await.unwrap();

        // Should either timeout or be killed
        assert!(
            result.status == ExecutionStatus::Timeout || result.status == ExecutionStatus::Error,
            "Expected timeout or error, got {:?}",
            result.status
        );
    }
}
