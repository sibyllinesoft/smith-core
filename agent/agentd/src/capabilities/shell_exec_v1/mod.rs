use async_trait::async_trait;
use serde_json::json;
use smith_protocol::{
    CapabilitySpec, ExecutionError, ExecutionStatus, Intent, ResourceRequirements,
};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::capability::{Capability, CapabilityResult, ExecCtx, ExecutionMetadata};

/// ShellExecV1 capability for executing shell commands
pub struct ShellExecV1Capability;

impl ShellExecV1Capability {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ShellExecV1Capability {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Capability for ShellExecV1Capability {
    fn name(&self) -> &'static str {
        "shell.exec.v1"
    }

    fn validate(&self, intent: &Intent) -> Result<(), ExecutionError> {
        if intent.capability != smith_protocol::Capability::ShellExec {
            return Err(ExecutionError {
                code: "CAPABILITY_MISMATCH".to_string(),
                message: format!("Expected shell.exec.v1, got {}", intent.capability),
            });
        }

        // Check for unexpected parameters
        if let serde_json::Value::Object(ref map) = intent.params {
            for key in map.keys() {
                match key.as_str() {
                    "command" | "args" | "env" | "cwd" | "timeout_ms" | "stdin" => {}
                    unexpected => {
                        return Err(ExecutionError {
                            code: "INVALID_PARAMS".to_string(),
                            message: format!("Unsupported parameter: {}", unexpected),
                        });
                    }
                }
            }
        }

        let params: smith_protocol::params::ShellExecV1 =
            serde_json::from_value(intent.params.clone()).map_err(|e| ExecutionError {
                code: "INVALID_PARAMS".to_string(),
                message: format!("Failed to parse shell.exec.v1 parameters: {}", e),
            })?;

        if params.command.is_empty() {
            return Err(ExecutionError {
                code: "INVALID_COMMAND".to_string(),
                message: "Command cannot be empty".to_string(),
            });
        }

        if params.command.len() > 4096 {
            return Err(ExecutionError {
                code: "INVALID_COMMAND".to_string(),
                message: "Command exceeds maximum length of 4096 characters".to_string(),
            });
        }

        // Validate timeout if specified
        if let Some(timeout_ms) = params.timeout_ms {
            if timeout_ms == 0 {
                return Err(ExecutionError {
                    code: "INVALID_TIMEOUT".to_string(),
                    message: "Timeout must be greater than 0".to_string(),
                });
            }
            if timeout_ms > 600_000 {
                return Err(ExecutionError {
                    code: "INVALID_TIMEOUT".to_string(),
                    message: "Timeout cannot exceed 600000ms (10 minutes)".to_string(),
                });
            }
        }

        debug!(
            "shell.exec.v1 parameters validated for command: {}",
            params.command
        );
        Ok(())
    }

    async fn execute(
        &self,
        intent: Intent,
        ctx: ExecCtx,
    ) -> Result<CapabilityResult, ExecutionError> {
        let start_time = std::time::Instant::now();

        info!("Executing shell.exec.v1 for intent: {}", intent.id);

        let params: smith_protocol::params::ShellExecV1 = serde_json::from_value(intent.params)
            .map_err(|e| ExecutionError {
                code: "PARAM_PARSE_ERROR".to_string(),
                message: format!("Failed to parse parameters: {}", e),
            })?;

        enforce_mode_guards(&ctx, &params)?;

        // Build command
        let mut cmd = Command::new(&params.command);

        // Add arguments
        if let Some(ref args) = params.args {
            cmd.args(args);
        }

        // Set working directory
        let cwd = resolve_workdir(&ctx, params.cwd.as_deref())?;
        cmd.current_dir(&cwd);

        // Set environment variables
        if matches!(
            ctx.sandbox.mode,
            smith_protocol::SandboxMode::Full | smith_protocol::SandboxMode::Demo
        ) {
            // Do not leak host daemon environment into command execution.
            cmd.env_clear();
            cmd.env("PATH", "/usr/bin:/bin");
            cmd.env("HOME", ctx.workdir.to_string_lossy().to_string());
        }
        if let Some(ref env) = params.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        // Configure stdio
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        if params.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        // Spawn process
        let mut child = cmd.spawn().map_err(|e| ExecutionError {
            code: "SPAWN_ERROR".to_string(),
            message: format!("Failed to spawn command '{}': {}", params.command, e),
        })?;

        // Write stdin if provided
        if let Some(ref stdin_data) = params.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin
                    .write_all(stdin_data.as_bytes())
                    .await
                    .map_err(|e| ExecutionError {
                        code: "STDIN_ERROR".to_string(),
                        message: format!("Failed to write to stdin: {}", e),
                    })?;
            }
        }

        // Wait for completion with timeout
        let timeout = std::time::Duration::from_millis(
            params.timeout_ms.unwrap_or(ctx.limits.timeout_ms as u32) as u64,
        );

        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| ExecutionError {
                code: "TIMEOUT".to_string(),
                message: format!("Command timed out after {}ms", timeout.as_millis()),
            })?
            .map_err(|e| ExecutionError {
                code: "EXEC_ERROR".to_string(),
                message: format!("Command execution failed: {}", e),
            })?;

        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        let status = if output.status.success() {
            ExecutionStatus::Ok
        } else {
            ExecutionStatus::Error
        };

        info!(
            "shell.exec.v1 completed: exit_code={}, duration={}ms, stdout_bytes={}, stderr_bytes={}",
            exit_code,
            duration_ms,
            stdout.len(),
            stderr.len()
        );

        let result_output = json!({
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "command": params.command,
            "duration_ms": duration_ms,
        });

        let error = if !output.status.success() {
            Some(ExecutionError {
                code: format!("EXIT_{}", exit_code),
                message: if stderr.is_empty() {
                    format!("Command exited with code {}", exit_code)
                } else {
                    stderr.trim().to_string()
                },
            })
        } else {
            None
        };

        Ok(CapabilityResult {
            status,
            output: Some(result_output),
            error,
            metadata: ExecutionMetadata {
                pid: std::process::id(),
                exit_code: Some(exit_code),
                duration_ms,
                stdout_bytes: stdout.len() as u64,
                stderr_bytes: stderr.len() as u64,
                artifacts: vec![],
            },
            resource_usage: smith_protocol::ResourceUsage {
                peak_memory_kb: 0,
                cpu_time_ms: duration_ms as u32,
                wall_time_ms: duration_ms as u32,
                fd_count: 3,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                network_tx_bytes: 0,
                network_rx_bytes: 0,
            },
        })
    }

    fn describe(&self) -> CapabilitySpec {
        CapabilitySpec {
            name: self.name().to_string(),
            description: "Execute shell commands and capture output".to_string(),
            params_schema: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Command to execute",
                        "maxLength": 4096
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command arguments"
                    },
                    "env": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Environment variables"
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory"
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 600000,
                        "description": "Timeout in milliseconds (default: 30000, max: 600000)"
                    },
                    "stdin": {
                        "type": "string",
                        "description": "Data to write to stdin"
                    }
                },
                "required": ["command"],
                "additionalProperties": false
            }),
            example_params: json!({
                "command": "ls",
                "args": ["-la"],
                "timeout_ms": 5000
            }),
            resource_requirements: ResourceRequirements {
                cpu_ms_typical: 100,
                memory_kb_max: 65536,
                network_access: true,
                filesystem_access: true,
                external_commands: true,
            },
            security_notes: vec![
                "Commands execute within sandbox isolation".to_string(),
                "Resource limits enforced via cgroups".to_string(),
                "Filesystem access restricted by Landlock".to_string(),
            ],
        }
    }
}

fn enforce_mode_guards(
    ctx: &ExecCtx,
    params: &smith_protocol::params::ShellExecV1,
) -> Result<(), ExecutionError> {
    if ctx.sandbox.mode != smith_protocol::SandboxMode::Full {
        return Ok(());
    }

    if let Some(cwd) = params.cwd.as_deref() {
        let path = Path::new(cwd);
        if path.is_absolute() {
            return Err(ExecutionError {
                code: "INVALID_CWD".to_string(),
                message: "Absolute cwd is not allowed in full sandbox mode".to_string(),
            });
        }
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
        {
            return Err(ExecutionError {
                code: "INVALID_CWD".to_string(),
                message: "cwd cannot contain traversal in full sandbox mode".to_string(),
            });
        }
    }

    if let Some(env) = params.env.as_ref() {
        for key in env.keys() {
            if matches!(
                key.as_str(),
                "LD_PRELOAD"
                    | "LD_LIBRARY_PATH"
                    | "DYLD_INSERT_LIBRARIES"
                    | "DYLD_LIBRARY_PATH"
                    | "BASH_ENV"
                    | "ENV"
            ) {
                return Err(ExecutionError {
                    code: "INVALID_ENV".to_string(),
                    message: format!(
                        "Environment variable '{}' is blocked in full sandbox mode",
                        key
                    ),
                });
            }
        }
    }

    Ok(())
}

fn resolve_workdir(ctx: &ExecCtx, cwd: Option<&str>) -> Result<PathBuf, ExecutionError> {
    let candidate = match cwd {
        Some(raw) => {
            let path = Path::new(raw);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                ctx.workdir.join(path)
            }
        }
        None => ctx.workdir.clone(),
    };

    if matches!(ctx.sandbox.mode, smith_protocol::SandboxMode::Full) {
        let root = ctx
            .workdir
            .canonicalize()
            .unwrap_or_else(|_| ctx.workdir.clone());
        let resolved = candidate.canonicalize().unwrap_or(candidate.clone());
        if !resolved.starts_with(&root) {
            return Err(ExecutionError {
                code: "INVALID_CWD".to_string(),
                message: format!(
                    "cwd '{}' resolves outside sandbox workdir",
                    candidate.display()
                ),
            });
        }
        Ok(resolved)
    } else {
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::Capability as CapabilityEnum;

    fn create_test_intent(params: serde_json::Value) -> Intent {
        Intent {
            id: "test-intent".to_string(),
            capability: CapabilityEnum::ShellExec,
            domain: "test".to_string(),
            params,
            created_at_ns: 0,
            ttl_ms: 30000,
            nonce: "nonce".to_string(),
            signer: "test".to_string(),
            signature_b64: String::new(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_validate_valid_command() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "echo",
            "args": ["hello"]
        }));
        assert!(cap.validate(&intent).is_ok());
    }

    #[test]
    fn test_validate_empty_command() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": ""
        }));
        let err = cap.validate(&intent).unwrap_err();
        assert_eq!(err.code, "INVALID_COMMAND");
    }

    #[test]
    fn test_validate_invalid_timeout() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "echo",
            "timeout_ms": 0
        }));
        let err = cap.validate(&intent).unwrap_err();
        assert_eq!(err.code, "INVALID_TIMEOUT");
    }

    #[test]
    fn test_validate_timeout_too_large() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "echo",
            "timeout_ms": 700000
        }));
        let err = cap.validate(&intent).unwrap_err();
        assert_eq!(err.code, "INVALID_TIMEOUT");
    }

    #[test]
    fn test_validate_unknown_param() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "echo",
            "unknown_param": "value"
        }));
        let err = cap.validate(&intent).unwrap_err();
        assert_eq!(err.code, "INVALID_PARAMS");
    }

    #[tokio::test]
    async fn test_execute_echo() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "echo",
            "args": ["hello world"]
        }));

        let ctx = ExecCtx {
            workdir: std::env::temp_dir(),
            limits: smith_protocol::ExecutionLimits::default(),
            scope: crate::capability::ExecutionScope::default(),
            trace_id: "test".to_string(),
            sandbox: crate::capability::SandboxConfig::default(),
        };

        let result = cap.execute(intent, ctx).await.unwrap();
        assert_eq!(result.status, ExecutionStatus::Ok);

        let output = result.output.unwrap();
        assert_eq!(output["exit_code"], 0);
        assert!(output["stdout"].as_str().unwrap().contains("hello world"));
    }

    #[tokio::test]
    async fn test_execute_failing_command() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "false"
        }));

        let ctx = ExecCtx {
            workdir: std::env::temp_dir(),
            limits: smith_protocol::ExecutionLimits::default(),
            scope: crate::capability::ExecutionScope::default(),
            trace_id: "test".to_string(),
            sandbox: crate::capability::SandboxConfig::default(),
        };

        let result = cap.execute(intent, ctx).await.unwrap();
        assert_eq!(result.status, ExecutionStatus::Error);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_execute_full_mode_rejects_absolute_cwd() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "echo",
            "args": ["hello"],
            "cwd": "/tmp"
        }));

        let ctx = ExecCtx {
            workdir: std::env::temp_dir(),
            limits: smith_protocol::ExecutionLimits::default(),
            scope: crate::capability::ExecutionScope::default(),
            trace_id: "test".to_string(),
            sandbox: crate::capability::SandboxConfig::default(),
        };

        let result = cap.execute(intent, ctx).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "INVALID_CWD");
    }

    #[tokio::test]
    async fn test_execute_full_mode_rejects_blocked_env() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "echo",
            "args": ["hello"],
            "env": {"LD_PRELOAD": "/tmp/pwn.so"}
        }));

        let ctx = ExecCtx {
            workdir: std::env::temp_dir(),
            limits: smith_protocol::ExecutionLimits::default(),
            scope: crate::capability::ExecutionScope::default(),
            trace_id: "test".to_string(),
            sandbox: crate::capability::SandboxConfig::default(),
        };

        let result = cap.execute(intent, ctx).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "INVALID_ENV");
    }

    #[tokio::test]
    async fn test_execute_demo_mode_allows_absolute_cwd() {
        let cap = ShellExecV1Capability::new();
        let intent = create_test_intent(json!({
            "command": "echo",
            "args": ["hello"],
            "cwd": "/tmp"
        }));

        let mut sandbox = crate::capability::SandboxConfig::default();
        sandbox.mode = smith_protocol::SandboxMode::Demo;
        let ctx = ExecCtx {
            workdir: std::env::temp_dir(),
            limits: smith_protocol::ExecutionLimits::default(),
            scope: crate::capability::ExecutionScope::default(),
            trace_id: "test".to_string(),
            sandbox,
        };

        let result = cap.execute(intent, ctx).await;
        assert!(result.is_ok());
    }
}
