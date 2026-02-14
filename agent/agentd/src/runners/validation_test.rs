use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, info};

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use smith_protocol::ExecutionStatus;

#[derive(Debug, Deserialize)]
struct ValidationConfig {
    #[serde(default = "default_command")]
    command: Vec<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    env: Vec<EnvVar>,
}

#[derive(Debug, Deserialize)]
struct EnvVar {
    key: String,
    value: String,
}

fn default_command() -> Vec<String> {
    vec![
        "cargo".to_string(),
        "test".to_string(),
        "--workspace".to_string(),
        "--quiet".to_string(),
    ]
}

pub struct ValidationTestRunner;

impl ValidationTestRunner {
    pub fn new() -> Self {
        Self
    }

    fn parse_config(params: &Value) -> Result<ValidationConfig> {
        serde_json::from_value(params.clone()).context("Failed to parse validation parameters")
    }

    fn resolve_working_dir(ctx: &ExecContext, dir: Option<String>) -> Result<PathBuf> {
        let Some(dir) = dir else {
            return Ok(ctx.workdir.clone());
        };

        let rel = PathBuf::from(&dir);
        if rel.is_absolute() {
            anyhow::bail!("Validation working_dir must be relative: {}", dir);
        }

        for component in rel.components() {
            if matches!(component, Component::ParentDir) {
                anyhow::bail!(
                    "Validation working_dir may not traverse parent directories: {}",
                    dir
                );
            }
        }

        Ok(ctx.workdir.join(rel))
    }
}

#[async_trait]
impl Runner for ValidationTestRunner {
    fn digest(&self) -> String {
        "validation-test-runner-v1".to_string()
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        let config = Self::parse_config(params)?;
        if config.command.is_empty() {
            anyhow::bail!("Validation runner requires a non-empty command");
        }
        Ok(())
    }

    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();
        let config = Self::parse_config(&params)?;
        let working_dir = Self::resolve_working_dir(ctx, config.working_dir)?;
        let timeout_ms = config.timeout_ms.unwrap_or(300_000);

        if config.command.is_empty() {
            anyhow::bail!("Validation command may not be empty");
        }

        let mut command = Command::new(&config.command[0]);
        command.args(&config.command[1..]);
        command.current_dir(&working_dir);

        for env_var in config.env {
            command.env(env_var.key, env_var.value);
        }

        info!(
            program = %config.command[0],
            args = ?&config.command[1..],
            dir = %working_dir.display(),
            "Running validation command"
        );

        let output = tokio::time::timeout(Duration::from_millis(timeout_ms), command.output())
            .await
            .map_err(|_| anyhow::anyhow!("Validation command timed out after {}ms", timeout_ms))?
            .context("Failed to execute validation command")?;

        if !output.stdout.is_empty() {
            out.write_stdout(&output.stdout)?;
        }
        if !output.stderr.is_empty() {
            out.write_stderr(&output.stderr)?;
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        debug!("validation runner completed in {}ms", duration_ms);

        let status = if output.status.success() {
            ExecutionStatus::Success
        } else {
            ExecutionStatus::Failed
        };

        Ok(ExecutionResult {
            status,
            exit_code: output.status.code(),
            artifacts: Vec::new(),
            duration_ms,
            stdout_bytes: output.stdout.len() as u64,
            stderr_bytes: output.stderr.len() as u64,
        })
    }
}
