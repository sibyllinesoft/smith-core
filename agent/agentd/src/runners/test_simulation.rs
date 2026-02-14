use anyhow::Result;
use async_trait::async_trait;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_json::Value;
use std::time::Instant;
use tracing::warn;

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use smith_protocol::ExecutionStatus;

pub struct RandomFailureRunner;
pub struct AlwaysFailRunner;
pub struct NoopSuccessRunner {
    digest: &'static str,
    message: &'static str,
}

impl RandomFailureRunner {
    pub fn new() -> Self {
        Self
    }
}

impl AlwaysFailRunner {
    pub fn new() -> Self {
        Self
    }
}

impl NoopSuccessRunner {
    pub fn new(digest: &'static str, message: &'static str) -> Self {
        Self { digest, message }
    }
}

#[async_trait]
impl Runner for RandomFailureRunner {
    fn digest(&self) -> String {
        "test-random-failure-runner-v1".to_string()
    }

    fn validate_params(&self, _params: &Value) -> Result<()> {
        Ok(())
    }

    async fn execute(
        &self,
        _ctx: &ExecContext,
        _params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let mut rng = StdRng::from_entropy();
        let start = Instant::now();
        let fail = rng.gen_bool(0.5);

        if fail {
            let message = "Simulated transient failure";
            out.write_stderr(message.as_bytes())?;
            warn!(message, "Random failure runner produced an error");
            Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(1),
                artifacts: Vec::new(),
                duration_ms: start.elapsed().as_millis() as u64,
                stdout_bytes: 0,
                stderr_bytes: message.as_bytes().len() as u64,
            })
        } else {
            let output = "Random failure runner executed successfully";
            out.write_stdout(output.as_bytes())?;
            Ok(ExecutionResult {
                status: ExecutionStatus::Success,
                exit_code: Some(0),
                artifacts: Vec::new(),
                duration_ms: start.elapsed().as_millis() as u64,
                stdout_bytes: output.as_bytes().len() as u64,
                stderr_bytes: 0,
            })
        }
    }
}

#[async_trait]
impl Runner for AlwaysFailRunner {
    fn digest(&self) -> String {
        "test-always-fail-runner-v1".to_string()
    }

    fn validate_params(&self, _params: &Value) -> Result<()> {
        Ok(())
    }

    async fn execute(
        &self,
        _ctx: &ExecContext,
        _params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();
        let message = "Deterministic failure for testing";
        out.write_stderr(message.as_bytes())?;

        Ok(ExecutionResult {
            status: ExecutionStatus::Error,
            exit_code: Some(2),
            artifacts: Vec::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            stdout_bytes: 0,
            stderr_bytes: message.as_bytes().len() as u64,
        })
    }
}

#[async_trait]
impl Runner for NoopSuccessRunner {
    fn digest(&self) -> String {
        self.digest.to_string()
    }

    fn validate_params(&self, _params: &Value) -> Result<()> {
        Ok(())
    }

    async fn execute(
        &self,
        _ctx: &ExecContext,
        _params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();
        if !self.message.is_empty() {
            out.write_stdout(self.message.as_bytes())?;
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(ExecutionResult {
            status: ExecutionStatus::Success,
            exit_code: Some(0),
            artifacts: Vec::new(),
            duration_ms,
            stdout_bytes: self.message.as_bytes().len() as u64,
            stderr_bytes: 0,
        })
    }
}
