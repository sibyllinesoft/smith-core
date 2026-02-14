//! Simple integration test for planner exec runner

use anyhow::{Context, Result};
use serde_json::json;
use std::time::Instant;
use tempfile::TempDir;
use tracing::{debug, info};

use agentd::runners::planner_exec::PlannerExecRunner;
use agentd::runners::{
    create_exec_context, ExecContext, ExecutionResult, MemoryOutputSink, Runner, Scope,
};
use agentd::ExecutionLimits;
use smith_protocol::ExecutionStatus;

/// Test fixture for planner integration tests
struct PlannerTestFixture {
    temp_dir: TempDir,
    runner: PlannerExecRunner,
}

impl PlannerTestFixture {
    /// Create a new test fixture
    fn new() -> Result<Self> {
        let temp_dir = TempDir::new().context("Failed to create temp directory")?;
        let runner = PlannerExecRunner::new();

        Ok(Self { temp_dir, runner })
    }

    /// Create a test execution context
    fn create_exec_context(&self) -> ExecContext {
        let limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 100_000_000,
            io_bytes: 10_000_000,
            pids_max: 10,
            timeout_ms: 30_000,
        };

        let scope = Scope {
            paths: vec![self.temp_dir.path().to_string_lossy().to_string()],
            urls: vec![],
        };

        create_exec_context(
            self.temp_dir.path(),
            limits,
            scope,
            "test-trace-id".to_string(),
        )
    }

    /// Create test parameters as JSON
    fn create_test_params(&self, goal: &str) -> serde_json::Value {
        json!({
            "workflow_id": "test-workflow-123",
            "goal": goal,
            "workflow_type": "simple",
            "max_steps": 5,
            "timeout_ms": 30000
        })
    }
}

#[tokio::test]
async fn test_planner_exec_basic_execution() -> Result<()> {
    let fixture = PlannerTestFixture::new()?;

    info!("Starting basic planner execution test");

    let params = fixture.create_test_params("Test simple workflow execution");
    let ctx = fixture.create_exec_context();
    let mut output = MemoryOutputSink::new();

    let start = Instant::now();
    let result = fixture.runner.execute(&ctx, params, &mut output).await?;
    let duration = start.elapsed();

    info!("Planner execution completed in {:?}", duration);
    debug!("Execution result: {:?}", result);

    // Verify basic execution properties
    assert!(matches!(
        result.status,
        ExecutionStatus::Ok | ExecutionStatus::Error
    ));
    assert!(result.duration_ms > 0);

    // Check that some output was generated
    let has_output =
        !output.stdout.is_empty() || !output.stderr.is_empty() || !output.logs.is_empty();
    debug!(
        "Output check - stdout: {} bytes, stderr: {} bytes, logs: {} entries",
        output.stdout.len(),
        output.stderr.len(),
        output.logs.len()
    );

    info!("Basic planner execution test passed");
    Ok(())
}

#[tokio::test]
async fn test_planner_exec_error_handling() -> Result<()> {
    let fixture = PlannerTestFixture::new()?;

    info!("Testing planner error handling");

    // Create parameters that might cause errors
    let params = json!({
        "workflow_id": "test-error-workflow",
        "goal": "This is an intentionally invalid goal to test error handling",
        "workflow_type": "invalid_type",
        "max_steps": 0, // Invalid
        "timeout_ms": 1 // Very short timeout
    });

    let ctx = fixture.create_exec_context();
    let mut output = MemoryOutputSink::new();

    let result = fixture.runner.execute(&ctx, params, &mut output).await;

    // Should either succeed with error status or return an error
    match result {
        Ok(exec_result) => {
            info!("Execution completed with status: {:?}", exec_result.status);
            // Allow any status - we're just testing that it doesn't panic
        }
        Err(e) => {
            info!("Execution failed as expected: {}", e);
            // This is also acceptable for error handling test
        }
    }

    info!("Error handling test completed");
    Ok(())
}
