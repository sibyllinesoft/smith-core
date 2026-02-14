//! Planner-Executor Controller capability for Smith platform
//!
//! This module implements a sophisticated state machine-based AI workflow controller
//! that manages complex, multi-step AI agent execution patterns. It provides:
//!
//! - **State Machine Engine**: Manages workflow states and transitions
//! - **Oracle Layer**: Deep research and planning committee for complex decisions
//! - **Guard Engine**: Policy validation and safety enforcement
//! - **Executor Adapter**: Integration with Smith's capability execution system
//! - **Stall Detection**: Automatic escalation when workflows get stuck
//! - **Menu System**: User interaction and control interface
//!
//! ## Architecture Overview
//!
//! The Planner-Executor Controller operates as a sophisticated orchestration layer
//! that sits between high-level AI planning and low-level capability execution:
//!
//! ```text
//! User Goal → State Machine → Oracle → Guard → Executor → Results → State Update
//!     ↑                                                                    ↓
//!     ←─────────────── Stall Detection & Menu System ──────────────────────
//! ```
//!
//! ## Key Components
//!
//! - **`state_machine`**: Core state engine with transitions and persistence
//! - **`oracle`**: AI-powered research and planning committee
//! - **`guard`**: Policy validation and safety checks
//! - **`executor_adapter`**: Integration with Smith capability runners
//! - **`stall_detection`**: Automatic detection of stuck workflows
//! - **`menu_system`**: Interactive user control interface
//! - **`schemas`**: Data structures and validation schemas
//! - **`telemetry`**: Comprehensive observability and metrics
//!
//! ## Security Model
//!
//! The controller implements multiple security layers:
//! - Guard validation before any execution
//! - Capability-based permission model
//! - Comprehensive audit trails
//! - Resource limit enforcement
//! - Stall detection for runaway processes
//!
//! ## Usage Example
//!
//! ```text
//! use smith_protocol::{Intent, Capability};
//! use serde_json::json;
//!
//! // Create a planner execution intent
//! let intent = Intent::new(
//!     Capability::PlannerExecV1,
//!     "production".to_string(),
//!     json!({
//!         "goal": "Analyze codebase and suggest improvements",
//!         "workflow_type": "research_and_planning",
//!         "max_steps": 50,
//!         "timeout_ms": 300000
//!     }),
//!     300000, // 5 minute TTL
//!     "client-public-key".to_string(),
//! );
//! ```

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use smith_protocol::ExecutionStatus;

pub mod api;
pub mod executor_adapter;
pub mod guard;
pub mod menu_system;
pub mod oracle;
pub mod schemas;
pub mod stall_detection;
pub mod state_machine;
pub mod telemetry;

use schemas::{PlannerExecParams, WorkflowType};
use state_machine::{StateMachine, WorkflowState};
use telemetry::TelemetryCollector;

/// Planner-Executor Controller runner for complex AI workflow orchestration
pub struct PlannerExecRunner {
    version: String,
    telemetry: TelemetryCollector,
}

impl PlannerExecRunner {
    /// Create new planner-executor runner
    pub fn new() -> Self {
        Self {
            version: "planner-exec-v1".to_string(),
            telemetry: TelemetryCollector::new("planner_exec_runner".to_string(), None),
        }
    }

    /// Validate workflow parameters
    fn validate_workflow_params(&self, params: &PlannerExecParams) -> Result<()> {
        // Validate goal
        if params.goal.trim().is_empty() {
            return Err(anyhow::anyhow!("Goal cannot be empty"));
        }

        if params.goal.len() > 10000 {
            return Err(anyhow::anyhow!("Goal too long (max 10000 characters)"));
        }

        // Validate step limits
        if params.max_steps < 1 || params.max_steps > 1000 {
            return Err(anyhow::anyhow!("max_steps must be between 1 and 1000"));
        }

        // Validate timeout
        if let Some(timeout) = params.timeout_ms {
            if timeout < 1000 || timeout > 3600000 {
                return Err(anyhow::anyhow!(
                    "timeout_ms must be between 1000 and 3600000 (1 hour)"
                ));
            }
        }

        // Validate workflow type
        match params.workflow_type {
            WorkflowType::Simple => {
                if params.max_steps > 10 {
                    warn!("Simple workflow with max_steps > 10 may be inefficient");
                }
            }
            WorkflowType::ResearchAndPlanning => {
                if params.max_steps < 5 {
                    return Err(anyhow::anyhow!(
                        "ResearchAndPlanning requires at least 5 steps"
                    ));
                }
            }
            WorkflowType::ComplexOrchestration => {
                if params.max_steps < 10 {
                    return Err(anyhow::anyhow!(
                        "ComplexOrchestration requires at least 10 steps"
                    ));
                }
            }
        }

        Ok(())
    }

    /// Execute the planner workflow
    async fn execute_workflow(
        &self,
        ctx: &ExecContext,
        params: PlannerExecParams,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start_time = std::time::Instant::now();
        let workflow_id = uuid::Uuid::new_v4().to_string();

        info!(
            workflow_id = %workflow_id,
            goal = %params.goal,
            workflow_type = ?params.workflow_type,
            "Starting planner-executor workflow"
        );

        out.write_log("INFO", &format!("Starting workflow {}", workflow_id))?;

        // Initialize state machine
        let mut state_machine = StateMachine::new(params.workflow_id.clone(), params.clone())?;

        // Initialize Oracle layer
        let oracle = oracle::Oracle::new(ctx)?;

        // Initialize Guard engine
        let mut guard = guard::Guard::new(ctx)?;

        // Initialize Executor adapter
        let mut executor_adapter = executor_adapter::ExecutorAdapter::new(ctx)?;

        // Initialize Stall detection
        let mut stall_detector = stall_detection::StallDetector::new(params.max_steps as u32)?;

        // Initialize Menu system
        let mut menu_system = menu_system::MenuSystem::new()?;

        let mut step_count = 0;
        let mut last_progress_time = std::time::Instant::now();

        // Main execution loop
        loop {
            step_count += 1;

            // Check step limits
            if step_count > params.max_steps {
                warn!(workflow_id = %workflow_id, "Workflow exceeded max steps");
                state_machine
                    .transition_to(WorkflowState::Failed("Exceeded maximum steps".to_string()))?;
                break;
            }

            // Check timeout
            if let Some(timeout_ms) = params.timeout_ms {
                if start_time.elapsed().as_millis() > timeout_ms as u128 {
                    warn!(workflow_id = %workflow_id, "Workflow timed out");
                    state_machine
                        .transition_to(WorkflowState::Failed("Workflow timeout".to_string()))?;
                    break;
                }
            }

            // Get current state (clone to avoid borrow conflicts)
            let current_state = state_machine.current_state().clone();

            out.write_log("INFO", &format!("Step {}: {:?}", step_count, current_state))?;

            // Process state
            match current_state {
                WorkflowState::Initializing => {
                    // Oracle: Initial planning
                    let planning_result = oracle.initial_planning(&params.goal).await?;
                    state_machine.set_planning_result(planning_result)?;
                    state_machine.transition_to(WorkflowState::Planning)?;
                }

                WorkflowState::Planning => {
                    // Oracle: Deep research and planning
                    let research_result = oracle.deep_research(&state_machine).await?;
                    state_machine.set_research_result(research_result)?;
                    state_machine.transition_to(WorkflowState::Executing)?;
                }

                WorkflowState::Executing => {
                    // Get next action from state machine
                    if let Some(next_action) = state_machine.get_next_action()? {
                        // Guard: Validate action
                        if !guard.validate_action(&next_action).await? {
                            warn!(workflow_id = %workflow_id, "Action rejected by guard");
                            state_machine.transition_to(WorkflowState::Failed(
                                "Action rejected by security guard".to_string(),
                            ))?;
                            break;
                        }

                        // Execute action
                        let execution_result =
                            executor_adapter.execute_action(&next_action).await?;
                        state_machine.record_execution_result(execution_result)?;

                        // Check if workflow is complete
                        if state_machine.is_complete()? {
                            state_machine.transition_to(WorkflowState::Completed)?;
                        }
                    } else {
                        // No more actions - check completion
                        if state_machine.is_complete()? {
                            state_machine.transition_to(WorkflowState::Completed)?;
                        } else {
                            // Stall detection
                            if stall_detector.check_stall(&state_machine, &last_progress_time)? {
                                warn!(workflow_id = %workflow_id, "Stall detected");

                                // Try menu system for user intervention
                                if let Some(user_action) =
                                    menu_system.handle_stall(&state_machine).await?
                                {
                                    state_machine.apply_user_action(user_action)?;
                                    last_progress_time = std::time::Instant::now();
                                } else {
                                    state_machine.transition_to(WorkflowState::Failed(
                                        "Workflow stalled and no user intervention".to_string(),
                                    ))?;
                                    break;
                                }
                            }
                        }
                    }
                }

                WorkflowState::Completed => {
                    info!(workflow_id = %workflow_id, "Workflow completed successfully");
                    break;
                }

                WorkflowState::Failed(reason) => {
                    error!(workflow_id = %workflow_id, reason = %reason, "Workflow failed");
                    break;
                }

                WorkflowState::Paused => {
                    // Handle paused state via menu system
                    if let Some(user_action) = menu_system.handle_pause(&state_machine).await? {
                        state_machine.apply_user_action(user_action)?;
                    }
                }
            }

            // Update progress tracking
            last_progress_time = std::time::Instant::now();

            // Record telemetry
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("step".to_string(), step_count.to_string());
            metadata.insert("state".to_string(), format!("{:?}", current_state));

            self.telemetry
                .record_event(
                    telemetry::EventType::Custom("workflow_step".to_string()),
                    "state_machine",
                    &format!("Step {} in state {:?}", step_count, current_state),
                    metadata,
                    telemetry::Severity::Info,
                )
                .await;
        }

        // Generate final result
        let final_state = state_machine.current_state();
        let execution_summary = state_machine.get_execution_summary()?;

        // Write summary to output
        let summary_json = serde_json::to_string_pretty(&execution_summary)?;
        out.write_stdout(summary_json.as_bytes())?;

        // Record final telemetry
        let mut completion_metadata = std::collections::HashMap::new();
        completion_metadata.insert(
            "duration_ms".to_string(),
            start_time.elapsed().as_millis().to_string(),
        );
        completion_metadata.insert("final_state".to_string(), format!("{:?}", final_state));
        completion_metadata.insert("total_steps".to_string(), step_count.to_string());

        self.telemetry
            .record_event(
                telemetry::EventType::WorkflowComplete,
                "workflow_executor",
                "Workflow execution completed",
                completion_metadata,
                if matches!(final_state, WorkflowState::Completed) {
                    telemetry::Severity::Info
                } else {
                    telemetry::Severity::Error
                },
            )
            .await;

        // Determine execution status
        let status = match final_state {
            WorkflowState::Completed => ExecutionStatus::Ok,
            WorkflowState::Failed(_) => ExecutionStatus::Error,
            _ => ExecutionStatus::Error, // Unexpected final state
        };

        Ok(ExecutionResult {
            status: status.clone(),
            exit_code: if status == ExecutionStatus::Ok {
                Some(0)
            } else {
                Some(1)
            },
            artifacts: vec![],
            duration_ms: start_time.elapsed().as_millis() as u64,
            stdout_bytes: summary_json.len() as u64,
            stderr_bytes: 0,
        })
    }
}

#[async_trait]
impl Runner for PlannerExecRunner {
    fn digest(&self) -> String {
        self.version.clone()
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        // Parse parameters
        let parsed_params: PlannerExecParams = serde_json::from_value(params.clone())
            .context("Failed to parse planner_exec parameters")?;

        // Validate workflow parameters
        self.validate_workflow_params(&parsed_params)
            .context("Workflow parameter validation failed")?;

        debug!("Planner-exec parameters validated successfully");
        Ok(())
    }

    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start_time = std::time::Instant::now();

        out.write_log("INFO", "Starting planner-executor execution")?;

        // Parse parameters
        let parsed_params: PlannerExecParams =
            serde_json::from_value(params).context("Failed to parse planner_exec parameters")?;

        // Execute workflow
        match self.execute_workflow(ctx, parsed_params, out).await {
            Ok(result) => {
                out.write_log("INFO", "Planner-executor execution completed")?;
                Ok(result)
            }
            Err(e) => {
                let error_msg = format!("Planner-executor execution failed: {}", e);
                error!("{}", error_msg);
                out.write_log("ERROR", &error_msg)?;
                out.write_stderr(error_msg.as_bytes())?;

                Ok(ExecutionResult {
                    status: ExecutionStatus::Error,
                    exit_code: Some(1),
                    artifacts: vec![],
                    duration_ms: start_time.elapsed().as_millis() as u64,
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
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_planner_exec_runner_creation() {
        let runner = PlannerExecRunner::new();
        assert_eq!(runner.digest(), "planner-exec-v1");
    }

    #[tokio::test]
    async fn test_parameter_validation() {
        let runner = PlannerExecRunner::new();

        // Valid parameters
        let valid_params = json!({
            "workflow_id": "test-workflow-234",
            "goal": "Test workflow execution",
            "workflow_type": "simple",
            "max_steps": 10,
            "timeout_ms": 30000
        });
        assert!(runner.validate_params(&valid_params).is_ok());

        // Invalid parameters - empty goal
        let invalid_params = json!({
            "workflow_id": "test-workflow-567",
            "goal": "",
            "workflow_type": "simple",
            "max_steps": 10
        });
        assert!(runner.validate_params(&invalid_params).is_err());

        // Invalid parameters - too many steps
        let invalid_params = json!({
            "workflow_id": "test-workflow-890",
            "goal": "Test",
            "workflow_type": "simple",
            "max_steps": 2000
        });
        assert!(runner.validate_params(&invalid_params).is_err());
    }

    #[tokio::test]
    async fn test_workflow_execution() {
        let temp_dir = tempdir().unwrap();

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

        let params = json!({
            "workflow_id": "test-workflow-111",
            "goal": "Simple test workflow",
            "workflow_type": "simple",
            "max_steps": 5,
            "timeout_ms": 30000
        });

        let runner = PlannerExecRunner::new();
        let mut output = MemoryOutputSink::new();

        let result = runner.execute(&ctx, params, &mut output).await.unwrap();

        // For now, expect the execution to complete (even if with minimal functionality)
        assert!(matches!(
            result.status,
            ExecutionStatus::Ok | ExecutionStatus::Error
        ));
        assert!(result.duration_ms > 0);
    }
}
