//! Executor adapter for integrating with Smith's capability execution system
//!
//! This module provides a bridge between the Planner-Executor Controller
//! and Smith's existing capability runners, allowing workflow actions
//! to be executed through the standard Smith execution pipeline.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::schemas::{
    ActionError, ActionMetadata, ActionResult, ActionStatus, ActionType, ExecutionEnvironment,
    ResourceUsage, WorkflowAction,
};
use crate::runners::{ExecContext, ExecutionResult, MemoryOutputSink, RunnerRegistry};
use smith_protocol::{Capability, ExecutionStatus, Intent};

/// Executor adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorAdapterConfig {
    /// Maximum parallel executions
    pub max_parallel_executions: u32,

    /// Default timeout for actions (milliseconds)
    pub default_timeout_ms: u64,

    /// Enable detailed resource tracking
    pub track_resources: bool,

    /// Retry configuration
    pub retry_config: RetryConfig,

    /// Output capture configuration
    pub output_config: OutputConfig,
}

impl Default for ExecutorAdapterConfig {
    fn default() -> Self {
        Self {
            max_parallel_executions: 4,
            default_timeout_ms: 30000, // 30 seconds
            track_resources: true,
            retry_config: RetryConfig::default(),
            output_config: OutputConfig::default(),
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Enable automatic retries
    pub enabled: bool,

    /// Base delay between retries (milliseconds)
    pub base_delay_ms: u64,

    /// Maximum delay between retries (milliseconds)
    pub max_delay_ms: u64,

    /// Backoff multiplier
    pub backoff_multiplier: f64,

    /// Maximum total retry time (milliseconds)
    pub max_total_time_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            max_total_time_ms: 300000, // 5 minutes
        }
    }
}

/// Output capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Maximum stdout capture size (bytes)
    pub max_stdout_bytes: usize,

    /// Maximum stderr capture size (bytes)
    pub max_stderr_bytes: usize,

    /// Enable log capture
    pub capture_logs: bool,

    /// Maximum log entries to capture
    pub max_log_entries: usize,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            max_stdout_bytes: 1024 * 1024, // 1MB
            max_stderr_bytes: 256 * 1024,  // 256KB
            capture_logs: true,
            max_log_entries: 1000,
        }
    }
}

/// Execution status tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTracker {
    /// Currently executing actions
    pub active_executions: HashMap<String, ActiveExecution>,

    /// Completed executions
    pub completed_executions: Vec<ActionResult>,

    /// Total resource usage
    pub total_resource_usage: ResourceUsage,

    /// Execution statistics
    pub statistics: ExecutionStatistics,
}

impl ExecutionTracker {
    pub fn new() -> Self {
        Self {
            active_executions: HashMap::new(),
            completed_executions: Vec::new(),
            total_resource_usage: ResourceUsage::default(),
            statistics: ExecutionStatistics::default(),
        }
    }
}

/// Active execution tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveExecution {
    /// Action being executed
    pub action: WorkflowAction,

    /// When execution started
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Execution timeout
    pub timeout_at: chrono::DateTime<chrono::Utc>,

    /// Current retry attempt
    pub retry_attempt: u32,

    /// Resource usage so far
    pub resource_usage: ResourceUsage,
}

/// Execution statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionStatistics {
    /// Total actions executed
    pub total_executions: u64,

    /// Successful executions
    pub successful_executions: u64,

    /// Failed executions
    pub failed_executions: u64,

    /// Retried executions
    pub retried_executions: u64,

    /// Average execution time (milliseconds)
    pub avg_execution_time_ms: f64,

    /// Peak memory usage (bytes)
    pub peak_memory_usage: u64,

    /// Total CPU time (milliseconds)
    pub total_cpu_time_ms: u64,
}

/// Main executor adapter implementation
pub struct ExecutorAdapter {
    config: ExecutorAdapterConfig,
    execution_context: ExecContext,
    runner_registry: RunnerRegistry,
    tracker: ExecutionTracker,
}

impl ExecutorAdapter {
    /// Create a new executor adapter
    pub fn new(exec_context: &ExecContext) -> Result<Self> {
        let config = ExecutorAdapterConfig::default();
        let runner_registry = RunnerRegistry::new(None);
        let tracker = ExecutionTracker::new();

        info!(
            max_parallel = config.max_parallel_executions,
            default_timeout_ms = config.default_timeout_ms,
            "Executor adapter initialized"
        );

        Ok(Self {
            config,
            execution_context: exec_context.clone(),
            runner_registry,
            tracker,
        })
    }

    /// Create executor adapter with custom configuration
    pub fn with_config(exec_context: &ExecContext, config: ExecutorAdapterConfig) -> Result<Self> {
        let runner_registry = RunnerRegistry::new(None);
        let tracker = ExecutionTracker::new();

        info!(
            max_parallel = config.max_parallel_executions,
            default_timeout_ms = config.default_timeout_ms,
            "Executor adapter initialized with custom config"
        );

        Ok(Self {
            config,
            execution_context: exec_context.clone(),
            runner_registry,
            tracker,
        })
    }

    /// Execute a workflow action
    pub async fn execute_action(&mut self, action: &WorkflowAction) -> Result<ActionResult> {
        let execution_id = Uuid::new_v4().to_string();

        info!(
            action_id = %action.id,
            execution_id = %execution_id,
            action_type = ?action.action_type,
            "Starting action execution"
        );

        // Check if we can start new execution
        if self.tracker.active_executions.len() >= self.config.max_parallel_executions as usize {
            return Err(anyhow::anyhow!(
                "Maximum parallel executions exceeded ({}/{})",
                self.tracker.active_executions.len(),
                self.config.max_parallel_executions
            ));
        }

        let started_at = chrono::Utc::now();
        let timeout_ms = action.timeout_ms.unwrap_or(self.config.default_timeout_ms);
        let timeout_at = started_at + chrono::Duration::milliseconds(timeout_ms as i64);

        // Track active execution
        let active_execution = ActiveExecution {
            action: action.clone(),
            started_at,
            timeout_at,
            retry_attempt: 0,
            resource_usage: ResourceUsage::default(),
        };

        self.tracker
            .active_executions
            .insert(execution_id.clone(), active_execution);

        // Execute with retry logic
        let result = self.execute_with_retry(action, &execution_id).await;

        // Remove from active executions
        self.tracker.active_executions.remove(&execution_id);

        // Process result
        let action_result = match result {
            Ok(execution_result) => {
                self.create_success_result(action, execution_result, started_at)
                    .await?
            }
            Err(e) => self.create_error_result(action, e, started_at).await?,
        };

        // Update statistics
        self.update_statistics(&action_result);

        // Track completed execution
        self.tracker
            .completed_executions
            .push(action_result.clone());

        info!(
            action_id = %action.id,
            execution_id = %execution_id,
            status = ?action_result.status,
            duration_ms = (chrono::Utc::now() - started_at).num_milliseconds(),
            "Action execution completed"
        );

        Ok(action_result)
    }

    /// Execute action with retry logic
    async fn execute_with_retry(
        &mut self,
        action: &WorkflowAction,
        execution_id: &str,
    ) -> Result<ExecutionResult> {
        let mut retry_attempt = 0;
        let mut last_error = None;
        let retry_start = std::time::Instant::now();

        loop {
            debug!(
                action_id = %action.id,
                execution_id = %execution_id,
                retry_attempt = retry_attempt,
                "Attempting action execution"
            );

            // Update retry attempt in tracker
            if let Some(active) = self.tracker.active_executions.get_mut(execution_id) {
                active.retry_attempt = retry_attempt;
            }

            // Attempt execution
            match self.execute_single_attempt(action).await {
                Ok(result) => {
                    if retry_attempt > 0 {
                        info!(
                            action_id = %action.id,
                            retry_attempt = retry_attempt,
                            "Action succeeded after retry"
                        );
                        self.tracker.statistics.retried_executions += 1;
                    }
                    return Ok(result);
                }
                Err(e) => {
                    last_error = Some(e);
                    retry_attempt += 1;

                    // Check if we should retry
                    if !self.should_retry(action, retry_attempt, &retry_start) {
                        break;
                    }

                    // Calculate delay
                    let delay = self.calculate_retry_delay(retry_attempt);

                    warn!(
                        action_id = %action.id,
                        retry_attempt = retry_attempt,
                        delay_ms = delay,
                        "Action failed, retrying after delay"
                    );

                    // Wait before retry
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                }
            }
        }

        // All retries exhausted
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Execution failed after all retries")))
    }

    /// Execute a single attempt
    async fn execute_single_attempt(&self, action: &WorkflowAction) -> Result<ExecutionResult> {
        // Map action type to capability
        let capability = self.map_action_to_capability(&action.action_type)?;

        // Get appropriate runner
        let runner = self
            .runner_registry
            .get_runner(&capability)
            .ok_or_else(|| anyhow::anyhow!("No runner available for capability: {}", capability))?;

        // Validate parameters
        runner
            .validate_params(&action.parameters)
            .context("Parameter validation failed")?;

        // Create output sink
        let mut output = MemoryOutputSink::new();

        // Execute action
        let result = runner
            .execute(
                &self.execution_context,
                action.parameters.clone(),
                &mut output,
            )
            .await
            .context("Action execution failed")?;

        debug!(
            action_id = %action.id,
            capability = %capability,
            status = ?result.status,
            stdout_bytes = result.stdout_bytes,
            stderr_bytes = result.stderr_bytes,
            duration_ms = result.duration_ms,
            "Single execution attempt completed"
        );

        Ok(result)
    }

    /// Map action type to capability string
    fn map_action_to_capability(&self, action_type: &ActionType) -> Result<String> {
        match action_type {
            ActionType::FileSystem(capability) => Ok(capability.clone()),
            ActionType::Http(capability) => Ok(capability.clone()),
            ActionType::Shell(capability) => Ok(capability.clone()),
            ActionType::Research(_) => Ok("research.analyze.v1".to_string()),
            ActionType::Planning(_) => Ok("planning.generate.v1".to_string()),
            ActionType::Analysis(_) => Ok("analysis.perform.v1".to_string()),
            ActionType::Custom(capability) => Ok(capability.clone()),
        }
    }

    /// Check if we should retry the action
    fn should_retry(
        &self,
        action: &WorkflowAction,
        retry_attempt: u32,
        retry_start: &std::time::Instant,
    ) -> bool {
        // Check if retries are enabled
        if !self.config.retry_config.enabled {
            return false;
        }

        // Check max retries
        if retry_attempt >= action.retry_policy.max_retries {
            return false;
        }

        // Check total time limit
        if retry_start.elapsed().as_millis() as u64 > self.config.retry_config.max_total_time_ms {
            return false;
        }

        true
    }

    /// Calculate retry delay
    fn calculate_retry_delay(&self, retry_attempt: u32) -> u64 {
        let base_delay = self.config.retry_config.base_delay_ms;
        let multiplier = self.config.retry_config.backoff_multiplier;
        let max_delay = self.config.retry_config.max_delay_ms;

        let delay = (base_delay as f64 * multiplier.powi(retry_attempt as i32 - 1)) as u64;
        delay.min(max_delay)
    }

    /// Create success result
    async fn create_success_result(
        &mut self,
        action: &WorkflowAction,
        execution_result: ExecutionResult,
        started_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ActionResult> {
        let finished_at = chrono::Utc::now();

        let resource_usage = ResourceUsage {
            cpu_ms: execution_result.duration_ms,
            memory_bytes: 0, // Would be tracked by the runner in a real implementation
            fs_operations: if matches!(action.action_type, ActionType::FileSystem(_)) {
                1
            } else {
                0
            },
            network_requests: if matches!(action.action_type, ActionType::Http(_)) {
                1
            } else {
                0
            },
        };

        let metadata = ActionMetadata {
            retry_count: 0, // TODO: Track actual retry count
            resource_usage: resource_usage.clone(),
            environment: ExecutionEnvironment {
                executor_id: self.execution_context.trace_id.clone(),
                sandbox_mode: "full".to_string(), // TODO: Get actual sandbox mode
                security_context: HashMap::new(),
            },
        };

        // Update total resource usage
        self.tracker.total_resource_usage.cpu_ms += resource_usage.cpu_ms;
        self.tracker.total_resource_usage.memory_bytes = self
            .tracker
            .total_resource_usage
            .memory_bytes
            .max(resource_usage.memory_bytes);
        self.tracker.total_resource_usage.fs_operations += resource_usage.fs_operations;
        self.tracker.total_resource_usage.network_requests += resource_usage.network_requests;

        let output = if execution_result.stdout_bytes > 0 {
            // In a real implementation, we'd capture the actual output
            Some(serde_json::json!({
                "status": "success",
                "stdout_bytes": execution_result.stdout_bytes,
                "stderr_bytes": execution_result.stderr_bytes,
                "exit_code": execution_result.exit_code
            }))
        } else {
            Some(serde_json::json!({
                "status": "success",
                "exit_code": execution_result.exit_code
            }))
        };

        Ok(ActionResult {
            action_id: action.id.clone(),
            status: match execution_result.status {
                ExecutionStatus::Ok => ActionStatus::Completed,
                ExecutionStatus::Success => ActionStatus::Completed,
                _ => ActionStatus::Failed,
            },
            output,
            error: None,
            metadata,
            started_at,
            finished_at,
        })
    }

    /// Create error result
    async fn create_error_result(
        &mut self,
        action: &WorkflowAction,
        error: anyhow::Error,
        started_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ActionResult> {
        let finished_at = chrono::Utc::now();

        let resource_usage = ResourceUsage::default();

        let metadata = ActionMetadata {
            retry_count: 0, // TODO: Track actual retry count
            resource_usage,
            environment: ExecutionEnvironment {
                executor_id: self.execution_context.trace_id.clone(),
                sandbox_mode: "full".to_string(),
                security_context: HashMap::new(),
            },
        };

        let action_error = ActionError {
            code: "EXECUTION_FAILED".to_string(),
            message: format!("{}", error),
            details: Some(serde_json::json!({
                "error_chain": format!("{:?}", error),
                "action_type": action.action_type
            })),
            retryable: self.is_error_retryable(&error),
        };

        Ok(ActionResult {
            action_id: action.id.clone(),
            status: ActionStatus::Failed,
            output: None,
            error: Some(action_error),
            metadata,
            started_at,
            finished_at,
        })
    }

    /// Check if an error is retryable
    fn is_error_retryable(&self, error: &anyhow::Error) -> bool {
        let error_msg = error.to_string().to_lowercase();

        // Network errors are generally retryable
        if error_msg.contains("connection")
            || error_msg.contains("timeout")
            || error_msg.contains("network")
        {
            return true;
        }

        // Temporary filesystem errors might be retryable
        if error_msg.contains("temporarily unavailable") || error_msg.contains("busy") {
            return true;
        }

        // Resource exhaustion might be retryable after delay
        if error_msg.contains("resource") && error_msg.contains("limit") {
            return true;
        }

        // Most other errors are not retryable
        false
    }

    /// Update execution statistics
    fn update_statistics(&mut self, result: &ActionResult) {
        self.tracker.statistics.total_executions += 1;

        match result.status {
            ActionStatus::Completed => {
                self.tracker.statistics.successful_executions += 1;
            }
            ActionStatus::Failed => {
                self.tracker.statistics.failed_executions += 1;
            }
            _ => {}
        }

        // Update average execution time
        let duration_ms = (result.finished_at - result.started_at).num_milliseconds() as f64;
        let total_executions = self.tracker.statistics.total_executions as f64;

        self.tracker.statistics.avg_execution_time_ms =
            (self.tracker.statistics.avg_execution_time_ms * (total_executions - 1.0)
                + duration_ms)
                / total_executions;

        // Update resource usage statistics
        self.tracker.statistics.peak_memory_usage = self
            .tracker
            .statistics
            .peak_memory_usage
            .max(result.metadata.resource_usage.memory_bytes);

        self.tracker.statistics.total_cpu_time_ms += result.metadata.resource_usage.cpu_ms;
    }

    /// Get execution statistics
    pub fn get_statistics(&self) -> &ExecutionStatistics {
        &self.tracker.statistics
    }

    /// Get total resource usage
    pub fn get_total_resource_usage(&self) -> &ResourceUsage {
        &self.tracker.total_resource_usage
    }

    /// Get currently active executions
    pub fn get_active_executions(&self) -> &HashMap<String, ActiveExecution> {
        &self.tracker.active_executions
    }

    /// Get completed executions
    pub fn get_completed_executions(&self) -> &[ActionResult] {
        &self.tracker.completed_executions
    }

    /// Check if execution capacity is available
    pub fn has_capacity(&self) -> bool {
        self.tracker.active_executions.len() < self.config.max_parallel_executions as usize
    }

    /// Cancel active execution
    pub async fn cancel_execution(&mut self, execution_id: &str) -> Result<bool> {
        if let Some(active) = self.tracker.active_executions.remove(execution_id) {
            warn!(
                action_id = %active.action.id,
                execution_id = %execution_id,
                "Execution cancelled"
            );

            // Create cancelled result
            let cancelled_result = ActionResult {
                action_id: active.action.id,
                status: ActionStatus::Cancelled,
                output: None,
                error: Some(ActionError {
                    code: "EXECUTION_CANCELLED".to_string(),
                    message: "Execution was cancelled".to_string(),
                    details: None,
                    retryable: false,
                }),
                metadata: ActionMetadata {
                    retry_count: active.retry_attempt,
                    resource_usage: active.resource_usage,
                    environment: ExecutionEnvironment {
                        executor_id: self.execution_context.trace_id.clone(),
                        sandbox_mode: "full".to_string(),
                        security_context: HashMap::new(),
                    },
                },
                started_at: active.started_at,
                finished_at: chrono::Utc::now(),
            };

            self.tracker.completed_executions.push(cancelled_result);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Cancel all active executions
    pub async fn cancel_all_executions(&mut self) -> Result<u32> {
        let execution_ids: Vec<String> = self.tracker.active_executions.keys().cloned().collect();
        let mut cancelled_count = 0;

        for execution_id in execution_ids {
            if self.cancel_execution(&execution_id).await? {
                cancelled_count += 1;
            }
        }

        Ok(cancelled_count)
    }

    /// Reset statistics and completed executions
    pub fn reset(&mut self) {
        self.tracker.completed_executions.clear();
        self.tracker.total_resource_usage = ResourceUsage::default();
        self.tracker.statistics = ExecutionStatistics::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::{create_exec_context, Scope};
    use serde_json::json;
    use smith_protocol::ExecutionLimits;
    use tempfile::tempdir;

    fn create_test_context() -> ExecContext {
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
        create_exec_context(temp_dir.path(), limits, scope, "test-trace-id".to_string())
    }

    #[tokio::test]
    async fn test_executor_adapter_creation() {
        let ctx = create_test_context();
        let adapter = ExecutorAdapter::new(&ctx).unwrap();

        assert_eq!(adapter.config.max_parallel_executions, 4);
        assert_eq!(adapter.config.default_timeout_ms, 30000);
        assert!(adapter.has_capacity());
    }

    #[tokio::test]
    async fn test_action_execution() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({
                "path": ctx.scope.paths[0].clone() + "/test.txt",
                "len": 1024
            }),
            "Read test file".to_string(),
        );

        // This will fail because the file doesn't exist, but we can test the execution path
        let result = adapter.execute_action(&action).await;

        // Should complete (even if with error due to missing file)
        assert!(result.is_ok());
        let action_result = result.unwrap();
        assert_eq!(action_result.action_id, action.id);

        // Check statistics
        let stats = adapter.get_statistics();
        assert_eq!(stats.total_executions, 1);
    }

    #[tokio::test]
    async fn test_capability_mapping() {
        let ctx = create_test_context();
        let adapter = ExecutorAdapter::new(&ctx).unwrap();

        // Test various action type mappings
        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::FileSystem("fs.read.v1".to_string()))
                .unwrap(),
            "fs.read.v1"
        );

        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::Http("http.fetch.v1".to_string()))
                .unwrap(),
            "http.fetch.v1"
        );

        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::Research("research_type".to_string()))
                .unwrap(),
            "research.analyze.v1"
        );
    }

    #[tokio::test]
    async fn test_retry_logic() {
        let ctx = create_test_context();
        let adapter = ExecutorAdapter::new(&ctx).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test action".to_string(),
        );

        // Test should retry logic
        let retry_start = std::time::Instant::now();
        assert!(adapter.should_retry(&action, 1, &retry_start));
        assert!(adapter.should_retry(&action, 2, &retry_start));
        assert!(!adapter.should_retry(&action, 10, &retry_start)); // Exceeds max retries

        // Test retry delay calculation
        assert_eq!(adapter.calculate_retry_delay(1), 1000); // Base delay
        assert_eq!(adapter.calculate_retry_delay(2), 2000); // 2x base delay
        assert_eq!(adapter.calculate_retry_delay(3), 4000); // 4x base delay
    }

    #[tokio::test]
    async fn test_error_retry_ability() {
        let ctx = create_test_context();
        let adapter = ExecutorAdapter::new(&ctx).unwrap();

        // Test retryable errors
        let network_error = anyhow::anyhow!("Connection timeout");
        assert!(adapter.is_error_retryable(&network_error));

        let resource_error = anyhow::anyhow!("Resource limit exceeded");
        assert!(adapter.is_error_retryable(&resource_error));

        // Test non-retryable errors
        let validation_error = anyhow::anyhow!("Invalid parameter format");
        assert!(!adapter.is_error_retryable(&validation_error));
    }

    #[tokio::test]
    async fn test_capacity_management() {
        let ctx = create_test_context();
        let mut config = ExecutorAdapterConfig::default();
        config.max_parallel_executions = 2; // Limit to 2 parallel executions

        let mut adapter = ExecutorAdapter::with_config(&ctx, config).unwrap();

        // Initially should have capacity
        assert!(adapter.has_capacity());

        // Simulate active executions
        let action1 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Action 1".to_string(),
        );

        let action2 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Action 2".to_string(),
        );

        // Add to active executions manually for testing
        let now = chrono::Utc::now();
        adapter.tracker.active_executions.insert(
            "exec1".to_string(),
            ActiveExecution {
                action: action1,
                started_at: now,
                timeout_at: now + chrono::Duration::minutes(1),
                retry_attempt: 0,
                resource_usage: ResourceUsage::default(),
            },
        );

        adapter.tracker.active_executions.insert(
            "exec2".to_string(),
            ActiveExecution {
                action: action2,
                started_at: now,
                timeout_at: now + chrono::Duration::minutes(1),
                retry_attempt: 0,
                resource_usage: ResourceUsage::default(),
            },
        );

        // Should not have capacity now
        assert!(!adapter.has_capacity());

        // Test cancellation
        assert!(adapter.cancel_execution("exec1").await.unwrap());
        assert!(adapter.has_capacity());
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        let initial_stats = adapter.get_statistics();
        assert_eq!(initial_stats.total_executions, 0);
        assert_eq!(initial_stats.successful_executions, 0);
        assert_eq!(initial_stats.failed_executions, 0);

        // Create a sample result
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test action".to_string(),
        );

        let result = ActionResult {
            action_id: action.id.clone(),
            status: ActionStatus::Completed,
            output: Some(json!({"result": "success"})),
            error: None,
            metadata: ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage {
                    cpu_ms: 100,
                    memory_bytes: 1024,
                    fs_operations: 1,
                    network_requests: 0,
                },
                environment: ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "full".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now() - chrono::Duration::milliseconds(100),
            finished_at: chrono::Utc::now(),
        };

        adapter.update_statistics(&result);

        let updated_stats = adapter.get_statistics();
        assert_eq!(updated_stats.total_executions, 1);
        assert_eq!(updated_stats.successful_executions, 1);
        assert_eq!(updated_stats.failed_executions, 0);
        assert!(updated_stats.avg_execution_time_ms > 0.0);
    }

    // Additional tests for improved coverage

    #[test]
    fn test_executor_adapter_config_serialization() {
        let config = ExecutorAdapterConfig::default();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ExecutorAdapterConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(
            config.max_parallel_executions,
            deserialized.max_parallel_executions
        );
        assert_eq!(config.default_timeout_ms, deserialized.default_timeout_ms);
    }

    #[test]
    fn test_retry_config_serialization() {
        let config = RetryConfig::default();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RetryConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.base_delay_ms, deserialized.base_delay_ms);
        assert_eq!(config.backoff_multiplier, deserialized.backoff_multiplier);
    }

    #[test]
    fn test_output_config_serialization() {
        let config = OutputConfig::default();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: OutputConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.max_stdout_bytes, deserialized.max_stdout_bytes);
        assert_eq!(config.max_stderr_bytes, deserialized.max_stderr_bytes);
    }

    #[test]
    fn test_execution_tracker_serialization() {
        let tracker = ExecutionTracker::new();

        let json = serde_json::to_string(&tracker).unwrap();
        let deserialized: ExecutionTracker = serde_json::from_str(&json).unwrap();

        assert!(deserialized.active_executions.is_empty());
        assert!(deserialized.completed_executions.is_empty());
    }

    #[test]
    fn test_active_execution_serialization() {
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test".to_string(),
        );

        let now = chrono::Utc::now();
        let execution = ActiveExecution {
            action,
            started_at: now,
            timeout_at: now + chrono::Duration::minutes(1),
            retry_attempt: 0,
            resource_usage: ResourceUsage::default(),
        };

        let json = serde_json::to_string(&execution).unwrap();
        let deserialized: ActiveExecution = serde_json::from_str(&json).unwrap();

        assert_eq!(execution.retry_attempt, deserialized.retry_attempt);
    }

    #[test]
    fn test_execution_statistics_serialization() {
        let stats = ExecutionStatistics {
            total_executions: 100,
            successful_executions: 90,
            failed_executions: 10,
            retried_executions: 5,
            avg_execution_time_ms: 150.5,
            peak_memory_usage: 1024 * 1024,
            total_cpu_time_ms: 15000,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: ExecutionStatistics = serde_json::from_str(&json).unwrap();

        assert_eq!(stats.total_executions, deserialized.total_executions);
        assert_eq!(stats.failed_executions, deserialized.failed_executions);
    }

    #[tokio::test]
    async fn test_cancel_all_executions() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        let action1 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Action 1".to_string(),
        );

        let action2 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Action 2".to_string(),
        );

        // Add to active executions
        let now = chrono::Utc::now();
        adapter.tracker.active_executions.insert(
            "exec1".to_string(),
            ActiveExecution {
                action: action1,
                started_at: now,
                timeout_at: now + chrono::Duration::minutes(1),
                retry_attempt: 0,
                resource_usage: ResourceUsage::default(),
            },
        );

        adapter.tracker.active_executions.insert(
            "exec2".to_string(),
            ActiveExecution {
                action: action2,
                started_at: now,
                timeout_at: now + chrono::Duration::minutes(1),
                retry_attempt: 0,
                resource_usage: ResourceUsage::default(),
            },
        );

        assert_eq!(adapter.tracker.active_executions.len(), 2);

        let cancelled = adapter.cancel_all_executions().await.unwrap();
        assert_eq!(cancelled, 2);
        assert!(adapter.tracker.active_executions.is_empty());
        assert_eq!(adapter.tracker.completed_executions.len(), 2);
    }

    #[tokio::test]
    async fn test_reset() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        // Add some data
        adapter.tracker.statistics.total_executions = 10;
        adapter.tracker.statistics.successful_executions = 8;
        adapter.tracker.total_resource_usage.cpu_ms = 1000;

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test".to_string(),
        );
        adapter.tracker.completed_executions.push(ActionResult {
            action_id: action.id.clone(),
            status: ActionStatus::Completed,
            output: None,
            error: None,
            metadata: ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage::default(),
                environment: ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "full".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        });

        // Reset
        adapter.reset();

        assert_eq!(adapter.tracker.statistics.total_executions, 0);
        assert_eq!(adapter.tracker.total_resource_usage.cpu_ms, 0);
        assert!(adapter.tracker.completed_executions.is_empty());
    }

    #[tokio::test]
    async fn test_get_active_executions() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test".to_string(),
        );

        let now = chrono::Utc::now();
        adapter.tracker.active_executions.insert(
            "exec1".to_string(),
            ActiveExecution {
                action,
                started_at: now,
                timeout_at: now + chrono::Duration::minutes(1),
                retry_attempt: 0,
                resource_usage: ResourceUsage::default(),
            },
        );

        let active = adapter.get_active_executions();
        assert_eq!(active.len(), 1);
        assert!(active.contains_key("exec1"));
    }

    #[tokio::test]
    async fn test_get_completed_executions() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test".to_string(),
        );
        adapter.tracker.completed_executions.push(ActionResult {
            action_id: action.id.clone(),
            status: ActionStatus::Completed,
            output: None,
            error: None,
            metadata: ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage::default(),
                environment: ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "full".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        });

        let completed = adapter.get_completed_executions();
        assert_eq!(completed.len(), 1);
    }

    #[tokio::test]
    async fn test_get_total_resource_usage() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        adapter.tracker.total_resource_usage.cpu_ms = 500;
        adapter.tracker.total_resource_usage.memory_bytes = 2048;
        adapter.tracker.total_resource_usage.fs_operations = 10;

        let usage = adapter.get_total_resource_usage();
        assert_eq!(usage.cpu_ms, 500);
        assert_eq!(usage.memory_bytes, 2048);
        assert_eq!(usage.fs_operations, 10);
    }

    #[tokio::test]
    async fn test_capability_mapping_all_types() {
        let ctx = create_test_context();
        let adapter = ExecutorAdapter::new(&ctx).unwrap();

        // FileSystem
        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::FileSystem("fs.read.v1".to_string()))
                .unwrap(),
            "fs.read.v1"
        );

        // Http
        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::Http("http.fetch.v1".to_string()))
                .unwrap(),
            "http.fetch.v1"
        );

        // Shell
        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::Shell("shell.exec.v1".to_string()))
                .unwrap(),
            "shell.exec.v1"
        );

        // Research
        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::Research("topic".to_string()))
                .unwrap(),
            "research.analyze.v1"
        );

        // Planning
        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::Planning("plan".to_string()))
                .unwrap(),
            "planning.generate.v1"
        );

        // Analysis
        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::Analysis("analyze".to_string()))
                .unwrap(),
            "analysis.perform.v1"
        );

        // Custom
        assert_eq!(
            adapter
                .map_action_to_capability(&ActionType::Custom("custom.capability.v1".to_string()))
                .unwrap(),
            "custom.capability.v1"
        );
    }

    #[tokio::test]
    async fn test_is_error_retryable_all_cases() {
        let ctx = create_test_context();
        let adapter = ExecutorAdapter::new(&ctx).unwrap();

        // Connection errors - retryable
        assert!(adapter.is_error_retryable(&anyhow::anyhow!("Connection refused")));
        assert!(adapter.is_error_retryable(&anyhow::anyhow!("Connection reset")));

        // Timeout errors - retryable
        assert!(adapter.is_error_retryable(&anyhow::anyhow!("Connection timeout")));
        assert!(adapter.is_error_retryable(&anyhow::anyhow!("Request timeout")));

        // Network errors - retryable
        assert!(adapter.is_error_retryable(&anyhow::anyhow!("Network unreachable")));

        // Temporary unavailable - retryable
        assert!(adapter.is_error_retryable(&anyhow::anyhow!("Resource temporarily unavailable")));
        assert!(adapter.is_error_retryable(&anyhow::anyhow!("Device busy")));

        // Resource limit - retryable
        assert!(adapter.is_error_retryable(&anyhow::anyhow!("Resource limit exceeded")));

        // Permission errors - not retryable
        assert!(!adapter.is_error_retryable(&anyhow::anyhow!("Permission denied")));

        // Validation errors - not retryable
        assert!(!adapter.is_error_retryable(&anyhow::anyhow!("Invalid argument")));

        // Not found errors - not retryable
        assert!(!adapter.is_error_retryable(&anyhow::anyhow!("File not found")));
    }

    #[tokio::test]
    async fn test_cancel_execution_not_found() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        let result = adapter.cancel_execution("nonexistent").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_update_statistics_failed() {
        let ctx = create_test_context();
        let mut adapter = ExecutorAdapter::new(&ctx).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test".to_string(),
        );

        let result = ActionResult {
            action_id: action.id.clone(),
            status: ActionStatus::Failed,
            output: None,
            error: Some(ActionError {
                code: "ERROR".to_string(),
                message: "Failed".to_string(),
                details: None,
                retryable: false,
            }),
            metadata: ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage {
                    cpu_ms: 50,
                    memory_bytes: 512,
                    fs_operations: 0,
                    network_requests: 0,
                },
                environment: ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "full".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now() - chrono::Duration::milliseconds(50),
            finished_at: chrono::Utc::now(),
        };

        adapter.update_statistics(&result);

        let stats = adapter.get_statistics();
        assert_eq!(stats.total_executions, 1);
        assert_eq!(stats.successful_executions, 0);
        assert_eq!(stats.failed_executions, 1);
    }

    #[tokio::test]
    async fn test_with_custom_config() {
        let ctx = create_test_context();
        let config = ExecutorAdapterConfig {
            max_parallel_executions: 10,
            default_timeout_ms: 60000,
            track_resources: false,
            retry_config: RetryConfig {
                enabled: false,
                base_delay_ms: 500,
                max_delay_ms: 10000,
                backoff_multiplier: 1.5,
                max_total_time_ms: 60000,
            },
            output_config: OutputConfig::default(),
        };

        let adapter = ExecutorAdapter::with_config(&ctx, config).unwrap();
        assert_eq!(adapter.config.max_parallel_executions, 10);
        assert_eq!(adapter.config.default_timeout_ms, 60000);
        assert!(!adapter.config.retry_config.enabled);
    }

    #[test]
    fn test_retry_config_custom_values() {
        let config = RetryConfig {
            enabled: false,
            base_delay_ms: 500,
            max_delay_ms: 10000,
            backoff_multiplier: 1.5,
            max_total_time_ms: 60000,
        };

        assert!(!config.enabled);
        assert_eq!(config.base_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 10000);
        assert_eq!(config.backoff_multiplier, 1.5);
    }

    #[test]
    fn test_output_config_custom_values() {
        let config = OutputConfig {
            max_stdout_bytes: 512 * 1024,
            max_stderr_bytes: 128 * 1024,
            capture_logs: false,
            max_log_entries: 500,
        };

        assert_eq!(config.max_stdout_bytes, 512 * 1024);
        assert!(!config.capture_logs);
    }

    #[test]
    fn test_execution_statistics_default() {
        let stats = ExecutionStatistics::default();

        assert_eq!(stats.total_executions, 0);
        assert_eq!(stats.successful_executions, 0);
        assert_eq!(stats.failed_executions, 0);
        assert_eq!(stats.retried_executions, 0);
        assert_eq!(stats.avg_execution_time_ms, 0.0);
        assert_eq!(stats.peak_memory_usage, 0);
        assert_eq!(stats.total_cpu_time_ms, 0);
    }

    #[tokio::test]
    async fn test_should_retry_disabled() {
        let ctx = create_test_context();
        let mut config = ExecutorAdapterConfig::default();
        config.retry_config.enabled = false;

        let adapter = ExecutorAdapter::with_config(&ctx, config).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test".to_string(),
        );

        let retry_start = std::time::Instant::now();
        assert!(!adapter.should_retry(&action, 1, &retry_start));
    }

    #[tokio::test]
    async fn test_calculate_retry_delay_capped() {
        let ctx = create_test_context();
        let mut config = ExecutorAdapterConfig::default();
        config.retry_config.max_delay_ms = 5000;

        let adapter = ExecutorAdapter::with_config(&ctx, config).unwrap();

        // Large retry attempt should be capped at max_delay
        let delay = adapter.calculate_retry_delay(10);
        assert!(delay <= 5000);
    }
}
