/*!
# Executor Adapter - Parallel Execution Engine

The Executor Adapter provides sophisticated parallel execution capabilities with:

- **Parallel Execution**: Smart parallelization of independent operations
- **Resource Management**: Dynamic resource allocation and monitoring
- **Result Aggregation**: Intelligent collection and synthesis of execution results
- **Error Handling**: Comprehensive failure recovery and retry mechanisms
- **Performance Monitoring**: Real-time execution metrics and optimization

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Executor Adapter                            │
├─────────────────────────────────────────────────────────────────┤
│  Parallel Execution Engine                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ Dependency  │  │   Task      │  │ Execution   │           │
│  │  Analysis   │  │ Scheduler   │  │  Monitor    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Resource Management                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Resource   │  │   Quota     │  │  Dynamic    │           │
│  │ Allocation  │  │ Management  │  │ Scaling     │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Result Aggregation                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Result    │  │    Data     │  │  Progress   │           │
│  │ Collection  │  │ Synthesis   │  │ Tracking    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Error Handling & Recovery                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Failure   │  │   Retry     │  │  Rollback   │           │
│  │ Detection   │  │  Strategy   │  │ Management  │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Execution Strategies

- **Independent Parallel**: Execute unrelated operations simultaneously
- **Pipeline Parallel**: Execute dependent operations in sequence with parallelism
- **Resource-Aware**: Balance parallelism with available system resources
- **Failure-Tolerant**: Continue execution despite individual operation failures

## Usage

```text
let adapter = ExecutorAdapter::new(&execution_config).await?;
let result = adapter.execute_plan(&execution_plan).await?;

match result.success {
    true => println!("Plan executed successfully: {} operations", result.completed_operations),
    false => println!("Execution failed: {}", result.error_message),
}
```
*/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::planner::oracle::{ExecutionPlan, PlanStep};
use crate::planner::{ExecutionConfig, ResourceLimits, RetryPolicy};
use crate::runners::{ExecContext, MemoryOutputSink, RunnerRegistry, Scope};
use smith_protocol::ExecutionLimits;
use smith_protocol::ExecutionStatus as RunnerExecutionStatus;

/// Executor adapter for parallel execution
#[derive(Clone)]
pub struct ExecutorAdapter {
    config: ExecutionConfig,
    parallel_execution: Arc<ParallelExecution>,
    resource_manager: Arc<ResourceManager>,
    result_aggregator: Arc<ResultAggregator>,
    execution_history: Arc<RwLock<HashMap<Uuid, ExecutionRecord>>>,
    performance_metrics: Arc<RwLock<ExecutionMetrics>>,
    runner_registry: Arc<RunnerRegistry>,
}

/// Parallel execution engine
#[derive(Clone)]
pub struct ParallelExecution {
    task_scheduler: Arc<TaskScheduler>,
    dependency_analyzer: Arc<DependencyAnalyzer>,
    execution_monitor: Arc<ExecutionMonitor>,
    concurrency_limiter: Arc<Semaphore>,
}

/// Resource management system
#[derive(Clone)]
pub struct ResourceManager {
    resource_allocator: Arc<ResourceAllocator>,
    quota_manager: Arc<QuotaManager>,
    scaling_controller: Arc<ScalingController>,
    resource_monitor: Arc<ResourceMonitor>,
}

/// Result aggregation system
#[derive(Clone)]
pub struct ResultAggregator {
    result_collector: Arc<ResultCollector>,
    data_synthesizer: Arc<DataSynthesizer>,
    progress_tracker: Arc<ProgressTracker>,
}

/// Execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub execution_id: Uuid,
    pub plan_id: Uuid,
    pub success: bool,
    pub completed_operations: u32,
    pub failed_operations: u32,
    pub total_operations: u32,
    pub execution_time_ms: u64,
    pub resource_usage: ResourceUsage,
    pub step_results: Vec<StepResult>,
    pub error_message: String,
    pub retryable: bool,
    pub attempt_count: u32,
    pub output: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

/// Individual step execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: Uuid,
    pub step_name: String,
    pub success: bool,
    pub execution_time_ms: u64,
    pub resource_usage: ResourceUsage,
    pub output: String,
    pub error_message: Option<String>,
    pub retry_count: u32,
    pub parallel_group: Option<String>,
    pub dependencies_satisfied: bool,
}

/// Resource usage tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_cores_used: f32,
    pub memory_mb_used: u64,
    pub disk_mb_used: u64,
    pub network_mbps_used: f32,
    pub peak_memory_mb: u64,
    pub total_cpu_time_ms: u64,
}

/// Execution record for history tracking
#[derive(Debug, Clone)]
struct ExecutionRecord {
    execution_id: Uuid,
    plan_id: Uuid,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    status: ExecutionStatus,
    step_statuses: HashMap<Uuid, StepStatus>,
    resource_allocation: ResourceAllocation,
}

/// Execution status
#[derive(Debug, Clone)]
enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Step execution status
#[derive(Debug, Clone)]
struct StepStatus {
    step_id: Uuid,
    status: ExecutionStatus,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    retry_count: u32,
    error_message: Option<String>,
    dependencies: Vec<Uuid>,
    dependents: Vec<Uuid>,
}

/// Resource allocation
#[derive(Debug, Clone, Default)]
struct ResourceAllocation {
    allocated_cpu_cores: f32,
    allocated_memory_mb: u64,
    allocated_disk_mb: u64,
    allocated_network_mbps: f32,
    allocation_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Execution metrics
#[derive(Debug, Clone, Default)]
struct ExecutionMetrics {
    total_executions: u64,
    successful_executions: u64,
    failed_executions: u64,
    average_execution_time_ms: f64,
    total_resource_usage: ResourceUsage,
    concurrency_metrics: ConcurrencyMetrics,
}

/// Concurrency metrics
#[derive(Debug, Clone, Default)]
struct ConcurrencyMetrics {
    max_concurrent_steps: u32,
    average_concurrent_steps: f32,
    total_parallel_groups: u32,
    parallelization_efficiency: f32,
}

/// Task scheduler
struct TaskScheduler {
    ready_queue: Arc<RwLock<Vec<ScheduledTask>>>,
    running_tasks: Arc<RwLock<HashMap<Uuid, RunningTask>>>,
    completed_tasks: Arc<RwLock<HashMap<Uuid, CompletedTask>>>,
}

/// Scheduled task
#[derive(Debug, Clone)]
struct ScheduledTask {
    task_id: Uuid,
    step: PlanStep,
    priority: TaskPriority,
    dependencies: Vec<Uuid>,
    estimated_resources: ResourceRequirement,
    scheduled_at: chrono::DateTime<chrono::Utc>,
}

/// Running task
#[derive(Debug, Clone)]
struct RunningTask {
    task_id: Uuid,
    step: PlanStep,
    started_at: chrono::DateTime<chrono::Utc>,
    allocated_resources: ResourceAllocation,
    progress: f32,
}

/// Completed task
#[derive(Debug, Clone)]
struct CompletedTask {
    task_id: Uuid,
    step: PlanStep,
    result: StepResult,
    completed_at: chrono::DateTime<chrono::Utc>,
}

/// Task priority
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TaskPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Resource requirement
#[derive(Debug, Clone, Default)]
struct ResourceRequirement {
    cpu_cores: f32,
    memory_mb: u64,
    disk_mb: u64,
    network_mbps: f32,
    duration_estimate_ms: u64,
}

/// Dependency analyzer
struct DependencyAnalyzer {
    dependency_graph: Arc<RwLock<DependencyGraph>>,
}

/// Dependency graph
#[derive(Debug, Clone, Default)]
struct DependencyGraph {
    nodes: HashMap<Uuid, DependencyNode>,
    edges: HashMap<Uuid, Vec<Uuid>>,
    reverse_edges: HashMap<Uuid, Vec<Uuid>>,
}

/// Dependency node
#[derive(Debug, Clone)]
struct DependencyNode {
    step_id: Uuid,
    step_name: String,
    status: ExecutionStatus,
    dependencies_satisfied: bool,
    parallel_group: Option<String>,
}

/// Execution monitor
struct ExecutionMonitor {
    active_executions: Arc<RwLock<HashMap<Uuid, ExecutionMonitorState>>>,
    performance_tracker: Arc<PerformanceTracker>,
}

/// Execution monitor state
#[derive(Debug, Clone)]
struct ExecutionMonitorState {
    execution_id: Uuid,
    started_at: Instant,
    step_monitors: HashMap<Uuid, StepMonitor>,
    resource_snapshots: Vec<ResourceSnapshot>,
}

/// Step monitor
#[derive(Debug, Clone)]
struct StepMonitor {
    step_id: Uuid,
    started_at: Instant,
    last_heartbeat: Instant,
    progress: f32,
    resource_usage: ResourceUsage,
}

/// Resource snapshot
#[derive(Debug, Clone)]
struct ResourceSnapshot {
    timestamp: Instant,
    cpu_usage: f32,
    memory_usage: u64,
    disk_usage: u64,
    network_usage: f32,
}

/// Performance tracker
struct PerformanceTracker {
    execution_history: Arc<RwLock<Vec<ExecutionPerformance>>>,
    optimization_suggestions: Arc<RwLock<Vec<OptimizationSuggestion>>>,
}

/// Execution performance record
#[derive(Debug, Clone)]
struct ExecutionPerformance {
    execution_id: Uuid,
    total_duration_ms: u64,
    parallelization_factor: f32,
    resource_efficiency: f32,
    bottlenecks: Vec<PerformanceBottleneck>,
}

/// Performance bottleneck
#[derive(Debug, Clone)]
struct PerformanceBottleneck {
    step_id: Uuid,
    bottleneck_type: BottleneckType,
    severity: f32,
    recommendation: String,
}

/// Bottleneck type
#[derive(Debug, Clone)]
enum BottleneckType {
    CpuBound,
    MemoryBound,
    DiskBound,
    NetworkBound,
    DependencyWait,
    ResourceContention,
}

/// Optimization suggestion
#[derive(Debug, Clone)]
struct OptimizationSuggestion {
    suggestion_id: Uuid,
    suggestion_type: OptimizationType,
    description: String,
    estimated_improvement: f32,
    implementation_effort: ImplementationEffort,
}

/// Optimization type
#[derive(Debug, Clone)]
enum OptimizationType {
    IncreaseParallelism,
    OptimizeResourceAllocation,
    CachingStrategy,
    DependencyOptimization,
    BatchProcessing,
}

/// Implementation effort
#[derive(Debug, Clone)]
enum ImplementationEffort {
    Low,
    Medium,
    High,
}

// Resource management components
struct ResourceAllocator {
    available_resources: Arc<RwLock<AvailableResources>>,
    allocation_history: Arc<RwLock<Vec<AllocationRecord>>>,
}

struct QuotaManager {
    quotas: Arc<RwLock<HashMap<String, ResourceQuota>>>,
    usage_tracking: Arc<RwLock<HashMap<String, ResourceUsage>>>,
}

struct ScalingController {
    scaling_policies: Arc<RwLock<Vec<ScalingPolicy>>>,
    scaling_history: Arc<RwLock<Vec<ScalingEvent>>>,
}

struct ResourceMonitor {
    monitoring_interval: Duration,
    resource_alerts: Arc<RwLock<Vec<ResourceAlert>>>,
}

#[derive(Debug, Clone, Default)]
struct AvailableResources {
    total_cpu_cores: f32,
    available_cpu_cores: f32,
    total_memory_mb: u64,
    available_memory_mb: u64,
    total_disk_mb: u64,
    available_disk_mb: u64,
    total_network_mbps: f32,
    available_network_mbps: f32,
}

#[derive(Debug, Clone)]
struct AllocationRecord {
    allocation_id: Uuid,
    execution_id: Uuid,
    allocated_resources: ResourceAllocation,
    allocated_at: chrono::DateTime<chrono::Utc>,
    released_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
struct ResourceQuota {
    quota_name: String,
    max_cpu_cores: f32,
    max_memory_mb: u64,
    max_disk_mb: u64,
    max_network_mbps: f32,
    max_concurrent_executions: u32,
}

#[derive(Debug, Clone)]
struct ScalingPolicy {
    policy_name: String,
    trigger_conditions: Vec<ScalingTrigger>,
    scaling_action: ScalingAction,
    cooldown_period: Duration,
}

#[derive(Debug, Clone)]
struct ScalingTrigger {
    metric: String,
    threshold: f32,
    duration: Duration,
}

#[derive(Debug, Clone)]
struct ScalingAction {
    action_type: ScalingActionType,
    magnitude: f32,
}

#[derive(Debug, Clone)]
enum ScalingActionType {
    ScaleUp,
    ScaleDown,
    AddResources,
    RemoveResources,
}

#[derive(Debug, Clone)]
struct ScalingEvent {
    event_id: Uuid,
    policy_name: String,
    trigger: ScalingTrigger,
    action: ScalingAction,
    occurred_at: chrono::DateTime<chrono::Utc>,
    success: bool,
}

#[derive(Debug, Clone)]
struct ResourceAlert {
    alert_id: Uuid,
    alert_type: ResourceAlertType,
    severity: AlertSeverity,
    description: String,
    triggered_at: chrono::DateTime<chrono::Utc>,
    resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
enum ResourceAlertType {
    HighCpuUsage,
    HighMemoryUsage,
    HighDiskUsage,
    HighNetworkUsage,
    ResourceExhaustion,
    AllocationFailure,
}

#[derive(Debug, Clone)]
enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

// Result aggregation components
struct ResultCollector {
    collection_strategies: HashMap<String, CollectionStrategy>,
    partial_results: Arc<RwLock<HashMap<Uuid, PartialResult>>>,
}

struct DataSynthesizer {
    synthesis_rules: Vec<SynthesisRule>,
    output_formatters: HashMap<String, OutputFormatter>,
}

struct ProgressTracker {
    progress_reports: Arc<RwLock<HashMap<Uuid, ProgressReport>>>,
    milestone_tracker: Arc<RwLock<HashMap<Uuid, Vec<Milestone>>>>,
}

#[derive(Debug, Clone)]
enum CollectionStrategy {
    WaitForAll,
    WaitForMajority,
    BestEffort,
    FirstSuccess,
}

#[derive(Debug, Clone)]
struct PartialResult {
    step_id: Uuid,
    step_name: String,
    status: ExecutionStatus,
    output: String,
    progress: f32,
    collected_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
struct SynthesisRule {
    rule_name: String,
    input_patterns: Vec<String>,
    synthesis_function: String,
    output_format: String,
}

#[derive(Debug, Clone)]
struct OutputFormatter {
    format_name: String,
    template: String,
    validation_rules: Vec<String>,
}

#[derive(Debug, Clone)]
struct ProgressReport {
    execution_id: Uuid,
    overall_progress: f32,
    step_progress: HashMap<Uuid, f32>,
    estimated_completion: chrono::DateTime<chrono::Utc>,
    blockers: Vec<String>,
}

#[derive(Debug, Clone)]
struct Milestone {
    milestone_id: Uuid,
    name: String,
    description: String,
    target_completion: chrono::DateTime<chrono::Utc>,
    actual_completion: Option<chrono::DateTime<chrono::Utc>>,
    dependencies: Vec<Uuid>,
}

impl ExecutorAdapter {
    /// Create new executor adapter
    pub async fn new(config: &ExecutionConfig) -> Result<Self> {
        info!("Initializing Executor Adapter");

        let concurrency_limit = config.max_concurrent_workflows as usize;
        let parallel_execution = Arc::new(ParallelExecution::new(concurrency_limit).await?);
        let resource_manager = Arc::new(ResourceManager::new(&config.resource_limits).await?);
        let result_aggregator = Arc::new(ResultAggregator::new().await?);
        let execution_history = Arc::new(RwLock::new(HashMap::new()));
        let performance_metrics = Arc::new(RwLock::new(ExecutionMetrics::default()));
        let runner_registry = Arc::new(RunnerRegistry::new(None));

        info!("Executor Adapter initialized successfully");

        Ok(Self {
            config: config.clone(),
            parallel_execution,
            resource_manager,
            result_aggregator,
            execution_history,
            performance_metrics,
            runner_registry,
        })
    }

    /// Execute plan with parallel operations
    #[instrument(skip(self, plan), fields(plan_id = %plan.plan_id))]
    pub async fn execute_plan(&self, plan: &ExecutionPlan) -> Result<ExecutionResult> {
        info!(plan_id = %plan.plan_id, "Starting plan execution");

        let execution_id = Uuid::new_v4();
        let start_time = Instant::now();

        // Create execution record
        let execution_record = ExecutionRecord {
            execution_id,
            plan_id: plan.plan_id,
            started_at: chrono::Utc::now(),
            completed_at: None,
            status: ExecutionStatus::Running,
            step_statuses: HashMap::new(),
            resource_allocation: ResourceAllocation::default(),
        };

        self.execution_history
            .write()
            .await
            .insert(execution_id, execution_record);

        // Allocate resources for the plan
        let resource_allocation = self
            .resource_manager
            .allocate_resources(execution_id, &plan.resource_requirements)
            .await?;

        // Analyze dependencies and create execution graph
        let dependency_graph = self
            .parallel_execution
            .dependency_analyzer
            .analyze_plan_dependencies(plan)
            .await?;

        // Schedule and execute steps
        let execution_result = self
            .execute_steps_with_parallelism(
                execution_id,
                plan,
                dependency_graph,
                resource_allocation,
            )
            .await;

        // Release resources
        self.resource_manager
            .release_resources(execution_id)
            .await?;

        // Complete execution record
        let mut history = self.execution_history.write().await;
        if let Some(record) = history.get_mut(&execution_id) {
            record.completed_at = Some(chrono::Utc::now());
            record.status = if execution_result
                .as_ref()
                .map(|r| r.success)
                .unwrap_or(false)
            {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Failed
            };
        }

        let elapsed = start_time.elapsed();
        let result = execution_result?;

        info!(
            plan_id = %plan.plan_id,
            execution_id = %execution_id,
            success = result.success,
            duration_ms = elapsed.as_millis(),
            "Plan execution completed"
        );

        // Update performance metrics
        self.update_performance_metrics(&result).await;

        Ok(result)
    }

    /// Execute steps with intelligent parallelism
    async fn execute_steps_with_parallelism(
        &self,
        execution_id: Uuid,
        plan: &ExecutionPlan,
        dependency_graph: DependencyGraph,
        _resource_allocation: ResourceAllocation,
    ) -> Result<ExecutionResult> {
        let mut step_results = Vec::new();
        let mut resource_usage = ResourceUsage::default();
        let start_time = Instant::now();

        // Group steps by parallel execution groups
        let parallel_groups = self.group_steps_by_parallelism(&plan.steps);

        let mut completed_operations = 0;
        let mut failed_operations = 0;
        let mut error_messages = Vec::new();

        // Execute each parallel group
        for group in parallel_groups {
            let group_size = group.len() as u32;
            match self
                .execute_parallel_group(execution_id, group, &dependency_graph)
                .await
            {
                Ok(group_results) => {
                    for result in group_results {
                        if result.success {
                            completed_operations += 1;
                        } else {
                            failed_operations += 1;
                            if let Some(error) = &result.error_message {
                                error_messages.push(error.clone());
                            }
                        }

                        // Aggregate resource usage
                        resource_usage.cpu_cores_used += result.resource_usage.cpu_cores_used;
                        resource_usage.memory_mb_used += result.resource_usage.memory_mb_used;
                        resource_usage.disk_mb_used += result.resource_usage.disk_mb_used;
                        resource_usage.network_mbps_used += result.resource_usage.network_mbps_used;
                        resource_usage.total_cpu_time_ms += result.resource_usage.total_cpu_time_ms;

                        if result.resource_usage.peak_memory_mb > resource_usage.peak_memory_mb {
                            resource_usage.peak_memory_mb = result.resource_usage.peak_memory_mb;
                        }

                        step_results.push(result);
                    }
                }
                Err(e) => {
                    error!(error = %e, "Parallel group execution failed");
                    failed_operations += group_size;
                    error_messages.push(e.to_string());
                }
            }

            // Stop execution if critical failures occurred
            if failed_operations > 0 && self.should_stop_on_failure(&plan.steps, failed_operations)
            {
                warn!("Stopping execution due to critical failures");
                break;
            }
        }

        let total_operations = plan.steps.len() as u32;
        let success = failed_operations == 0;
        let execution_time_ms = start_time.elapsed().as_millis().max(1) as u64;

        let error_message = if error_messages.is_empty() {
            String::new()
        } else {
            error_messages.join("; ")
        };

        // Synthesize output before moving step_results
        let output = self.synthesize_execution_output(&step_results).await;

        Ok(ExecutionResult {
            execution_id,
            plan_id: plan.plan_id,
            success,
            completed_operations,
            failed_operations,
            total_operations,
            execution_time_ms,
            resource_usage,
            step_results,
            error_message,
            retryable: failed_operations < total_operations / 2, // Retryable if < 50% failed
            attempt_count: 1,
            output,
            metadata: HashMap::new(),
            completed_at: chrono::Utc::now(),
        })
    }

    /// Group steps by parallel execution capability
    fn group_steps_by_parallelism(&self, steps: &[PlanStep]) -> Vec<Vec<PlanStep>> {
        let mut groups = Vec::new();
        let mut parallel_groups: HashMap<String, Vec<PlanStep>> = HashMap::new();
        let mut sequential_steps = Vec::new();

        for step in steps {
            if let Some(group_name) = &step.parallel_group {
                parallel_groups
                    .entry(group_name.clone())
                    .or_insert_with(Vec::new)
                    .push(step.clone());
            } else {
                sequential_steps.push(step.clone());
            }
        }

        // Add parallel groups
        for (_, group_steps) in parallel_groups {
            groups.push(group_steps);
        }

        // Add sequential steps as individual groups
        for step in sequential_steps {
            groups.push(vec![step]);
        }

        // Sort groups by sequence number of their first step
        groups.sort_by_key(|group| group.iter().map(|s| s.sequence).min().unwrap_or(0));

        groups
    }

    /// Execute a parallel group of steps
    async fn execute_parallel_group(
        &self,
        execution_id: Uuid,
        steps: Vec<PlanStep>,
        _dependency_graph: &DependencyGraph,
    ) -> Result<Vec<StepResult>> {
        debug!(execution_id = %execution_id, steps = steps.len(), "Executing parallel group");

        let semaphore = Arc::new(Semaphore::new(
            steps
                .len()
                .min(self.config.max_concurrent_workflows as usize),
        ));
        let mut handles = Vec::new();

        for step in steps {
            let step_semaphore = semaphore.clone();
            let adapter = self.clone();

            let handle = tokio::spawn(async move {
                let _permit = step_semaphore.acquire().await.unwrap();
                adapter.execute_single_step(execution_id, step).await
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result?),
                Err(e) => {
                    error!(error = %e, "Step execution task failed");
                    return Err(anyhow::anyhow!("Parallel execution failed: {}", e));
                }
            }
        }

        Ok(results)
    }

    /// Execute a single step
    async fn execute_single_step(&self, execution_id: Uuid, step: PlanStep) -> Result<StepResult> {
        debug!(
            execution_id = %execution_id,
            step_id = %step.step_id,
            capability = %step.capability,
            "Executing step"
        );

        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(step.expected_duration_minutes as u64 * 60);

        // Execute step with timeout and retry logic
        let mut retry_count = 0;
        let mut last_error = None;

        while retry_count <= self.config.retry_policy.max_retries {
            match timeout(timeout_duration, self.perform_step_execution(&step)).await {
                Ok(Ok(output)) => {
                    let execution_time_ms = start_time.elapsed().as_millis().max(1) as u64;

                    return Ok(StepResult {
                        step_id: step.step_id,
                        step_name: step.description.clone(),
                        success: true,
                        execution_time_ms,
                        resource_usage: Self::estimate_resource_usage(&step, execution_time_ms),
                        output,
                        error_message: None,
                        retry_count,
                        parallel_group: step.parallel_group.clone(),
                        dependencies_satisfied: true, // Simplified for this implementation
                    });
                }
                Ok(Err(e)) => {
                    warn!(
                        step_id = %step.step_id,
                        retry_count = retry_count,
                        error = %e,
                        "Step execution failed"
                    );
                    last_error = Some(e);
                }
                Err(_) => {
                    warn!(
                        step_id = %step.step_id,
                        retry_count = retry_count,
                        "Step execution timed out"
                    );
                    last_error = Some(anyhow::anyhow!("Step execution timed out"));
                }
            }

            retry_count += 1;

            // Apply backoff delay
            if retry_count <= self.config.retry_policy.max_retries {
                let backoff_ms = self.config.retry_policy.initial_backoff_ms
                    * (self
                        .config
                        .retry_policy
                        .backoff_multiplier
                        .powi(retry_count as i32 - 1) as u64);
                let backoff_duration =
                    Duration::from_millis(backoff_ms.min(self.config.retry_policy.max_backoff_ms));

                debug!(
                    step_id = %step.step_id,
                    backoff_ms = backoff_duration.as_millis(),
                    "Applying retry backoff"
                );

                tokio::time::sleep(backoff_duration).await;
            }
        }

        let execution_time_ms = start_time.elapsed().as_millis().max(1) as u64;
        let error_message = last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Unknown error".to_string());

        Ok(StepResult {
            step_id: step.step_id,
            step_name: step.description.clone(),
            success: false,
            execution_time_ms,
            resource_usage: Self::estimate_resource_usage(&step, execution_time_ms),
            output: String::new(),
            error_message: Some(error_message),
            retry_count,
            parallel_group: step.parallel_group.clone(),
            dependencies_satisfied: true,
        })
    }

    /// Map planner capability identifiers onto registered runners.
    fn normalize_capability(capability: &str) -> String {
        match capability {
            "analysis.system" => "analysis.system.v1".to_string(),
            other => other.to_string(),
        }
    }

    fn step_params_to_value(step: &PlanStep) -> serde_json::Value {
        let mut map = serde_json::Map::with_capacity(step.parameters.len());
        for (key, value) in &step.parameters {
            map.insert(key.clone(), value.clone());
        }
        serde_json::Value::Object(map)
    }

    fn build_execution_context(&self, step: &PlanStep) -> Result<ExecContext> {
        let workspace_root = env::current_dir().context("Failed to determine workspace root")?;
        let scope = Scope {
            paths: vec![workspace_root.to_string_lossy().to_string()],
            urls: Vec::new(),
        };

        Ok(ExecContext {
            workdir: workspace_root,
            limits: Self::default_execution_limits(),
            scope,
            creds: None,
            netns: None,
            trace_id: format!("planner-step-{}", step.step_id),
            session: None,
        })
    }

    fn default_execution_limits() -> ExecutionLimits {
        ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 256 * 1024 * 1024,
            io_bytes: 10 * 1024 * 1024,
            pids_max: 32,
            timeout_ms: 300_000,
        }
    }

    /// Perform the actual step execution using the registered runner
    async fn perform_step_execution(&self, step: &PlanStep) -> Result<String> {
        debug!(
            step_id = %step.step_id,
            capability = %step.capability,
            "Performing step execution"
        );

        let capability = Self::normalize_capability(&step.capability);
        let runner = self
            .runner_registry
            .get_runner(&capability)
            .ok_or_else(|| {
                anyhow::anyhow!("No runner registered for capability: {}", capability)
            })?;

        let params = Self::step_params_to_value(step);
        runner
            .validate_params(&params)
            .context("Capability parameter validation failed")?;

        let exec_context = self
            .build_execution_context(step)
            .context("Unable to create execution context")?;

        let mut output_sink = MemoryOutputSink::new();
        let execution_result = runner
            .execute(&exec_context, params, &mut output_sink)
            .await
            .context("Capability execution failed")?;

        if execution_result.status != RunnerExecutionStatus::Success
            && execution_result.status != RunnerExecutionStatus::Ok
        {
            return Err(anyhow::anyhow!(
                "Capability '{}' returned non-success status: {:?}",
                capability,
                execution_result.status
            ));
        }

        let mut output = String::from_utf8_lossy(&output_sink.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output_sink.stderr);
        if !stderr.trim().is_empty() {
            output.push_str("\n[stderr]\n");
            output.push_str(stderr.trim());
        }

        Ok(output.trim().to_string())
    }

    /// Estimate resource usage for a step
    fn estimate_resource_usage(step: &PlanStep, execution_time_ms: u64) -> ResourceUsage {
        // Simple resource estimation based on step characteristics
        let base_cpu = 0.5;
        let base_memory = 64; // MB
        let base_disk = 10; // MB
        let base_network = 1.0; // Mbps

        // Scale based on execution time and capability
        let time_factor = (execution_time_ms as f32 / 1000.0).max(1.0);
        let complexity_factor = match step.capability.as_str() {
            "analysis.system.v1" => 1.5,
            "implementation.execute.v1" => 2.0,
            "validation.test.v1" => 1.2,
            _ => 1.0,
        };

        ResourceUsage {
            cpu_cores_used: base_cpu * complexity_factor,
            memory_mb_used: (base_memory as f32 * complexity_factor) as u64,
            disk_mb_used: (base_disk as f32 * complexity_factor) as u64,
            network_mbps_used: base_network * complexity_factor,
            peak_memory_mb: ((base_memory as f32 * complexity_factor) * 1.2) as u64,
            total_cpu_time_ms: (execution_time_ms as f32 * base_cpu * complexity_factor) as u64,
        }
    }

    /// Determine if execution should stop on failure
    fn should_stop_on_failure(&self, steps: &[PlanStep], failed_operations: u32) -> bool {
        // Check if any critical steps failed
        let critical_steps = steps
            .iter()
            .filter(|s| s.failure_recovery.is_none() || s.capability.contains("validation"))
            .count();

        // Stop if more than 25% of operations failed or any critical step failed
        failed_operations as f32 / steps.len() as f32 > 0.25
            || (critical_steps > 0 && failed_operations > 0)
    }

    /// Synthesize execution output from step results
    async fn synthesize_execution_output(&self, step_results: &[StepResult]) -> String {
        let successful_steps = step_results.iter().filter(|r| r.success).count();
        let total_steps = step_results.len();

        if successful_steps == total_steps {
            format!("All {} steps completed successfully", total_steps)
        } else {
            let failed_steps = total_steps - successful_steps;
            format!(
                "{} of {} steps completed successfully, {} failed",
                successful_steps, total_steps, failed_steps
            )
        }
    }

    /// Update performance metrics
    async fn update_performance_metrics(&self, result: &ExecutionResult) {
        let mut metrics = self.performance_metrics.write().await;

        metrics.total_executions += 1;

        if result.success {
            metrics.successful_executions += 1;
        } else {
            metrics.failed_executions += 1;
        }

        // Update average execution time
        let current_avg = metrics.average_execution_time_ms;
        let new_avg = (current_avg * (metrics.total_executions - 1) as f64
            + result.execution_time_ms as f64)
            / metrics.total_executions as f64;
        metrics.average_execution_time_ms = new_avg;

        // Update resource usage
        metrics.total_resource_usage.cpu_cores_used += result.resource_usage.cpu_cores_used;
        metrics.total_resource_usage.memory_mb_used += result.resource_usage.memory_mb_used;
        metrics.total_resource_usage.disk_mb_used += result.resource_usage.disk_mb_used;
        metrics.total_resource_usage.network_mbps_used += result.resource_usage.network_mbps_used;
        metrics.total_resource_usage.total_cpu_time_ms += result.resource_usage.total_cpu_time_ms;

        if result.resource_usage.peak_memory_mb > metrics.total_resource_usage.peak_memory_mb {
            metrics.total_resource_usage.peak_memory_mb = result.resource_usage.peak_memory_mb;
        }

        // Update concurrency metrics
        let concurrent_steps = result
            .step_results
            .iter()
            .filter_map(|r| r.parallel_group.as_ref())
            .collect::<HashSet<_>>()
            .len() as u32;

        if concurrent_steps > metrics.concurrency_metrics.max_concurrent_steps {
            metrics.concurrency_metrics.max_concurrent_steps = concurrent_steps;
        }

        let avg_concurrent = (metrics.concurrency_metrics.average_concurrent_steps
            * (metrics.total_executions - 1) as f32
            + concurrent_steps as f32)
            / metrics.total_executions as f32;
        metrics.concurrency_metrics.average_concurrent_steps = avg_concurrent;
    }

    /// Get execution history
    pub async fn get_execution_history(&self) -> Vec<ExecutionRecord> {
        self.execution_history
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Export performance metrics
    pub async fn export_metrics(&self) -> ExecutionMetrics {
        self.performance_metrics.read().await.clone()
    }
}

impl ParallelExecution {
    async fn new(concurrency_limit: usize) -> Result<Self> {
        Ok(Self {
            task_scheduler: Arc::new(TaskScheduler::new()),
            dependency_analyzer: Arc::new(DependencyAnalyzer::new()),
            execution_monitor: Arc::new(ExecutionMonitor::new()),
            concurrency_limiter: Arc::new(Semaphore::new(concurrency_limit)),
        })
    }
}

impl TaskScheduler {
    fn new() -> Self {
        Self {
            ready_queue: Arc::new(RwLock::new(Vec::new())),
            running_tasks: Arc::new(RwLock::new(HashMap::new())),
            completed_tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl DependencyAnalyzer {
    fn new() -> Self {
        Self {
            dependency_graph: Arc::new(RwLock::new(DependencyGraph::default())),
        }
    }

    async fn analyze_plan_dependencies(&self, plan: &ExecutionPlan) -> Result<DependencyGraph> {
        let mut graph = DependencyGraph::default();

        // Build nodes for each step
        for step in &plan.steps {
            let node = DependencyNode {
                step_id: step.step_id,
                step_name: step.description.clone(),
                status: ExecutionStatus::Pending,
                dependencies_satisfied: false,
                parallel_group: step.parallel_group.clone(),
            };
            graph.nodes.insert(step.step_id, node);
        }

        // Build edges based on sequence dependencies
        let mut sorted_steps = plan.steps.clone();
        sorted_steps.sort_by_key(|s| s.sequence);

        for window in sorted_steps.windows(2) {
            let from_step = &window[0];
            let to_step = &window[1];

            // Only create dependency if they're not in the same parallel group
            if from_step.parallel_group != to_step.parallel_group {
                graph
                    .edges
                    .entry(from_step.step_id)
                    .or_insert_with(Vec::new)
                    .push(to_step.step_id);

                graph
                    .reverse_edges
                    .entry(to_step.step_id)
                    .or_insert_with(Vec::new)
                    .push(from_step.step_id);
            }
        }

        Ok(graph)
    }
}

impl ExecutionMonitor {
    fn new() -> Self {
        Self {
            active_executions: Arc::new(RwLock::new(HashMap::new())),
            performance_tracker: Arc::new(PerformanceTracker::new()),
        }
    }
}

impl PerformanceTracker {
    fn new() -> Self {
        Self {
            execution_history: Arc::new(RwLock::new(Vec::new())),
            optimization_suggestions: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl ResourceManager {
    async fn new(_resource_limits: &ResourceLimits) -> Result<Self> {
        Ok(Self {
            resource_allocator: Arc::new(ResourceAllocator::new()),
            quota_manager: Arc::new(QuotaManager::new()),
            scaling_controller: Arc::new(ScalingController::new()),
            resource_monitor: Arc::new(ResourceMonitor::new()),
        })
    }

    async fn allocate_resources(
        &self,
        execution_id: Uuid,
        _requirements: &crate::planner::oracle::ResourceRequirements,
    ) -> Result<ResourceAllocation> {
        // Simplified resource allocation
        Ok(ResourceAllocation {
            allocated_cpu_cores: 1.0,
            allocated_memory_mb: 512,
            allocated_disk_mb: 1024,
            allocated_network_mbps: 10.0,
            allocation_timestamp: chrono::Utc::now(),
        })
    }

    async fn release_resources(&self, _execution_id: Uuid) -> Result<()> {
        // Simplified resource release
        Ok(())
    }
}

impl ResourceAllocator {
    fn new() -> Self {
        Self {
            available_resources: Arc::new(RwLock::new(AvailableResources::default())),
            allocation_history: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl QuotaManager {
    fn new() -> Self {
        Self {
            quotas: Arc::new(RwLock::new(HashMap::new())),
            usage_tracking: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl ScalingController {
    fn new() -> Self {
        Self {
            scaling_policies: Arc::new(RwLock::new(Vec::new())),
            scaling_history: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl ResourceMonitor {
    fn new() -> Self {
        Self {
            monitoring_interval: Duration::from_secs(30),
            resource_alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl ResultAggregator {
    async fn new() -> Result<Self> {
        Ok(Self {
            result_collector: Arc::new(ResultCollector::new()),
            data_synthesizer: Arc::new(DataSynthesizer::new()),
            progress_tracker: Arc::new(ProgressTracker::new()),
        })
    }
}

impl ResultCollector {
    fn new() -> Self {
        Self {
            collection_strategies: HashMap::new(),
            partial_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl DataSynthesizer {
    fn new() -> Self {
        Self {
            synthesis_rules: Vec::new(),
            output_formatters: HashMap::new(),
        }
    }
}

impl ProgressTracker {
    fn new() -> Self {
        Self {
            progress_reports: Arc::new(RwLock::new(HashMap::new())),
            milestone_tracker: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::{ExecutionConfig, ResourceLimits, RetryPolicy};

    #[tokio::test]
    async fn test_executor_adapter_creation() {
        let config = ExecutionConfig {
            max_concurrent_workflows: 2,
            max_workflow_duration_hours: 1,
            resource_limits: ResourceLimits {
                max_memory_mb: 1024,
                max_cpu_percent: 80,
                max_disk_mb: 1024,
                max_network_connections: 50,
            },
            retry_policy: RetryPolicy {
                max_retries: 3,
                initial_backoff_ms: 1000,
                max_backoff_ms: 30000,
                backoff_multiplier: 2.0,
            },
        };

        let adapter = ExecutorAdapter::new(&config).await;
        assert!(adapter.is_ok());
    }

    #[tokio::test]
    async fn test_step_grouping() {
        let config = ExecutionConfig {
            max_concurrent_workflows: 2,
            max_workflow_duration_hours: 1,
            resource_limits: ResourceLimits {
                max_memory_mb: 1024,
                max_cpu_percent: 80,
                max_disk_mb: 1024,
                max_network_connections: 50,
            },
            retry_policy: RetryPolicy {
                max_retries: 3,
                initial_backoff_ms: 1000,
                max_backoff_ms: 30000,
                backoff_multiplier: 2.0,
            },
        };

        let adapter = ExecutorAdapter::new(&config).await.unwrap();

        let steps = vec![
            PlanStep {
                step_id: Uuid::new_v4(),
                sequence: 1,
                description: "Step 1".to_string(),
                capability: "test.v1".to_string(),
                parameters: HashMap::new(),
                expected_duration_minutes: 5,
                success_criteria: vec![],
                failure_recovery: None,
                parallel_group: Some("group1".to_string()),
            },
            PlanStep {
                step_id: Uuid::new_v4(),
                sequence: 2,
                description: "Step 2".to_string(),
                capability: "test.v1".to_string(),
                parameters: HashMap::new(),
                expected_duration_minutes: 5,
                success_criteria: vec![],
                failure_recovery: None,
                parallel_group: Some("group1".to_string()),
            },
            PlanStep {
                step_id: Uuid::new_v4(),
                sequence: 3,
                description: "Step 3".to_string(),
                capability: "test.v1".to_string(),
                parameters: HashMap::new(),
                expected_duration_minutes: 5,
                success_criteria: vec![],
                failure_recovery: None,
                parallel_group: None,
            },
        ];

        let groups = adapter.group_steps_by_parallelism(&steps);
        assert_eq!(groups.len(), 2); // One parallel group + one sequential step
        assert_eq!(groups[0].len(), 2); // Parallel group with 2 steps
        assert_eq!(groups[1].len(), 1); // Sequential step
    }

    #[tokio::test]
    async fn test_resource_usage_estimation() {
        let step = PlanStep {
            step_id: Uuid::new_v4(),
            sequence: 1,
            description: "Test step".to_string(),
            capability: "analysis.system.v1".to_string(),
            parameters: HashMap::new(),
            expected_duration_minutes: 10,
            success_criteria: vec![],
            failure_recovery: None,
            parallel_group: None,
        };

        let usage = ExecutorAdapter::estimate_resource_usage(&step, 5000);
        assert!(usage.cpu_cores_used > 0.0);
        assert!(usage.memory_mb_used > 0);
        assert!(usage.total_cpu_time_ms > 0);
    }
}
