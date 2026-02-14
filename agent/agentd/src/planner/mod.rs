/*!
# Planner-Executor Controller

The planner-executor controller implements sophisticated AI workflow orchestration with:

- **State Machine Engine**: 6-state workflow management for deterministic execution
- **Oracle System**: AI-powered planning with Deep Research + Planning Committee
- **Guard Engine**: Comprehensive security validation and policy enforcement
- **Executor Adapter**: Parallel execution with capability-based isolation
- **Stall Detection**: 5 algorithms for identifying and recovering from blocked workflows
- **Menu System**: User intervention capabilities for complex decision-making
- **Telemetry**: Performance metrics and audit trail collection

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Planner-Executor Controller                  │
├─────────────────────────────────────────────────────────────────┤
│  State Machine Engine                                          │
│  ┌─────┐   ┌─────┐   ┌─────┐   ┌─────┐   ┌─────┐   ┌─────┐   │
│  │Init │→ │Plan │→ │Exec │→ │Eval │→ │Done │⇄ │Fail │   │
│  └─────┘   └─────┘   └─────┘   └─────┘   └─────┘   └─────┘   │
├─────────────────────────────────────────────────────────────────┤
│  Oracle System (AI-Powered Planning)                          │
│  ┌───────────────┐  ┌─────────────────────────────────────┐   │
│  │ Deep Research │  │        Planning Committee           │   │
│  │   Assistant   │  │ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ │   │
│  │               │  │ │Arch │ │Sec  │ │Perf │ │QA   │ │   │
│  └───────────────┘  │ └─────┘ └─────┘ └─────┘ └─────┘ │   │
│                      └─────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  Guard Engine (Security & Policy)                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Policy    │  │  Security   │  │ Capability  │           │
│  │ Validation  │  │  Analysis   │  │  Mapping    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Executor Adapter (Parallel Execution)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Capability │  │   Resource  │  │   Result    │           │
│  │  Execution  │  │ Management  │  │ Aggregation │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Stall Detection & Recovery                                    │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────────────────┐         │
│  │Time │ │Prog │ │Dep  │ │Res  │ │      Menu       │         │
│  │out  │ │ress │ │lock │ │ource│ │    System       │         │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

```text
use smith_planner::{
    PlannerExecutorController,
    WorkflowType,
    PlannerConfig,
    Goal
};

// Create controller with configuration
let config = PlannerConfig::production();
let controller = PlannerExecutorController::new(config).await?;

// Submit complex goal
let goal = Goal::new("Optimize database performance for user queries")
    .with_context("E-commerce platform with 1M+ users")
    .with_constraints(vec!["Zero downtime", "< 100ms response time"]);

// Execute workflow with monitoring
let workflow_id = controller.submit_goal(goal, WorkflowType::ComplexOrchestration).await?;
let result = controller.monitor_execution(workflow_id).await?;
```
*/

pub mod executor_adapter;
pub mod guard;
pub mod menu;
pub mod menu_system;
pub mod oracle;
pub mod stall_detection;
pub mod state_machine;
pub mod telemetry;

pub use executor_adapter::{ExecutorAdapter, ParallelExecution, ResourceManager, ResultAggregator};
pub use guard::{CapabilityMapper, GuardEngine, PolicyValidator, SecurityAnalyzer};
pub use menu::{InterventionResult, MenuSystem, UserInterventionOption};
pub use oracle::{
    DeepResearchAssistant, Oracle, PlanningCommittee, PlanningConsensus, ResearchResult,
};
pub use stall_detection::{RecoveryStrategy, StallDetectionConfig, StallDetector, StallType};
pub use state_machine::{StateMachine, StateTransition, WorkflowState, WorkflowType};
pub use telemetry::{ExportFormat, TelemetryCollector, WorkflowMetrics};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Main controller for planner-executor workflows
#[derive(Clone)]
pub struct PlannerExecutorController {
    config: PlannerConfig,
    state_machine: Arc<RwLock<StateMachine>>,
    oracle: Arc<Oracle>,
    guard: Arc<GuardEngine>,
    executor_adapter: Arc<ExecutorAdapter>,
    stall_detector: Arc<StallDetector>,
    menu_system: Arc<MenuSystem>,
    telemetry: Arc<Mutex<TelemetryCollector>>,
    active_workflows: Arc<RwLock<HashMap<Uuid, WorkflowContext>>>,
}

/// Configuration for planner-executor controller
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerConfig {
    /// AI model configuration for oracle system
    pub ai_config: AiConfig,
    /// Security and policy enforcement settings
    pub security_config: SecurityConfig,
    /// Resource limits and execution constraints
    pub execution_config: ExecutionConfig,
    /// Stall detection thresholds and timeouts
    pub stall_config: StallDetectionConfig,
    /// Telemetry and monitoring settings
    pub telemetry_config: TelemetryConfig,
    /// NATS integration settings
    pub nats_config: NatsConfig,
}

/// AI model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub provider: String, // "claude", "openai", "local"
    pub model: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
    pub rate_limit_per_minute: u32,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_policy_validation: bool,
    pub enable_security_analysis: bool,
    pub enable_capability_restrictions: bool,
    pub max_execution_time_seconds: u64,
    pub max_parallel_operations: u32,
    pub allowed_capabilities: Vec<String>,
}

/// Execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    pub max_concurrent_workflows: u32,
    pub max_workflow_duration_hours: u32,
    pub resource_limits: ResourceLimits,
    pub retry_policy: RetryPolicy,
}

/// Resource limits for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: u64,
    pub max_cpu_percent: u32,
    pub max_disk_mb: u64,
    pub max_network_connections: u32,
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier: f32,
}

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enable_metrics: bool,
    pub enable_audit_trail: bool,
    pub export_formats: Vec<ExportFormat>,
    pub retention_days: u32,
    pub metrics_interval_seconds: u64,
}

/// NATS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    pub servers: Vec<String>,
    pub subjects: NatsSubjects,
    pub stream_config: NatsStreamConfig,
}

/// NATS subject configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsSubjects {
    pub goals: String,
    pub workflows: String,
    pub results: String,
    pub telemetry: String,
    pub interventions: String,
}

/// NATS stream configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsStreamConfig {
    pub max_messages: u64,
    pub max_bytes: u64,
    pub retention_hours: u64,
    pub replicas: u32,
}

/// Goal submitted for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Goal {
    pub id: Uuid,
    pub description: String,
    pub context: Option<String>,
    pub constraints: Vec<String>,
    pub success_criteria: Vec<String>,
    pub priority: Priority,
    pub metadata: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Goal priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

/// Workflow execution context
#[derive(Debug, Clone)]
pub struct WorkflowContext {
    pub goal: Goal,
    pub workflow_type: WorkflowType,
    pub current_state: WorkflowState,
    pub execution_history: Vec<StateTransition>,
    pub oracle_decisions: Vec<oracle::OracleDecision>,
    pub guard_validations: Vec<guard::GuardResult>,
    pub execution_results: Vec<executor_adapter::ExecutionResult>,
    pub stall_detections: Vec<stall_detection::StallEvent>,
    pub user_interventions: Vec<menu_system::InterventionEvent>,
    pub metrics: WorkflowMetrics,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl PlannerConfig {
    /// Create production configuration with secure defaults
    pub fn production() -> Self {
        Self {
            ai_config: AiConfig {
                provider: "claude".to_string(),
                model: "claude-3-5-sonnet-20241022".to_string(),
                max_tokens: 4096,
                temperature: 0.1,
                timeout_seconds: 120,
                retry_attempts: 3,
                rate_limit_per_minute: 60,
            },
            security_config: SecurityConfig {
                enable_policy_validation: true,
                enable_security_analysis: true,
                enable_capability_restrictions: true,
                max_execution_time_seconds: 3600,
                max_parallel_operations: 10,
                allowed_capabilities: vec![
                    "fs.read.v1".to_string(),
                    "http.fetch.v1".to_string(),
                    "process.run.v1".to_string(),
                ],
            },
            execution_config: ExecutionConfig {
                max_concurrent_workflows: 5,
                max_workflow_duration_hours: 24,
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
            },
            stall_config: StallDetectionConfig::default(),
            telemetry_config: TelemetryConfig {
                enable_metrics: true,
                enable_audit_trail: true,
                export_formats: vec![ExportFormat::Json, ExportFormat::Prometheus],
                retention_days: 30,
                metrics_interval_seconds: 60,
            },
            nats_config: NatsConfig {
                servers: vec!["nats://localhost:4222".to_string()],
                subjects: NatsSubjects {
                    goals: "smith.planner.goals".to_string(),
                    workflows: "smith.planner.workflows".to_string(),
                    results: "smith.planner.results".to_string(),
                    telemetry: "smith.planner.telemetry".to_string(),
                    interventions: "smith.planner.interventions".to_string(),
                },
                stream_config: NatsStreamConfig {
                    max_messages: 1000000,
                    max_bytes: 1073741824, // 1GB
                    retention_hours: 168,  // 7 days
                    replicas: 1,
                },
            },
        }
    }

    /// Create development configuration with relaxed settings
    pub fn development() -> Self {
        let mut config = Self::production();
        config.security_config.enable_policy_validation = false;
        config.security_config.enable_security_analysis = false;
        config.ai_config.temperature = 0.2;
        config.execution_config.max_concurrent_workflows = 2;
        config.telemetry_config.retention_days = 7;
        config
    }

    /// Create test configuration with minimal settings
    pub fn test() -> Self {
        let mut config = Self::development();
        config.ai_config.provider = "mock".to_string();
        config.ai_config.timeout_seconds = 5;
        config.execution_config.max_workflow_duration_hours = 1;
        config.telemetry_config.enable_audit_trail = false;
        config
    }
}

impl Goal {
    /// Create new goal with description
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            description: description.into(),
            context: None,
            constraints: Vec::new(),
            success_criteria: Vec::new(),
            priority: Priority::Medium,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        }
    }

    /// Add context information
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Add constraints
    pub fn with_constraints(mut self, constraints: Vec<String>) -> Self {
        self.constraints = constraints;
        self
    }

    /// Add success criteria
    pub fn with_success_criteria(mut self, criteria: Vec<String>) -> Self {
        self.success_criteria = criteria;
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

impl PlannerExecutorController {
    /// Create new planner-executor controller
    pub async fn new(config: PlannerConfig) -> Result<Self> {
        info!("Initializing planner-executor controller");

        // Initialize core components
        let state_machine = Arc::new(RwLock::new(StateMachine::new()));
        let oracle = Arc::new(Oracle::new(&config.ai_config).await?);
        let guard = Arc::new(GuardEngine::new(&config.security_config).await?);
        let executor_adapter = Arc::new(ExecutorAdapter::new(&config.execution_config).await?);
        let stall_detector = Arc::new(StallDetector::new(config.stall_config.clone()));
        let menu_system = Arc::new(MenuSystem::new());
        let telemetry = Arc::new(Mutex::new(
            TelemetryCollector::new(telemetry::TelemetryConfig::default()).await?,
        ));
        let active_workflows = Arc::new(RwLock::new(HashMap::new()));

        info!("Planner-executor controller initialized successfully");

        Ok(Self {
            config,
            state_machine,
            oracle,
            guard,
            executor_adapter,
            stall_detector,
            menu_system,
            telemetry,
            active_workflows,
        })
    }

    /// Submit goal for execution
    pub async fn submit_goal(&self, goal: Goal, workflow_type: WorkflowType) -> Result<Uuid> {
        let workflow_id = Uuid::new_v4();

        info!(
            workflow_id = %workflow_id,
            goal_id = %goal.id,
            "Submitting goal for execution"
        );

        // Create workflow context
        let context = WorkflowContext {
            goal: goal.clone(),
            workflow_type,
            current_state: WorkflowState::Initializing,
            execution_history: Vec::new(),
            oracle_decisions: Vec::new(),
            guard_validations: Vec::new(),
            execution_results: Vec::new(),
            stall_detections: Vec::new(),
            user_interventions: Vec::new(),
            metrics: WorkflowMetrics {
                total_workflows: 1,
                active_workflows: 1,
                successful_workflows: 0,
                failed_workflows: 0,
                average_completion_time: None,
                state_distribution: HashMap::new(),
                recent_events: Vec::new(),
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Store workflow context
        self.active_workflows
            .write()
            .await
            .insert(workflow_id, context);

        // Start workflow execution asynchronously
        let controller = self.clone();
        tokio::spawn(async move {
            if let Err(e) = controller.execute_workflow(workflow_id).await {
                error!(workflow_id = %workflow_id, error = %e, "Workflow execution failed");
            }
        });

        Ok(workflow_id)
    }

    /// Execute workflow through state machine
    async fn execute_workflow(&self, workflow_id: Uuid) -> Result<()> {
        info!(workflow_id = %workflow_id, "Starting workflow execution");

        loop {
            // Get current state
            let current_state = {
                let workflows = self.active_workflows.read().await;
                workflows
                    .get(&workflow_id)
                    .map(|ctx| ctx.current_state.clone())
                    .ok_or_else(|| anyhow::anyhow!("Workflow not found: {}", workflow_id))?
            };

            // Check for stalls
            if let Some(stall_event) = self
                .stall_detector
                .check_stall(workflow_id, &current_state)
                .await?
            {
                warn!(workflow_id = %workflow_id, stall_type = ?stall_event.stall_type, "Stall detected");

                // Handle stall with recovery strategy or user intervention
                let recovery_result = self.handle_stall(workflow_id, stall_event).await?;
                if !recovery_result {
                    return Err(anyhow::anyhow!("Unable to recover from stall"));
                }
            }

            // Execute state transition
            let transition_result = match current_state {
                WorkflowState::Initializing => self.handle_initialize_state(workflow_id).await?,
                WorkflowState::Planning => self.handle_planning_state(workflow_id).await?,
                WorkflowState::Executing => self.handle_executing_state(workflow_id).await?,
                WorkflowState::Evaluating => self.handle_evaluating_state(workflow_id).await?,
                WorkflowState::Completed => {
                    info!(workflow_id = %workflow_id, "Workflow completed successfully");
                    break;
                }
                WorkflowState::Failed => {
                    warn!(workflow_id = %workflow_id, "Workflow failed");
                    break;
                }
            };

            // Update workflow state
            self.update_workflow_state(workflow_id, transition_result)
                .await?;

            // Brief pause to prevent tight loops
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        // Finalize workflow
        self.finalize_workflow(workflow_id).await?;

        Ok(())
    }

    /// Handle workflow initialization state
    async fn handle_initialize_state(&self, workflow_id: Uuid) -> Result<StateTransition> {
        debug!(workflow_id = %workflow_id, "Handling initialize state");

        // Get workflow context
        let goal = {
            let workflows = self.active_workflows.read().await;
            workflows
                .get(&workflow_id)
                .map(|ctx| ctx.goal.clone())
                .ok_or_else(|| anyhow::anyhow!("Workflow not found: {}", workflow_id))?
        };

        // Perform initial validation with guard engine
        let guard_result = self.guard.validate_goal(&goal).await?;

        // Record guard validation
        {
            let mut workflows = self.active_workflows.write().await;
            if let Some(ctx) = workflows.get_mut(&workflow_id) {
                ctx.guard_validations.push(guard_result.clone());
                ctx.updated_at = chrono::Utc::now();
            }
        }

        // Check if goal passes initial validation
        if guard_result.approved {
            Ok(StateTransition {
                from: WorkflowState::Initializing,
                to: WorkflowState::Planning,
                timestamp: chrono::Utc::now(),
                reason: "Initial validation passed".to_string(),
                metadata: HashMap::new(),
            })
        } else {
            Ok(StateTransition {
                from: WorkflowState::Initializing,
                to: WorkflowState::Failed,
                timestamp: chrono::Utc::now(),
                reason: format!("Initial validation failed: {}", guard_result.reason),
                metadata: HashMap::new(),
            })
        }
    }

    /// Handle workflow planning state
    async fn handle_planning_state(&self, workflow_id: Uuid) -> Result<StateTransition> {
        debug!(workflow_id = %workflow_id, "Handling planning state");

        // Get workflow context
        let goal = {
            let workflows = self.active_workflows.read().await;
            workflows
                .get(&workflow_id)
                .map(|ctx| ctx.goal.clone())
                .ok_or_else(|| anyhow::anyhow!("Workflow not found: {}", workflow_id))?
        };

        // Use oracle system for planning
        let oracle_decision = self.oracle.plan_execution(&goal).await?;

        // Record oracle decision
        {
            let mut workflows = self.active_workflows.write().await;
            if let Some(ctx) = workflows.get_mut(&workflow_id) {
                ctx.oracle_decisions.push(oracle_decision.clone());
                ctx.updated_at = chrono::Utc::now();
            }
        }

        // Validate plan with guard engine
        let plan_validation = self.guard.validate_plan(&oracle_decision.plan).await?;

        if plan_validation.approved {
            Ok(StateTransition {
                from: WorkflowState::Planning,
                to: WorkflowState::Executing,
                timestamp: chrono::Utc::now(),
                reason: "Plan validated and approved".to_string(),
                metadata: HashMap::new(),
            })
        } else {
            // Plan rejected, need replanning or failure
            if oracle_decision.confidence > 0.7 {
                // High confidence plan rejected - might need user intervention
                Ok(StateTransition {
                    from: WorkflowState::Planning,
                    to: WorkflowState::Planning, // Stay in planning for retry
                    timestamp: chrono::Utc::now(),
                    reason: format!("Plan rejected, retrying: {}", plan_validation.reason),
                    metadata: HashMap::new(),
                })
            } else {
                Ok(StateTransition {
                    from: WorkflowState::Planning,
                    to: WorkflowState::Failed,
                    timestamp: chrono::Utc::now(),
                    reason: format!("Low confidence plan rejected: {}", plan_validation.reason),
                    metadata: HashMap::new(),
                })
            }
        }
    }

    /// Handle workflow execution state
    async fn handle_executing_state(&self, workflow_id: Uuid) -> Result<StateTransition> {
        debug!(workflow_id = %workflow_id, "Handling executing state");

        // Get latest oracle decision
        let plan = {
            let workflows = self.active_workflows.read().await;
            workflows
                .get(&workflow_id)
                .and_then(|ctx| ctx.oracle_decisions.last())
                .map(|decision| decision.plan.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!("No execution plan found for workflow: {}", workflow_id)
                })?
        };

        // Execute plan using executor adapter
        let execution_result = self.executor_adapter.execute_plan(&plan).await?;

        // Record execution result
        {
            let mut workflows = self.active_workflows.write().await;
            if let Some(ctx) = workflows.get_mut(&workflow_id) {
                ctx.execution_results.push(execution_result.clone());
                ctx.updated_at = chrono::Utc::now();
            }
        }

        // Determine next state based on execution result
        if execution_result.success {
            Ok(StateTransition {
                from: WorkflowState::Executing,
                to: WorkflowState::Evaluating,
                timestamp: chrono::Utc::now(),
                reason: "Execution completed successfully".to_string(),
                metadata: HashMap::new(),
            })
        } else {
            // Check if retry is possible
            if execution_result.retryable && execution_result.attempt_count < 3 {
                Ok(StateTransition {
                    from: WorkflowState::Executing,
                    to: WorkflowState::Executing, // Retry execution
                    timestamp: chrono::Utc::now(),
                    reason: format!(
                        "Execution failed, retrying: {}",
                        execution_result.error_message
                    ),
                    metadata: HashMap::new(),
                })
            } else {
                Ok(StateTransition {
                    from: WorkflowState::Executing,
                    to: WorkflowState::Failed,
                    timestamp: chrono::Utc::now(),
                    reason: format!("Execution failed: {}", execution_result.error_message),
                    metadata: HashMap::new(),
                })
            }
        }
    }

    /// Handle workflow evaluation state
    async fn handle_evaluating_state(&self, workflow_id: Uuid) -> Result<StateTransition> {
        debug!(workflow_id = %workflow_id, "Handling evaluating state");

        // Get workflow context for evaluation
        let (goal, execution_results) = {
            let workflows = self.active_workflows.read().await;
            workflows
                .get(&workflow_id)
                .map(|ctx| (ctx.goal.clone(), ctx.execution_results.clone()))
                .ok_or_else(|| anyhow::anyhow!("Workflow not found: {}", workflow_id))?
        };

        // Use oracle to evaluate results against goal
        let evaluation = self
            .oracle
            .evaluate_results(&goal, &execution_results)
            .await?;

        if evaluation.success {
            Ok(StateTransition {
                from: WorkflowState::Evaluating,
                to: WorkflowState::Completed,
                timestamp: chrono::Utc::now(),
                reason: format!("Goal achieved: {}", evaluation.summary),
                metadata: HashMap::new(),
            })
        } else {
            // Goal not achieved - check if we should retry or improve
            if evaluation.improvement_possible && evaluation.confidence > 0.5 {
                Ok(StateTransition {
                    from: WorkflowState::Evaluating,
                    to: WorkflowState::Planning, // Re-plan for improvement
                    timestamp: chrono::Utc::now(),
                    reason: format!("Goal not achieved, re-planning: {}", evaluation.summary),
                    metadata: HashMap::new(),
                })
            } else {
                Ok(StateTransition {
                    from: WorkflowState::Evaluating,
                    to: WorkflowState::Failed,
                    timestamp: chrono::Utc::now(),
                    reason: format!("Goal not achievable: {}", evaluation.summary),
                    metadata: HashMap::new(),
                })
            }
        }
    }

    /// Handle workflow stall situations
    async fn handle_stall(
        &self,
        workflow_id: Uuid,
        stall_event: stall_detection::StallEvent,
    ) -> Result<bool> {
        warn!(workflow_id = %workflow_id, stall_type = ?stall_event.stall_type, "Handling workflow stall");

        // Record stall event
        {
            let mut workflows = self.active_workflows.write().await;
            if let Some(ctx) = workflows.get_mut(&workflow_id) {
                ctx.stall_detections.push(stall_event.clone());
                ctx.updated_at = chrono::Utc::now();
            }
        }

        // Determine recovery strategy
        match stall_event.recovery_strategy {
            RecoveryStrategy::AutoRetry => {
                info!(workflow_id = %workflow_id, "Attempting automatic retry for stall recovery");
                // Reset state or retry current operation
                Ok(true)
            }
            RecoveryStrategy::UserIntervention => {
                info!(workflow_id = %workflow_id, "Requesting user intervention for stall recovery");
                // Present intervention options to user
                let intervention_result = self
                    .menu_system
                    .request_intervention(workflow_id, &stall_event)
                    .await?;

                // Record user intervention
                {
                    let mut workflows = self.active_workflows.write().await;
                    if let Some(ctx) = workflows.get_mut(&workflow_id) {
                        ctx.user_interventions
                            .push(intervention_result.clone().into());
                        ctx.updated_at = chrono::Utc::now();
                    }
                }

                Ok(intervention_result.continue_execution)
            }
            RecoveryStrategy::Escalate => {
                warn!(workflow_id = %workflow_id, "Escalating stall - manual resolution required");
                // Log for manual intervention
                Ok(false)
            }
            RecoveryStrategy::Fail => {
                error!(workflow_id = %workflow_id, "Unrecoverable stall detected");
                Ok(false)
            }
        }
    }

    /// Update workflow state
    async fn update_workflow_state(
        &self,
        workflow_id: Uuid,
        transition: StateTransition,
    ) -> Result<()> {
        let mut workflows = self.active_workflows.write().await;
        if let Some(ctx) = workflows.get_mut(&workflow_id) {
            ctx.current_state = transition.to.clone();
            ctx.execution_history.push(transition);
            ctx.updated_at = chrono::Utc::now();

            debug!(
                workflow_id = %workflow_id,
                new_state = ?ctx.current_state,
                "Workflow state updated"
            );
        }
        Ok(())
    }

    /// Finalize workflow and collect telemetry
    async fn finalize_workflow(&self, workflow_id: Uuid) -> Result<()> {
        info!(workflow_id = %workflow_id, "Finalizing workflow");

        // Get final workflow context
        let final_context = {
            let workflows = self.active_workflows.read().await;
            workflows.get(&workflow_id).cloned()
        };

        if let Some(context) = final_context {
            // Collect final telemetry
            let mut telemetry = self.telemetry.lock().await;
            telemetry
                .record_workflow_event(telemetry::WorkflowEvent {
                    workflow_id: workflow_id,
                    event_type: telemetry::WorkflowEventType::GoalCompleted {
                        success: context.current_state == WorkflowState::Completed,
                        duration: std::time::Duration::from_secs(0), // TODO: calculate actual duration
                    },
                    timestamp: std::time::SystemTime::now(),
                    user_id: None,
                    metadata: HashMap::new(),
                })
                .await;

            // Remove from active workflows
            self.active_workflows.write().await.remove(&workflow_id);

            info!(
                workflow_id = %workflow_id,
                final_state = ?context.current_state,
                duration_seconds = (context.updated_at - context.created_at).num_seconds(),
                "Workflow finalized"
            );
        }

        Ok(())
    }

    /// Get workflow status
    pub async fn get_workflow_status(&self, workflow_id: Uuid) -> Result<Option<WorkflowContext>> {
        let workflows = self.active_workflows.read().await;
        Ok(workflows.get(&workflow_id).cloned())
    }

    /// List active workflows
    pub async fn list_active_workflows(&self) -> Result<Vec<Uuid>> {
        let workflows = self.active_workflows.read().await;
        Ok(workflows.keys().cloned().collect())
    }

    /// Export telemetry data
    pub async fn export_telemetry(&self, format: ExportFormat) -> Result<String> {
        let telemetry = self.telemetry.lock().await;
        telemetry
            .export_metrics(format)
            .await
            .map_err(|e| anyhow::anyhow!("Telemetry export failed: {}", e))
    }

    /// Graceful shutdown
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down planner-executor controller");

        // Wait for active workflows to complete (with timeout)
        let timeout = tokio::time::Duration::from_secs(300); // 5 minutes
        let start = tokio::time::Instant::now();

        while !self.active_workflows.read().await.is_empty() && start.elapsed() < timeout {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        // Force shutdown remaining workflows
        let remaining = self.active_workflows.read().await.len();
        if remaining > 0 {
            warn!(
                remaining_workflows = remaining,
                "Force shutting down remaining workflows"
            );
        }

        // Final telemetry export
        let telemetry = self.telemetry.lock().await;
        if let Ok(export) = telemetry.export_metrics(ExportFormat::Json).await {
            info!("Final telemetry export completed: {} bytes", export.len());
        }

        info!("Planner-executor controller shutdown completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_controller_initialization() {
        let config = PlannerConfig::test();
        let controller = PlannerExecutorController::new(config).await;
        assert!(controller.is_ok());
    }

    #[tokio::test]
    async fn test_goal_submission() {
        let config = PlannerConfig::test();
        let controller = PlannerExecutorController::new(config).await.unwrap();

        let goal = Goal::new("Test goal")
            .with_context("Test context")
            .with_priority(Priority::Low);

        let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await;
        assert!(workflow_id.is_ok());
    }

    #[tokio::test]
    async fn test_workflow_status() {
        let config = PlannerConfig::test();
        let controller = PlannerExecutorController::new(config).await.unwrap();

        let goal = Goal::new("Test goal");
        let workflow_id = controller
            .submit_goal(goal, WorkflowType::Simple)
            .await
            .unwrap();

        // Allow some time for workflow to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let status = controller.get_workflow_status(workflow_id).await.unwrap();
        assert!(status.is_some());
    }
}

// Comprehensive test modules
#[cfg(test)]
mod mod_tests;
