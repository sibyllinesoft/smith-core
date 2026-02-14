//! Data structures and schemas for the Planner-Executor Controller
//!
//! This module defines all the core data structures, parameter schemas,
//! and state representations used throughout the planner-executor system.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Parameters for planner-executor capability
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct PlannerExecParams {
    /// Workflow identifier
    pub workflow_id: String,

    /// High-level goal description
    pub goal: String,

    /// Type of workflow to execute
    pub workflow_type: WorkflowType,

    /// Maximum number of execution steps
    pub max_steps: usize,

    /// Timeout in milliseconds (optional)
    pub timeout_ms: Option<u64>,

    /// Additional context and constraints
    #[serde(default)]
    pub context: HashMap<String, serde_json::Value>,

    /// Capabilities allowed for this workflow
    #[serde(default)]
    pub allowed_capabilities: Vec<String>,

    /// Resource limits for execution
    #[serde(default)]
    pub resource_limits: ResourceLimits,

    /// Execution preferences
    #[serde(default)]
    pub preferences: ExecutionPreferences,
}

/// Type of workflow execution pattern
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum WorkflowType {
    /// Simple linear execution (1-10 steps)
    Simple,
    /// Research and planning workflow (5-50 steps)
    ResearchAndPlanning,
    /// Complex orchestration with sub-workflows (10-1000 steps)
    ComplexOrchestration,
}

/// Resource limits for workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct ResourceLimits {
    /// Maximum memory usage in MB
    pub max_memory_mb: u64,

    /// Maximum CPU time in seconds
    pub max_cpu_seconds: u64,

    /// Maximum file system operations
    pub max_fs_operations: u64,

    /// Maximum network requests
    pub max_network_requests: u64,

    /// Maximum parallel executions
    pub max_parallel_executions: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            max_cpu_seconds: 300,
            max_fs_operations: 1000,
            max_network_requests: 100,
            max_parallel_executions: 4,
        }
    }
}

/// Execution preferences and behavior settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct ExecutionPreferences {
    /// Verbosity level for logging and output
    pub verbosity: VerbosityLevel,

    /// Whether to enable interactive mode
    pub interactive: bool,

    /// Whether to continue on non-critical errors
    pub continue_on_error: bool,

    /// Stall detection sensitivity
    pub stall_detection_ms: u64,

    /// Whether to enable automatic escalation
    pub auto_escalation: bool,

    /// User intervention timeout in seconds
    pub user_intervention_timeout_s: u64,
}

impl Default for ExecutionPreferences {
    fn default() -> Self {
        Self {
            verbosity: VerbosityLevel::Normal,
            interactive: false,
            continue_on_error: false,
            stall_detection_ms: 30000, // 30 seconds
            auto_escalation: true,
            user_intervention_timeout_s: 60,
        }
    }
}

/// Verbosity level for output and logging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum VerbosityLevel {
    Quiet,
    Normal,
    Verbose,
    Debug,
}

/// Workflow action to be executed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowAction {
    /// Unique action identifier
    pub id: String,

    /// Action type and capability
    pub action_type: ActionType,

    /// Action-specific parameters
    pub parameters: serde_json::Value,

    /// Dependencies on other actions
    pub dependencies: Vec<String>,

    /// Expected outcome description
    pub expected_outcome: String,

    /// Retry policy
    pub retry_policy: RetryPolicy,

    /// Timeout for this specific action
    pub timeout_ms: Option<u64>,
}

impl WorkflowAction {
    /// Create a new workflow action
    pub fn new(
        action_type: ActionType,
        parameters: serde_json::Value,
        expected_outcome: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            action_type,
            parameters,
            dependencies: vec![],
            expected_outcome,
            retry_policy: RetryPolicy::default(),
            timeout_ms: None,
        }
    }

    /// Add a dependency on another action
    pub fn add_dependency(&mut self, action_id: String) {
        if !self.dependencies.contains(&action_id) {
            self.dependencies.push(action_id);
        }
    }

    /// Check if this action can be executed (all dependencies satisfied)
    pub fn can_execute(&self, completed_actions: &[String]) -> bool {
        self.dependencies
            .iter()
            .all(|dep| completed_actions.contains(dep))
    }
}

/// Type of action to execute
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "capability")]
pub enum ActionType {
    /// File system operation
    FileSystem(String),
    /// HTTP request
    Http(String),
    /// Shell command execution
    Shell(String),
    /// Research operation
    Research(String),
    /// Planning operation
    Planning(String),
    /// Analysis operation
    Analysis(String),
    /// Custom capability
    Custom(String),
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::FileSystem(cap) => write!(f, "FileSystem({})", cap),
            ActionType::Http(cap) => write!(f, "Http({})", cap),
            ActionType::Shell(cap) => write!(f, "Shell({})", cap),
            ActionType::Research(cap) => write!(f, "Research({})", cap),
            ActionType::Planning(cap) => write!(f, "Planning({})", cap),
            ActionType::Analysis(cap) => write!(f, "Analysis({})", cap),
            ActionType::Custom(cap) => write!(f, "Custom({})", cap),
        }
    }
}

/// Retry policy for failed actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retries
    pub max_retries: u32,

    /// Backoff strategy
    pub backoff_strategy: BackoffStrategy,

    /// Base delay in milliseconds
    pub base_delay_ms: u64,

    /// Maximum delay in milliseconds
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_strategy: BackoffStrategy::Exponential,
            base_delay_ms: 1000,
            max_delay_ms: 30000,
        }
    }
}

/// Backoff strategy for retries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BackoffStrategy {
    Fixed,
    Linear,
    Exponential,
    Jittered,
}

/// Result of executing a workflow action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// Action that was executed
    pub action_id: String,

    /// Execution status
    pub status: ActionStatus,

    /// Output from the action
    pub output: Option<serde_json::Value>,

    /// Error details if failed
    pub error: Option<ActionError>,

    /// Execution metadata
    pub metadata: ActionMetadata,

    /// When execution started
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// When execution finished
    pub finished_at: chrono::DateTime<chrono::Utc>,
}

/// Status of action execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Skipped,
}

/// Error details for failed actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionError {
    /// Error code
    pub code: String,

    /// Human-readable error message
    pub message: String,

    /// Detailed error context
    pub details: Option<serde_json::Value>,

    /// Whether this error is retryable
    pub retryable: bool,
}

/// Metadata about action execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMetadata {
    /// Number of retry attempts
    pub retry_count: u32,

    /// Resource usage
    pub resource_usage: ResourceUsage,

    /// Execution environment
    pub environment: ExecutionEnvironment,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU time in milliseconds
    pub cpu_ms: u64,

    /// Memory usage in bytes
    pub memory_bytes: u64,

    /// File system operations count
    pub fs_operations: u64,

    /// Network requests count
    pub network_requests: u64,
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            cpu_ms: 0,
            memory_bytes: 0,
            fs_operations: 0,
            network_requests: 0,
        }
    }
}

/// Execution environment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEnvironment {
    /// Executor instance ID
    pub executor_id: String,

    /// Sandbox mode used
    pub sandbox_mode: String,

    /// Security context
    pub security_context: HashMap<String, serde_json::Value>,
}

/// Oracle planning result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanningResult {
    /// Planned actions
    pub actions: Vec<WorkflowAction>,

    /// Overall strategy description
    pub strategy: String,

    /// Risk assessment
    pub risks: Vec<RiskAssessment>,

    /// Success criteria
    pub success_criteria: Vec<String>,

    /// Planning confidence (0.0 - 1.0)
    pub confidence: f64,
}

/// Risk assessment for the workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Risk description
    pub description: String,

    /// Risk level (Low, Medium, High, Critical)
    pub level: RiskLevel,

    /// Mitigation strategy
    pub mitigation: String,

    /// Impact if risk occurs
    pub impact: String,
}

/// Risk level enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Research result from the Oracle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchResult {
    /// Research findings
    pub findings: Vec<ResearchFinding>,

    /// Recommended next actions
    pub recommendations: Vec<String>,

    /// Research confidence (0.0 - 1.0)
    pub confidence: f64,

    /// Sources used for research
    pub sources: Vec<String>,
}

/// Individual research finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchFinding {
    /// Finding title
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Evidence supporting this finding
    pub evidence: Vec<String>,

    /// Relevance to the goal (0.0 - 1.0)
    pub relevance: f64,
}

/// User action for manual intervention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAction {
    /// Action type
    pub action_type: UserActionType,

    /// User input or selection
    pub input: Option<serde_json::Value>,

    /// Reason for the action
    pub reason: String,
}

/// Type of user action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UserActionType {
    /// Continue execution
    Continue,
    /// Pause execution
    Pause,
    /// Stop execution
    Stop,
    /// Modify parameters
    ModifyParameters,
    /// Add new action
    AddAction,
    /// Remove action
    RemoveAction,
    /// Override result
    OverrideResult,
    /// Escalate to human
    Escalate,
}

/// Complete workflow execution summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSummary {
    /// Workflow identifier
    pub workflow_id: String,

    /// Session identifier
    pub session_id: String,

    /// Workflow type
    pub workflow_type: WorkflowType,

    /// Original goal
    pub goal: String,

    /// Final status
    pub status: WorkflowStatus,

    /// All executed actions and their results
    pub actions: Vec<ActionResult>,

    /// Total execution time
    pub duration_ms: u64,

    /// Total duration (in time units)
    pub total_duration: std::time::Duration,

    /// Total number of actions
    pub total_actions: u32,

    /// Number of successful actions
    pub successful_actions: u32,

    /// Number of failed actions
    pub failed_actions: u32,

    /// Final state of the workflow
    pub final_state: WorkflowStatus,

    /// Error message if failed
    pub error_message: Option<String>,

    /// Resource usage summary
    pub resource_usage: ResourceUsage,

    /// Success criteria evaluation
    pub success_criteria_met: Vec<String>,

    /// Lessons learned
    pub lessons_learned: Vec<String>,

    /// Recommendations for improvement
    pub recommendations: Vec<String>,

    /// Final output or result
    pub final_output: Option<serde_json::Value>,
}

/// Overall workflow status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    Initializing,
    Planning,
    Executing,
    Completed,
    Failed,
    Cancelled,
    Paused,
}

/// Guard validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardResult {
    /// Whether the action is allowed
    pub allowed: bool,

    /// Reason for the decision
    pub reason: String,

    /// Security violations found
    pub violations: Vec<SecurityViolation>,

    /// Recommended modifications
    pub modifications: Vec<ActionModification>,
}

/// Security violation detected by the guard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityViolation {
    /// Violation type
    pub violation_type: String,

    /// Severity level
    pub severity: RiskLevel,

    /// Description of the violation
    pub description: String,

    /// How to fix the violation
    pub remediation: String,
}

/// Suggested modification to an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionModification {
    /// Field to modify
    pub field: String,

    /// Suggested new value
    pub suggested_value: serde_json::Value,

    /// Reason for the modification
    pub reason: String,
}

/// Stall detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallInfo {
    /// Whether a stall was detected
    pub stalled: bool,

    /// Time since last progress
    pub time_since_progress_ms: u64,

    /// Possible causes of the stall
    pub possible_causes: Vec<String>,

    /// Suggested interventions
    pub suggested_interventions: Vec<String>,
}

/// Menu system interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuInteraction {
    /// Available menu options
    pub options: Vec<MenuOption>,

    /// Current workflow context
    pub context: MenuContext,

    /// Timeout for user response
    pub timeout_ms: u64,
}

/// Individual menu option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuOption {
    /// Option identifier
    pub id: String,

    /// Display text
    pub text: String,

    /// Description of what this option does
    pub description: String,

    /// Whether this option requires additional input
    pub requires_input: bool,
}

/// Context for menu system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuContext {
    /// Current workflow state
    pub workflow_state: WorkflowStatus,

    /// Last few actions and their results
    pub recent_actions: Vec<ActionResult>,

    /// Current stall information
    pub stall_info: Option<StallInfo>,

    /// Available capabilities
    pub available_capabilities: Vec<String>,
}

impl PlannerExecParams {
    /// Validate the parameters
    pub fn validate(&self) -> Result<()> {
        if self.goal.trim().is_empty() {
            return Err(anyhow::anyhow!("Goal cannot be empty"));
        }

        if self.max_steps == 0 || self.max_steps > 1000 {
            return Err(anyhow::anyhow!("max_steps must be between 1 and 1000"));
        }

        if let Some(timeout) = self.timeout_ms {
            if timeout < 1000 {
                return Err(anyhow::anyhow!("timeout_ms must be at least 1000ms"));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_planner_exec_params_serialization() {
        let params = PlannerExecParams {
            workflow_id: "test-workflow-678".to_string(),
            goal: "Test goal".to_string(),
            workflow_type: WorkflowType::Simple,
            max_steps: 10,
            timeout_ms: Some(30000),
            context: HashMap::new(),
            allowed_capabilities: vec!["fs.read.v1".to_string()],
            resource_limits: ResourceLimits::default(),
            preferences: ExecutionPreferences::default(),
        };

        let json = serde_json::to_value(&params).unwrap();
        let deserialized: PlannerExecParams = serde_json::from_value(json).unwrap();

        assert_eq!(deserialized.goal, "Test goal");
        assert_eq!(deserialized.workflow_type, WorkflowType::Simple);
        assert_eq!(deserialized.max_steps, 10);
    }

    #[test]
    fn test_workflow_action_dependencies() {
        let mut action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test"}),
            "Read test file".to_string(),
        );

        action.add_dependency("action-1".to_string());
        action.add_dependency("action-2".to_string());

        assert_eq!(action.dependencies.len(), 2);
        assert!(!action.can_execute(&[]));
        assert!(!action.can_execute(&["action-1".to_string()]));
        assert!(action.can_execute(&["action-1".to_string(), "action-2".to_string()]));
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_parameter_validation() {
        let mut params = PlannerExecParams {
            workflow_id: "test-workflow-901".to_string(),
            goal: "Valid goal".to_string(),
            workflow_type: WorkflowType::Simple,
            max_steps: 10,
            timeout_ms: Some(30000),
            context: HashMap::new(),
            allowed_capabilities: vec![],
            resource_limits: ResourceLimits::default(),
            preferences: ExecutionPreferences::default(),
        };

        assert!(params.validate().is_ok());

        // Test empty goal
        params.goal = "".to_string();
        assert!(params.validate().is_err());

        // Test invalid max_steps
        params.goal = "Valid goal".to_string();
        params.max_steps = 0;
        assert!(params.validate().is_err());

        params.max_steps = 2000;
        assert!(params.validate().is_err());

        // Test invalid timeout
        params.max_steps = 10;
        params.timeout_ms = Some(500);
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_workflow_type_serialization() {
        let types = vec![
            (WorkflowType::Simple, "simple"),
            (WorkflowType::ResearchAndPlanning, "research_and_planning"),
            (WorkflowType::ComplexOrchestration, "complex_orchestration"),
        ];

        for (wt, expected_str) in types {
            let json = serde_json::to_string(&wt).unwrap();
            assert!(json.contains(expected_str));

            let deserialized: WorkflowType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, wt);
        }
    }

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_memory_mb, 512);
        assert_eq!(limits.max_cpu_seconds, 300);
        assert_eq!(limits.max_fs_operations, 1000);
        assert_eq!(limits.max_network_requests, 100);
        assert_eq!(limits.max_parallel_executions, 4);
    }

    #[test]
    fn test_execution_preferences_default() {
        let prefs = ExecutionPreferences::default();
        assert_eq!(prefs.verbosity, VerbosityLevel::Normal);
        assert!(!prefs.interactive);
        assert!(!prefs.continue_on_error);
        assert_eq!(prefs.stall_detection_ms, 30000);
        assert!(prefs.auto_escalation);
        assert_eq!(prefs.user_intervention_timeout_s, 60);
    }

    #[test]
    fn test_verbosity_level_serialization() {
        let levels = vec![
            VerbosityLevel::Quiet,
            VerbosityLevel::Normal,
            VerbosityLevel::Verbose,
            VerbosityLevel::Debug,
        ];

        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let deserialized: VerbosityLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, level);
        }
    }

    #[test]
    fn test_action_type_display() {
        assert_eq!(
            format!("{}", ActionType::FileSystem("fs.read.v1".to_string())),
            "FileSystem(fs.read.v1)"
        );
        assert_eq!(
            format!("{}", ActionType::Http("http.fetch.v1".to_string())),
            "Http(http.fetch.v1)"
        );
        assert_eq!(
            format!("{}", ActionType::Shell("shell.exec.v1".to_string())),
            "Shell(shell.exec.v1)"
        );
        assert_eq!(
            format!("{}", ActionType::Research("research.web".to_string())),
            "Research(research.web)"
        );
        assert_eq!(
            format!("{}", ActionType::Planning("planning.v1".to_string())),
            "Planning(planning.v1)"
        );
        assert_eq!(
            format!("{}", ActionType::Analysis("analysis.v1".to_string())),
            "Analysis(analysis.v1)"
        );
        assert_eq!(
            format!("{}", ActionType::Custom("custom.cap".to_string())),
            "Custom(custom.cap)"
        );
    }

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.backoff_strategy, BackoffStrategy::Exponential);
        assert_eq!(policy.base_delay_ms, 1000);
        assert_eq!(policy.max_delay_ms, 30000);
    }

    #[test]
    fn test_backoff_strategy_serialization() {
        let strategies = vec![
            BackoffStrategy::Fixed,
            BackoffStrategy::Linear,
            BackoffStrategy::Exponential,
            BackoffStrategy::Jittered,
        ];

        for strategy in strategies {
            let json = serde_json::to_string(&strategy).unwrap();
            let deserialized: BackoffStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, strategy);
        }
    }

    #[test]
    fn test_action_status_serialization() {
        let statuses = vec![
            ActionStatus::Pending,
            ActionStatus::Running,
            ActionStatus::Completed,
            ActionStatus::Failed,
            ActionStatus::Cancelled,
            ActionStatus::Skipped,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: ActionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_resource_usage_default() {
        let usage = ResourceUsage::default();
        assert_eq!(usage.cpu_ms, 0);
        assert_eq!(usage.memory_bytes, 0);
        assert_eq!(usage.fs_operations, 0);
        assert_eq!(usage.network_requests, 0);
    }

    #[test]
    fn test_workflow_status_serialization() {
        let statuses = vec![
            WorkflowStatus::Initializing,
            WorkflowStatus::Planning,
            WorkflowStatus::Executing,
            WorkflowStatus::Completed,
            WorkflowStatus::Failed,
            WorkflowStatus::Cancelled,
            WorkflowStatus::Paused,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: WorkflowStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_user_action_type_serialization() {
        let action_types = vec![
            UserActionType::Continue,
            UserActionType::Pause,
            UserActionType::Stop,
            UserActionType::ModifyParameters,
            UserActionType::AddAction,
            UserActionType::RemoveAction,
            UserActionType::OverrideResult,
            UserActionType::Escalate,
        ];

        for action_type in action_types {
            let json = serde_json::to_string(&action_type).unwrap();
            let deserialized: UserActionType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, action_type);
        }
    }

    #[test]
    fn test_action_error_creation() {
        let error = ActionError {
            code: "E001".to_string(),
            message: "Test error".to_string(),
            details: Some(json!({"info": "details"})),
            retryable: true,
        };

        assert_eq!(error.code, "E001");
        assert!(error.retryable);

        let json = serde_json::to_value(&error).unwrap();
        let deserialized: ActionError = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.code, "E001");
    }

    #[test]
    fn test_guard_result_creation() {
        let result = GuardResult {
            allowed: true,
            reason: "All checks passed".to_string(),
            violations: vec![],
            modifications: vec![],
        };

        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_security_violation_creation() {
        let violation = SecurityViolation {
            violation_type: "path_traversal".to_string(),
            severity: RiskLevel::High,
            description: "Attempted path traversal".to_string(),
            remediation: "Use absolute paths".to_string(),
        };

        assert_eq!(violation.severity, RiskLevel::High);
    }

    #[test]
    fn test_stall_info_creation() {
        let stall_info = StallInfo {
            stalled: true,
            time_since_progress_ms: 45000,
            possible_causes: vec!["Network timeout".to_string()],
            suggested_interventions: vec!["Retry operation".to_string()],
        };

        assert!(stall_info.stalled);
        assert_eq!(stall_info.time_since_progress_ms, 45000);
    }

    #[test]
    fn test_menu_option_creation() {
        let option = MenuOption {
            id: "opt-1".to_string(),
            text: "Continue".to_string(),
            description: "Continue execution".to_string(),
            requires_input: false,
        };

        assert_eq!(option.id, "opt-1");
        assert!(!option.requires_input);
    }

    #[test]
    fn test_workflow_action_add_dependency_no_duplicates() {
        let mut action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({}),
            "Test".to_string(),
        );

        action.add_dependency("dep-1".to_string());
        action.add_dependency("dep-1".to_string()); // Try to add duplicate

        assert_eq!(action.dependencies.len(), 1);
    }

    #[test]
    fn test_planning_result_creation() {
        let result = PlanningResult {
            actions: vec![],
            strategy: "Sequential execution".to_string(),
            risks: vec![],
            success_criteria: vec!["Task completed".to_string()],
            confidence: 0.85,
        };

        assert_eq!(result.confidence, 0.85);
        assert!(result.actions.is_empty());
    }

    #[test]
    fn test_research_finding_creation() {
        let finding = ResearchFinding {
            title: "Test Finding".to_string(),
            description: "A test finding".to_string(),
            evidence: vec!["Evidence 1".to_string()],
            relevance: 0.9,
        };

        assert_eq!(finding.relevance, 0.9);
    }

    #[test]
    fn test_user_action_creation() {
        let action = UserAction {
            action_type: UserActionType::Continue,
            input: None,
            reason: "User approved".to_string(),
        };

        assert_eq!(action.action_type, UserActionType::Continue);
        assert!(action.input.is_none());
    }

    #[test]
    fn test_action_modification_creation() {
        let modification = ActionModification {
            field: "path".to_string(),
            suggested_value: json!("/safe/path"),
            reason: "Original path was dangerous".to_string(),
        };

        assert_eq!(modification.field, "path");
    }

    #[test]
    fn test_execution_environment_creation() {
        let env = ExecutionEnvironment {
            executor_id: "exec-123".to_string(),
            sandbox_mode: "landlock".to_string(),
            security_context: HashMap::new(),
        };

        assert_eq!(env.executor_id, "exec-123");
        assert_eq!(env.sandbox_mode, "landlock");
    }

    #[test]
    fn test_action_metadata_creation() {
        let metadata = ActionMetadata {
            retry_count: 2,
            resource_usage: ResourceUsage::default(),
            environment: ExecutionEnvironment {
                executor_id: "exec-1".to_string(),
                sandbox_mode: "none".to_string(),
                security_context: HashMap::new(),
            },
        };

        assert_eq!(metadata.retry_count, 2);
    }

    // === Additional serialization tests ===

    #[test]
    fn test_action_result_serialization() {
        let result = ActionResult {
            action_id: "action-123".to_string(),
            status: ActionStatus::Completed,
            output: Some(json!({"result": "success"})),
            error: None,
            metadata: ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage::default(),
                environment: ExecutionEnvironment {
                    executor_id: "exec-1".to_string(),
                    sandbox_mode: "none".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("action-123"));
        let parsed: ActionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action_id, "action-123");
        assert_eq!(parsed.status, ActionStatus::Completed);
    }

    #[test]
    fn test_action_result_with_error() {
        let result = ActionResult {
            action_id: "action-456".to_string(),
            status: ActionStatus::Failed,
            output: None,
            error: Some(ActionError {
                code: "TIMEOUT".to_string(),
                message: "Operation timed out".to_string(),
                details: Some(json!({"elapsed_ms": 30000})),
                retryable: true,
            }),
            metadata: ActionMetadata {
                retry_count: 3,
                resource_usage: ResourceUsage::default(),
                environment: ExecutionEnvironment {
                    executor_id: "exec-1".to_string(),
                    sandbox_mode: "none".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("TIMEOUT"));
        let parsed: ActionResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, "TIMEOUT");
    }

    #[test]
    fn test_risk_level_serialization() {
        let levels = vec![
            (RiskLevel::Low, "low"),
            (RiskLevel::Medium, "medium"),
            (RiskLevel::High, "high"),
            (RiskLevel::Critical, "critical"),
        ];

        for (level, expected) in levels {
            let json = serde_json::to_string(&level).unwrap();
            assert!(json.contains(expected));
            let parsed: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, level);
        }
    }

    #[test]
    fn test_risk_assessment_serialization() {
        let assessment = RiskAssessment {
            description: "Data loss risk".to_string(),
            level: RiskLevel::High,
            mitigation: "Enable backups".to_string(),
            impact: "Potential data corruption".to_string(),
        };

        let json = serde_json::to_string(&assessment).unwrap();
        assert!(json.contains("Data loss risk"));
        let parsed: RiskAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.level, RiskLevel::High);
    }

    #[test]
    fn test_research_result_serialization() {
        let result = ResearchResult {
            findings: vec![ResearchFinding {
                title: "Finding 1".to_string(),
                description: "Test finding".to_string(),
                evidence: vec!["Source 1".to_string()],
                relevance: 0.85,
            }],
            recommendations: vec!["Recommendation 1".to_string()],
            confidence: 0.9,
            sources: vec!["https://example.com".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Finding 1"));
        let parsed: ResearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.confidence, 0.9);
        assert_eq!(parsed.findings.len(), 1);
    }

    #[test]
    fn test_menu_interaction_serialization() {
        let interaction = MenuInteraction {
            options: vec![MenuOption {
                id: "opt-1".to_string(),
                text: "Continue".to_string(),
                description: "Continue execution".to_string(),
                requires_input: false,
            }],
            context: MenuContext {
                workflow_state: WorkflowStatus::Executing,
                recent_actions: vec![],
                stall_info: None,
                available_capabilities: vec!["fs.read.v1".to_string()],
            },
            timeout_ms: 60000,
        };

        let json = serde_json::to_string(&interaction).unwrap();
        assert!(json.contains("opt-1"));
        let parsed: MenuInteraction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.timeout_ms, 60000);
        assert_eq!(parsed.options.len(), 1);
    }

    #[test]
    fn test_menu_context_serialization() {
        let context = MenuContext {
            workflow_state: WorkflowStatus::Paused,
            recent_actions: vec![],
            stall_info: Some(StallInfo {
                stalled: true,
                time_since_progress_ms: 30000,
                possible_causes: vec!["Network issue".to_string()],
                suggested_interventions: vec!["Retry".to_string()],
            }),
            available_capabilities: vec!["http.fetch.v1".to_string()],
        };

        let json = serde_json::to_string(&context).unwrap();
        assert!(json.contains("paused"));
        let parsed: MenuContext = serde_json::from_str(&json).unwrap();
        assert!(parsed.stall_info.is_some());
        assert_eq!(parsed.workflow_state, WorkflowStatus::Paused);
    }

    #[test]
    fn test_action_type_serialization_all_variants() {
        let types = vec![
            ActionType::FileSystem("fs.read.v1".to_string()),
            ActionType::Http("http.fetch.v1".to_string()),
            ActionType::Shell("shell.exec.v1".to_string()),
            ActionType::Research("research.v1".to_string()),
            ActionType::Planning("planning.v1".to_string()),
            ActionType::Analysis("analysis.v1".to_string()),
            ActionType::Custom("custom.v1".to_string()),
        ];

        for action_type in types {
            let json = serde_json::to_string(&action_type).unwrap();
            let parsed: ActionType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action_type);
        }
    }

    #[test]
    fn test_workflow_action_serialization() {
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/test.txt"}),
            "Read test file".to_string(),
        );

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("Read test file"));
        let parsed: WorkflowAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.expected_outcome, "Read test file");
    }

    #[test]
    fn test_retry_policy_serialization() {
        let policy = RetryPolicy {
            max_retries: 5,
            backoff_strategy: BackoffStrategy::Jittered,
            base_delay_ms: 500,
            max_delay_ms: 10000,
        };

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("jittered"));
        let parsed: RetryPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_retries, 5);
        assert_eq!(parsed.backoff_strategy, BackoffStrategy::Jittered);
    }

    #[test]
    fn test_resource_limits_serialization() {
        let limits = ResourceLimits {
            max_memory_mb: 1024,
            max_cpu_seconds: 600,
            max_fs_operations: 5000,
            max_network_requests: 500,
            max_parallel_executions: 8,
        };

        let json = serde_json::to_string(&limits).unwrap();
        assert!(json.contains("1024"));
        let parsed: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_memory_mb, 1024);
        assert_eq!(parsed.max_parallel_executions, 8);
    }

    #[test]
    fn test_execution_preferences_serialization() {
        let prefs = ExecutionPreferences {
            verbosity: VerbosityLevel::Debug,
            interactive: true,
            continue_on_error: true,
            stall_detection_ms: 60000,
            auto_escalation: false,
            user_intervention_timeout_s: 120,
        };

        let json = serde_json::to_string(&prefs).unwrap();
        assert!(json.contains("debug"));
        let parsed: ExecutionPreferences = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verbosity, VerbosityLevel::Debug);
        assert!(parsed.interactive);
    }

    #[test]
    fn test_resource_usage_serialization() {
        let usage = ResourceUsage {
            cpu_ms: 5000,
            memory_bytes: 1024 * 1024 * 100,
            fs_operations: 50,
            network_requests: 10,
        };

        let json = serde_json::to_string(&usage).unwrap();
        let parsed: ResourceUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cpu_ms, 5000);
        assert_eq!(parsed.fs_operations, 50);
    }

    #[test]
    fn test_execution_environment_serialization() {
        let mut security_context = HashMap::new();
        security_context.insert("user".to_string(), json!("test_user"));
        security_context.insert("permissions".to_string(), json!(["read", "write"]));

        let env = ExecutionEnvironment {
            executor_id: "exec-789".to_string(),
            sandbox_mode: "landlock".to_string(),
            security_context,
        };

        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("exec-789"));
        let parsed: ExecutionEnvironment = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.executor_id, "exec-789");
        assert!(parsed.security_context.contains_key("user"));
    }

    #[test]
    fn test_planning_result_serialization() {
        let result = PlanningResult {
            actions: vec![WorkflowAction::new(
                ActionType::Research("research.v1".to_string()),
                json!({}),
                "Research phase".to_string(),
            )],
            strategy: "Multi-phase approach".to_string(),
            risks: vec![RiskAssessment {
                description: "Time risk".to_string(),
                level: RiskLevel::Low,
                mitigation: "Monitor closely".to_string(),
                impact: "Delay".to_string(),
            }],
            success_criteria: vec!["Complete all actions".to_string()],
            confidence: 0.95,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Multi-phase approach"));
        let parsed: PlanningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.confidence, 0.95);
        assert_eq!(parsed.actions.len(), 1);
    }

    #[test]
    fn test_guard_result_serialization() {
        let result = GuardResult {
            allowed: false,
            reason: "Path traversal detected".to_string(),
            violations: vec![SecurityViolation {
                violation_type: "path_traversal".to_string(),
                severity: RiskLevel::Critical,
                description: "Attempted to access parent directory".to_string(),
                remediation: "Use absolute paths only".to_string(),
            }],
            modifications: vec![ActionModification {
                field: "path".to_string(),
                suggested_value: json!("/safe/path"),
                reason: "Sanitized path".to_string(),
            }],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("path_traversal"));
        let parsed: GuardResult = serde_json::from_str(&json).unwrap();
        assert!(!parsed.allowed);
        assert_eq!(parsed.violations.len(), 1);
    }

    #[test]
    fn test_user_action_serialization() {
        let action = UserAction {
            action_type: UserActionType::ModifyParameters,
            input: Some(json!({"new_timeout": 60000})),
            reason: "Increased timeout for slow operation".to_string(),
        };

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("modify_parameters"));
        let parsed: UserAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action_type, UserActionType::ModifyParameters);
        assert!(parsed.input.is_some());
    }

    #[test]
    fn test_stall_info_serialization() {
        let info = StallInfo {
            stalled: true,
            time_since_progress_ms: 90000,
            possible_causes: vec!["Deadlock".to_string(), "Resource exhaustion".to_string()],
            suggested_interventions: vec!["Restart".to_string(), "Increase resources".to_string()],
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Deadlock"));
        let parsed: StallInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.stalled);
        assert_eq!(parsed.possible_causes.len(), 2);
    }

    #[test]
    fn test_action_metadata_serialization() {
        let metadata = ActionMetadata {
            retry_count: 2,
            resource_usage: ResourceUsage {
                cpu_ms: 1000,
                memory_bytes: 512000,
                fs_operations: 5,
                network_requests: 2,
            },
            environment: ExecutionEnvironment {
                executor_id: "exec-test".to_string(),
                sandbox_mode: "seccomp".to_string(),
                security_context: HashMap::new(),
            },
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("exec-test"));
        let parsed: ActionMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.retry_count, 2);
        assert_eq!(parsed.resource_usage.cpu_ms, 1000);
    }

    #[test]
    fn test_workflow_action_with_timeout() {
        let mut action = WorkflowAction::new(
            ActionType::Http("http.fetch.v1".to_string()),
            json!({"url": "https://api.example.com"}),
            "Fetch API data".to_string(),
        );
        action.timeout_ms = Some(30000);

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("30000"));
        let parsed: WorkflowAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.timeout_ms, Some(30000));
    }

    #[test]
    fn test_workflow_action_can_execute_empty_deps() {
        let action = WorkflowAction::new(
            ActionType::Analysis("analysis.v1".to_string()),
            json!({}),
            "Analyze data".to_string(),
        );

        // No dependencies, can always execute
        assert!(action.can_execute(&[]));
        assert!(action.can_execute(&["other-action".to_string()]));
    }

    #[test]
    fn test_parameter_validation_whitespace_goal() {
        let params = PlannerExecParams {
            workflow_id: "test".to_string(),
            goal: "   ".to_string(), // Only whitespace
            workflow_type: WorkflowType::Simple,
            max_steps: 10,
            timeout_ms: None,
            context: HashMap::new(),
            allowed_capabilities: vec![],
            resource_limits: ResourceLimits::default(),
            preferences: ExecutionPreferences::default(),
        };

        assert!(params.validate().is_err());
    }

    #[test]
    fn test_security_violation_serialization() {
        let violation = SecurityViolation {
            violation_type: "command_injection".to_string(),
            severity: RiskLevel::Critical,
            description: "Potential command injection detected".to_string(),
            remediation: "Escape special characters".to_string(),
        };

        let json = serde_json::to_string(&violation).unwrap();
        assert!(json.contains("command_injection"));
        let parsed: SecurityViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.severity, RiskLevel::Critical);
    }

    #[test]
    fn test_action_modification_serialization() {
        let modification = ActionModification {
            field: "command".to_string(),
            suggested_value: json!("safe_command --arg1 value"),
            reason: "Sanitized user input".to_string(),
        };

        let json = serde_json::to_string(&modification).unwrap();
        assert!(json.contains("safe_command"));
        let parsed: ActionModification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.field, "command");
    }

    #[test]
    fn test_research_finding_serialization() {
        let finding = ResearchFinding {
            title: "API Endpoint Discovery".to_string(),
            description: "Found REST API endpoints".to_string(),
            evidence: vec!["/api/v1/users".to_string(), "/api/v1/items".to_string()],
            relevance: 0.92,
        };

        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("API Endpoint Discovery"));
        let parsed: ResearchFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.evidence.len(), 2);
        assert_eq!(parsed.relevance, 0.92);
    }
}
