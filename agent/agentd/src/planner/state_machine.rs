/*!
# State Machine Engine

Implements a deterministic 6-state workflow management system for planner-executor coordination.

## State Diagram

```text
┌─────────────┐   validate   ┌─────────────┐   plan      ┌─────────────┐
│             │─────────────→│             │────────────→│             │
│Initializing │              │  Planning   │             │ Executing   │
│             │←─────────────│             │←────────────│             │
└─────────────┘   retry      └─────────────┘   replan    └─────────────┘
       │                            │                            │
       │ fail                       │ fail                       │ execute
       ↓                            ↓                            ↓
┌─────────────┐                                        ┌─────────────┐
│             │                                        │             │
│   Failed    │                                        │ Evaluating  │
│             │                                        │             │
└─────────────┘                                        └─────────────┘
                                                              │     │
                                                        success│     │fail/retry
                                                              ↓     ↓
                                                       ┌─────────────┐
                                                       │             │
                                                       │ Completed   │
                                                       │             │
                                                       └─────────────┘
```

## State Descriptions

- **Initializing**: Initial validation and setup
- **Planning**: AI-powered planning with oracle system
- **Executing**: Parallel execution of planned operations
- **Evaluating**: Result evaluation against goals
- **Completed**: Successful workflow completion
- **Failed**: Terminal failure state

## Transitions

All state transitions are logged with timestamps, reasons, and metadata for full auditability.
*/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Workflow state machine states
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkflowState {
    /// Initial state - performing validation and setup
    Initializing,
    /// Planning state - using AI oracle for execution planning
    Planning,
    /// Execution state - running planned operations
    Executing,
    /// Evaluation state - assessing results against goals
    Evaluating,
    /// Terminal success state
    Completed,
    /// Terminal failure state
    Failed,
}

/// Types of workflows supported
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowType {
    /// Simple workflow - direct execution without complex planning
    Simple,
    /// Research and planning workflow - extensive analysis before execution
    ResearchAndPlanning,
    /// Complex orchestration - multi-phase execution with coordination
    ComplexOrchestration,
}

/// State transition record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Source state
    pub from: WorkflowState,
    /// Destination state
    pub to: WorkflowState,
    /// Transition timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Reason for transition
    pub reason: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// State machine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachineConfig {
    /// Maximum number of retries per state
    pub max_retries_per_state: u32,
    /// Maximum total workflow duration (seconds)
    pub max_workflow_duration_seconds: u64,
    /// Enable detailed transition logging
    pub enable_detailed_logging: bool,
    /// State-specific timeouts
    pub state_timeouts: HashMap<WorkflowState, u64>,
}

/// State machine engine
#[derive(Debug, Clone)]
pub struct StateMachine {
    config: StateMachineConfig,
    state_history: HashMap<Uuid, Vec<StateTransition>>,
    state_metrics: HashMap<WorkflowState, StateMetrics>,
}

/// Metrics for each state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateMetrics {
    pub total_entries: u64,
    pub total_duration_ms: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub retry_count: u64,
}

/// State transition validation result
#[derive(Debug, Clone)]
pub struct TransitionValidation {
    pub valid: bool,
    pub reason: String,
    pub suggested_action: Option<String>,
}

/// Workflow execution context for state machine
#[derive(Debug, Clone)]
pub struct WorkflowExecutionContext {
    pub workflow_id: Uuid,
    pub current_state: WorkflowState,
    pub workflow_type: WorkflowType,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub last_transition_at: chrono::DateTime<chrono::Utc>,
    pub retry_count: HashMap<WorkflowState, u32>,
    pub execution_metadata: HashMap<String, String>,
}

impl Default for StateMachineConfig {
    fn default() -> Self {
        let mut state_timeouts = HashMap::new();
        state_timeouts.insert(WorkflowState::Initializing, 300); // 5 minutes
        state_timeouts.insert(WorkflowState::Planning, 1800); // 30 minutes
        state_timeouts.insert(WorkflowState::Executing, 3600); // 1 hour
        state_timeouts.insert(WorkflowState::Evaluating, 600); // 10 minutes

        Self {
            max_retries_per_state: 3,
            max_workflow_duration_seconds: 14400, // 4 hours
            enable_detailed_logging: true,
            state_timeouts,
        }
    }
}

impl StateMachine {
    /// Create new state machine
    pub fn new() -> Self {
        Self::with_config(StateMachineConfig::default())
    }

    /// Create state machine with custom configuration
    pub fn with_config(config: StateMachineConfig) -> Self {
        Self {
            config,
            state_history: HashMap::new(),
            state_metrics: HashMap::new(),
        }
    }

    /// Validate state transition
    pub fn validate_transition(
        &self,
        from: &WorkflowState,
        to: &WorkflowState,
        workflow_type: &WorkflowType,
    ) -> TransitionValidation {
        use WorkflowState::*;

        let valid_transitions = match (from, to) {
            // From Initializing
            (Initializing, Planning) => true,
            (Initializing, Failed) => true,

            // From Planning
            (Planning, Executing) => true,
            (Planning, Planning) => true, // Retry planning
            (Planning, Failed) => true,

            // From Executing
            (Executing, Evaluating) => true,
            (Executing, Executing) => true, // Retry execution
            (Executing, Planning) => true,  // Replan if execution fails
            (Executing, Failed) => true,

            // From Evaluating
            (Evaluating, Completed) => true,
            (Evaluating, Planning) => true, // Replan if goals not met
            (Evaluating, Failed) => true,

            // Terminal states
            (Completed, _) => false, // No transitions from completed
            (Failed, _) => false,    // No transitions from failed

            // All other transitions invalid
            _ => false,
        };

        if valid_transitions {
            TransitionValidation {
                valid: true,
                reason: format!("Valid transition from {:?} to {:?}", from, to),
                suggested_action: None,
            }
        } else {
            TransitionValidation {
                valid: false,
                reason: format!("Invalid transition from {:?} to {:?}", from, to),
                suggested_action: Some(self.suggest_valid_transitions(from, workflow_type)),
            }
        }
    }

    /// Get valid transitions from current state
    pub fn get_valid_transitions(&self, from: &WorkflowState) -> Vec<WorkflowState> {
        use WorkflowState::*;

        match from {
            Initializing => vec![Planning, Failed],
            Planning => vec![Executing, Planning, Failed],
            Executing => vec![Evaluating, Executing, Planning, Failed],
            Evaluating => vec![Completed, Planning, Failed],
            Completed => vec![], // Terminal state
            Failed => vec![],    // Terminal state
        }
    }

    /// Suggest valid transitions as string
    fn suggest_valid_transitions(
        &self,
        from: &WorkflowState,
        _workflow_type: &WorkflowType,
    ) -> String {
        let valid = self.get_valid_transitions(from);
        if valid.is_empty() {
            "No valid transitions (terminal state)".to_string()
        } else {
            format!("Valid transitions: {:?}", valid)
        }
    }

    /// Execute state transition
    pub async fn transition(
        &mut self,
        workflow_id: Uuid,
        from: WorkflowState,
        to: WorkflowState,
        reason: String,
        workflow_type: WorkflowType,
        metadata: HashMap<String, String>,
    ) -> Result<StateTransition> {
        // Validate transition
        let validation = self.validate_transition(&from, &to, &workflow_type);
        if !validation.valid {
            return Err(anyhow::anyhow!(
                "Invalid state transition: {}. {}",
                validation.reason,
                validation.suggested_action.unwrap_or_default()
            ));
        }

        // Create transition record
        let transition = StateTransition {
            from: from.clone(),
            to: to.clone(),
            timestamp: chrono::Utc::now(),
            reason,
            metadata,
        };

        // Record transition in history
        self.state_history
            .entry(workflow_id)
            .or_insert_with(Vec::new)
            .push(transition.clone());

        // Update metrics
        self.update_state_metrics(&from, &to, &transition);

        // Log transition
        if self.config.enable_detailed_logging {
            info!(
                workflow_id = %workflow_id,
                from = ?from,
                to = ?to,
                reason = %transition.reason,
                "State transition executed"
            );
        }

        Ok(transition)
    }

    /// Update state metrics
    fn update_state_metrics(
        &mut self,
        from: &WorkflowState,
        to: &WorkflowState,
        transition: &StateTransition,
    ) {
        // Update source state metrics
        let from_metrics = self.state_metrics.entry(from.clone()).or_default();

        if to != from {
            // State exit
            match to {
                WorkflowState::Failed => from_metrics.failure_count += 1,
                _ => from_metrics.success_count += 1,
            }
        } else {
            // Retry in same state
            from_metrics.retry_count += 1;
        }

        // Update destination state metrics
        let to_metrics = self.state_metrics.entry(to.clone()).or_default();
        to_metrics.total_entries += 1;
    }

    /// Get workflow state history
    pub fn get_state_history(&self, workflow_id: Uuid) -> Option<&Vec<StateTransition>> {
        self.state_history.get(&workflow_id)
    }

    /// Get current state for workflow
    pub fn get_current_state(&self, workflow_id: Uuid) -> Option<WorkflowState> {
        self.state_history
            .get(&workflow_id)?
            .last()
            .map(|transition| transition.to.clone())
    }

    /// Check if workflow is in terminal state
    pub fn is_terminal_state(&self, state: &WorkflowState) -> bool {
        matches!(state, WorkflowState::Completed | WorkflowState::Failed)
    }

    /// Check for state timeout
    pub fn check_state_timeout(
        &self,
        workflow_id: Uuid,
        current_state: &WorkflowState,
    ) -> Option<chrono::Duration> {
        let history = self.state_history.get(&workflow_id)?;
        let last_transition = history.last()?;

        // Only check timeout if we're still in the same state as last transition
        if &last_transition.to != current_state {
            return None;
        }

        let timeout_seconds = self.config.state_timeouts.get(current_state)?;
        let elapsed = chrono::Utc::now() - last_transition.timestamp;
        let timeout = chrono::Duration::seconds(*timeout_seconds as i64);

        if elapsed > timeout {
            Some(elapsed - timeout)
        } else {
            None
        }
    }

    /// Get retry count for workflow in specific state
    pub fn get_retry_count(&self, workflow_id: Uuid, state: &WorkflowState) -> u32 {
        let history = match self.state_history.get(&workflow_id) {
            Some(history) => history,
            None => return 0,
        };

        history
            .iter()
            .filter(|transition| &transition.from == state && &transition.to == state)
            .count() as u32
    }

    /// Check if max retries exceeded for state
    pub fn is_max_retries_exceeded(&self, workflow_id: Uuid, state: &WorkflowState) -> bool {
        self.get_retry_count(workflow_id, state) >= self.config.max_retries_per_state
    }

    /// Get state metrics
    pub fn get_state_metrics(&self, state: &WorkflowState) -> Option<&StateMetrics> {
        self.state_metrics.get(state)
    }

    /// Get all state metrics
    pub fn get_all_state_metrics(&self) -> &HashMap<WorkflowState, StateMetrics> {
        &self.state_metrics
    }

    /// Clean up completed workflow history
    pub fn cleanup_workflow(&mut self, workflow_id: Uuid) {
        if let Some(history) = self.state_history.remove(&workflow_id) {
            debug!(
                workflow_id = %workflow_id,
                transitions = history.len(),
                "Cleaned up workflow state history"
            );
        }
    }

    /// Get workflow execution summary
    pub fn get_workflow_summary(&self, workflow_id: Uuid) -> Option<WorkflowExecutionSummary> {
        let history = self.state_history.get(&workflow_id)?;
        if history.is_empty() {
            return None;
        }

        let started_at = history.first()?.timestamp;
        let completed_at = history.last()?.timestamp;
        let duration = completed_at - started_at;
        let final_state = history.last()?.to.clone();

        // Count state visits
        let mut state_visits = HashMap::new();
        for transition in history {
            *state_visits.entry(transition.to.clone()).or_insert(0) += 1;
        }

        // Count retries
        let mut retries = HashMap::new();
        for transition in history {
            if transition.from == transition.to {
                *retries.entry(transition.from.clone()).or_insert(0) += 1;
            }
        }

        Some(WorkflowExecutionSummary {
            workflow_id,
            started_at,
            completed_at,
            duration,
            final_state: final_state.clone(),
            total_transitions: history.len(),
            state_visits,
            retries,
            success: matches!(final_state, WorkflowState::Completed),
        })
    }

    /// Export state machine metrics
    pub fn export_metrics(&self) -> StateMachineMetrics {
        StateMachineMetrics {
            total_workflows: self.state_history.len(),
            active_workflows: self
                .state_history
                .values()
                .filter(|history| {
                    history
                        .last()
                        .map(|t| !self.is_terminal_state(&t.to))
                        .unwrap_or(false)
                })
                .count(),
            state_metrics: self.state_metrics.clone(),
            config: self.config.clone(),
        }
    }
}

/// Workflow execution summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecutionSummary {
    pub workflow_id: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub duration: chrono::Duration,
    pub final_state: WorkflowState,
    pub total_transitions: usize,
    pub state_visits: HashMap<WorkflowState, u32>,
    pub retries: HashMap<WorkflowState, u32>,
    pub success: bool,
}

/// State machine metrics export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachineMetrics {
    pub total_workflows: usize,
    pub active_workflows: usize,
    pub state_metrics: HashMap<WorkflowState, StateMetrics>,
    pub config: StateMachineConfig,
}

impl fmt::Display for WorkflowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_str = match self {
            WorkflowState::Initializing => "INIT",
            WorkflowState::Planning => "PLAN",
            WorkflowState::Executing => "EXEC",
            WorkflowState::Evaluating => "EVAL",
            WorkflowState::Completed => "DONE",
            WorkflowState::Failed => "FAIL",
        };
        write!(f, "{}", state_str)
    }
}

impl fmt::Display for WorkflowType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_str = match self {
            WorkflowType::Simple => "Simple",
            WorkflowType::ResearchAndPlanning => "Research+Planning",
            WorkflowType::ComplexOrchestration => "Complex",
        };
        write!(f, "{}", type_str)
    }
}

impl WorkflowType {
    /// Get recommended configuration for workflow type
    pub fn get_recommended_config(&self) -> StateMachineConfig {
        let mut config = StateMachineConfig::default();

        match self {
            WorkflowType::Simple => {
                config.max_retries_per_state = 1;
                config.max_workflow_duration_seconds = 1800; // 30 minutes
                config.state_timeouts.insert(WorkflowState::Planning, 300); // 5 minutes
            }
            WorkflowType::ResearchAndPlanning => {
                config.max_retries_per_state = 3;
                config.max_workflow_duration_seconds = 7200; // 2 hours
                config.state_timeouts.insert(WorkflowState::Planning, 3600); // 1 hour
            }
            WorkflowType::ComplexOrchestration => {
                config.max_retries_per_state = 5;
                config.max_workflow_duration_seconds = 28800; // 8 hours
                config.state_timeouts.insert(WorkflowState::Planning, 1800); // 30 minutes
                config.state_timeouts.insert(WorkflowState::Executing, 7200); // 2 hours
            }
        }

        config
    }

    /// Check if workflow type supports feature
    pub fn supports_feature(&self, feature: &str) -> bool {
        match (self, feature) {
            (_, "basic_execution") => true,
            (WorkflowType::Simple, "complex_planning") => false,
            (WorkflowType::ResearchAndPlanning, "deep_research") => true,
            (WorkflowType::ComplexOrchestration, "parallel_execution") => true,
            (WorkflowType::ComplexOrchestration, "coordination") => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_machine_creation() {
        let sm = StateMachine::new();
        assert!(sm.state_history.is_empty());
        assert!(sm.state_metrics.is_empty());
    }

    #[test]
    fn test_state_machine_with_config() {
        let mut config = StateMachineConfig::default();
        config.max_retries_per_state = 5;
        config.enable_detailed_logging = false;

        let sm = StateMachine::with_config(config);
        assert!(sm.state_history.is_empty());
        assert_eq!(sm.config.max_retries_per_state, 5);
        assert!(!sm.config.enable_detailed_logging);
    }

    #[test]
    fn test_valid_transitions() {
        let sm = StateMachine::new();

        // Test valid transitions
        let validation = sm.validate_transition(
            &WorkflowState::Initializing,
            &WorkflowState::Planning,
            &WorkflowType::Simple,
        );
        assert!(validation.valid);

        let validation = sm.validate_transition(
            &WorkflowState::Planning,
            &WorkflowState::Executing,
            &WorkflowType::Simple,
        );
        assert!(validation.valid);
    }

    #[test]
    fn test_invalid_transitions() {
        let sm = StateMachine::new();

        // Test invalid transition
        let validation = sm.validate_transition(
            &WorkflowState::Completed,
            &WorkflowState::Planning,
            &WorkflowType::Simple,
        );
        assert!(!validation.valid);
    }

    #[tokio::test]
    async fn test_state_transition() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        let transition = sm
            .transition(
                workflow_id,
                WorkflowState::Initializing,
                WorkflowState::Planning,
                "Test transition".to_string(),
                WorkflowType::Simple,
                HashMap::new(),
            )
            .await;

        assert!(transition.is_ok());

        let current = sm.get_current_state(workflow_id);
        assert_eq!(current, Some(WorkflowState::Planning));
    }

    #[test]
    fn test_workflow_type_features() {
        assert!(WorkflowType::Simple.supports_feature("basic_execution"));
        assert!(!WorkflowType::Simple.supports_feature("complex_planning"));
        assert!(WorkflowType::ResearchAndPlanning.supports_feature("deep_research"));
        assert!(WorkflowType::ComplexOrchestration.supports_feature("parallel_execution"));
    }

    #[test]
    fn test_retry_counting() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        // Simulate retry in planning state
        let transition1 = StateTransition {
            from: WorkflowState::Planning,
            to: WorkflowState::Planning,
            timestamp: chrono::Utc::now(),
            reason: "Retry".to_string(),
            metadata: HashMap::new(),
        };

        sm.state_history
            .entry(workflow_id)
            .or_default()
            .push(transition1);

        assert_eq!(sm.get_retry_count(workflow_id, &WorkflowState::Planning), 1);
    }

    #[test]
    fn test_terminal_states() {
        let sm = StateMachine::new();

        assert!(sm.is_terminal_state(&WorkflowState::Completed));
        assert!(sm.is_terminal_state(&WorkflowState::Failed));
        assert!(!sm.is_terminal_state(&WorkflowState::Planning));
    }

    // New tests for coverage improvement

    #[test]
    fn test_state_machine_config_default() {
        let config = StateMachineConfig::default();
        assert_eq!(config.max_retries_per_state, 3);
        assert_eq!(config.max_workflow_duration_seconds, 14400);
        assert!(config.enable_detailed_logging);
        assert_eq!(
            config.state_timeouts.get(&WorkflowState::Initializing),
            Some(&300)
        );
        assert_eq!(
            config.state_timeouts.get(&WorkflowState::Planning),
            Some(&1800)
        );
        assert_eq!(
            config.state_timeouts.get(&WorkflowState::Executing),
            Some(&3600)
        );
        assert_eq!(
            config.state_timeouts.get(&WorkflowState::Evaluating),
            Some(&600)
        );
    }

    #[test]
    fn test_get_valid_transitions_initializing() {
        let sm = StateMachine::new();
        let valid = sm.get_valid_transitions(&WorkflowState::Initializing);
        assert_eq!(valid.len(), 2);
        assert!(valid.contains(&WorkflowState::Planning));
        assert!(valid.contains(&WorkflowState::Failed));
    }

    #[test]
    fn test_get_valid_transitions_planning() {
        let sm = StateMachine::new();
        let valid = sm.get_valid_transitions(&WorkflowState::Planning);
        assert_eq!(valid.len(), 3);
        assert!(valid.contains(&WorkflowState::Executing));
        assert!(valid.contains(&WorkflowState::Planning));
        assert!(valid.contains(&WorkflowState::Failed));
    }

    #[test]
    fn test_get_valid_transitions_executing() {
        let sm = StateMachine::new();
        let valid = sm.get_valid_transitions(&WorkflowState::Executing);
        assert_eq!(valid.len(), 4);
        assert!(valid.contains(&WorkflowState::Evaluating));
        assert!(valid.contains(&WorkflowState::Executing));
        assert!(valid.contains(&WorkflowState::Planning));
        assert!(valid.contains(&WorkflowState::Failed));
    }

    #[test]
    fn test_get_valid_transitions_evaluating() {
        let sm = StateMachine::new();
        let valid = sm.get_valid_transitions(&WorkflowState::Evaluating);
        assert_eq!(valid.len(), 3);
        assert!(valid.contains(&WorkflowState::Completed));
        assert!(valid.contains(&WorkflowState::Planning));
        assert!(valid.contains(&WorkflowState::Failed));
    }

    #[test]
    fn test_get_valid_transitions_terminal() {
        let sm = StateMachine::new();
        assert!(sm
            .get_valid_transitions(&WorkflowState::Completed)
            .is_empty());
        assert!(sm.get_valid_transitions(&WorkflowState::Failed).is_empty());
    }

    #[test]
    fn test_workflow_state_display() {
        assert_eq!(format!("{}", WorkflowState::Initializing), "INIT");
        assert_eq!(format!("{}", WorkflowState::Planning), "PLAN");
        assert_eq!(format!("{}", WorkflowState::Executing), "EXEC");
        assert_eq!(format!("{}", WorkflowState::Evaluating), "EVAL");
        assert_eq!(format!("{}", WorkflowState::Completed), "DONE");
        assert_eq!(format!("{}", WorkflowState::Failed), "FAIL");
    }

    #[test]
    fn test_workflow_type_display() {
        assert_eq!(format!("{}", WorkflowType::Simple), "Simple");
        assert_eq!(
            format!("{}", WorkflowType::ResearchAndPlanning),
            "Research+Planning"
        );
        assert_eq!(format!("{}", WorkflowType::ComplexOrchestration), "Complex");
    }

    #[test]
    fn test_workflow_type_recommended_config_simple() {
        let config = WorkflowType::Simple.get_recommended_config();
        assert_eq!(config.max_retries_per_state, 1);
        assert_eq!(config.max_workflow_duration_seconds, 1800);
        assert_eq!(
            config.state_timeouts.get(&WorkflowState::Planning),
            Some(&300)
        );
    }

    #[test]
    fn test_workflow_type_recommended_config_research() {
        let config = WorkflowType::ResearchAndPlanning.get_recommended_config();
        assert_eq!(config.max_retries_per_state, 3);
        assert_eq!(config.max_workflow_duration_seconds, 7200);
        assert_eq!(
            config.state_timeouts.get(&WorkflowState::Planning),
            Some(&3600)
        );
    }

    #[test]
    fn test_workflow_type_recommended_config_complex() {
        let config = WorkflowType::ComplexOrchestration.get_recommended_config();
        assert_eq!(config.max_retries_per_state, 5);
        assert_eq!(config.max_workflow_duration_seconds, 28800);
        assert_eq!(
            config.state_timeouts.get(&WorkflowState::Planning),
            Some(&1800)
        );
        assert_eq!(
            config.state_timeouts.get(&WorkflowState::Executing),
            Some(&7200)
        );
    }

    #[test]
    fn test_workflow_type_supports_feature_extended() {
        // Test coordination feature
        assert!(WorkflowType::ComplexOrchestration.supports_feature("coordination"));
        assert!(!WorkflowType::Simple.supports_feature("coordination"));
        assert!(!WorkflowType::ResearchAndPlanning.supports_feature("coordination"));

        // Test unknown features
        assert!(!WorkflowType::Simple.supports_feature("unknown_feature"));
        assert!(!WorkflowType::ResearchAndPlanning.supports_feature("unknown"));
        assert!(!WorkflowType::ComplexOrchestration.supports_feature("invalid"));
    }

    #[test]
    fn test_validate_transition_with_suggestion() {
        let sm = StateMachine::new();

        // Invalid transition should provide suggestion
        let validation = sm.validate_transition(
            &WorkflowState::Initializing,
            &WorkflowState::Completed,
            &WorkflowType::Simple,
        );
        assert!(!validation.valid);
        assert!(validation.suggested_action.is_some());
        let suggestion = validation.suggested_action.unwrap();
        assert!(suggestion.contains("Valid transitions"));
    }

    #[test]
    fn test_validate_all_valid_transitions() {
        let sm = StateMachine::new();

        // Initializing transitions
        assert!(
            sm.validate_transition(
                &WorkflowState::Initializing,
                &WorkflowState::Planning,
                &WorkflowType::Simple
            )
            .valid
        );
        assert!(
            sm.validate_transition(
                &WorkflowState::Initializing,
                &WorkflowState::Failed,
                &WorkflowType::Simple
            )
            .valid
        );

        // Planning transitions
        assert!(
            sm.validate_transition(
                &WorkflowState::Planning,
                &WorkflowState::Executing,
                &WorkflowType::Simple
            )
            .valid
        );
        assert!(
            sm.validate_transition(
                &WorkflowState::Planning,
                &WorkflowState::Planning,
                &WorkflowType::Simple
            )
            .valid
        );
        assert!(
            sm.validate_transition(
                &WorkflowState::Planning,
                &WorkflowState::Failed,
                &WorkflowType::Simple
            )
            .valid
        );

        // Executing transitions
        assert!(
            sm.validate_transition(
                &WorkflowState::Executing,
                &WorkflowState::Evaluating,
                &WorkflowType::Simple
            )
            .valid
        );
        assert!(
            sm.validate_transition(
                &WorkflowState::Executing,
                &WorkflowState::Executing,
                &WorkflowType::Simple
            )
            .valid
        );
        assert!(
            sm.validate_transition(
                &WorkflowState::Executing,
                &WorkflowState::Planning,
                &WorkflowType::Simple
            )
            .valid
        );
        assert!(
            sm.validate_transition(
                &WorkflowState::Executing,
                &WorkflowState::Failed,
                &WorkflowType::Simple
            )
            .valid
        );

        // Evaluating transitions
        assert!(
            sm.validate_transition(
                &WorkflowState::Evaluating,
                &WorkflowState::Completed,
                &WorkflowType::Simple
            )
            .valid
        );
        assert!(
            sm.validate_transition(
                &WorkflowState::Evaluating,
                &WorkflowState::Planning,
                &WorkflowType::Simple
            )
            .valid
        );
        assert!(
            sm.validate_transition(
                &WorkflowState::Evaluating,
                &WorkflowState::Failed,
                &WorkflowType::Simple
            )
            .valid
        );
    }

    #[test]
    fn test_is_max_retries_exceeded() {
        let mut sm = StateMachine::with_config(StateMachineConfig {
            max_retries_per_state: 2,
            ..StateMachineConfig::default()
        });
        let workflow_id = Uuid::new_v4();

        // No retries yet
        assert!(!sm.is_max_retries_exceeded(workflow_id, &WorkflowState::Planning));

        // Add 2 retry transitions
        for _ in 0..2 {
            sm.state_history
                .entry(workflow_id)
                .or_default()
                .push(StateTransition {
                    from: WorkflowState::Planning,
                    to: WorkflowState::Planning,
                    timestamp: chrono::Utc::now(),
                    reason: "Retry".to_string(),
                    metadata: HashMap::new(),
                });
        }

        // Now max retries exceeded
        assert!(sm.is_max_retries_exceeded(workflow_id, &WorkflowState::Planning));
    }

    #[test]
    fn test_get_state_metrics_empty() {
        let sm = StateMachine::new();
        assert!(sm.get_state_metrics(&WorkflowState::Planning).is_none());
    }

    #[test]
    fn test_get_all_state_metrics() {
        let sm = StateMachine::new();
        let all_metrics = sm.get_all_state_metrics();
        assert!(all_metrics.is_empty());
    }

    #[test]
    fn test_cleanup_workflow() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        // Add some history
        sm.state_history.insert(
            workflow_id,
            vec![StateTransition {
                from: WorkflowState::Initializing,
                to: WorkflowState::Planning,
                timestamp: chrono::Utc::now(),
                reason: "Start".to_string(),
                metadata: HashMap::new(),
            }],
        );

        assert!(sm.state_history.contains_key(&workflow_id));

        sm.cleanup_workflow(workflow_id);

        assert!(!sm.state_history.contains_key(&workflow_id));
    }

    #[test]
    fn test_cleanup_nonexistent_workflow() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        // Should not panic
        sm.cleanup_workflow(workflow_id);
    }

    #[test]
    fn test_get_state_history() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        // No history initially
        assert!(sm.get_state_history(workflow_id).is_none());

        // Add history
        sm.state_history.insert(
            workflow_id,
            vec![StateTransition {
                from: WorkflowState::Initializing,
                to: WorkflowState::Planning,
                timestamp: chrono::Utc::now(),
                reason: "Test".to_string(),
                metadata: HashMap::new(),
            }],
        );

        let history = sm.get_state_history(workflow_id);
        assert!(history.is_some());
        assert_eq!(history.unwrap().len(), 1);
    }

    #[test]
    fn test_get_current_state_empty_history() {
        let sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();
        assert!(sm.get_current_state(workflow_id).is_none());
    }

    #[test]
    fn test_get_workflow_summary_empty() {
        let sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();
        assert!(sm.get_workflow_summary(workflow_id).is_none());
    }

    #[test]
    fn test_get_workflow_summary_with_history() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        // Add workflow history
        let now = chrono::Utc::now();
        sm.state_history.insert(
            workflow_id,
            vec![
                StateTransition {
                    from: WorkflowState::Initializing,
                    to: WorkflowState::Planning,
                    timestamp: now,
                    reason: "Start".to_string(),
                    metadata: HashMap::new(),
                },
                StateTransition {
                    from: WorkflowState::Planning,
                    to: WorkflowState::Executing,
                    timestamp: now + chrono::Duration::seconds(10),
                    reason: "Plan ready".to_string(),
                    metadata: HashMap::new(),
                },
                StateTransition {
                    from: WorkflowState::Executing,
                    to: WorkflowState::Completed,
                    timestamp: now + chrono::Duration::seconds(20),
                    reason: "Done".to_string(),
                    metadata: HashMap::new(),
                },
            ],
        );

        let summary = sm.get_workflow_summary(workflow_id);
        assert!(summary.is_some());

        let summary = summary.unwrap();
        assert_eq!(summary.workflow_id, workflow_id);
        assert_eq!(summary.total_transitions, 3);
        assert!(summary.success);
        assert_eq!(summary.final_state, WorkflowState::Completed);
        assert_eq!(summary.state_visits.get(&WorkflowState::Planning), Some(&1));
        assert_eq!(
            summary.state_visits.get(&WorkflowState::Executing),
            Some(&1)
        );
        assert_eq!(
            summary.state_visits.get(&WorkflowState::Completed),
            Some(&1)
        );
    }

    #[test]
    fn test_get_workflow_summary_with_retries() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        let now = chrono::Utc::now();
        sm.state_history.insert(
            workflow_id,
            vec![
                StateTransition {
                    from: WorkflowState::Planning,
                    to: WorkflowState::Planning, // Retry
                    timestamp: now,
                    reason: "Retry 1".to_string(),
                    metadata: HashMap::new(),
                },
                StateTransition {
                    from: WorkflowState::Planning,
                    to: WorkflowState::Planning, // Retry
                    timestamp: now + chrono::Duration::seconds(5),
                    reason: "Retry 2".to_string(),
                    metadata: HashMap::new(),
                },
                StateTransition {
                    from: WorkflowState::Planning,
                    to: WorkflowState::Failed,
                    timestamp: now + chrono::Duration::seconds(10),
                    reason: "Max retries".to_string(),
                    metadata: HashMap::new(),
                },
            ],
        );

        let summary = sm.get_workflow_summary(workflow_id).unwrap();
        assert!(!summary.success);
        assert_eq!(summary.final_state, WorkflowState::Failed);
        assert_eq!(summary.retries.get(&WorkflowState::Planning), Some(&2));
    }

    #[test]
    fn test_export_metrics() {
        let sm = StateMachine::new();
        let metrics = sm.export_metrics();

        assert_eq!(metrics.total_workflows, 0);
        assert_eq!(metrics.active_workflows, 0);
        assert!(metrics.state_metrics.is_empty());
        assert_eq!(metrics.config.max_retries_per_state, 3);
    }

    #[test]
    fn test_export_metrics_with_workflows() {
        let mut sm = StateMachine::new();

        // Add active workflow
        let active_id = Uuid::new_v4();
        sm.state_history.insert(
            active_id,
            vec![StateTransition {
                from: WorkflowState::Initializing,
                to: WorkflowState::Planning,
                timestamp: chrono::Utc::now(),
                reason: "Active".to_string(),
                metadata: HashMap::new(),
            }],
        );

        // Add completed workflow
        let completed_id = Uuid::new_v4();
        sm.state_history.insert(
            completed_id,
            vec![StateTransition {
                from: WorkflowState::Evaluating,
                to: WorkflowState::Completed,
                timestamp: chrono::Utc::now(),
                reason: "Done".to_string(),
                metadata: HashMap::new(),
            }],
        );

        let metrics = sm.export_metrics();
        assert_eq!(metrics.total_workflows, 2);
        assert_eq!(metrics.active_workflows, 1);
    }

    #[tokio::test]
    async fn test_update_state_metrics_via_transition() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        // First transition
        sm.transition(
            workflow_id,
            WorkflowState::Initializing,
            WorkflowState::Planning,
            "Test".to_string(),
            WorkflowType::Simple,
            HashMap::new(),
        )
        .await
        .unwrap();

        // Check metrics updated
        let metrics = sm.get_state_metrics(&WorkflowState::Initializing);
        assert!(metrics.is_some());
        assert_eq!(metrics.unwrap().success_count, 1);

        let planning_metrics = sm.get_state_metrics(&WorkflowState::Planning);
        assert!(planning_metrics.is_some());
        assert_eq!(planning_metrics.unwrap().total_entries, 1);
    }

    #[tokio::test]
    async fn test_transition_to_failed_updates_failure_count() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        sm.transition(
            workflow_id,
            WorkflowState::Planning,
            WorkflowState::Failed,
            "Error".to_string(),
            WorkflowType::Simple,
            HashMap::new(),
        )
        .await
        .unwrap();

        let metrics = sm.get_state_metrics(&WorkflowState::Planning);
        assert_eq!(metrics.unwrap().failure_count, 1);
    }

    #[tokio::test]
    async fn test_retry_transition_updates_retry_count() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        sm.transition(
            workflow_id,
            WorkflowState::Planning,
            WorkflowState::Planning, // Retry
            "Retry".to_string(),
            WorkflowType::Simple,
            HashMap::new(),
        )
        .await
        .unwrap();

        let metrics = sm.get_state_metrics(&WorkflowState::Planning);
        assert_eq!(metrics.unwrap().retry_count, 1);
    }

    #[tokio::test]
    async fn test_invalid_transition_error() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        let result = sm
            .transition(
                workflow_id,
                WorkflowState::Completed,
                WorkflowState::Planning,
                "Invalid".to_string(),
                WorkflowType::Simple,
                HashMap::new(),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid state transition"));
    }

    #[test]
    fn test_check_state_timeout_no_history() {
        let sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        let timeout = sm.check_state_timeout(workflow_id, &WorkflowState::Planning);
        assert!(timeout.is_none());
    }

    #[test]
    fn test_check_state_timeout_wrong_state() {
        let mut sm = StateMachine::new();
        let workflow_id = Uuid::new_v4();

        // Add transition to Executing
        sm.state_history.insert(
            workflow_id,
            vec![StateTransition {
                from: WorkflowState::Planning,
                to: WorkflowState::Executing,
                timestamp: chrono::Utc::now(),
                reason: "Test".to_string(),
                metadata: HashMap::new(),
            }],
        );

        // Check timeout for Planning (wrong state)
        let timeout = sm.check_state_timeout(workflow_id, &WorkflowState::Planning);
        assert!(timeout.is_none());
    }

    #[test]
    fn test_state_transition_serialization() {
        let transition = StateTransition {
            from: WorkflowState::Planning,
            to: WorkflowState::Executing,
            timestamp: chrono::Utc::now(),
            reason: "Test reason".to_string(),
            metadata: HashMap::from([("key".to_string(), "value".to_string())]),
        };

        let json = serde_json::to_string(&transition).unwrap();
        let parsed: StateTransition = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.from, WorkflowState::Planning);
        assert_eq!(parsed.to, WorkflowState::Executing);
        assert_eq!(parsed.reason, "Test reason");
        assert_eq!(parsed.metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_workflow_state_serialization() {
        let states = vec![
            WorkflowState::Initializing,
            WorkflowState::Planning,
            WorkflowState::Executing,
            WorkflowState::Evaluating,
            WorkflowState::Completed,
            WorkflowState::Failed,
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: WorkflowState = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, state);
        }
    }

    #[test]
    fn test_workflow_type_serialization() {
        let types = vec![
            WorkflowType::Simple,
            WorkflowType::ResearchAndPlanning,
            WorkflowType::ComplexOrchestration,
        ];

        for wf_type in types {
            let json = serde_json::to_string(&wf_type).unwrap();
            let parsed: WorkflowType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, wf_type);
        }
    }

    #[test]
    fn test_state_machine_config_serialization() {
        let config = StateMachineConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: StateMachineConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.max_retries_per_state, config.max_retries_per_state);
        assert_eq!(
            parsed.max_workflow_duration_seconds,
            config.max_workflow_duration_seconds
        );
        assert_eq!(
            parsed.enable_detailed_logging,
            config.enable_detailed_logging
        );
    }

    #[test]
    fn test_state_metrics_default() {
        let metrics = StateMetrics::default();
        assert_eq!(metrics.total_entries, 0);
        assert_eq!(metrics.total_duration_ms, 0);
        assert_eq!(metrics.success_count, 0);
        assert_eq!(metrics.failure_count, 0);
        assert_eq!(metrics.retry_count, 0);
    }

    #[test]
    fn test_state_metrics_serialization() {
        let metrics = StateMetrics {
            total_entries: 10,
            total_duration_ms: 5000,
            success_count: 8,
            failure_count: 1,
            retry_count: 3,
        };

        let json = serde_json::to_string(&metrics).unwrap();
        let parsed: StateMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total_entries, 10);
        assert_eq!(parsed.total_duration_ms, 5000);
        assert_eq!(parsed.success_count, 8);
        assert_eq!(parsed.failure_count, 1);
        assert_eq!(parsed.retry_count, 3);
    }

    #[test]
    fn test_transition_validation_fields() {
        let validation = TransitionValidation {
            valid: true,
            reason: "Valid transition".to_string(),
            suggested_action: Some("Continue".to_string()),
        };

        assert!(validation.valid);
        assert_eq!(validation.reason, "Valid transition");
        assert_eq!(validation.suggested_action, Some("Continue".to_string()));
    }

    #[test]
    fn test_workflow_execution_context() {
        let context = WorkflowExecutionContext {
            workflow_id: Uuid::new_v4(),
            current_state: WorkflowState::Planning,
            workflow_type: WorkflowType::ResearchAndPlanning,
            started_at: chrono::Utc::now(),
            last_transition_at: chrono::Utc::now(),
            retry_count: HashMap::new(),
            execution_metadata: HashMap::from([("key".to_string(), "value".to_string())]),
        };

        assert_eq!(context.current_state, WorkflowState::Planning);
        assert_eq!(context.workflow_type, WorkflowType::ResearchAndPlanning);
        assert_eq!(
            context.execution_metadata.get("key"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_workflow_state_equality() {
        assert_eq!(WorkflowState::Planning, WorkflowState::Planning);
        assert_ne!(WorkflowState::Planning, WorkflowState::Executing);
    }

    #[test]
    fn test_workflow_state_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(WorkflowState::Planning);
        set.insert(WorkflowState::Executing);

        assert!(set.contains(&WorkflowState::Planning));
        assert!(set.contains(&WorkflowState::Executing));
        assert!(!set.contains(&WorkflowState::Completed));
    }

    #[test]
    fn test_workflow_state_clone() {
        let state = WorkflowState::Evaluating;
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_workflow_type_clone() {
        let wf_type = WorkflowType::ComplexOrchestration;
        let cloned = wf_type.clone();
        assert_eq!(wf_type, cloned);
    }
}
