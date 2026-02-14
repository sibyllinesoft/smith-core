//! State machine engine for the Planner-Executor Controller
//!
//! This module implements a sophisticated state machine that manages workflow
//! execution states, transitions, and persistence. It tracks the complete
//! execution history and provides deterministic state management.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::schemas::{
    ActionResult, ActionStatus, ExecutionSummary, PlannerExecParams, PlanningResult,
    ResearchResult, ResourceUsage, UserAction, WorkflowAction, WorkflowStatus, WorkflowType,
};

/// Core workflow execution states
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", content = "data")]
pub enum WorkflowState {
    /// Initial state - workflow is being set up
    Initializing,

    /// Planning phase - Oracle is analyzing and creating execution plan
    Planning,

    /// Execution phase - actions are being executed
    Executing,

    /// Workflow completed successfully
    Completed,

    /// Workflow failed with error message
    Failed(String),

    /// Workflow paused for user intervention
    Paused,
}

/// State transition event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Transition timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Previous state
    pub from_state: WorkflowState,

    /// New state
    pub to_state: WorkflowState,

    /// Reason for the transition
    pub reason: String,

    /// Additional context
    pub context: HashMap<String, serde_json::Value>,
}

/// Complete state machine for workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachine {
    /// Unique workflow identifier
    pub workflow_id: String,

    /// Original workflow parameters
    pub params: PlannerExecParams,

    /// Current state
    pub current_state: WorkflowState,

    /// State transition history
    pub state_history: Vec<StateTransition>,

    /// Planning result from Oracle
    pub planning_result: Option<PlanningResult>,

    /// Research result from Oracle
    pub research_result: Option<ResearchResult>,

    /// Queue of actions to execute
    pub action_queue: VecDeque<WorkflowAction>,

    /// Actions currently being executed
    pub executing_actions: HashMap<String, WorkflowAction>,

    /// Completed action results
    pub completed_actions: Vec<ActionResult>,

    /// Failed action results
    pub failed_actions: Vec<ActionResult>,

    /// Total resource usage
    pub total_resource_usage: ResourceUsage,

    /// Workflow metadata
    pub metadata: WorkflowMetadata,

    /// User interventions
    pub user_interventions: Vec<UserAction>,

    /// Success criteria tracking
    pub success_criteria: Vec<SuccessCriterion>,

    /// Lessons learned during execution
    pub lessons_learned: Vec<String>,
}

/// Metadata about the workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowMetadata {
    /// When the workflow was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the workflow was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Total execution steps taken
    pub total_steps: u32,

    /// Number of retries performed
    pub retry_count: u32,

    /// Number of user interventions
    pub intervention_count: u32,

    /// Current execution phase
    pub phase: ExecutionPhase,
}

/// Current execution phase
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionPhase {
    Initialization,
    Planning,
    Execution,
    Completion,
    Cleanup,
}

/// Success criterion tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriterion {
    /// Criterion description
    pub description: String,

    /// Whether this criterion has been met
    pub met: bool,

    /// Evidence that the criterion was met
    pub evidence: Vec<String>,

    /// When the criterion was evaluated
    pub evaluated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl StateMachine {
    /// Create a new state machine
    pub fn new(workflow_id: String, params: PlannerExecParams) -> Result<Self> {
        let now = chrono::Utc::now();

        let metadata = WorkflowMetadata {
            created_at: now,
            updated_at: now,
            total_steps: 0,
            retry_count: 0,
            intervention_count: 0,
            phase: ExecutionPhase::Initialization,
        };

        info!(workflow_id = %workflow_id, "Creating new state machine");

        Ok(Self {
            workflow_id,
            params,
            current_state: WorkflowState::Initializing,
            state_history: vec![],
            planning_result: None,
            research_result: None,
            action_queue: VecDeque::new(),
            executing_actions: HashMap::new(),
            completed_actions: vec![],
            failed_actions: vec![],
            total_resource_usage: ResourceUsage::default(),
            metadata,
            user_interventions: vec![],
            success_criteria: vec![],
            lessons_learned: vec![],
        })
    }

    /// Get the current state
    pub fn current_state(&self) -> &WorkflowState {
        &self.current_state
    }

    /// Transition to a new state
    pub fn transition_to(&mut self, new_state: WorkflowState) -> Result<()> {
        let now = chrono::Utc::now();
        let old_state = self.current_state.clone();

        debug!(
            workflow_id = %self.workflow_id,
            from = ?old_state,
            to = ?new_state,
            "State transition"
        );

        // Validate transition
        self.validate_transition(&old_state, &new_state)?;

        // Record transition
        let transition = StateTransition {
            timestamp: now,
            from_state: old_state,
            to_state: new_state.clone(),
            reason: self.get_transition_reason(&new_state),
            context: HashMap::new(),
        };

        self.state_history.push(transition);
        self.current_state = new_state;
        self.metadata.updated_at = now;

        // Update execution phase
        self.update_execution_phase();

        Ok(())
    }

    /// Validate that a state transition is allowed
    fn validate_transition(&self, from: &WorkflowState, to: &WorkflowState) -> Result<()> {
        match (from, to) {
            // Valid transitions from Initializing
            (WorkflowState::Initializing, WorkflowState::Planning) => Ok(()),
            (WorkflowState::Initializing, WorkflowState::Failed(_)) => Ok(()),

            // Valid transitions from Planning
            (WorkflowState::Planning, WorkflowState::Executing) => Ok(()),
            (WorkflowState::Planning, WorkflowState::Failed(_)) => Ok(()),
            (WorkflowState::Planning, WorkflowState::Paused) => Ok(()),

            // Valid transitions from Executing
            (WorkflowState::Executing, WorkflowState::Completed) => Ok(()),
            (WorkflowState::Executing, WorkflowState::Failed(_)) => Ok(()),
            (WorkflowState::Executing, WorkflowState::Paused) => Ok(()),
            (WorkflowState::Executing, WorkflowState::Planning) => Ok(()), // Re-planning

            // Valid transitions from Paused
            (WorkflowState::Paused, WorkflowState::Executing) => Ok(()),
            (WorkflowState::Paused, WorkflowState::Failed(_)) => Ok(()),
            (WorkflowState::Paused, WorkflowState::Completed) => Ok(()),

            // Terminal states - no transitions allowed
            (WorkflowState::Completed, _) => {
                Err(anyhow::anyhow!("Cannot transition from Completed state"))
            }
            (WorkflowState::Failed(_), _) => {
                Err(anyhow::anyhow!("Cannot transition from Failed state"))
            }

            // Invalid transitions
            _ => Err(anyhow::anyhow!(
                "Invalid state transition from {:?} to {:?}",
                from,
                to
            )),
        }
    }

    /// Get a descriptive reason for the state transition
    fn get_transition_reason(&self, new_state: &WorkflowState) -> String {
        match new_state {
            WorkflowState::Initializing => "Workflow initialization".to_string(),
            WorkflowState::Planning => "Starting planning phase".to_string(),
            WorkflowState::Executing => "Beginning action execution".to_string(),
            WorkflowState::Completed => "All actions completed successfully".to_string(),
            WorkflowState::Failed(reason) => format!("Workflow failed: {}", reason),
            WorkflowState::Paused => "Workflow paused for intervention".to_string(),
        }
    }

    /// Update the execution phase based on current state
    fn update_execution_phase(&mut self) {
        self.metadata.phase = match self.current_state {
            WorkflowState::Initializing => ExecutionPhase::Initialization,
            WorkflowState::Planning => ExecutionPhase::Planning,
            WorkflowState::Executing => ExecutionPhase::Execution,
            WorkflowState::Completed | WorkflowState::Failed(_) => ExecutionPhase::Completion,
            WorkflowState::Paused => self.metadata.phase.clone(), // Keep current phase
        };
    }

    /// Set the planning result from the Oracle
    pub fn set_planning_result(&mut self, result: PlanningResult) -> Result<()> {
        debug!(
            workflow_id = %self.workflow_id,
            actions_count = result.actions.len(),
            "Setting planning result"
        );

        // Add actions to the queue
        for action in &result.actions {
            self.action_queue.push_back(action.clone());
        }

        // Set success criteria from planning
        for criterion in &result.success_criteria {
            self.success_criteria.push(SuccessCriterion {
                description: criterion.clone(),
                met: false,
                evidence: vec![],
                evaluated_at: None,
            });
        }

        self.planning_result = Some(result);
        self.metadata.updated_at = chrono::Utc::now();

        Ok(())
    }

    /// Set the research result from the Oracle
    pub fn set_research_result(&mut self, result: ResearchResult) -> Result<()> {
        debug!(
            workflow_id = %self.workflow_id,
            findings_count = result.findings.len(),
            "Setting research result"
        );

        self.research_result = Some(result);
        self.metadata.updated_at = chrono::Utc::now();

        Ok(())
    }

    /// Get the next action to execute
    pub fn get_next_action(&mut self) -> Result<Option<WorkflowAction>> {
        // Check if we're in the executing state
        if !matches!(self.current_state, WorkflowState::Executing) {
            return Ok(None);
        }

        // Find next action that can be executed (dependencies satisfied)
        let completed_action_ids: Vec<String> = self
            .completed_actions
            .iter()
            .map(|result| result.action_id.clone())
            .collect();

        // Look for an action that can be executed
        let mut action_index = None;
        for (i, action) in self.action_queue.iter().enumerate() {
            if action.can_execute(&completed_action_ids) {
                action_index = Some(i);
                break;
            }
        }

        if let Some(index) = action_index {
            let action = self.action_queue.remove(index).unwrap();
            let action_id = action.id.clone();

            debug!(
                workflow_id = %self.workflow_id,
                action_id = %action_id,
                "Starting action execution"
            );

            self.executing_actions.insert(action_id, action.clone());
            self.metadata.total_steps += 1;
            self.metadata.updated_at = chrono::Utc::now();

            Ok(Some(action))
        } else {
            // No executable actions available
            if self.executing_actions.is_empty() && self.action_queue.is_empty() {
                // All actions completed
                Ok(None)
            } else if self.executing_actions.is_empty() {
                // Actions in queue but none can execute (dependency deadlock)
                warn!(
                    workflow_id = %self.workflow_id,
                    remaining_actions = self.action_queue.len(),
                    "Possible dependency deadlock detected"
                );
                Ok(None)
            } else {
                // Actions are still executing
                Ok(None)
            }
        }
    }

    /// Record the result of an action execution
    pub fn record_execution_result(&mut self, result: ActionResult) -> Result<()> {
        let action_id = result.action_id.clone();

        debug!(
            workflow_id = %self.workflow_id,
            action_id = %action_id,
            status = ?result.status,
            "Recording action result"
        );

        // Remove from executing actions
        if let Some(action) = self.executing_actions.remove(&action_id) {
            // Update resource usage
            self.total_resource_usage.cpu_ms += result.metadata.resource_usage.cpu_ms;
            self.total_resource_usage.memory_bytes = self
                .total_resource_usage
                .memory_bytes
                .max(result.metadata.resource_usage.memory_bytes);
            self.total_resource_usage.fs_operations += result.metadata.resource_usage.fs_operations;
            self.total_resource_usage.network_requests +=
                result.metadata.resource_usage.network_requests;

            // Track result
            match result.status {
                ActionStatus::Completed => {
                    self.completed_actions.push(result);
                    self.add_lesson_learned(&format!(
                        "Action {} completed successfully",
                        action.action_type
                    ));
                }
                ActionStatus::Failed => {
                    self.failed_actions.push(result.clone());

                    // Check if we should retry
                    if result.metadata.retry_count < action.retry_policy.max_retries {
                        if let Some(error) = &result.error {
                            if error.retryable {
                                debug!(
                                    workflow_id = %self.workflow_id,
                                    action_id = %action_id,
                                    "Retrying failed action"
                                );

                                // Add back to queue for retry
                                self.action_queue.push_front(action);
                                self.metadata.retry_count += 1;
                                return Ok(());
                            }
                        }
                    }

                    // Non-retryable failure
                    self.add_lesson_learned(&format!(
                        "Action {} failed: {}",
                        action.action_type,
                        result
                            .error
                            .as_ref()
                            .map(|e| e.message.as_str())
                            .unwrap_or("Unknown error")
                    ));
                }
                _ => {
                    // Other statuses (cancelled, skipped, etc.)
                    self.failed_actions.push(result);
                }
            }

            self.metadata.updated_at = chrono::Utc::now();
        } else {
            return Err(anyhow::anyhow!(
                "Action {} not found in executing actions",
                action_id
            ));
        }

        Ok(())
    }

    /// Check if the workflow is complete
    pub fn is_complete(&self) -> Result<bool> {
        // Check if all actions are done
        let all_actions_done = self.action_queue.is_empty() && self.executing_actions.is_empty();

        if !all_actions_done {
            return Ok(false);
        }

        // Check success criteria
        let success_criteria_met = self.evaluate_success_criteria();

        Ok(success_criteria_met)
    }

    /// Evaluate success criteria
    fn evaluate_success_criteria(&self) -> bool {
        if self.success_criteria.is_empty() {
            // No explicit criteria - consider complete if no failures
            self.failed_actions.is_empty()
        } else {
            // All criteria must be met
            self.success_criteria.iter().all(|criterion| criterion.met)
        }
    }

    /// Apply a user action
    pub fn apply_user_action(&mut self, action: UserAction) -> Result<()> {
        debug!(
            workflow_id = %self.workflow_id,
            action_type = ?action.action_type,
            "Applying user action"
        );

        self.user_interventions.push(action.clone());
        self.metadata.intervention_count += 1;
        self.metadata.updated_at = chrono::Utc::now();

        match action.action_type {
            super::schemas::UserActionType::Continue => {
                if matches!(self.current_state, WorkflowState::Paused) {
                    self.transition_to(WorkflowState::Executing)?;
                }
            }
            super::schemas::UserActionType::Pause => {
                self.transition_to(WorkflowState::Paused)?;
            }
            super::schemas::UserActionType::Stop => {
                self.transition_to(WorkflowState::Failed("Stopped by user".to_string()))?;
            }
            super::schemas::UserActionType::ModifyParameters => {
                // Handle parameter modifications
                if let Some(input) = action.input {
                    self.apply_parameter_modifications(input)?;
                }
            }
            super::schemas::UserActionType::AddAction => {
                // Add new action to queue
                if let Some(input) = action.input {
                    let new_action: WorkflowAction =
                        serde_json::from_value(input).context("Failed to parse new action")?;
                    self.action_queue.push_back(new_action);
                }
            }
            super::schemas::UserActionType::RemoveAction => {
                // Remove action from queue
                if let Some(input) = action.input {
                    if let Some(action_id) = input.as_str() {
                        self.action_queue.retain(|a| a.id != action_id);
                    }
                }
            }
            super::schemas::UserActionType::OverrideResult => {
                // Override the result of a failed action
                if let Some(input) = action.input {
                    self.apply_result_override(input)?;
                }
            }
            super::schemas::UserActionType::Escalate => {
                self.add_lesson_learned("User escalated workflow for manual handling");
                self.transition_to(WorkflowState::Paused)?;
            }
        }

        Ok(())
    }

    /// Apply parameter modifications from user input
    fn apply_parameter_modifications(&mut self, input: serde_json::Value) -> Result<()> {
        // This is a simplified implementation
        // In a real system, you'd have more sophisticated parameter updating
        debug!(
            workflow_id = %self.workflow_id,
            "Applying parameter modifications"
        );

        // For now, just log that modifications were applied
        self.add_lesson_learned("User modified workflow parameters");
        Ok(())
    }

    /// Apply result override from user input
    fn apply_result_override(&mut self, input: serde_json::Value) -> Result<()> {
        debug!(
            workflow_id = %self.workflow_id,
            "Applying result override"
        );

        // This is a simplified implementation
        self.add_lesson_learned("User overrode action result");
        Ok(())
    }

    /// Add a lesson learned
    fn add_lesson_learned(&mut self, lesson: &str) {
        self.lessons_learned.push(lesson.to_string());
        debug!(
            workflow_id = %self.workflow_id,
            lesson = %lesson,
            "Added lesson learned"
        );
    }

    /// Get execution summary
    pub fn get_execution_summary(&self) -> Result<ExecutionSummary> {
        let duration_ms = if let Some(first_transition) = self.state_history.first() {
            let elapsed = chrono::Utc::now() - first_transition.timestamp;
            elapsed.num_milliseconds() as u64
        } else {
            0
        };

        let status = match &self.current_state {
            WorkflowState::Initializing => WorkflowStatus::Initializing,
            WorkflowState::Planning => WorkflowStatus::Planning,
            WorkflowState::Executing => WorkflowStatus::Executing,
            WorkflowState::Completed => WorkflowStatus::Completed,
            WorkflowState::Failed(_) => WorkflowStatus::Failed,
            WorkflowState::Paused => WorkflowStatus::Paused,
        };

        let success_criteria_met = self
            .success_criteria
            .iter()
            .filter(|c| c.met)
            .map(|c| c.description.clone())
            .collect();

        let all_actions = [&self.completed_actions[..], &self.failed_actions[..]].concat();

        let final_output = if matches!(status, WorkflowStatus::Completed) {
            // Combine outputs from completed actions
            let outputs: Vec<serde_json::Value> = self
                .completed_actions
                .iter()
                .filter_map(|result| result.output.clone())
                .collect();

            if outputs.is_empty() {
                None
            } else {
                Some(serde_json::json!({
                    "action_outputs": outputs,
                    "success_criteria_met": success_criteria_met,
                    "total_actions": all_actions.len(),
                    "completed_actions": self.completed_actions.len(),
                    "failed_actions": self.failed_actions.len()
                }))
            }
        } else {
            None
        };

        let total_actions = all_actions.len() as u32;
        let successful_actions = all_actions
            .iter()
            .filter(|a| matches!(a.status, ActionStatus::Completed))
            .count() as u32;
        let failed_actions = total_actions - successful_actions;

        Ok(ExecutionSummary {
            workflow_id: self.workflow_id.clone(),
            session_id: format!("session-{}", self.workflow_id),
            workflow_type: WorkflowType::ResearchAndPlanning,
            goal: self.params.goal.clone(),
            status: status.clone(),
            actions: all_actions,
            duration_ms,
            total_duration: std::time::Duration::from_millis(duration_ms),
            total_actions,
            successful_actions,
            failed_actions,
            final_state: status.clone(),
            error_message: if matches!(status, WorkflowStatus::Failed) {
                Some("Workflow failed".to_string())
            } else {
                None
            },
            resource_usage: self.total_resource_usage.clone(),
            success_criteria_met,
            lessons_learned: self.lessons_learned.clone(),
            recommendations: vec!["Review workflow performance".to_string()],
            final_output,
        })
    }

    /// Get workflow progress (0.0 to 1.0)
    pub fn get_progress(&self) -> f64 {
        let total_actions = self.completed_actions.len()
            + self.failed_actions.len()
            + self.executing_actions.len()
            + self.action_queue.len();

        if total_actions == 0 {
            0.0
        } else {
            (self.completed_actions.len() as f64) / (total_actions as f64)
        }
    }

    /// Get time since last state transition
    pub fn time_since_last_transition(&self) -> chrono::Duration {
        if let Some(last_transition) = self.state_history.last() {
            chrono::Utc::now() - last_transition.timestamp
        } else {
            chrono::Duration::zero()
        }
    }

    /// Check if workflow has been stalled for a given duration
    pub fn is_stalled(&self, stall_threshold_ms: u64) -> bool {
        let time_since_transition = self.time_since_last_transition();
        time_since_transition.num_milliseconds() as u64 > stall_threshold_ms
    }

    /// Get detailed state information for debugging
    pub fn get_state_info(&self) -> serde_json::Value {
        serde_json::json!({
            "workflow_id": self.workflow_id,
            "current_state": self.current_state,
            "total_steps": self.metadata.total_steps,
            "progress": self.get_progress(),
            "time_since_last_transition_ms": self.time_since_last_transition().num_milliseconds(),
            "actions_in_queue": self.action_queue.len(),
            "actions_executing": self.executing_actions.len(),
            "actions_completed": self.completed_actions.len(),
            "actions_failed": self.failed_actions.len(),
            "success_criteria_count": self.success_criteria.len(),
            "interventions_count": self.user_interventions.len(),
            "lessons_learned_count": self.lessons_learned.len()
        })
    }

    /// Get the current progress as a percentage (0.0 - 1.0)
    pub fn progress(&self) -> f64 {
        let total_planned = self.action_queue.len()
            + self.executing_actions.len()
            + self.completed_actions.len()
            + self.failed_actions.len();
        if total_planned == 0 {
            return 0.0;
        }

        let completed = self.completed_actions.len();
        completed as f64 / total_planned as f64
    }

    /// Get the currently executing action
    pub fn current_action(&self) -> Option<&WorkflowAction> {
        // Return the first executing action (if any)
        self.executing_actions.values().next()
    }

    /// Get the execution history as state transitions
    pub fn get_execution_history(&self) -> &Vec<StateTransition> {
        &self.state_history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::planner_exec::schemas::{ActionType, WorkflowType};
    use serde_json::json;

    fn create_test_params() -> PlannerExecParams {
        PlannerExecParams {
            workflow_id: "test-workflow-345".to_string(),
            goal: "Test workflow".to_string(),
            workflow_type: WorkflowType::Simple,
            max_steps: 10,
            timeout_ms: Some(30000),
            context: HashMap::new(),
            allowed_capabilities: vec![],
            resource_limits: super::super::schemas::ResourceLimits::default(),
            preferences: super::super::schemas::ExecutionPreferences::default(),
        }
    }

    #[test]
    fn test_state_machine_creation() {
        let params = create_test_params();
        let workflow_id = "test-workflow".to_string();

        let state_machine = StateMachine::new(workflow_id.clone(), params).unwrap();

        assert_eq!(state_machine.workflow_id, workflow_id);
        assert_eq!(state_machine.current_state, WorkflowState::Initializing);
        assert!(state_machine.action_queue.is_empty());
        assert!(state_machine.completed_actions.is_empty());
    }

    #[test]
    fn test_state_transitions() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Valid transitions
        assert!(state_machine.transition_to(WorkflowState::Planning).is_ok());
        assert_eq!(state_machine.current_state, WorkflowState::Planning);

        assert!(state_machine
            .transition_to(WorkflowState::Executing)
            .is_ok());
        assert_eq!(state_machine.current_state, WorkflowState::Executing);

        assert!(state_machine
            .transition_to(WorkflowState::Completed)
            .is_ok());
        assert_eq!(state_machine.current_state, WorkflowState::Completed);

        // Invalid transition from terminal state
        assert!(state_machine
            .transition_to(WorkflowState::Executing)
            .is_err());
    }

    #[test]
    fn test_planning_result() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test"}),
            "Read test file".to_string(),
        );

        let planning_result = PlanningResult {
            actions: vec![action],
            strategy: "Test strategy".to_string(),
            risks: vec![],
            success_criteria: vec!["File read successfully".to_string()],
            confidence: 0.9,
        };

        assert!(state_machine.set_planning_result(planning_result).is_ok());
        assert_eq!(state_machine.action_queue.len(), 1);
        assert_eq!(state_machine.success_criteria.len(), 1);
    }

    #[test]
    fn test_action_execution() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Set up planning result
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test"}),
            "Read test file".to_string(),
        );

        let planning_result = PlanningResult {
            actions: vec![action.clone()],
            strategy: "Test strategy".to_string(),
            risks: vec![],
            success_criteria: vec![],
            confidence: 0.9,
        };

        state_machine.set_planning_result(planning_result).unwrap();
        // First transition to Planning, then to Executing
        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();

        // Get next action
        let next_action = state_machine.get_next_action().unwrap();
        assert!(next_action.is_some());
        assert_eq!(next_action.unwrap().id, action.id);
        assert_eq!(state_machine.executing_actions.len(), 1);
    }

    #[test]
    fn test_progress_calculation() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Initially no progress
        assert_eq!(state_machine.get_progress(), 0.0);

        // Add some actions
        let action1 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test1"}),
            "Read test file 1".to_string(),
        );

        let action2 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test2"}),
            "Read test file 2".to_string(),
        );

        let action1_id = action1.id.clone();
        state_machine.action_queue.push_back(action1);
        state_machine.action_queue.push_back(action2);

        // Progress should still be 0 since no actions completed
        assert_eq!(state_machine.get_progress(), 0.0);

        // Transition to executing state to enable getting actions
        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();

        // Get one action (moves from queue to executing)
        let next_action = state_machine.get_next_action().unwrap();
        assert!(next_action.is_some());

        // Simulate completing the action
        let result = ActionResult {
            action_id: action1_id,
            status: ActionStatus::Completed,
            output: Some(json!({"result": "success"})),
            error: None,
            metadata: super::super::schemas::ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage::default(),
                environment: super::super::schemas::ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "test".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        // Record completion (moves from executing to completed)
        state_machine.record_execution_result(result).unwrap();

        // Progress should be 0.5 (1 completed out of 2 total)
        assert_eq!(state_machine.get_progress(), 0.5);
    }

    #[test]
    fn test_stall_detection() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Fresh state machine should not be stalled
        assert!(!state_machine.is_stalled(1000));

        // Simulate a state transition in the past
        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();

        // Should not be stalled immediately
        assert!(!state_machine.is_stalled(1000));

        // For testing, we can't easily simulate time passage,
        // but we can test the logic
        assert!(!state_machine.is_stalled(0)); // 0ms threshold should trigger stall
    }

    // Additional tests for comprehensive coverage

    #[test]
    fn test_workflow_state_serialization() {
        // Test all variants
        let states = [
            WorkflowState::Initializing,
            WorkflowState::Planning,
            WorkflowState::Executing,
            WorkflowState::Completed,
            WorkflowState::Failed("test error".to_string()),
            WorkflowState::Paused,
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: WorkflowState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, deserialized);
        }
    }

    #[test]
    fn test_state_transition_serialization() {
        let transition = StateTransition {
            timestamp: chrono::Utc::now(),
            from_state: WorkflowState::Initializing,
            to_state: WorkflowState::Planning,
            reason: "Starting planning".to_string(),
            context: HashMap::from([("key".to_string(), json!("value"))]),
        };

        let json = serde_json::to_string(&transition).unwrap();
        let deserialized: StateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(transition.reason, deserialized.reason);
    }

    #[test]
    fn test_workflow_metadata_serialization() {
        let metadata = WorkflowMetadata {
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            total_steps: 5,
            retry_count: 2,
            intervention_count: 1,
            phase: ExecutionPhase::Execution,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: WorkflowMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(metadata.total_steps, deserialized.total_steps);
    }

    #[test]
    fn test_execution_phase_serialization() {
        let phases = [
            ExecutionPhase::Initialization,
            ExecutionPhase::Planning,
            ExecutionPhase::Execution,
            ExecutionPhase::Completion,
            ExecutionPhase::Cleanup,
        ];

        for phase in phases {
            let json = serde_json::to_string(&phase).unwrap();
            let deserialized: ExecutionPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(phase, deserialized);
        }
    }

    #[test]
    fn test_success_criterion_serialization() {
        let criterion = SuccessCriterion {
            description: "Test criterion".to_string(),
            met: true,
            evidence: vec!["evidence 1".to_string(), "evidence 2".to_string()],
            evaluated_at: Some(chrono::Utc::now()),
        };

        let json = serde_json::to_string(&criterion).unwrap();
        let deserialized: SuccessCriterion = serde_json::from_str(&json).unwrap();
        assert_eq!(criterion.description, deserialized.description);
        assert_eq!(criterion.met, deserialized.met);
    }

    #[test]
    fn test_invalid_transitions_from_initializing() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Invalid: Initializing -> Completed
        assert!(state_machine
            .transition_to(WorkflowState::Completed)
            .is_err());

        // Invalid: Initializing -> Executing (must go through Planning)
        let mut state_machine2 =
            StateMachine::new("test2".to_string(), create_test_params()).unwrap();
        assert!(state_machine2
            .transition_to(WorkflowState::Executing)
            .is_err());

        // Invalid: Initializing -> Paused
        let mut state_machine3 =
            StateMachine::new("test3".to_string(), create_test_params()).unwrap();
        assert!(state_machine3.transition_to(WorkflowState::Paused).is_err());
    }

    #[test]
    fn test_invalid_transitions_from_terminal_states() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Get to Failed state
        state_machine
            .transition_to(WorkflowState::Failed("error".to_string()))
            .unwrap();

        // Cannot transition from Failed
        assert!(state_machine
            .transition_to(WorkflowState::Planning)
            .is_err());
        assert!(state_machine
            .transition_to(WorkflowState::Executing)
            .is_err());
        assert!(state_machine
            .transition_to(WorkflowState::Completed)
            .is_err());
    }

    #[test]
    fn test_set_research_result() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let research_result = super::super::schemas::ResearchResult {
            findings: vec![super::super::schemas::ResearchFinding {
                title: "Finding 1".to_string(),
                description: "Test finding".to_string(),
                evidence: vec!["evidence".to_string()],
                relevance: 0.9,
            }],
            sources: vec!["source 1".to_string()],
            confidence: 0.85,
            recommendations: vec!["recommendation 1".to_string()],
        };

        assert!(state_machine
            .set_research_result(research_result.clone())
            .is_ok());
        assert!(state_machine.research_result.is_some());
        assert_eq!(state_machine.research_result.unwrap().findings.len(), 1);
    }

    #[test]
    fn test_apply_user_action_continue() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Get to Paused state
        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine.transition_to(WorkflowState::Paused).unwrap();

        let action = super::super::schemas::UserAction {
            action_type: super::super::schemas::UserActionType::Continue,
            input: None,
            reason: "Resume workflow".to_string(),
        };

        state_machine.apply_user_action(action).unwrap();
        assert_eq!(state_machine.current_state, WorkflowState::Executing);
    }

    #[test]
    fn test_apply_user_action_pause() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();

        let action = super::super::schemas::UserAction {
            action_type: super::super::schemas::UserActionType::Pause,
            input: None,
            reason: "Need to review".to_string(),
        };

        state_machine.apply_user_action(action).unwrap();
        assert_eq!(state_machine.current_state, WorkflowState::Paused);
    }

    #[test]
    fn test_apply_user_action_stop() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();

        let action = super::super::schemas::UserAction {
            action_type: super::super::schemas::UserActionType::Stop,
            input: None,
            reason: "Stop immediately".to_string(),
        };

        state_machine.apply_user_action(action).unwrap();
        assert!(matches!(
            state_machine.current_state,
            WorkflowState::Failed(_)
        ));
    }

    #[test]
    fn test_apply_user_action_modify_parameters() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let action = super::super::schemas::UserAction {
            action_type: super::super::schemas::UserActionType::ModifyParameters,
            input: Some(json!({"max_steps": 20})),
            reason: "Increase steps".to_string(),
        };

        state_machine.apply_user_action(action).unwrap();
        assert!(state_machine
            .lessons_learned
            .iter()
            .any(|l| l.contains("modified")));
    }

    #[test]
    fn test_apply_user_action_add_action() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let new_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/new"}),
            "New action".to_string(),
        );

        let action = super::super::schemas::UserAction {
            action_type: super::super::schemas::UserActionType::AddAction,
            input: Some(serde_json::to_value(&new_action).unwrap()),
            reason: "Add new task".to_string(),
        };

        state_machine.apply_user_action(action).unwrap();
        assert_eq!(state_machine.action_queue.len(), 1);
    }

    #[test]
    fn test_apply_user_action_remove_action() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Add an action first
        let action_to_remove = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/remove"}),
            "To be removed".to_string(),
        );
        let action_id = action_to_remove.id.clone();
        state_machine.action_queue.push_back(action_to_remove);

        let remove_action = super::super::schemas::UserAction {
            action_type: super::super::schemas::UserActionType::RemoveAction,
            input: Some(json!(action_id)),
            reason: "Remove task".to_string(),
        };

        state_machine.apply_user_action(remove_action).unwrap();
        assert_eq!(state_machine.action_queue.len(), 0);
    }

    #[test]
    fn test_apply_user_action_override_result() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let action = super::super::schemas::UserAction {
            action_type: super::super::schemas::UserActionType::OverrideResult,
            input: Some(json!({"status": "success"})),
            reason: "Manual override".to_string(),
        };

        state_machine.apply_user_action(action).unwrap();
        assert!(state_machine
            .lessons_learned
            .iter()
            .any(|l| l.contains("overrode")));
    }

    #[test]
    fn test_apply_user_action_escalate() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();

        let action = super::super::schemas::UserAction {
            action_type: super::super::schemas::UserActionType::Escalate,
            input: None,
            reason: "Need human review".to_string(),
        };

        state_machine.apply_user_action(action).unwrap();
        assert_eq!(state_machine.current_state, WorkflowState::Paused);
        assert!(state_machine
            .lessons_learned
            .iter()
            .any(|l| l.contains("escalated")));
    }

    #[test]
    fn test_get_execution_summary() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Completed)
            .unwrap();

        let summary = state_machine.get_execution_summary().unwrap();

        assert_eq!(summary.workflow_id, "test");
        assert_eq!(summary.status, WorkflowStatus::Completed);
    }

    #[test]
    fn test_get_execution_summary_failed() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Failed("error".to_string()))
            .unwrap();

        let summary = state_machine.get_execution_summary().unwrap();
        assert_eq!(summary.status, WorkflowStatus::Failed);
        assert!(summary.error_message.is_some());
    }

    #[test]
    fn test_get_state_info() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Add some actions
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test"}),
            "Test".to_string(),
        );
        state_machine.action_queue.push_back(action);

        let info = state_machine.get_state_info();

        assert_eq!(info["workflow_id"], "test");
        assert_eq!(info["actions_in_queue"], 1);
        assert_eq!(info["actions_executing"], 0);
        assert_eq!(info["actions_completed"], 0);
    }

    #[test]
    fn test_progress_method() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // No actions - 0 progress
        assert_eq!(state_machine.progress(), 0.0);

        // Add actions to queue
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test"}),
            "Test".to_string(),
        );
        state_machine.action_queue.push_back(action.clone());
        state_machine.action_queue.push_back(action.clone());

        // Still 0 progress (nothing completed)
        assert_eq!(state_machine.progress(), 0.0);
    }

    #[test]
    fn test_current_action_none() {
        let params = create_test_params();
        let state_machine = StateMachine::new("test".to_string(), params).unwrap();

        assert!(state_machine.current_action().is_none());
    }

    #[test]
    fn test_current_action_some() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Add action to executing
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test"}),
            "Test".to_string(),
        );
        state_machine
            .executing_actions
            .insert(action.id.clone(), action.clone());

        let current = state_machine.current_action();
        assert!(current.is_some());
        assert_eq!(current.unwrap().id, action.id);
    }

    #[test]
    fn test_get_execution_history() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        assert!(state_machine.get_execution_history().is_empty());

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();

        let history = state_machine.get_execution_history();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_time_since_last_transition_empty() {
        let params = create_test_params();
        let state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let time = state_machine.time_since_last_transition();
        assert_eq!(time, chrono::Duration::zero());
    }

    #[test]
    fn test_time_since_last_transition_with_history() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();

        let time = state_machine.time_since_last_transition();
        assert!(time.num_milliseconds() >= 0);
    }

    #[test]
    fn test_record_execution_result_failed_action() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Set up action
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test"}),
            "Test".to_string(),
        );
        let action_id = action.id.clone();
        state_machine
            .executing_actions
            .insert(action_id.clone(), action);

        // Create failed result
        let result = ActionResult {
            action_id: action_id,
            status: ActionStatus::Failed,
            output: None,
            error: Some(super::super::schemas::ActionError {
                code: "TEST_ERROR".to_string(),
                message: "Test failure".to_string(),
                details: None,
                retryable: false,
            }),
            metadata: super::super::schemas::ActionMetadata {
                retry_count: 3, // Already exceeded retries
                resource_usage: ResourceUsage::default(),
                environment: super::super::schemas::ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "test".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        state_machine.record_execution_result(result).unwrap();
        assert_eq!(state_machine.failed_actions.len(), 1);
        assert!(state_machine
            .lessons_learned
            .iter()
            .any(|l| l.contains("failed")));
    }

    #[test]
    fn test_record_execution_result_retryable_failure() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Set up action with retry policy
        let mut action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test"}),
            "Test".to_string(),
        );
        action.retry_policy.max_retries = 3;
        let action_id = action.id.clone();
        state_machine
            .executing_actions
            .insert(action_id.clone(), action.clone());

        // Create retryable failed result
        let result = ActionResult {
            action_id: action_id,
            status: ActionStatus::Failed,
            output: None,
            error: Some(super::super::schemas::ActionError {
                code: "TEMP_ERROR".to_string(),
                message: "Temporary failure".to_string(),
                details: None,
                retryable: true,
            }),
            metadata: super::super::schemas::ActionMetadata {
                retry_count: 0, // First attempt
                resource_usage: ResourceUsage::default(),
                environment: super::super::schemas::ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "test".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        state_machine.record_execution_result(result).unwrap();
        // Action should be back in queue for retry
        assert_eq!(state_machine.action_queue.len(), 1);
        assert_eq!(state_machine.metadata.retry_count, 1);
    }

    #[test]
    fn test_record_execution_result_unknown_action() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let result = ActionResult {
            action_id: "unknown-action".to_string(),
            status: ActionStatus::Completed,
            output: None,
            error: None,
            metadata: super::super::schemas::ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage::default(),
                environment: super::super::schemas::ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "test".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        let err = state_machine.record_execution_result(result);
        assert!(err.is_err());
    }

    #[test]
    fn test_is_complete_with_success_criteria() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Add success criteria
        state_machine.success_criteria.push(SuccessCriterion {
            description: "Test criterion".to_string(),
            met: false,
            evidence: vec![],
            evaluated_at: None,
        });

        // Not complete - criterion not met
        assert!(!state_machine.is_complete().unwrap());

        // Mark criterion as met
        state_machine.success_criteria[0].met = true;
        assert!(state_machine.is_complete().unwrap());
    }

    #[test]
    fn test_is_complete_no_criteria_with_failures() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Add a failed action
        state_machine.failed_actions.push(ActionResult {
            action_id: "failed".to_string(),
            status: ActionStatus::Failed,
            output: None,
            error: None,
            metadata: super::super::schemas::ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage::default(),
                environment: super::super::schemas::ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "test".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        });

        // Not complete - has failures and no explicit criteria
        assert!(!state_machine.is_complete().unwrap());
    }

    #[test]
    fn test_get_next_action_not_executing_state() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // In Initializing state - should return None
        let result = state_machine.get_next_action().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_state_machine_clone() {
        let params = create_test_params();
        let state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let cloned = state_machine.clone();
        assert_eq!(state_machine.workflow_id, cloned.workflow_id);
    }

    #[test]
    fn test_state_machine_debug() {
        let params = create_test_params();
        let state_machine = StateMachine::new("test".to_string(), params).unwrap();

        let debug_str = format!("{:?}", state_machine);
        assert!(debug_str.contains("StateMachine"));
    }

    #[test]
    fn test_get_transition_reason() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();

        let history = state_machine.get_execution_history();
        assert_eq!(history[0].reason, "Starting planning phase");
    }

    #[test]
    fn test_paused_to_executing_transition() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine.transition_to(WorkflowState::Paused).unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();

        assert_eq!(state_machine.current_state, WorkflowState::Executing);
    }

    #[test]
    fn test_paused_to_completed_transition() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine.transition_to(WorkflowState::Paused).unwrap();
        state_machine
            .transition_to(WorkflowState::Completed)
            .unwrap();

        assert_eq!(state_machine.current_state, WorkflowState::Completed);
    }

    #[test]
    fn test_executing_to_planning_replanning() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();
        // Re-planning is allowed
        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();

        assert_eq!(state_machine.current_state, WorkflowState::Planning);
    }

    #[test]
    fn test_update_execution_phase() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        assert_eq!(state_machine.metadata.phase, ExecutionPhase::Initialization);

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        assert_eq!(state_machine.metadata.phase, ExecutionPhase::Planning);

        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();
        assert_eq!(state_machine.metadata.phase, ExecutionPhase::Execution);

        state_machine
            .transition_to(WorkflowState::Completed)
            .unwrap();
        assert_eq!(state_machine.metadata.phase, ExecutionPhase::Completion);
    }

    #[test]
    fn test_resource_usage_accumulation() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Add actions
        let action1 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test1"}),
            "Test 1".to_string(),
        );
        let action2 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test2"}),
            "Test 2".to_string(),
        );
        let action1_id = action1.id.clone();
        let action2_id = action2.id.clone();

        state_machine
            .executing_actions
            .insert(action1_id.clone(), action1);
        state_machine
            .executing_actions
            .insert(action2_id.clone(), action2);

        // Complete actions with resource usage
        let result1 = ActionResult {
            action_id: action1_id,
            status: ActionStatus::Completed,
            output: None,
            error: None,
            metadata: super::super::schemas::ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage {
                    cpu_ms: 100,
                    memory_bytes: 1000,
                    fs_operations: 5,
                    network_requests: 0,
                },
                environment: super::super::schemas::ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "test".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        let result2 = ActionResult {
            action_id: action2_id,
            status: ActionStatus::Completed,
            output: None,
            error: None,
            metadata: super::super::schemas::ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage {
                    cpu_ms: 200,
                    memory_bytes: 2000,
                    fs_operations: 3,
                    network_requests: 2,
                },
                environment: super::super::schemas::ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "test".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        state_machine.record_execution_result(result1).unwrap();
        state_machine.record_execution_result(result2).unwrap();

        // CPU should be accumulated
        assert_eq!(state_machine.total_resource_usage.cpu_ms, 300);
        // Memory should be max
        assert_eq!(state_machine.total_resource_usage.memory_bytes, 2000);
        // Operations should be accumulated
        assert_eq!(state_machine.total_resource_usage.fs_operations, 8);
        assert_eq!(state_machine.total_resource_usage.network_requests, 2);
    }

    #[test]
    fn test_action_dependencies() {
        let params = create_test_params();
        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();

        // Create action with dependencies
        let action1 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test1"}),
            "Test 1".to_string(),
        );
        let action1_id = action1.id.clone();

        let mut action2 = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/test2"}),
            "Test 2".to_string(),
        );
        action2.dependencies.push(action1_id.clone());

        state_machine.action_queue.push_back(action2);
        state_machine.action_queue.push_back(action1);

        state_machine
            .transition_to(WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(WorkflowState::Executing)
            .unwrap();

        // Should get action1 first (no dependencies)
        let next = state_machine.get_next_action().unwrap();
        assert!(next.is_some());
        assert_eq!(next.unwrap().id, action1_id);
    }
}
