//! Interactive menu system for user intervention and control
//!
//! This module provides a sophisticated interactive menu system that allows
//! users to intervene in workflow execution, monitor progress, and control
//! the behavior of the Planner-Executor Controller.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::schemas::{
    MenuContext, MenuInteraction, MenuOption, StallInfo, UserAction, UserActionType, WorkflowStatus,
};
use super::state_machine::{StateMachine, WorkflowState};

/// Menu system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuSystemConfig {
    /// Default timeout for user response (seconds)
    pub default_timeout_s: u64,

    /// Enable interactive mode
    pub interactive_mode: bool,

    /// Enable automatic suggestions
    pub auto_suggestions: bool,

    /// Maximum number of menu options to show
    pub max_menu_options: usize,

    /// User interface style
    pub ui_style: UiStyle,

    /// Intervention strategies
    pub intervention_strategies: Vec<InterventionStrategy>,
}

impl Default for MenuSystemConfig {
    fn default() -> Self {
        Self {
            default_timeout_s: 60,
            interactive_mode: true,
            auto_suggestions: true,
            max_menu_options: 10,
            ui_style: UiStyle::Console,
            intervention_strategies: vec![
                InterventionStrategy::Continue,
                InterventionStrategy::Pause,
                InterventionStrategy::ModifyParameters,
                InterventionStrategy::SkipAction,
                InterventionStrategy::RestartWorkflow,
                InterventionStrategy::Escalate,
            ],
        }
    }
}

/// User interface styles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UiStyle {
    /// Simple console-based interface
    Console,
    /// Rich terminal UI with formatting
    Terminal,
    /// Web-based interface
    Web,
    /// API-only (no visual interface)
    Api,
}

/// Available intervention strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InterventionStrategy {
    Continue,
    Pause,
    Stop,
    ModifyParameters,
    AddAction,
    RemoveAction,
    SkipAction,
    RestartWorkflow,
    OverrideResult,
    Escalate,
}

/// Menu display context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuDisplayContext {
    /// Current workflow status
    pub workflow_status: WorkflowStatus,

    /// Progress percentage (0-100)
    pub progress_percentage: u8,

    /// Current step information
    pub current_step: Option<String>,

    /// Time elapsed
    pub elapsed_time_s: u64,

    /// Recent messages
    pub recent_messages: Vec<String>,

    /// Available capabilities
    pub available_capabilities: Vec<String>,

    /// Resource usage summary
    pub resource_summary: ResourceSummary,
}

/// Resource usage summary for display
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceSummary {
    /// CPU usage percentage
    pub cpu_usage_percent: f64,

    /// Memory usage in MB
    pub memory_usage_mb: u64,

    /// Actions completed
    pub actions_completed: u32,

    /// Actions remaining
    pub actions_remaining: u32,
}

/// User input capture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInput {
    /// Selected option ID
    pub option_id: String,

    /// Additional input data
    pub input_data: Option<serde_json::Value>,

    /// User provided reason
    pub reason: Option<String>,

    /// Timestamp of input
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Menu session tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuSession {
    /// Session identifier
    pub session_id: String,

    /// When session started
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Session context
    pub context: MenuDisplayContext,

    /// Available options
    pub options: Vec<MenuOption>,

    /// Session timeout
    pub timeout_at: chrono::DateTime<chrono::Utc>,

    /// Whether session is active
    pub active: bool,
}

impl MenuSession {
    /// Check if session has timed out
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.timeout_at
    }

    /// Get time remaining in seconds
    pub fn time_remaining_s(&self) -> i64 {
        (self.timeout_at - chrono::Utc::now()).num_seconds().max(0)
    }
}

/// Main menu system implementation
pub struct MenuSystem {
    config: MenuSystemConfig,
    active_sessions: HashMap<String, MenuSession>,
    interaction_history: Vec<UserAction>,
    suggestion_engine: SuggestionEngine,
}

impl MenuSystem {
    /// Create a new menu system
    pub fn new() -> Result<Self> {
        let config = MenuSystemConfig::default();
        let suggestion_engine = SuggestionEngine::new(&config)?;

        info!(
            interactive_mode = config.interactive_mode,
            ui_style = ?config.ui_style,
            "Menu system initialized"
        );

        Ok(Self {
            config,
            active_sessions: HashMap::new(),
            interaction_history: Vec::new(),
            suggestion_engine,
        })
    }

    /// Create menu system with custom configuration
    pub fn with_config(config: MenuSystemConfig) -> Result<Self> {
        let suggestion_engine = SuggestionEngine::new(&config)?;

        info!(
            interactive_mode = config.interactive_mode,
            ui_style = ?config.ui_style,
            "Menu system initialized with custom config"
        );

        Ok(Self {
            config,
            active_sessions: HashMap::new(),
            interaction_history: Vec::new(),
            suggestion_engine,
        })
    }

    /// Handle workflow stall with user intervention
    pub async fn handle_stall(
        &mut self,
        state_machine: &StateMachine,
    ) -> Result<Option<UserAction>> {
        if !self.config.interactive_mode {
            debug!("Interactive mode disabled, skipping stall handling");
            return Ok(None);
        }

        info!(
            workflow_id = %state_machine.workflow_id,
            "Handling workflow stall"
        );

        // Create menu context
        let context = self.create_menu_context(state_machine, None).await?;

        // Generate stall-specific options
        let options = self.generate_stall_options(state_machine, &context).await?;

        // Create menu session
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = self
            .create_menu_session(session_id.clone(), context, options)
            .await?;

        // Present menu to user
        let user_input = self.present_menu_and_wait(&session).await?;

        // Process user input
        if let Some(input) = user_input {
            let user_action = self.process_user_input(input, state_machine).await?;
            self.interaction_history.push(user_action.clone());
            Ok(Some(user_action))
        } else {
            warn!("Menu session timed out or cancelled");
            Ok(None)
        }
    }

    /// Handle workflow pause with user interaction
    pub async fn handle_pause(
        &mut self,
        state_machine: &StateMachine,
    ) -> Result<Option<UserAction>> {
        if !self.config.interactive_mode {
            debug!("Interactive mode disabled, skipping pause handling");
            return Ok(None);
        }

        info!(
            workflow_id = %state_machine.workflow_id,
            "Handling workflow pause"
        );

        // Create menu context
        let context = self.create_menu_context(state_machine, None).await?;

        // Generate pause-specific options
        let options = self.generate_pause_options(state_machine, &context).await?;

        // Create menu session
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = self
            .create_menu_session(session_id.clone(), context, options)
            .await?;

        // Present menu to user
        let user_input = self.present_menu_and_wait(&session).await?;

        // Process user input
        if let Some(input) = user_input {
            let user_action = self.process_user_input(input, state_machine).await?;
            self.interaction_history.push(user_action.clone());
            Ok(Some(user_action))
        } else {
            Ok(None)
        }
    }

    /// Create menu context from state machine
    async fn create_menu_context(
        &self,
        state_machine: &StateMachine,
        stall_info: Option<&StallInfo>,
    ) -> Result<MenuDisplayContext> {
        let workflow_status = match state_machine.current_state() {
            WorkflowState::Initializing => WorkflowStatus::Initializing,
            WorkflowState::Planning => WorkflowStatus::Planning,
            WorkflowState::Executing => WorkflowStatus::Executing,
            WorkflowState::Completed => WorkflowStatus::Completed,
            WorkflowState::Failed(_) => WorkflowStatus::Failed,
            WorkflowState::Paused => WorkflowStatus::Paused,
        };

        let progress_percentage = (state_machine.get_progress() * 100.0) as u8;

        let current_step = if let Some(executing) = state_machine.executing_actions.values().next()
        {
            Some(format!("Executing: {}", executing.expected_outcome))
        } else if let Some(next_action) = state_machine.action_queue.front() {
            Some(format!("Next: {}", next_action.expected_outcome))
        } else {
            None
        };

        let elapsed_time_s = if let Some(first_transition) = state_machine.state_history.first() {
            (chrono::Utc::now() - first_transition.timestamp).num_seconds() as u64
        } else {
            0
        };

        let mut recent_messages = Vec::new();

        // Add stall information if present
        if let Some(stall) = stall_info {
            recent_messages.push(format!(
                "⚠️  Stall detected: {}",
                stall.possible_causes.join(", ")
            ));
        }

        // Add recent completed actions
        for result in state_machine.completed_actions.iter().rev().take(3) {
            recent_messages.push(format!("✅ Completed: {}", result.action_id));
        }

        // Add failed actions
        for result in state_machine.failed_actions.iter().rev().take(2) {
            if let Some(error) = &result.error {
                recent_messages.push(format!(
                    "❌ Failed: {} - {}",
                    result.action_id, error.message
                ));
            }
        }

        let available_capabilities = self.get_available_capabilities();

        let resource_summary = ResourceSummary {
            cpu_usage_percent: 0.0, // Would be calculated from actual resource monitoring
            memory_usage_mb: state_machine.total_resource_usage.memory_bytes / (1024 * 1024),
            actions_completed: state_machine.completed_actions.len() as u32,
            actions_remaining: state_machine.action_queue.len() as u32,
        };

        Ok(MenuDisplayContext {
            workflow_status,
            progress_percentage,
            current_step,
            elapsed_time_s,
            recent_messages,
            available_capabilities,
            resource_summary,
        })
    }

    /// Generate options for stall handling
    async fn generate_stall_options(
        &self,
        state_machine: &StateMachine,
        context: &MenuDisplayContext,
    ) -> Result<Vec<MenuOption>> {
        let mut options = Vec::new();

        // Get suggestions from suggestion engine
        let suggestions = self
            .suggestion_engine
            .suggest_stall_interventions(state_machine, context)
            .await?;

        // Convert suggestions to menu options
        for (i, suggestion) in suggestions
            .iter()
            .take(self.config.max_menu_options)
            .enumerate()
        {
            let option = MenuOption {
                id: format!("suggestion_{}", i),
                text: suggestion.title.clone(),
                description: suggestion.description.clone(),
                requires_input: suggestion.requires_input,
            };
            options.push(option);
        }

        // Add standard options
        if options.len() < self.config.max_menu_options {
            options.extend(self.get_standard_stall_options());
        }

        Ok(options)
    }

    /// Generate options for pause handling
    async fn generate_pause_options(
        &self,
        state_machine: &StateMachine,
        context: &MenuDisplayContext,
    ) -> Result<Vec<MenuOption>> {
        let mut options = Vec::new();

        // Add pause-specific options
        options.push(MenuOption {
            id: "continue".to_string(),
            text: "Continue Execution".to_string(),
            description: "Resume workflow execution from current state".to_string(),
            requires_input: false,
        });

        options.push(MenuOption {
            id: "stop".to_string(),
            text: "Stop Workflow".to_string(),
            description: "Terminate workflow execution".to_string(),
            requires_input: true, // Require confirmation
        });

        options.push(MenuOption {
            id: "modify_params".to_string(),
            text: "Modify Parameters".to_string(),
            description: "Change workflow parameters before continuing".to_string(),
            requires_input: true,
        });

        options.push(MenuOption {
            id: "inspect_state".to_string(),
            text: "Inspect State".to_string(),
            description: "View detailed workflow state information".to_string(),
            requires_input: false,
        });

        if state_machine.action_queue.len() > 0 {
            options.push(MenuOption {
                id: "modify_actions".to_string(),
                text: "Modify Actions".to_string(),
                description: "Add, remove, or modify queued actions".to_string(),
                requires_input: true,
            });
        }

        options.push(MenuOption {
            id: "escalate".to_string(),
            text: "Escalate to Human".to_string(),
            description: "Request human expert assistance".to_string(),
            requires_input: true,
        });

        Ok(options)
    }

    /// Get standard stall intervention options
    fn get_standard_stall_options(&self) -> Vec<MenuOption> {
        vec![
            MenuOption {
                id: "continue".to_string(),
                text: "Continue and Wait".to_string(),
                description: "Continue execution and wait longer for progress".to_string(),
                requires_input: false,
            },
            MenuOption {
                id: "restart_current".to_string(),
                text: "Restart Current Action".to_string(),
                description: "Cancel and restart the currently executing action".to_string(),
                requires_input: false,
            },
            MenuOption {
                id: "skip_current".to_string(),
                text: "Skip Current Action".to_string(),
                description: "Skip the current action and move to the next one".to_string(),
                requires_input: true,
            },
            MenuOption {
                id: "increase_timeout".to_string(),
                text: "Increase Timeout".to_string(),
                description: "Increase the timeout threshold for current operation".to_string(),
                requires_input: true,
            },
            MenuOption {
                id: "manual_intervention".to_string(),
                text: "Manual Intervention".to_string(),
                description: "Manually provide input or override current state".to_string(),
                requires_input: true,
            },
            MenuOption {
                id: "escalate".to_string(),
                text: "Escalate to Human".to_string(),
                description: "Request human expert assistance with this workflow".to_string(),
                requires_input: true,
            },
        ]
    }

    /// Create a new menu session
    async fn create_menu_session(
        &mut self,
        session_id: String,
        context: MenuDisplayContext,
        options: Vec<MenuOption>,
    ) -> Result<MenuSession> {
        let now = chrono::Utc::now();
        let timeout_at = now + chrono::Duration::seconds(self.config.default_timeout_s as i64);

        let session = MenuSession {
            session_id: session_id.clone(),
            started_at: now,
            context,
            options,
            timeout_at,
            active: true,
        };

        self.active_sessions.insert(session_id, session.clone());

        debug!(
            session_id = %session.session_id,
            options_count = session.options.len(),
            timeout_s = self.config.default_timeout_s,
            "Menu session created"
        );

        Ok(session)
    }

    /// Present menu to user and wait for input
    async fn present_menu_and_wait(&mut self, session: &MenuSession) -> Result<Option<UserInput>> {
        match self.config.ui_style {
            UiStyle::Console => self.present_console_menu(session).await,
            UiStyle::Terminal => self.present_terminal_menu(session).await,
            UiStyle::Web => self.present_web_menu(session).await,
            UiStyle::Api => self.present_api_menu(session).await,
        }
    }

    /// Present console-based menu
    async fn present_console_menu(&mut self, session: &MenuSession) -> Result<Option<UserInput>> {
        // In a real implementation, this would use proper console I/O
        // For now, we'll simulate user interaction

        debug!("=== WORKFLOW INTERVENTION MENU ===");
        debug!("Status: {:?}", session.context.workflow_status);
        debug!("Progress: {}%", session.context.progress_percentage);
        debug!("Time Elapsed: {}s", session.context.elapsed_time_s);

        if let Some(step) = &session.context.current_step {
            debug!("Current Step: {}", step);
        }

        for message in &session.context.recent_messages {
            debug!("  {}", message);
        }

        debug!("\nAvailable Options:");
        for (i, option) in session.options.iter().enumerate() {
            debug!("  {}: {} - {}", i + 1, option.text, option.description);
        }

        debug!("\nTime remaining: {}s", session.time_remaining_s());

        // Simulate user selection (in real implementation, this would wait for user input)
        // For testing, we'll return a default "continue" action
        let user_input = UserInput {
            option_id: "continue".to_string(),
            input_data: None,
            reason: Some("Automated test selection".to_string()),
            timestamp: chrono::Utc::now(),
        };

        Ok(Some(user_input))
    }

    /// Present terminal-based menu (placeholder)
    async fn present_terminal_menu(&mut self, session: &MenuSession) -> Result<Option<UserInput>> {
        // Would use a rich terminal UI library like ratatui
        debug!("Terminal UI not implemented, falling back to console");
        self.present_console_menu(session).await
    }

    /// Present web-based menu (placeholder)
    async fn present_web_menu(&mut self, session: &MenuSession) -> Result<Option<UserInput>> {
        // Would integrate with web interface
        debug!("Web UI not implemented, falling back to console");
        self.present_console_menu(session).await
    }

    /// Present API-only menu (placeholder)
    async fn present_api_menu(&mut self, session: &MenuSession) -> Result<Option<UserInput>> {
        // Would provide API endpoints for external integration
        debug!("API mode - menu session available via API endpoints");

        // Return timeout after waiting period (simulated)
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        Ok(None)
    }

    /// Process user input and create user action
    async fn process_user_input(
        &self,
        input: UserInput,
        state_machine: &StateMachine,
    ) -> Result<UserAction> {
        debug!(
            option_id = %input.option_id,
            "Processing user input"
        );

        let (action_type, input_data) = match input.option_id.as_str() {
            "continue" => (UserActionType::Continue, None),
            "stop" => (UserActionType::Stop, None),
            "pause" => (UserActionType::Pause, None),
            "restart_current" => (UserActionType::Continue, None), // Simplified
            "skip_current" => (UserActionType::RemoveAction, input.input_data),
            "modify_params" => (UserActionType::ModifyParameters, input.input_data),
            "modify_actions" => (UserActionType::AddAction, input.input_data),
            "manual_intervention" => (UserActionType::OverrideResult, input.input_data),
            "escalate" => (UserActionType::Escalate, None),
            _ => {
                // Handle suggestion-based options
                if input.option_id.starts_with("suggestion_") {
                    (UserActionType::Continue, input.input_data)
                } else {
                    return Err(anyhow::anyhow!("Unknown option: {}", input.option_id));
                }
            }
        };

        let reason = input
            .reason
            .unwrap_or_else(|| format!("User selected option: {}", input.option_id));

        Ok(UserAction {
            action_type,
            input: input_data,
            reason,
        })
    }

    /// Get available capabilities for menu context
    fn get_available_capabilities(&self) -> Vec<String> {
        vec![
            "fs.read.v1".to_string(),
            "fs.write.v1".to_string(),
            "http.fetch.v1".to_string(),
            "shell.exec.v1".to_string(),
            "planner.exec.v1".to_string(),
        ]
    }

    /// Get interaction history
    pub fn get_interaction_history(&self) -> &[UserAction] {
        &self.interaction_history
    }

    /// Get active sessions
    pub fn get_active_sessions(&self) -> &HashMap<String, MenuSession> {
        &self.active_sessions
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(&mut self) -> u32 {
        let initial_count = self.active_sessions.len();
        self.active_sessions
            .retain(|_, session| !session.is_expired());
        (initial_count - self.active_sessions.len()) as u32
    }

    /// Get menu system statistics
    pub fn get_statistics(&self) -> MenuStatistics {
        MenuStatistics {
            total_interactions: self.interaction_history.len() as u32,
            active_sessions: self.active_sessions.len() as u32,
            successful_interventions: self
                .interaction_history
                .iter()
                .filter(|action| !matches!(action.action_type, UserActionType::Escalate))
                .count() as u32,
            escalations: self
                .interaction_history
                .iter()
                .filter(|action| matches!(action.action_type, UserActionType::Escalate))
                .count() as u32,
        }
    }
}

/// Suggestion engine for intelligent menu options
pub struct SuggestionEngine {
    config: MenuSystemConfig,
}

impl SuggestionEngine {
    /// Create new suggestion engine
    pub fn new(config: &MenuSystemConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Suggest interventions for stall situations
    pub async fn suggest_stall_interventions(
        &self,
        state_machine: &StateMachine,
        context: &MenuDisplayContext,
    ) -> Result<Vec<MenuSuggestion>> {
        let mut suggestions = Vec::new();

        // Analyze current state and suggest appropriate interventions
        match context.workflow_status {
            WorkflowStatus::Executing => {
                if context.progress_percentage < 10 && context.elapsed_time_s > 60 {
                    suggestions.push(MenuSuggestion {
                        title: "Restart with Lower Complexity".to_string(),
                        description: "Low progress after significant time - consider simplifying the approach".to_string(),
                        confidence: 0.8,
                        requires_input: true,
                    });
                }

                if state_machine.executing_actions.is_empty()
                    && !state_machine.action_queue.is_empty()
                {
                    suggestions.push(MenuSuggestion {
                        title: "Break Dependency Deadlock".to_string(),
                        description:
                            "Actions are queued but none can execute - likely dependency issue"
                                .to_string(),
                        confidence: 0.9,
                        requires_input: false,
                    });
                }

                if context.resource_summary.memory_usage_mb > 1000 {
                    suggestions.push(MenuSuggestion {
                        title: "Reduce Memory Usage".to_string(),
                        description: "High memory usage detected - consider resource optimization"
                            .to_string(),
                        confidence: 0.7,
                        requires_input: true,
                    });
                }
            }

            WorkflowStatus::Planning => {
                if context.elapsed_time_s > 300 {
                    // 5 minutes
                    suggestions.push(MenuSuggestion {
                        title: "Simplify Planning Scope".to_string(),
                        description:
                            "Planning is taking too long - consider reducing scope or complexity"
                                .to_string(),
                        confidence: 0.8,
                        requires_input: true,
                    });
                }
            }

            _ => {
                // General suggestions for other states
                suggestions.push(MenuSuggestion {
                    title: "Continue with Monitoring".to_string(),
                    description: "Monitor progress and wait for natural resolution".to_string(),
                    confidence: 0.6,
                    requires_input: false,
                });
            }
        }

        // Add pattern-based suggestions based on history
        suggestions.extend(self.suggest_from_patterns(state_machine).await?);

        // Sort by confidence and take top suggestions
        suggestions.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        suggestions.truncate(self.config.max_menu_options);

        Ok(suggestions)
    }

    /// Suggest interventions based on historical patterns
    async fn suggest_from_patterns(
        &self,
        state_machine: &StateMachine,
    ) -> Result<Vec<MenuSuggestion>> {
        let mut suggestions = Vec::new();

        // Check if there are repeated failures
        if state_machine.failed_actions.len() > 2 {
            let repeated_errors = self.analyze_error_patterns(&state_machine.failed_actions);
            if !repeated_errors.is_empty() {
                suggestions.push(MenuSuggestion {
                    title: "Address Recurring Error".to_string(),
                    description: format!("Detected pattern: {}", repeated_errors[0]),
                    confidence: 0.85,
                    requires_input: true,
                });
            }
        }

        // Check for resource usage patterns
        if state_machine.total_resource_usage.cpu_ms > 60000 {
            // 1 minute of CPU
            suggestions.push(MenuSuggestion {
                title: "Optimize Resource Usage".to_string(),
                description: "High CPU usage detected - consider optimization or batching"
                    .to_string(),
                confidence: 0.7,
                requires_input: false,
            });
        }

        Ok(suggestions)
    }

    /// Analyze error patterns in failed actions
    fn analyze_error_patterns(
        &self,
        failed_actions: &[super::schemas::ActionResult],
    ) -> Vec<String> {
        let mut patterns = Vec::new();

        // Simple pattern detection - look for repeated error codes
        let mut error_counts: HashMap<String, u32> = HashMap::new();

        for action in failed_actions {
            if let Some(error) = &action.error {
                *error_counts.entry(error.code.clone()).or_insert(0) += 1;
            }
        }

        for (error_code, count) in error_counts {
            if count > 1 {
                patterns.push(format!("Repeated '{}' errors", error_code));
            }
        }

        patterns
    }
}

/// Menu suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuSuggestion {
    /// Suggestion title
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Confidence in this suggestion (0.0 - 1.0)
    pub confidence: f64,

    /// Whether this suggestion requires additional user input
    pub requires_input: bool,
}

/// Menu system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuStatistics {
    /// Total user interactions
    pub total_interactions: u32,

    /// Currently active menu sessions
    pub active_sessions: u32,

    /// Successful interventions (non-escalations)
    pub successful_interventions: u32,

    /// Number of escalations to humans
    pub escalations: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::planner_exec::schemas::{PlannerExecParams, WorkflowType};
    use std::collections::HashMap;

    fn create_test_state_machine() -> StateMachine {
        let params = PlannerExecParams {
            workflow_id: "test-workflow-456".to_string(),
            goal: "Test workflow".to_string(),
            workflow_type: WorkflowType::Simple,
            max_steps: 10,
            timeout_ms: Some(30000),
            context: HashMap::new(),
            allowed_capabilities: vec![],
            resource_limits: super::super::schemas::ResourceLimits::default(),
            preferences: super::super::schemas::ExecutionPreferences::default(),
        };

        StateMachine::new("test-workflow".to_string(), params).unwrap()
    }

    #[tokio::test]
    async fn test_menu_system_creation() {
        let menu_system = MenuSystem::new().unwrap();

        assert!(menu_system.config.interactive_mode);
        assert_eq!(menu_system.config.default_timeout_s, 60);
        assert_eq!(menu_system.active_sessions.len(), 0);
    }

    #[tokio::test]
    async fn test_menu_context_creation() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let context = menu_system
            .create_menu_context(&state_machine, None)
            .await
            .unwrap();

        assert_eq!(context.workflow_status, WorkflowStatus::Initializing);
        assert_eq!(context.progress_percentage, 0);
        assert!(context.elapsed_time_s >= 0);
    }

    #[tokio::test]
    async fn test_stall_option_generation() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let context = menu_system
            .create_menu_context(&state_machine, None)
            .await
            .unwrap();
        let options = menu_system
            .generate_stall_options(&state_machine, &context)
            .await
            .unwrap();

        assert!(!options.is_empty());
        assert!(options.len() <= menu_system.config.max_menu_options);

        // Check for expected options
        let option_ids: Vec<String> = options.iter().map(|o| o.id.clone()).collect();
        assert!(option_ids.contains(&"continue".to_string()));
    }

    #[tokio::test]
    async fn test_pause_option_generation() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let context = menu_system
            .create_menu_context(&state_machine, None)
            .await
            .unwrap();
        let options = menu_system
            .generate_pause_options(&state_machine, &context)
            .await
            .unwrap();

        assert!(!options.is_empty());

        // Check for expected pause options
        let option_texts: Vec<String> = options.iter().map(|o| o.text.clone()).collect();
        assert!(option_texts.iter().any(|text| text.contains("Continue")));
        assert!(option_texts.iter().any(|text| text.contains("Stop")));
    }

    #[tokio::test]
    async fn test_user_input_processing() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "continue".to_string(),
            input_data: None,
            reason: Some("Test reason".to_string()),
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::Continue);
        assert_eq!(user_action.reason, "Test reason");
    }

    #[tokio::test]
    async fn test_suggestion_engine() {
        let config = MenuSystemConfig::default();
        let suggestion_engine = SuggestionEngine::new(&config).unwrap();
        let state_machine = create_test_state_machine();

        let context = MenuDisplayContext {
            workflow_status: WorkflowStatus::Executing,
            progress_percentage: 5,
            current_step: None,
            elapsed_time_s: 120, // 2 minutes
            recent_messages: vec![],
            available_capabilities: vec![],
            resource_summary: ResourceSummary::default(),
        };

        let suggestions = suggestion_engine
            .suggest_stall_interventions(&state_machine, &context)
            .await
            .unwrap();

        assert!(!suggestions.is_empty());

        // Should suggest restart with lower complexity due to low progress and high elapsed time
        assert!(suggestions
            .iter()
            .any(|s| s.title.contains("Restart") || s.title.contains("complexity")));
    }

    #[tokio::test]
    async fn test_menu_session_management() {
        let mut menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let context = menu_system
            .create_menu_context(&state_machine, None)
            .await
            .unwrap();
        let options = menu_system
            .generate_stall_options(&state_machine, &context)
            .await
            .unwrap();

        let session_id = "test-session".to_string();
        let session = menu_system
            .create_menu_session(session_id.clone(), context, options)
            .await
            .unwrap();

        assert_eq!(session.session_id, session_id);
        assert!(session.active);
        assert!(!session.is_expired());
        assert!(session.time_remaining_s() > 0);

        // Check session is stored
        assert!(menu_system.active_sessions.contains_key(&session_id));
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let mut menu_system = MenuSystem::new().unwrap();

        // Create expired session manually
        let expired_session = MenuSession {
            session_id: "expired".to_string(),
            started_at: chrono::Utc::now() - chrono::Duration::hours(1),
            context: MenuDisplayContext {
                workflow_status: WorkflowStatus::Executing,
                progress_percentage: 50,
                current_step: None,
                elapsed_time_s: 3600,
                recent_messages: vec![],
                available_capabilities: vec![],
                resource_summary: ResourceSummary::default(),
            },
            options: vec![],
            timeout_at: chrono::Utc::now() - chrono::Duration::minutes(30),
            active: true,
        };

        menu_system
            .active_sessions
            .insert("expired".to_string(), expired_session);

        let cleaned_count = menu_system.cleanup_expired_sessions();
        assert_eq!(cleaned_count, 1);
        assert!(menu_system.active_sessions.is_empty());
    }

    #[tokio::test]
    async fn test_statistics() {
        let mut menu_system = MenuSystem::new().unwrap();

        // Add some test interactions
        menu_system.interaction_history.push(UserAction {
            action_type: UserActionType::Continue,
            input: None,
            reason: "Test interaction 1".to_string(),
        });

        menu_system.interaction_history.push(UserAction {
            action_type: UserActionType::Escalate,
            input: None,
            reason: "Test escalation".to_string(),
        });

        let stats = menu_system.get_statistics();

        assert_eq!(stats.total_interactions, 2);
        assert_eq!(stats.successful_interventions, 1);
        assert_eq!(stats.escalations, 1);
    }

    // === UiStyle Serialization Tests ===

    #[test]
    fn test_ui_style_console_serialization() {
        let style = UiStyle::Console;
        let json = serde_json::to_string(&style).unwrap();
        assert!(json.contains("console"));
        let parsed: UiStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, UiStyle::Console);
    }

    #[test]
    fn test_ui_style_terminal_serialization() {
        let style = UiStyle::Terminal;
        let json = serde_json::to_string(&style).unwrap();
        assert!(json.contains("terminal"));
        let parsed: UiStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, UiStyle::Terminal);
    }

    #[test]
    fn test_ui_style_web_serialization() {
        let style = UiStyle::Web;
        let json = serde_json::to_string(&style).unwrap();
        assert!(json.contains("web"));
        let parsed: UiStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, UiStyle::Web);
    }

    #[test]
    fn test_ui_style_api_serialization() {
        let style = UiStyle::Api;
        let json = serde_json::to_string(&style).unwrap();
        assert!(json.contains("api"));
        let parsed: UiStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, UiStyle::Api);
    }

    // === InterventionStrategy Serialization Tests ===

    #[test]
    fn test_intervention_strategy_continue_serialization() {
        let strategy = InterventionStrategy::Continue;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("continue"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::Continue);
    }

    #[test]
    fn test_intervention_strategy_pause_serialization() {
        let strategy = InterventionStrategy::Pause;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("pause"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::Pause);
    }

    #[test]
    fn test_intervention_strategy_stop_serialization() {
        let strategy = InterventionStrategy::Stop;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("stop"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::Stop);
    }

    #[test]
    fn test_intervention_strategy_modify_parameters_serialization() {
        let strategy = InterventionStrategy::ModifyParameters;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("modify_parameters"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::ModifyParameters);
    }

    #[test]
    fn test_intervention_strategy_add_action_serialization() {
        let strategy = InterventionStrategy::AddAction;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("add_action"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::AddAction);
    }

    #[test]
    fn test_intervention_strategy_remove_action_serialization() {
        let strategy = InterventionStrategy::RemoveAction;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("remove_action"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::RemoveAction);
    }

    #[test]
    fn test_intervention_strategy_skip_action_serialization() {
        let strategy = InterventionStrategy::SkipAction;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("skip_action"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::SkipAction);
    }

    #[test]
    fn test_intervention_strategy_restart_workflow_serialization() {
        let strategy = InterventionStrategy::RestartWorkflow;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("restart_workflow"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::RestartWorkflow);
    }

    #[test]
    fn test_intervention_strategy_override_result_serialization() {
        let strategy = InterventionStrategy::OverrideResult;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("override_result"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::OverrideResult);
    }

    #[test]
    fn test_intervention_strategy_escalate_serialization() {
        let strategy = InterventionStrategy::Escalate;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("escalate"));
        let parsed: InterventionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionStrategy::Escalate);
    }

    // === MenuSystemConfig Tests ===

    #[test]
    fn test_menu_system_config_default() {
        let config = MenuSystemConfig::default();
        assert_eq!(config.default_timeout_s, 60);
        assert!(config.interactive_mode);
        assert!(config.auto_suggestions);
        assert_eq!(config.max_menu_options, 10);
        assert_eq!(config.ui_style, UiStyle::Console);
        assert!(!config.intervention_strategies.is_empty());
    }

    #[test]
    fn test_menu_system_config_serialization() {
        let config = MenuSystemConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("default_timeout_s"));
        assert!(json.contains("interactive_mode"));
        let parsed: MenuSystemConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.default_timeout_s, config.default_timeout_s);
        assert_eq!(parsed.interactive_mode, config.interactive_mode);
    }

    // === ResourceSummary Tests ===

    #[test]
    fn test_resource_summary_default() {
        let summary = ResourceSummary::default();
        assert_eq!(summary.cpu_usage_percent, 0.0);
        assert_eq!(summary.memory_usage_mb, 0);
        assert_eq!(summary.actions_completed, 0);
        assert_eq!(summary.actions_remaining, 0);
    }

    #[test]
    fn test_resource_summary_serialization() {
        let summary = ResourceSummary {
            cpu_usage_percent: 45.5,
            memory_usage_mb: 512,
            actions_completed: 10,
            actions_remaining: 5,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("cpu_usage_percent"));
        assert!(json.contains("45.5"));
        let parsed: ResourceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cpu_usage_percent, 45.5);
        assert_eq!(parsed.memory_usage_mb, 512);
    }

    // === MenuDisplayContext Tests ===

    #[test]
    fn test_menu_display_context_serialization() {
        let context = MenuDisplayContext {
            workflow_status: WorkflowStatus::Executing,
            progress_percentage: 75,
            current_step: Some("Processing data".to_string()),
            elapsed_time_s: 120,
            recent_messages: vec!["Message 1".to_string(), "Message 2".to_string()],
            available_capabilities: vec!["fs.read.v1".to_string()],
            resource_summary: ResourceSummary::default(),
        };
        let json = serde_json::to_string(&context).unwrap();
        assert!(json.contains("workflow_status"));
        assert!(json.contains("progress_percentage"));
        let parsed: MenuDisplayContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.progress_percentage, 75);
        assert_eq!(parsed.current_step, Some("Processing data".to_string()));
    }

    // === UserInput Tests ===

    #[test]
    fn test_user_input_serialization() {
        let input = UserInput {
            option_id: "continue".to_string(),
            input_data: Some(serde_json::json!({"key": "value"})),
            reason: Some("Test reason".to_string()),
            timestamp: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("option_id"));
        assert!(json.contains("continue"));
        let parsed: UserInput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.option_id, "continue");
        assert!(parsed.input_data.is_some());
    }

    #[test]
    fn test_user_input_without_optional_fields() {
        let input = UserInput {
            option_id: "stop".to_string(),
            input_data: None,
            reason: None,
            timestamp: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&input).unwrap();
        let parsed: UserInput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.option_id, "stop");
        assert!(parsed.input_data.is_none());
        assert!(parsed.reason.is_none());
    }

    // === MenuSession Tests ===

    #[test]
    fn test_menu_session_is_expired_not_expired() {
        let session = MenuSession {
            session_id: "test".to_string(),
            started_at: chrono::Utc::now(),
            context: MenuDisplayContext {
                workflow_status: WorkflowStatus::Executing,
                progress_percentage: 50,
                current_step: None,
                elapsed_time_s: 60,
                recent_messages: vec![],
                available_capabilities: vec![],
                resource_summary: ResourceSummary::default(),
            },
            options: vec![],
            timeout_at: chrono::Utc::now() + chrono::Duration::hours(1),
            active: true,
        };
        assert!(!session.is_expired());
        assert!(session.time_remaining_s() > 0);
    }

    #[test]
    fn test_menu_session_is_expired_expired() {
        let session = MenuSession {
            session_id: "test".to_string(),
            started_at: chrono::Utc::now() - chrono::Duration::hours(2),
            context: MenuDisplayContext {
                workflow_status: WorkflowStatus::Executing,
                progress_percentage: 50,
                current_step: None,
                elapsed_time_s: 60,
                recent_messages: vec![],
                available_capabilities: vec![],
                resource_summary: ResourceSummary::default(),
            },
            options: vec![],
            timeout_at: chrono::Utc::now() - chrono::Duration::hours(1),
            active: true,
        };
        assert!(session.is_expired());
        assert_eq!(session.time_remaining_s(), 0);
    }

    #[test]
    fn test_menu_session_serialization() {
        let session = MenuSession {
            session_id: "test-session-123".to_string(),
            started_at: chrono::Utc::now(),
            context: MenuDisplayContext {
                workflow_status: WorkflowStatus::Executing,
                progress_percentage: 50,
                current_step: None,
                elapsed_time_s: 60,
                recent_messages: vec![],
                available_capabilities: vec![],
                resource_summary: ResourceSummary::default(),
            },
            options: vec![],
            timeout_at: chrono::Utc::now() + chrono::Duration::hours(1),
            active: true,
        };
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("test-session-123"));
        let parsed: MenuSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "test-session-123");
        assert!(parsed.active);
    }

    // === MenuSuggestion Tests ===

    #[test]
    fn test_menu_suggestion_serialization() {
        let suggestion = MenuSuggestion {
            title: "Test Suggestion".to_string(),
            description: "A test suggestion description".to_string(),
            confidence: 0.85,
            requires_input: true,
        };
        let json = serde_json::to_string(&suggestion).unwrap();
        assert!(json.contains("Test Suggestion"));
        assert!(json.contains("0.85"));
        let parsed: MenuSuggestion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "Test Suggestion");
        assert_eq!(parsed.confidence, 0.85);
        assert!(parsed.requires_input);
    }

    // === MenuStatistics Tests ===

    #[test]
    fn test_menu_statistics_serialization() {
        let stats = MenuStatistics {
            total_interactions: 100,
            active_sessions: 5,
            successful_interventions: 80,
            escalations: 20,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("total_interactions"));
        assert!(json.contains("100"));
        let parsed: MenuStatistics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_interactions, 100);
        assert_eq!(parsed.escalations, 20);
    }

    // === MenuSystem Additional Tests ===

    #[tokio::test]
    async fn test_menu_system_with_custom_config() {
        let config = MenuSystemConfig {
            default_timeout_s: 120,
            interactive_mode: false,
            auto_suggestions: false,
            max_menu_options: 5,
            ui_style: UiStyle::Web,
            intervention_strategies: vec![
                InterventionStrategy::Continue,
                InterventionStrategy::Stop,
            ],
        };
        let menu_system = MenuSystem::with_config(config.clone()).unwrap();
        assert_eq!(menu_system.config.default_timeout_s, 120);
        assert!(!menu_system.config.interactive_mode);
        assert_eq!(menu_system.config.ui_style, UiStyle::Web);
    }

    #[tokio::test]
    async fn test_handle_stall_non_interactive_mode() {
        let config = MenuSystemConfig {
            interactive_mode: false,
            ..MenuSystemConfig::default()
        };
        let mut menu_system = MenuSystem::with_config(config).unwrap();
        let state_machine = create_test_state_machine();

        let result = menu_system.handle_stall(&state_machine).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_handle_pause_non_interactive_mode() {
        let config = MenuSystemConfig {
            interactive_mode: false,
            ..MenuSystemConfig::default()
        };
        let mut menu_system = MenuSystem::with_config(config).unwrap();
        let state_machine = create_test_state_machine();

        let result = menu_system.handle_pause(&state_machine).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_process_user_input_stop() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "stop".to_string(),
            input_data: None,
            reason: None,
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::Stop);
    }

    #[tokio::test]
    async fn test_process_user_input_pause() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "pause".to_string(),
            input_data: None,
            reason: None,
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::Pause);
    }

    #[tokio::test]
    async fn test_process_user_input_skip_current() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "skip_current".to_string(),
            input_data: Some(serde_json::json!({"action_id": "action-123"})),
            reason: Some("Skipping action".to_string()),
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::RemoveAction);
    }

    #[tokio::test]
    async fn test_process_user_input_modify_params() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "modify_params".to_string(),
            input_data: Some(serde_json::json!({"param": "new_value"})),
            reason: None,
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::ModifyParameters);
    }

    #[tokio::test]
    async fn test_process_user_input_modify_actions() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "modify_actions".to_string(),
            input_data: Some(serde_json::json!({"new_action": "test"})),
            reason: None,
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::AddAction);
    }

    #[tokio::test]
    async fn test_process_user_input_manual_intervention() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "manual_intervention".to_string(),
            input_data: Some(serde_json::json!({"override_value": true})),
            reason: Some("Manual override".to_string()),
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::OverrideResult);
    }

    #[tokio::test]
    async fn test_process_user_input_escalate() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "escalate".to_string(),
            input_data: None,
            reason: Some("Need expert help".to_string()),
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::Escalate);
    }

    #[tokio::test]
    async fn test_process_user_input_suggestion_based() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "suggestion_0".to_string(),
            input_data: None,
            reason: None,
            timestamp: chrono::Utc::now(),
        };

        let user_action = menu_system
            .process_user_input(user_input, &state_machine)
            .await
            .unwrap();

        assert_eq!(user_action.action_type, UserActionType::Continue);
    }

    #[tokio::test]
    async fn test_process_user_input_unknown_option() {
        let menu_system = MenuSystem::new().unwrap();
        let state_machine = create_test_state_machine();

        let user_input = UserInput {
            option_id: "unknown_option".to_string(),
            input_data: None,
            reason: None,
            timestamp: chrono::Utc::now(),
        };

        let result = menu_system
            .process_user_input(user_input, &state_machine)
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_get_standard_stall_options() {
        let menu_system = MenuSystem::new().unwrap();
        let options = menu_system.get_standard_stall_options();

        assert!(!options.is_empty());
        assert!(options.iter().any(|o| o.id == "continue"));
        assert!(options.iter().any(|o| o.id == "restart_current"));
        assert!(options.iter().any(|o| o.id == "skip_current"));
        assert!(options.iter().any(|o| o.id == "increase_timeout"));
        assert!(options.iter().any(|o| o.id == "manual_intervention"));
        assert!(options.iter().any(|o| o.id == "escalate"));
    }

    #[test]
    fn test_get_available_capabilities() {
        let menu_system = MenuSystem::new().unwrap();
        let capabilities = menu_system.get_available_capabilities();

        assert!(!capabilities.is_empty());
        assert!(capabilities.contains(&"fs.read.v1".to_string()));
        assert!(capabilities.contains(&"fs.write.v1".to_string()));
        assert!(capabilities.contains(&"http.fetch.v1".to_string()));
    }

    #[test]
    fn test_get_interaction_history() {
        let menu_system = MenuSystem::new().unwrap();
        let history = menu_system.get_interaction_history();
        assert!(history.is_empty());
    }

    #[test]
    fn test_get_active_sessions() {
        let menu_system = MenuSystem::new().unwrap();
        let sessions = menu_system.get_active_sessions();
        assert!(sessions.is_empty());
    }

    // === SuggestionEngine Tests ===

    #[tokio::test]
    async fn test_suggestion_engine_planning_status() {
        let config = MenuSystemConfig::default();
        let suggestion_engine = SuggestionEngine::new(&config).unwrap();
        let state_machine = create_test_state_machine();

        let context = MenuDisplayContext {
            workflow_status: WorkflowStatus::Planning,
            progress_percentage: 10,
            current_step: None,
            elapsed_time_s: 400, // Over 5 minutes
            recent_messages: vec![],
            available_capabilities: vec![],
            resource_summary: ResourceSummary::default(),
        };

        let suggestions = suggestion_engine
            .suggest_stall_interventions(&state_machine, &context)
            .await
            .unwrap();

        assert!(!suggestions.is_empty());
        // Should suggest simplifying planning scope
        assert!(suggestions
            .iter()
            .any(|s| s.title.contains("Planning") || s.title.contains("Scope")));
    }

    #[tokio::test]
    async fn test_suggestion_engine_default_status() {
        let config = MenuSystemConfig::default();
        let suggestion_engine = SuggestionEngine::new(&config).unwrap();
        let state_machine = create_test_state_machine();

        let context = MenuDisplayContext {
            workflow_status: WorkflowStatus::Initializing,
            progress_percentage: 0,
            current_step: None,
            elapsed_time_s: 10,
            recent_messages: vec![],
            available_capabilities: vec![],
            resource_summary: ResourceSummary::default(),
        };

        let suggestions = suggestion_engine
            .suggest_stall_interventions(&state_machine, &context)
            .await
            .unwrap();

        assert!(!suggestions.is_empty());
    }

    #[tokio::test]
    async fn test_suggestion_engine_high_memory_usage() {
        let config = MenuSystemConfig::default();
        let suggestion_engine = SuggestionEngine::new(&config).unwrap();
        let state_machine = create_test_state_machine();

        let context = MenuDisplayContext {
            workflow_status: WorkflowStatus::Executing,
            progress_percentage: 50,
            current_step: None,
            elapsed_time_s: 60,
            recent_messages: vec![],
            available_capabilities: vec![],
            resource_summary: ResourceSummary {
                cpu_usage_percent: 50.0,
                memory_usage_mb: 2000, // High memory
                actions_completed: 5,
                actions_remaining: 5,
            },
        };

        let suggestions = suggestion_engine
            .suggest_stall_interventions(&state_machine, &context)
            .await
            .unwrap();

        // Should suggest memory optimization
        assert!(suggestions
            .iter()
            .any(|s| s.title.contains("Memory") || s.description.contains("memory")));
    }

    fn create_test_action_result(
        action_id: &str,
        error_code: Option<&str>,
    ) -> super::super::schemas::ActionResult {
        use super::super::schemas::{
            ActionError, ActionMetadata, ActionResult, ActionStatus, ExecutionEnvironment,
            ResourceUsage,
        };

        ActionResult {
            action_id: action_id.to_string(),
            status: ActionStatus::Failed,
            output: None,
            error: error_code.map(|code| ActionError {
                code: code.to_string(),
                message: format!("Error: {}", code),
                details: None,
                retryable: true,
            }),
            metadata: ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage {
                    cpu_ms: 100,
                    memory_bytes: 1024,
                    fs_operations: 10,
                    network_requests: 0,
                },
                environment: ExecutionEnvironment {
                    executor_id: "test-executor".to_string(),
                    sandbox_mode: "test".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_analyze_error_patterns_with_repeated_errors() {
        let config = MenuSystemConfig::default();
        let suggestion_engine = SuggestionEngine::new(&config).unwrap();

        let failed_actions = vec![
            create_test_action_result("action-1", Some("TIMEOUT")),
            create_test_action_result("action-2", Some("TIMEOUT")),
        ];

        let patterns = suggestion_engine.analyze_error_patterns(&failed_actions);
        assert!(!patterns.is_empty());
        assert!(patterns[0].contains("TIMEOUT"));
    }

    #[test]
    fn test_analyze_error_patterns_no_repeats() {
        let config = MenuSystemConfig::default();
        let suggestion_engine = SuggestionEngine::new(&config).unwrap();

        let failed_actions = vec![
            create_test_action_result("action-1", Some("TIMEOUT")),
            create_test_action_result("action-2", Some("PERMISSION_DENIED")),
        ];

        let patterns = suggestion_engine.analyze_error_patterns(&failed_actions);
        assert!(patterns.is_empty()); // No repeated errors
    }

    #[test]
    fn test_analyze_error_patterns_no_errors() {
        let config = MenuSystemConfig::default();
        let suggestion_engine = SuggestionEngine::new(&config).unwrap();

        let failed_actions = vec![
            create_test_action_result("action-1", None),
            create_test_action_result("action-2", None),
        ];

        let patterns = suggestion_engine.analyze_error_patterns(&failed_actions);
        assert!(patterns.is_empty());
    }

    // === UI Style Menu Presentation Tests ===

    #[tokio::test]
    async fn test_present_terminal_menu() {
        let mut menu_system = MenuSystem::with_config(MenuSystemConfig {
            ui_style: UiStyle::Terminal,
            ..MenuSystemConfig::default()
        })
        .unwrap();

        let session = MenuSession {
            session_id: "test".to_string(),
            started_at: chrono::Utc::now(),
            context: MenuDisplayContext {
                workflow_status: WorkflowStatus::Executing,
                progress_percentage: 50,
                current_step: Some("Testing".to_string()),
                elapsed_time_s: 60,
                recent_messages: vec!["Test message".to_string()],
                available_capabilities: vec![],
                resource_summary: ResourceSummary::default(),
            },
            options: vec![MenuOption {
                id: "continue".to_string(),
                text: "Continue".to_string(),
                description: "Continue execution".to_string(),
                requires_input: false,
            }],
            timeout_at: chrono::Utc::now() + chrono::Duration::hours(1),
            active: true,
        };

        let result = menu_system.present_menu_and_wait(&session).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_present_web_menu() {
        let mut menu_system = MenuSystem::with_config(MenuSystemConfig {
            ui_style: UiStyle::Web,
            ..MenuSystemConfig::default()
        })
        .unwrap();

        let session = MenuSession {
            session_id: "test".to_string(),
            started_at: chrono::Utc::now(),
            context: MenuDisplayContext {
                workflow_status: WorkflowStatus::Executing,
                progress_percentage: 50,
                current_step: None,
                elapsed_time_s: 60,
                recent_messages: vec![],
                available_capabilities: vec![],
                resource_summary: ResourceSummary::default(),
            },
            options: vec![],
            timeout_at: chrono::Utc::now() + chrono::Duration::hours(1),
            active: true,
        };

        let result = menu_system.present_menu_and_wait(&session).await.unwrap();
        assert!(result.is_some()); // Falls back to console
    }

    #[tokio::test]
    async fn test_present_api_menu() {
        let mut menu_system = MenuSystem::with_config(MenuSystemConfig {
            ui_style: UiStyle::Api,
            ..MenuSystemConfig::default()
        })
        .unwrap();

        let session = MenuSession {
            session_id: "test".to_string(),
            started_at: chrono::Utc::now(),
            context: MenuDisplayContext {
                workflow_status: WorkflowStatus::Executing,
                progress_percentage: 50,
                current_step: None,
                elapsed_time_s: 60,
                recent_messages: vec![],
                available_capabilities: vec![],
                resource_summary: ResourceSummary::default(),
            },
            options: vec![],
            timeout_at: chrono::Utc::now() + chrono::Duration::hours(1),
            active: true,
        };

        let result = menu_system.present_menu_and_wait(&session).await.unwrap();
        assert!(result.is_none()); // API mode returns None (timeout)
    }
}
