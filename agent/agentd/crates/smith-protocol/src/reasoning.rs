//! Reasoning session types for client-facing APIs
//! These are minimal types for Phase 1 cleanup - full reasoning logic stays in service

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Minimal reasoning session type for client visibility  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningSession {
    /// Unique identifier for this session
    pub id: Uuid,
    /// The original goal/query for this session  
    pub goal: String,
    /// Current state of the session
    pub state: SessionState,
    /// All reasoning steps in chronological order
    pub steps: Vec<ReasoningStep>,
    /// Maximum number of reasoning iterations allowed
    pub max_iterations: usize,
    /// Current iteration count
    pub current_iteration: usize,
    /// Timestamp when session was created  
    pub created_at: DateTime<Utc>,
    /// Timestamp when session was last updated
    pub updated_at: DateTime<Utc>,
    /// Start time of session
    pub start_time: DateTime<Utc>,
    /// Optional end time
    pub end_time: Option<DateTime<Utc>>,
}

/// Current state of a reasoning session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    /// Session is actively being processed
    Active,
    /// Session completed successfully
    Completed,
    /// Session failed with an error
    Failed,
    /// Session was cancelled by user
    Cancelled,
    /// Session timed out
    Timeout,
}

/// A single reasoning step within a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    /// Unique identifier for this step
    pub id: Uuid,
    /// Type/category of this reasoning step
    pub step_type: ReasoningStepType,
    /// Human-readable description of what this step does
    pub description: String,
    /// Content of the step
    pub content: String,
    /// Timestamp when this step was created
    pub timestamp: DateTime<Utc>,
    /// Optional metadata for this step
    pub metadata: std::collections::HashMap<String, String>,
}

/// Types of reasoning steps
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ReasoningStepType {
    /// Initial problem analysis
    Analysis,
    /// Planning phase
    Planning,
    /// Code generation/modification
    Implementation,
    /// Testing or validation
    Verification,
    /// Error handling or debugging
    Debugging,
    /// Final review or cleanup
    Review,
    /// Reasoning/thinking step
    Reason,
    /// Action/execution step
    Act,
    /// Observation/monitoring step
    Observe,
    /// Conclusion step
    Conclude,
}
