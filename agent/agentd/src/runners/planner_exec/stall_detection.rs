//! Stall detection and escalation system
//!
//! This module implements sophisticated stall detection algorithms that monitor
//! workflow progress and automatically detect when workflows become stuck or
//! unproductive. It provides escalation mechanisms and intervention strategies.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tracing::{debug, info, warn};

use super::schemas::{StallInfo, UserAction, UserActionType};
use super::state_machine::{StateMachine, WorkflowState};

/// Stall detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallDetectorConfig {
    /// Base stall threshold in milliseconds
    pub base_stall_threshold_ms: u64,

    /// Maximum stalls before escalation
    pub max_stalls_before_escalation: u32,

    /// Progress monitoring window size
    pub progress_window_size: usize,

    /// Minimum progress required in window
    pub min_progress_threshold: f64,

    /// Enable adaptive thresholds
    pub adaptive_thresholds: bool,

    /// Detection algorithms to use
    pub detection_algorithms: Vec<DetectionAlgorithm>,

    /// Escalation strategy
    pub escalation_strategy: EscalationStrategy,
}

impl Default for StallDetectorConfig {
    fn default() -> Self {
        Self {
            base_stall_threshold_ms: 30000, // 30 seconds
            max_stalls_before_escalation: 3,
            progress_window_size: 10,
            min_progress_threshold: 0.01, // 1% progress in window
            adaptive_thresholds: true,
            detection_algorithms: vec![
                DetectionAlgorithm::TimeBasedStall,
                DetectionAlgorithm::ProgressStagnation,
                DetectionAlgorithm::ResourceStall,
                DetectionAlgorithm::DependencyDeadlock,
                DetectionAlgorithm::CyclicalBehavior,
            ],
            escalation_strategy: EscalationStrategy::Progressive,
        }
    }
}

/// Stall detection algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DetectionAlgorithm {
    /// Time-based stall detection
    TimeBasedStall,
    /// Progress stagnation detection
    ProgressStagnation,
    /// Resource exhaustion stall
    ResourceStall,
    /// Dependency deadlock detection
    DependencyDeadlock,
    /// Cyclical behavior detection
    CyclicalBehavior,
    /// Error cascade detection
    ErrorCascade,
    /// Memory leak detection
    MemoryLeak,
}

/// Escalation strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStrategy {
    /// No escalation - just detect and report
    None,
    /// Immediate escalation on first stall
    Immediate,
    /// Progressive escalation with increasing interventions
    Progressive,
    /// Adaptive escalation based on workflow characteristics
    Adaptive,
}

/// Progress tracking data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressDataPoint {
    /// Timestamp of measurement
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Workflow progress (0.0 - 1.0)
    pub progress: f64,

    /// Number of active actions
    pub active_actions: u32,

    /// Number of completed actions
    pub completed_actions: u32,

    /// Current state
    pub state: String,

    /// Resource usage at this point
    pub resource_usage: ProgressResourceUsage,
}

/// Resource usage for progress tracking
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProgressResourceUsage {
    /// CPU time used (milliseconds)
    pub cpu_ms: u64,

    /// Memory usage (bytes)
    pub memory_bytes: u64,

    /// Actions per minute
    pub actions_per_minute: f64,
}

/// Stall detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallDetectionResult {
    /// Whether a stall was detected
    pub stall_detected: bool,

    /// Type of stall detected
    pub stall_type: Option<StallType>,

    /// Confidence in stall detection (0.0 - 1.0)
    pub confidence: f64,

    /// Time since last progress
    pub time_since_progress_ms: u64,

    /// Detected issues
    pub issues: Vec<StallIssue>,

    /// Recommended interventions
    pub interventions: Vec<StallIntervention>,

    /// Should escalate to human
    pub should_escalate: bool,
}

/// Types of stalls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
#[serde(rename_all = "snake_case")]
pub enum StallType {
    /// Time-based stall (no progress for time threshold)
    TimeoutStall,
    /// Progress stagnation (very slow progress)
    ProgressStagnation,
    /// Resource exhaustion causing stall
    ResourceExhaustion,
    /// Dependency deadlock
    DependencyDeadlock,
    /// Cyclical execution pattern
    CyclicalExecution,
    /// Error cascade preventing progress
    ErrorCascade,
    /// Memory leak causing degradation
    MemoryLeak,
    /// External service stall
    ExternalServiceStall,
}

/// Specific stall issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallIssue {
    /// Issue type
    pub issue_type: String,

    /// Severity (Low, Medium, High, Critical)
    pub severity: StallSeverity,

    /// Description of the issue
    pub description: String,

    /// Evidence supporting this issue
    pub evidence: Vec<String>,

    /// Potential root causes
    pub root_causes: Vec<String>,
}

/// Stall severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StallSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Stall intervention recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallIntervention {
    /// Intervention type
    pub intervention_type: InterventionType,

    /// Priority (1-10, 1 being highest)
    pub priority: u8,

    /// Description of intervention
    pub description: String,

    /// Estimated effectiveness (0.0 - 1.0)
    pub effectiveness: f64,

    /// Implementation details
    pub implementation: InterventionImplementation,
}

/// Types of interventions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InterventionType {
    /// Restart current action
    RestartAction,
    /// Skip current action
    SkipAction,
    /// Increase timeout
    IncreaseTimeout,
    /// Reduce resource usage
    ReduceResources,
    /// Break dependency deadlock
    BreakDeadlock,
    /// Clear and restart
    ClearAndRestart,
    /// Manual intervention required
    ManualIntervention,
    /// Escalate to human
    EscalateToHuman,
}

/// Intervention implementation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterventionImplementation {
    /// Automatic or manual implementation
    pub automatic: bool,

    /// Required user actions
    pub user_actions: Vec<UserActionType>,

    /// Parameters for implementation
    pub parameters: HashMap<String, serde_json::Value>,

    /// Rollback strategy if intervention fails
    pub rollback_strategy: Option<String>,
}

/// Historical stall tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallHistory {
    /// Previous stalls
    pub stalls: VecDeque<StallEvent>,

    /// Intervention effectiveness tracking
    pub intervention_history: Vec<InterventionResult>,

    /// Patterns identified
    pub patterns: Vec<StallPattern>,
}

/// Individual stall event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallEvent {
    /// When the stall was detected
    pub detected_at: chrono::DateTime<chrono::Utc>,

    /// Type of stall
    pub stall_type: StallType,

    /// Duration of stall before resolution
    pub duration_ms: u64,

    /// How it was resolved
    pub resolution: StallResolution,

    /// Effectiveness of resolution
    pub resolution_effectiveness: f64,
}

/// How a stall was resolved
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StallResolution {
    /// Automatic resolution
    Automatic,
    /// User intervention
    UserIntervention,
    /// Escalation to human
    HumanEscalation,
    /// Workflow cancelled
    Cancelled,
    /// Timeout/abandonment
    Timeout,
}

/// Result of an intervention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterventionResult {
    /// Intervention that was applied
    pub intervention: StallIntervention,

    /// When it was applied
    pub applied_at: chrono::DateTime<chrono::Utc>,

    /// Whether it was successful
    pub successful: bool,

    /// Time to resolution after intervention
    pub resolution_time_ms: u64,

    /// Additional progress made
    pub progress_improvement: f64,
}

/// Identified stall pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallPattern {
    /// Pattern identifier
    pub pattern_id: String,

    /// Pattern description
    pub description: String,

    /// Conditions that trigger this pattern
    pub triggers: Vec<String>,

    /// Frequency of occurrence
    pub frequency: f64,

    /// Best intervention for this pattern
    pub best_intervention: InterventionType,
}

/// Main stall detector implementation
pub struct StallDetector {
    config: StallDetectorConfig,
    progress_history: VecDeque<ProgressDataPoint>,
    stall_history: StallHistory,
    current_stall: Option<StallDetectionResult>,
    last_progress_time: Option<std::time::Instant>,
    stall_count: u32,
}

impl StallDetector {
    /// Create a new stall detector
    pub fn new(max_steps: u32) -> Result<Self> {
        let mut config = StallDetectorConfig::default();

        // Adjust thresholds based on workflow complexity
        if max_steps > 50 {
            config.base_stall_threshold_ms = 60000; // 1 minute for complex workflows
        } else if max_steps > 20 {
            config.base_stall_threshold_ms = 45000; // 45 seconds for medium workflows
        }

        info!(
            base_threshold_ms = config.base_stall_threshold_ms,
            max_stalls = config.max_stalls_before_escalation,
            "Stall detector initialized"
        );

        let window_size = config.progress_window_size;
        Ok(Self {
            config,
            progress_history: VecDeque::with_capacity(window_size),
            stall_history: StallHistory {
                stalls: VecDeque::with_capacity(100),
                intervention_history: Vec::new(),
                patterns: Vec::new(),
            },
            current_stall: None,
            last_progress_time: None,
            stall_count: 0,
        })
    }

    /// Check for stalls in the given state machine
    pub fn check_stall(
        &mut self,
        state_machine: &StateMachine,
        last_progress_time: &std::time::Instant,
    ) -> Result<bool> {
        // Record current progress
        self.record_progress(state_machine)?;

        // Run detection algorithms
        let detection_result = self.run_detection_algorithms(state_machine, last_progress_time)?;

        // Update stall state
        if detection_result.stall_detected {
            if self.current_stall.is_none() {
                // New stall detected
                self.stall_count += 1;
                info!(
                    stall_type = ?detection_result.stall_type,
                    confidence = detection_result.confidence,
                    stall_count = self.stall_count,
                    "Stall detected"
                );
            }
            self.current_stall = Some(detection_result.clone());
        } else {
            // No stall or stall resolved
            if let Some(previous_stall) = self.current_stall.take() {
                self.record_stall_resolution(previous_stall)?;
            }
        }

        Ok(detection_result.stall_detected)
    }

    /// Record current progress
    fn record_progress(&mut self, state_machine: &StateMachine) -> Result<()> {
        let now = chrono::Utc::now();
        let progress = state_machine.get_progress();

        // Calculate actions per minute
        let actions_per_minute = if let Some(last_point) = self.progress_history.back() {
            let time_diff = (now - last_point.timestamp).num_seconds() as f64 / 60.0;
            if time_diff > 0.0 {
                let action_diff = state_machine.completed_actions.len() as f64
                    - last_point.completed_actions as f64;
                action_diff / time_diff
            } else {
                0.0
            }
        } else {
            0.0
        };

        let data_point = ProgressDataPoint {
            timestamp: now,
            progress,
            active_actions: state_machine.executing_actions.len() as u32,
            completed_actions: state_machine.completed_actions.len() as u32,
            state: format!("{:?}", state_machine.current_state()),
            resource_usage: ProgressResourceUsage {
                cpu_ms: state_machine.total_resource_usage.cpu_ms,
                memory_bytes: state_machine.total_resource_usage.memory_bytes,
                actions_per_minute,
            },
        };

        // Add to history
        if self.progress_history.len() >= self.config.progress_window_size {
            self.progress_history.pop_front();
        }
        self.progress_history.push_back(data_point);

        debug!(
            progress = %progress,
            active_actions = self.progress_history.back().unwrap().active_actions,
            completed_actions = self.progress_history.back().unwrap().completed_actions,
            "Progress recorded"
        );

        Ok(())
    }

    /// Run all detection algorithms
    fn run_detection_algorithms(
        &self,
        state_machine: &StateMachine,
        last_progress_time: &std::time::Instant,
    ) -> Result<StallDetectionResult> {
        let mut issues = Vec::new();
        let mut interventions = Vec::new();
        let mut max_confidence = 0.0;
        let mut detected_stall_type = None;

        let time_since_progress_ms = last_progress_time.elapsed().as_millis() as u64;

        // Run each enabled algorithm
        for algorithm in &self.config.detection_algorithms {
            match algorithm {
                DetectionAlgorithm::TimeBasedStall => {
                    if let Some((issue, intervention, confidence)) =
                        self.detect_time_based_stall(time_since_progress_ms)?
                    {
                        issues.push(issue);
                        interventions.push(intervention);
                        if confidence > max_confidence {
                            max_confidence = confidence;
                            detected_stall_type = Some(StallType::TimeoutStall);
                        }
                    }
                }

                DetectionAlgorithm::ProgressStagnation => {
                    if let Some((issue, intervention, confidence)) =
                        self.detect_progress_stagnation()?
                    {
                        issues.push(issue);
                        interventions.push(intervention);
                        if confidence > max_confidence {
                            max_confidence = confidence;
                            detected_stall_type = Some(StallType::ProgressStagnation);
                        }
                    }
                }

                DetectionAlgorithm::ResourceStall => {
                    if let Some((issue, intervention, confidence)) =
                        self.detect_resource_stall(state_machine)?
                    {
                        issues.push(issue);
                        interventions.push(intervention);
                        if confidence > max_confidence {
                            max_confidence = confidence;
                            detected_stall_type = Some(StallType::ResourceExhaustion);
                        }
                    }
                }

                DetectionAlgorithm::DependencyDeadlock => {
                    if let Some((issue, intervention, confidence)) =
                        self.detect_dependency_deadlock(state_machine)?
                    {
                        issues.push(issue);
                        interventions.push(intervention);
                        if confidence > max_confidence {
                            max_confidence = confidence;
                            detected_stall_type = Some(StallType::DependencyDeadlock);
                        }
                    }
                }

                DetectionAlgorithm::CyclicalBehavior => {
                    if let Some((issue, intervention, confidence)) =
                        self.detect_cyclical_behavior()?
                    {
                        issues.push(issue);
                        interventions.push(intervention);
                        if confidence > max_confidence {
                            max_confidence = confidence;
                            detected_stall_type = Some(StallType::CyclicalExecution);
                        }
                    }
                }

                _ => {
                    // Other algorithms not yet implemented
                    debug!(algorithm = ?algorithm, "Algorithm not implemented");
                }
            }
        }

        // Determine if stall should be escalated
        let should_escalate = self.should_escalate(max_confidence);

        Ok(StallDetectionResult {
            stall_detected: max_confidence > 0.5, // 50% confidence threshold
            stall_type: detected_stall_type,
            confidence: max_confidence,
            time_since_progress_ms,
            issues,
            interventions,
            should_escalate,
        })
    }

    /// Detect time-based stalls
    fn detect_time_based_stall(
        &self,
        time_since_progress_ms: u64,
    ) -> Result<Option<(StallIssue, StallIntervention, f64)>> {
        let threshold = if self.config.adaptive_thresholds {
            self.calculate_adaptive_threshold()
        } else {
            self.config.base_stall_threshold_ms
        };

        if time_since_progress_ms > threshold {
            let severity = if time_since_progress_ms > threshold * 3 {
                StallSeverity::Critical
            } else if time_since_progress_ms > threshold * 2 {
                StallSeverity::High
            } else {
                StallSeverity::Medium
            };

            let issue = StallIssue {
                issue_type: "TIME_BASED_STALL".to_string(),
                severity,
                description: format!(
                    "No progress detected for {}ms (threshold: {}ms)",
                    time_since_progress_ms, threshold
                ),
                evidence: vec![
                    format!("Time since last progress: {}ms", time_since_progress_ms),
                    format!("Threshold: {}ms", threshold),
                ],
                root_causes: vec![
                    "Long-running operation".to_string(),
                    "External service delay".to_string(),
                    "Resource contention".to_string(),
                ],
            };

            let intervention = StallIntervention {
                intervention_type: InterventionType::IncreaseTimeout,
                priority: 3,
                description: "Increase timeout threshold or restart current operation".to_string(),
                effectiveness: 0.7,
                implementation: InterventionImplementation {
                    automatic: true,
                    user_actions: vec![UserActionType::Continue],
                    parameters: HashMap::from_iter(
                        serde_json::json!({
                            "new_timeout_ms": threshold * 2
                        })
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                    ),
                    rollback_strategy: Some("Revert to original timeout".to_string()),
                },
            };

            let confidence = ((time_since_progress_ms as f64 / threshold as f64) - 1.0).min(1.0);

            Ok(Some((issue, intervention, confidence)))
        } else {
            Ok(None)
        }
    }

    /// Detect progress stagnation
    fn detect_progress_stagnation(&self) -> Result<Option<(StallIssue, StallIntervention, f64)>> {
        if self.progress_history.len() < 3 {
            return Ok(None);
        }

        // Check progress change over window
        let first_progress = self.progress_history.front().unwrap().progress;
        let last_progress = self.progress_history.back().unwrap().progress;
        let progress_change = last_progress - first_progress;

        if progress_change < self.config.min_progress_threshold {
            let issue = StallIssue {
                issue_type: "PROGRESS_STAGNATION".to_string(),
                severity: StallSeverity::Medium,
                description: format!(
                    "Progress change too small: {:.3}% over {} measurements (threshold: {:.3}%)",
                    progress_change * 100.0,
                    self.progress_history.len(),
                    self.config.min_progress_threshold * 100.0
                ),
                evidence: vec![
                    format!("Initial progress: {:.3}%", first_progress * 100.0),
                    format!("Current progress: {:.3}%", last_progress * 100.0),
                    format!("Change: {:.3}%", progress_change * 100.0),
                ],
                root_causes: vec![
                    "Actions not completing".to_string(),
                    "Dependencies not being resolved".to_string(),
                    "Resource bottleneck".to_string(),
                ],
            };

            let intervention = StallIntervention {
                intervention_type: InterventionType::RestartAction,
                priority: 2,
                description: "Restart current actions or skip problematic actions".to_string(),
                effectiveness: 0.8,
                implementation: InterventionImplementation {
                    automatic: false,
                    user_actions: vec![UserActionType::Continue, UserActionType::RemoveAction],
                    parameters: HashMap::new(),
                    rollback_strategy: None,
                },
            };

            let confidence = (1.0 - progress_change / self.config.min_progress_threshold).min(1.0);

            Ok(Some((issue, intervention, confidence)))
        } else {
            Ok(None)
        }
    }

    /// Detect resource-based stalls
    fn detect_resource_stall(
        &self,
        state_machine: &StateMachine,
    ) -> Result<Option<(StallIssue, StallIntervention, f64)>> {
        if self.progress_history.len() < 2 {
            return Ok(None);
        }

        let current = self.progress_history.back().unwrap();
        let previous = &self.progress_history[self.progress_history.len() - 2];

        // Check for memory growth without progress
        let memory_growth = current.resource_usage.memory_bytes as f64
            / previous.resource_usage.memory_bytes.max(1) as f64;
        let progress_change = current.progress - previous.progress;

        if memory_growth > 2.0 && progress_change < 0.01 {
            let issue = StallIssue {
                issue_type: "RESOURCE_STALL".to_string(),
                severity: StallSeverity::High,
                description: format!(
                    "Memory usage increased {:.1}x without progress",
                    memory_growth
                ),
                evidence: vec![
                    format!(
                        "Previous memory: {} bytes",
                        previous.resource_usage.memory_bytes
                    ),
                    format!(
                        "Current memory: {} bytes",
                        current.resource_usage.memory_bytes
                    ),
                    format!("Progress change: {:.3}%", progress_change * 100.0),
                ],
                root_causes: vec![
                    "Memory leak".to_string(),
                    "Resource exhaustion".to_string(),
                    "Inefficient algorithm".to_string(),
                ],
            };

            let intervention = StallIntervention {
                intervention_type: InterventionType::ReduceResources,
                priority: 1,
                description: "Reduce resource usage or restart with lower limits".to_string(),
                effectiveness: 0.9,
                implementation: InterventionImplementation {
                    automatic: true,
                    user_actions: vec![UserActionType::ModifyParameters],
                    parameters: HashMap::from_iter(
                        serde_json::json!({
                            "memory_limit_reduction": 0.5
                        })
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                    ),
                    rollback_strategy: Some("Restore original resource limits".to_string()),
                },
            };

            let confidence = ((memory_growth - 1.0) / 2.0).min(1.0);

            Ok(Some((issue, intervention, confidence)))
        } else {
            Ok(None)
        }
    }

    /// Detect dependency deadlocks
    fn detect_dependency_deadlock(
        &self,
        state_machine: &StateMachine,
    ) -> Result<Option<(StallIssue, StallIntervention, f64)>> {
        // Check if we have actions in queue but none can execute
        if !state_machine.action_queue.is_empty() && state_machine.executing_actions.is_empty() {
            let completed_ids: Vec<String> = state_machine
                .completed_actions
                .iter()
                .map(|r| r.action_id.clone())
                .collect();

            let blocked_actions = state_machine
                .action_queue
                .iter()
                .filter(|action| !action.can_execute(&completed_ids))
                .count();

            if blocked_actions == state_machine.action_queue.len() {
                let issue = StallIssue {
                    issue_type: "DEPENDENCY_DEADLOCK".to_string(),
                    severity: StallSeverity::Critical,
                    description: format!(
                        "All {} queued actions are blocked by dependencies",
                        state_machine.action_queue.len()
                    ),
                    evidence: vec![
                        format!("Queued actions: {}", state_machine.action_queue.len()),
                        format!("Blocked actions: {}", blocked_actions),
                        format!(
                            "Executing actions: {}",
                            state_machine.executing_actions.len()
                        ),
                    ],
                    root_causes: vec![
                        "Circular dependencies".to_string(),
                        "Missing dependency completion".to_string(),
                        "Failed dependency action".to_string(),
                    ],
                };

                let intervention = StallIntervention {
                    intervention_type: InterventionType::BreakDeadlock,
                    priority: 1,
                    description: "Break dependency deadlock by skipping or modifying dependencies"
                        .to_string(),
                    effectiveness: 0.85,
                    implementation: InterventionImplementation {
                        automatic: false,
                        user_actions: vec![
                            UserActionType::RemoveAction,
                            UserActionType::ModifyParameters,
                        ],
                        parameters: HashMap::new(),
                        rollback_strategy: Some("Restore original dependencies".to_string()),
                    },
                };

                Ok(Some((issue, intervention, 1.0))) // High confidence for clear deadlock
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Detect cyclical behavior
    fn detect_cyclical_behavior(&self) -> Result<Option<(StallIssue, StallIntervention, f64)>> {
        if self.progress_history.len() < 6 {
            return Ok(None);
        }

        // Look for repeating patterns in state
        let recent_states: Vec<&String> = self
            .progress_history
            .iter()
            .rev()
            .take(6)
            .map(|p| &p.state)
            .collect();

        // Simple cycle detection - check for ABAB or ABCABC patterns
        let has_cycle = if recent_states.len() >= 4 {
            // Check for ABAB pattern
            recent_states[0] == recent_states[2] && recent_states[1] == recent_states[3]
        } else {
            false
        };

        if has_cycle {
            let issue = StallIssue {
                issue_type: "CYCLICAL_BEHAVIOR".to_string(),
                severity: StallSeverity::Medium,
                description: "Cyclical state pattern detected - workflow may be stuck in loop"
                    .to_string(),
                evidence: vec![
                    format!("Recent states: {:?}", recent_states),
                    "Repeating pattern observed".to_string(),
                ],
                root_causes: vec![
                    "Logic error in workflow".to_string(),
                    "Incorrect retry logic".to_string(),
                    "State transition error".to_string(),
                ],
            };

            let intervention = StallIntervention {
                intervention_type: InterventionType::ClearAndRestart,
                priority: 2,
                description: "Break cycle by clearing state and restarting from checkpoint"
                    .to_string(),
                effectiveness: 0.7,
                implementation: InterventionImplementation {
                    automatic: false,
                    user_actions: vec![UserActionType::Pause, UserActionType::ModifyParameters],
                    parameters: HashMap::new(),
                    rollback_strategy: Some("Return to pre-cycle state".to_string()),
                },
            };

            Ok(Some((issue, intervention, 0.8)))
        } else {
            Ok(None)
        }
    }

    /// Calculate adaptive threshold based on workflow characteristics
    fn calculate_adaptive_threshold(&self) -> u64 {
        if self.progress_history.is_empty() {
            return self.config.base_stall_threshold_ms;
        }

        // Base threshold on recent action completion rate
        let recent_actions_per_minute = self
            .progress_history
            .iter()
            .rev()
            .take(5)
            .map(|p| p.resource_usage.actions_per_minute)
            .sum::<f64>()
            / 5.0;

        if recent_actions_per_minute > 2.0 {
            // Fast workflow - shorter threshold
            self.config.base_stall_threshold_ms / 2
        } else if recent_actions_per_minute < 0.5 {
            // Slow workflow - longer threshold
            self.config.base_stall_threshold_ms * 2
        } else {
            self.config.base_stall_threshold_ms
        }
    }

    /// Determine if stall should be escalated
    fn should_escalate(&self, confidence: f64) -> bool {
        match self.config.escalation_strategy {
            EscalationStrategy::None => false,
            EscalationStrategy::Immediate => confidence > 0.5,
            EscalationStrategy::Progressive => {
                self.stall_count >= self.config.max_stalls_before_escalation
            }
            EscalationStrategy::Adaptive => {
                // Escalate based on confidence and stall count
                confidence > 0.7 || self.stall_count >= self.config.max_stalls_before_escalation
            }
        }
    }

    /// Record stall resolution
    fn record_stall_resolution(&mut self, stall: StallDetectionResult) -> Result<()> {
        if let Some(stall_type) = stall.stall_type {
            let stall_event = StallEvent {
                detected_at: chrono::Utc::now()
                    - chrono::Duration::milliseconds(stall.time_since_progress_ms as i64),
                stall_type: stall_type.clone(),
                duration_ms: stall.time_since_progress_ms,
                resolution: StallResolution::Automatic, // Simplified for now
                resolution_effectiveness: 1.0 - stall.confidence,
            };

            if self.stall_history.stalls.len() >= 100 {
                self.stall_history.stalls.pop_front();
            }
            self.stall_history.stalls.push_back(stall_event);

            info!(
                stall_type = ?stall_type,
                duration_ms = stall.time_since_progress_ms,
                "Stall resolved"
            );
        }

        Ok(())
    }

    /// Get current stall information
    pub fn get_current_stall(&self) -> Option<&StallDetectionResult> {
        self.current_stall.as_ref()
    }

    /// Get stall statistics
    pub fn get_statistics(&self) -> StallStatistics {
        let total_stalls = self.stall_history.stalls.len();
        let avg_duration = if total_stalls > 0 {
            self.stall_history
                .stalls
                .iter()
                .map(|s| s.duration_ms)
                .sum::<u64>()
                / total_stalls as u64
        } else {
            0
        };

        StallStatistics {
            total_stalls: total_stalls as u32,
            current_stall_count: self.stall_count,
            avg_stall_duration_ms: avg_duration,
            escalation_count: self
                .stall_history
                .stalls
                .iter()
                .filter(|s| matches!(s.resolution, StallResolution::HumanEscalation))
                .count() as u32,
            most_common_stall_type: self.get_most_common_stall_type(),
        }
    }

    /// Get most common stall type
    fn get_most_common_stall_type(&self) -> Option<StallType> {
        let mut type_counts: HashMap<StallType, u32> = HashMap::new();

        for stall in &self.stall_history.stalls {
            *type_counts.entry(stall.stall_type.clone()).or_insert(0) += 1;
        }

        type_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(stall_type, _)| stall_type)
    }

    /// Reset detector state
    pub fn reset(&mut self) {
        self.progress_history.clear();
        self.current_stall = None;
        self.last_progress_time = None;
        self.stall_count = 0;
    }
}

/// Stall detector statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallStatistics {
    /// Total number of stalls detected
    pub total_stalls: u32,

    /// Current stall count for this workflow
    pub current_stall_count: u32,

    /// Average stall duration
    pub avg_stall_duration_ms: u64,

    /// Number of escalations
    pub escalation_count: u32,

    /// Most common stall type
    pub most_common_stall_type: Option<StallType>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::planner_exec::schemas::{PlannerExecParams, WorkflowType};
    use std::collections::HashMap;

    fn create_test_state_machine() -> StateMachine {
        let params = PlannerExecParams {
            workflow_id: "test-workflow-012".to_string(),
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

    #[test]
    fn test_stall_detector_creation() {
        let detector = StallDetector::new(10).unwrap();
        assert_eq!(detector.config.base_stall_threshold_ms, 30000);
        assert_eq!(detector.stall_count, 0);
    }

    #[test]
    fn test_adaptive_threshold_calculation() {
        let mut detector = StallDetector::new(10).unwrap();

        // Initially should use base threshold
        assert_eq!(detector.calculate_adaptive_threshold(), 30000);

        // Add some progress history with slow actions
        let now = chrono::Utc::now();
        for i in 0..3 {
            let data_point = ProgressDataPoint {
                timestamp: now + chrono::Duration::minutes(i),
                progress: i as f64 * 0.1,
                active_actions: 1,
                completed_actions: i as u32,
                state: "Executing".to_string(),
                resource_usage: ProgressResourceUsage {
                    cpu_ms: 1000 * i as u64,
                    memory_bytes: 1024 * 1024,
                    actions_per_minute: 0.3, // Slow
                },
            };
            detector.progress_history.push_back(data_point);
        }

        // Should increase threshold for slow workflow
        assert!(detector.calculate_adaptive_threshold() > 30000);
    }

    #[tokio::test]
    async fn test_time_based_stall_detection() {
        let detector = StallDetector::new(10).unwrap();

        // Test no stall
        let result = detector.detect_time_based_stall(15000).unwrap();
        assert!(result.is_none());

        // Test stall
        let result = detector.detect_time_based_stall(45000).unwrap();
        assert!(result.is_some());

        let (issue, intervention, confidence) = result.unwrap();
        assert_eq!(issue.issue_type, "TIME_BASED_STALL");
        assert_eq!(
            intervention.intervention_type,
            InterventionType::IncreaseTimeout
        );
        assert!(confidence > 0.0);
    }

    #[tokio::test]
    async fn test_dependency_deadlock_detection() {
        let detector = StallDetector::new(10).unwrap();
        let mut state_machine = create_test_state_machine();

        // Add an action with unresolved dependencies
        let mut action = super::super::schemas::WorkflowAction::new(
            super::super::schemas::ActionType::FileSystem("fs.read.v1".to_string()),
            serde_json::json!({"path": "/test"}),
            "Test action".to_string(),
        );
        action.add_dependency("missing-action".to_string());

        state_machine.action_queue.push_back(action);

        let result = detector.detect_dependency_deadlock(&state_machine).unwrap();
        assert!(result.is_some());

        let (issue, intervention, confidence) = result.unwrap();
        assert_eq!(issue.issue_type, "DEPENDENCY_DEADLOCK");
        assert_eq!(
            intervention.intervention_type,
            InterventionType::BreakDeadlock
        );
        assert_eq!(confidence, 1.0);
    }

    #[tokio::test]
    async fn test_progress_stagnation_detection() {
        let mut detector = StallDetector::new(10).unwrap();

        // Add progress history with no progress
        let now = chrono::Utc::now();
        for i in 0..5 {
            let data_point = ProgressDataPoint {
                timestamp: now + chrono::Duration::minutes(i),
                progress: 0.1, // No progress change
                active_actions: 1,
                completed_actions: 1,
                state: "Executing".to_string(),
                resource_usage: ProgressResourceUsage::default(),
            };
            detector.progress_history.push_back(data_point);
        }

        let result = detector.detect_progress_stagnation().unwrap();
        assert!(result.is_some());

        let (issue, intervention, confidence) = result.unwrap();
        assert_eq!(issue.issue_type, "PROGRESS_STAGNATION");
        assert_eq!(
            intervention.intervention_type,
            InterventionType::RestartAction
        );
        assert!(confidence > 0.0);
    }

    #[tokio::test]
    async fn test_stall_statistics() {
        let mut detector = StallDetector::new(10).unwrap();

        // Add some stall events
        let stall_event = StallEvent {
            detected_at: chrono::Utc::now(),
            stall_type: StallType::TimeoutStall,
            duration_ms: 30000,
            resolution: StallResolution::Automatic,
            resolution_effectiveness: 0.8,
        };

        detector.stall_history.stalls.push_back(stall_event);
        detector.stall_count = 2;

        let stats = detector.get_statistics();
        assert_eq!(stats.total_stalls, 1);
        assert_eq!(stats.current_stall_count, 2);
        assert_eq!(stats.avg_stall_duration_ms, 30000);
        assert_eq!(stats.most_common_stall_type, Some(StallType::TimeoutStall));
    }

    #[tokio::test]
    async fn test_escalation_logic() {
        let mut config = StallDetectorConfig::default();
        config.escalation_strategy = EscalationStrategy::Progressive;
        config.max_stalls_before_escalation = 2;

        let mut detector = StallDetector::new(10).unwrap();
        detector.config = config;

        // First stall - no escalation
        detector.stall_count = 1;
        assert!(!detector.should_escalate(0.8));

        // Second stall - should escalate
        detector.stall_count = 2;
        assert!(detector.should_escalate(0.8));

        // Test immediate escalation
        detector.config.escalation_strategy = EscalationStrategy::Immediate;
        detector.stall_count = 1;
        assert!(detector.should_escalate(0.8));
        assert!(!detector.should_escalate(0.3));
    }

    // ==================== StallType Serialization Tests ====================

    #[test]
    fn test_stall_type_serialization_timeout() {
        let stall_type = StallType::TimeoutStall;
        let json = serde_json::to_string(&stall_type).unwrap();
        assert!(json.contains("timeout_stall"));
        let parsed: StallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallType::TimeoutStall);
    }

    #[test]
    fn test_stall_type_serialization_progress_stagnation() {
        let stall_type = StallType::ProgressStagnation;
        let json = serde_json::to_string(&stall_type).unwrap();
        assert!(json.contains("progress_stagnation"));
        let parsed: StallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallType::ProgressStagnation);
    }

    #[test]
    fn test_stall_type_serialization_resource_exhaustion() {
        let stall_type = StallType::ResourceExhaustion;
        let json = serde_json::to_string(&stall_type).unwrap();
        assert!(json.contains("resource_exhaustion"));
        let parsed: StallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallType::ResourceExhaustion);
    }

    #[test]
    fn test_stall_type_serialization_dependency_deadlock() {
        let stall_type = StallType::DependencyDeadlock;
        let json = serde_json::to_string(&stall_type).unwrap();
        assert!(json.contains("dependency_deadlock"));
        let parsed: StallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallType::DependencyDeadlock);
    }

    #[test]
    fn test_stall_type_serialization_cyclical() {
        let stall_type = StallType::CyclicalExecution;
        let json = serde_json::to_string(&stall_type).unwrap();
        assert!(json.contains("cyclical_execution"));
        let parsed: StallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallType::CyclicalExecution);
    }

    #[test]
    fn test_stall_type_serialization_error_cascade() {
        let stall_type = StallType::ErrorCascade;
        let json = serde_json::to_string(&stall_type).unwrap();
        assert!(json.contains("error_cascade"));
        let parsed: StallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallType::ErrorCascade);
    }

    #[test]
    fn test_stall_type_serialization_memory_leak() {
        let stall_type = StallType::MemoryLeak;
        let json = serde_json::to_string(&stall_type).unwrap();
        assert!(json.contains("memory_leak"));
        let parsed: StallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallType::MemoryLeak);
    }

    #[test]
    fn test_stall_type_serialization_external_service() {
        let stall_type = StallType::ExternalServiceStall;
        let json = serde_json::to_string(&stall_type).unwrap();
        assert!(json.contains("external_service_stall"));
        let parsed: StallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallType::ExternalServiceStall);
    }

    // ==================== StallSeverity Serialization Tests ====================

    #[test]
    fn test_stall_severity_serialization_low() {
        let severity = StallSeverity::Low;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("low"));
        let parsed: StallSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallSeverity::Low);
    }

    #[test]
    fn test_stall_severity_serialization_medium() {
        let severity = StallSeverity::Medium;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("medium"));
        let parsed: StallSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallSeverity::Medium);
    }

    #[test]
    fn test_stall_severity_serialization_high() {
        let severity = StallSeverity::High;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("high"));
        let parsed: StallSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallSeverity::High);
    }

    #[test]
    fn test_stall_severity_serialization_critical() {
        let severity = StallSeverity::Critical;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("critical"));
        let parsed: StallSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallSeverity::Critical);
    }

    #[test]
    fn test_stall_severity_ordering() {
        assert!(StallSeverity::Low < StallSeverity::Medium);
        assert!(StallSeverity::Medium < StallSeverity::High);
        assert!(StallSeverity::High < StallSeverity::Critical);
    }

    // ==================== InterventionType Serialization Tests ====================

    #[test]
    fn test_intervention_type_serialization_restart() {
        let intervention = InterventionType::RestartAction;
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("restart_action"));
        let parsed: InterventionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionType::RestartAction);
    }

    #[test]
    fn test_intervention_type_serialization_skip() {
        let intervention = InterventionType::SkipAction;
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("skip_action"));
        let parsed: InterventionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionType::SkipAction);
    }

    #[test]
    fn test_intervention_type_serialization_timeout() {
        let intervention = InterventionType::IncreaseTimeout;
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("increase_timeout"));
        let parsed: InterventionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionType::IncreaseTimeout);
    }

    #[test]
    fn test_intervention_type_serialization_reduce_resources() {
        let intervention = InterventionType::ReduceResources;
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("reduce_resources"));
        let parsed: InterventionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionType::ReduceResources);
    }

    #[test]
    fn test_intervention_type_serialization_break_deadlock() {
        let intervention = InterventionType::BreakDeadlock;
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("break_deadlock"));
        let parsed: InterventionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionType::BreakDeadlock);
    }

    #[test]
    fn test_intervention_type_serialization_clear_restart() {
        let intervention = InterventionType::ClearAndRestart;
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("clear_and_restart"));
        let parsed: InterventionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionType::ClearAndRestart);
    }

    #[test]
    fn test_intervention_type_serialization_manual() {
        let intervention = InterventionType::ManualIntervention;
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("manual_intervention"));
        let parsed: InterventionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionType::ManualIntervention);
    }

    #[test]
    fn test_intervention_type_serialization_escalate() {
        let intervention = InterventionType::EscalateToHuman;
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("escalate_to_human"));
        let parsed: InterventionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InterventionType::EscalateToHuman);
    }

    // ==================== EscalationStrategy Serialization Tests ====================

    #[test]
    fn test_escalation_strategy_serialization_none() {
        let strategy = EscalationStrategy::None;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("none"));
        let parsed: EscalationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EscalationStrategy::None);
    }

    #[test]
    fn test_escalation_strategy_serialization_immediate() {
        let strategy = EscalationStrategy::Immediate;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("immediate"));
        let parsed: EscalationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EscalationStrategy::Immediate);
    }

    #[test]
    fn test_escalation_strategy_serialization_progressive() {
        let strategy = EscalationStrategy::Progressive;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("progressive"));
        let parsed: EscalationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EscalationStrategy::Progressive);
    }

    #[test]
    fn test_escalation_strategy_serialization_adaptive() {
        let strategy = EscalationStrategy::Adaptive;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("adaptive"));
        let parsed: EscalationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EscalationStrategy::Adaptive);
    }

    // ==================== DetectionAlgorithm Serialization Tests ====================

    #[test]
    fn test_detection_algorithm_serialization_time_based() {
        let algo = DetectionAlgorithm::TimeBasedStall;
        let json = serde_json::to_string(&algo).unwrap();
        assert!(json.contains("time_based_stall"));
        let parsed: DetectionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DetectionAlgorithm::TimeBasedStall);
    }

    #[test]
    fn test_detection_algorithm_serialization_progress() {
        let algo = DetectionAlgorithm::ProgressStagnation;
        let json = serde_json::to_string(&algo).unwrap();
        assert!(json.contains("progress_stagnation"));
        let parsed: DetectionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DetectionAlgorithm::ProgressStagnation);
    }

    #[test]
    fn test_detection_algorithm_serialization_resource() {
        let algo = DetectionAlgorithm::ResourceStall;
        let json = serde_json::to_string(&algo).unwrap();
        assert!(json.contains("resource_stall"));
        let parsed: DetectionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DetectionAlgorithm::ResourceStall);
    }

    #[test]
    fn test_detection_algorithm_serialization_deadlock() {
        let algo = DetectionAlgorithm::DependencyDeadlock;
        let json = serde_json::to_string(&algo).unwrap();
        assert!(json.contains("dependency_deadlock"));
        let parsed: DetectionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DetectionAlgorithm::DependencyDeadlock);
    }

    #[test]
    fn test_detection_algorithm_serialization_cyclical() {
        let algo = DetectionAlgorithm::CyclicalBehavior;
        let json = serde_json::to_string(&algo).unwrap();
        assert!(json.contains("cyclical_behavior"));
        let parsed: DetectionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DetectionAlgorithm::CyclicalBehavior);
    }

    #[test]
    fn test_detection_algorithm_serialization_error_cascade() {
        let algo = DetectionAlgorithm::ErrorCascade;
        let json = serde_json::to_string(&algo).unwrap();
        assert!(json.contains("error_cascade"));
        let parsed: DetectionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DetectionAlgorithm::ErrorCascade);
    }

    #[test]
    fn test_detection_algorithm_serialization_memory_leak() {
        let algo = DetectionAlgorithm::MemoryLeak;
        let json = serde_json::to_string(&algo).unwrap();
        assert!(json.contains("memory_leak"));
        let parsed: DetectionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DetectionAlgorithm::MemoryLeak);
    }

    // ==================== StallResolution Serialization Tests ====================

    #[test]
    fn test_stall_resolution_serialization_automatic() {
        let resolution = StallResolution::Automatic;
        let json = serde_json::to_string(&resolution).unwrap();
        assert!(json.contains("automatic"));
        let parsed: StallResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallResolution::Automatic);
    }

    #[test]
    fn test_stall_resolution_serialization_user() {
        let resolution = StallResolution::UserIntervention;
        let json = serde_json::to_string(&resolution).unwrap();
        assert!(json.contains("user_intervention"));
        let parsed: StallResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallResolution::UserIntervention);
    }

    #[test]
    fn test_stall_resolution_serialization_escalation() {
        let resolution = StallResolution::HumanEscalation;
        let json = serde_json::to_string(&resolution).unwrap();
        assert!(json.contains("human_escalation"));
        let parsed: StallResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallResolution::HumanEscalation);
    }

    #[test]
    fn test_stall_resolution_serialization_timeout() {
        let resolution = StallResolution::Timeout;
        let json = serde_json::to_string(&resolution).unwrap();
        assert!(json.contains("timeout"));
        let parsed: StallResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StallResolution::Timeout);
    }

    // ==================== ProgressResourceUsage Tests ====================

    #[test]
    fn test_progress_resource_usage_default() {
        let usage = ProgressResourceUsage::default();
        assert_eq!(usage.cpu_ms, 0);
        assert_eq!(usage.memory_bytes, 0);
        assert_eq!(usage.actions_per_minute, 0.0);
    }

    #[test]
    fn test_progress_resource_usage_serialization() {
        let usage = ProgressResourceUsage {
            cpu_ms: 1500,
            memory_bytes: 1024 * 1024 * 128,
            actions_per_minute: 3.5,
        };
        let json = serde_json::to_string(&usage).unwrap();
        assert!(json.contains("1500"));
        assert!(json.contains("3.5"));
        let parsed: ProgressResourceUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cpu_ms, 1500);
        assert_eq!(parsed.memory_bytes, 1024 * 1024 * 128);
    }

    // ==================== ProgressDataPoint Tests ====================

    #[test]
    fn test_progress_data_point_serialization() {
        let data_point = ProgressDataPoint {
            timestamp: chrono::Utc::now(),
            progress: 0.75,
            active_actions: 3,
            completed_actions: 10,
            state: "Executing".to_string(),
            resource_usage: ProgressResourceUsage::default(),
        };
        let json = serde_json::to_string(&data_point).unwrap();
        assert!(json.contains("0.75"));
        assert!(json.contains("Executing"));
        let parsed: ProgressDataPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.progress, 0.75);
        assert_eq!(parsed.active_actions, 3);
        assert_eq!(parsed.completed_actions, 10);
    }

    // ==================== StallDetectionResult Tests ====================

    #[test]
    fn test_stall_detection_result_serialization() {
        let result = StallDetectionResult {
            stall_detected: true,
            stall_type: Some(StallType::TimeoutStall),
            confidence: 0.85,
            time_since_progress_ms: 45000,
            issues: vec![],
            interventions: vec![],
            should_escalate: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("true"));
        assert!(json.contains("0.85"));
        assert!(json.contains("45000"));
        let parsed: StallDetectionResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.stall_detected);
        assert_eq!(parsed.stall_type, Some(StallType::TimeoutStall));
    }

    // ==================== StallIssue Tests ====================

    #[test]
    fn test_stall_issue_serialization() {
        let issue = StallIssue {
            issue_type: "TEST_ISSUE".to_string(),
            severity: StallSeverity::High,
            description: "Test issue description".to_string(),
            evidence: vec!["evidence1".to_string(), "evidence2".to_string()],
            root_causes: vec!["cause1".to_string()],
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("TEST_ISSUE"));
        assert!(json.contains("evidence1"));
        let parsed: StallIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.issue_type, "TEST_ISSUE");
        assert_eq!(parsed.evidence.len(), 2);
    }

    // ==================== StallIntervention Tests ====================

    #[test]
    fn test_stall_intervention_serialization() {
        let intervention = StallIntervention {
            intervention_type: InterventionType::RestartAction,
            priority: 1,
            description: "Restart the action".to_string(),
            effectiveness: 0.9,
            implementation: InterventionImplementation {
                automatic: true,
                user_actions: vec![],
                parameters: HashMap::new(),
                rollback_strategy: Some("rollback".to_string()),
            },
        };
        let json = serde_json::to_string(&intervention).unwrap();
        assert!(json.contains("restart_action"));
        assert!(json.contains("0.9"));
        let parsed: StallIntervention = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.priority, 1);
        assert!(parsed.implementation.automatic);
    }

    // ==================== InterventionImplementation Tests ====================

    #[test]
    fn test_intervention_implementation_serialization() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), serde_json::json!("value"));
        let impl_details = InterventionImplementation {
            automatic: false,
            user_actions: vec![UserActionType::Pause, UserActionType::ModifyParameters],
            parameters: params,
            rollback_strategy: None,
        };
        let json = serde_json::to_string(&impl_details).unwrap();
        assert!(json.contains("false"));
        assert!(json.contains("key"));
        let parsed: InterventionImplementation = serde_json::from_str(&json).unwrap();
        assert!(!parsed.automatic);
        assert_eq!(parsed.user_actions.len(), 2);
    }

    // ==================== StallEvent Tests ====================

    #[test]
    fn test_stall_event_serialization() {
        let event = StallEvent {
            detected_at: chrono::Utc::now(),
            stall_type: StallType::ProgressStagnation,
            duration_ms: 15000,
            resolution: StallResolution::Automatic,
            resolution_effectiveness: 0.95,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("15000"));
        assert!(json.contains("0.95"));
        let parsed: StallEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.duration_ms, 15000);
    }

    // ==================== StallHistory Tests ====================

    #[test]
    fn test_stall_history_serialization() {
        let history = StallHistory {
            stalls: VecDeque::new(),
            intervention_history: vec![],
            patterns: vec![],
        };
        let json = serde_json::to_string(&history).unwrap();
        assert!(json.contains("stalls"));
        let parsed: StallHistory = serde_json::from_str(&json).unwrap();
        assert!(parsed.stalls.is_empty());
    }

    // ==================== StallStatistics Tests ====================

    #[test]
    fn test_stall_statistics_serialization() {
        let stats = StallStatistics {
            total_stalls: 5,
            current_stall_count: 2,
            avg_stall_duration_ms: 25000,
            escalation_count: 1,
            most_common_stall_type: Some(StallType::TimeoutStall),
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("25000"));
        assert!(json.contains("5"));
        let parsed: StallStatistics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_stalls, 5);
        assert_eq!(parsed.most_common_stall_type, Some(StallType::TimeoutStall));
    }

    // ==================== StallDetectorConfig Tests ====================

    #[test]
    fn test_stall_detector_config_default() {
        let config = StallDetectorConfig::default();
        assert_eq!(config.base_stall_threshold_ms, 30000);
        assert_eq!(config.max_stalls_before_escalation, 3);
        assert_eq!(config.progress_window_size, 10);
        assert_eq!(config.min_progress_threshold, 0.01);
        assert!(config.adaptive_thresholds);
        assert_eq!(config.detection_algorithms.len(), 5);
        assert_eq!(config.escalation_strategy, EscalationStrategy::Progressive);
    }

    #[test]
    fn test_stall_detector_config_serialization() {
        let config = StallDetectorConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("30000"));
        assert!(json.contains("progressive"));
        let parsed: StallDetectorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_stall_threshold_ms, 30000);
    }

    // ==================== StallDetector Reset Tests ====================

    #[test]
    fn test_stall_detector_reset() {
        let mut detector = StallDetector::new(10).unwrap();

        // Add some state
        detector.stall_count = 5;
        let data_point = ProgressDataPoint {
            timestamp: chrono::Utc::now(),
            progress: 0.5,
            active_actions: 2,
            completed_actions: 5,
            state: "Executing".to_string(),
            resource_usage: ProgressResourceUsage::default(),
        };
        detector.progress_history.push_back(data_point);

        // Reset
        detector.reset();

        assert_eq!(detector.stall_count, 0);
        assert!(detector.progress_history.is_empty());
        assert!(detector.current_stall.is_none());
        assert!(detector.last_progress_time.is_none());
    }

    // ==================== Escalation None Strategy Test ====================

    #[test]
    fn test_escalation_strategy_none() {
        let mut detector = StallDetector::new(10).unwrap();
        detector.config.escalation_strategy = EscalationStrategy::None;
        detector.stall_count = 10;
        // Should never escalate with None strategy
        assert!(!detector.should_escalate(1.0));
    }

    // ==================== Escalation Adaptive Strategy Test ====================

    #[test]
    fn test_escalation_strategy_adaptive() {
        let mut detector = StallDetector::new(10).unwrap();
        detector.config.escalation_strategy = EscalationStrategy::Adaptive;
        detector.config.max_stalls_before_escalation = 5;

        // High confidence should trigger
        detector.stall_count = 1;
        assert!(detector.should_escalate(0.8));

        // Low confidence, low stall count should not trigger
        assert!(!detector.should_escalate(0.3));

        // High stall count should trigger regardless of confidence
        detector.stall_count = 5;
        assert!(detector.should_escalate(0.3));
    }

    // ==================== Most Common Stall Type Tests ====================

    #[test]
    fn test_get_most_common_stall_type_empty() {
        let detector = StallDetector::new(10).unwrap();
        assert!(detector.get_most_common_stall_type().is_none());
    }

    #[test]
    fn test_get_most_common_stall_type_multiple() {
        let mut detector = StallDetector::new(10).unwrap();

        // Add various stall types
        for _ in 0..3 {
            detector.stall_history.stalls.push_back(StallEvent {
                detected_at: chrono::Utc::now(),
                stall_type: StallType::TimeoutStall,
                duration_ms: 1000,
                resolution: StallResolution::Automatic,
                resolution_effectiveness: 0.9,
            });
        }

        detector.stall_history.stalls.push_back(StallEvent {
            detected_at: chrono::Utc::now(),
            stall_type: StallType::ProgressStagnation,
            duration_ms: 1000,
            resolution: StallResolution::Automatic,
            resolution_effectiveness: 0.9,
        });

        assert_eq!(
            detector.get_most_common_stall_type(),
            Some(StallType::TimeoutStall)
        );
    }

    // ==================== Cyclical Behavior Detection Tests ====================

    #[test]
    fn test_cyclical_behavior_detection_no_cycle() {
        let mut detector = StallDetector::new(10).unwrap();

        // Add different states - no cycle
        let states = ["A", "B", "C", "D", "E", "F"];
        for state in states {
            detector.progress_history.push_back(ProgressDataPoint {
                timestamp: chrono::Utc::now(),
                progress: 0.1,
                active_actions: 1,
                completed_actions: 1,
                state: state.to_string(),
                resource_usage: ProgressResourceUsage::default(),
            });
        }

        let result = detector.detect_cyclical_behavior().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cyclical_behavior_detection_with_cycle() {
        let mut detector = StallDetector::new(10).unwrap();

        // Add ABAB pattern (cycle)
        let states = ["A", "B", "A", "B", "A", "B"];
        for state in states {
            detector.progress_history.push_back(ProgressDataPoint {
                timestamp: chrono::Utc::now(),
                progress: 0.1,
                active_actions: 1,
                completed_actions: 1,
                state: state.to_string(),
                resource_usage: ProgressResourceUsage::default(),
            });
        }

        let result = detector.detect_cyclical_behavior().unwrap();
        assert!(result.is_some());
        let (issue, _, _) = result.unwrap();
        assert_eq!(issue.issue_type, "CYCLICAL_BEHAVIOR");
    }

    // ==================== Resource Stall Detection Tests ====================

    #[test]
    fn test_resource_stall_detection_no_stall() {
        let mut detector = StallDetector::new(10).unwrap();
        let state_machine = create_test_state_machine();

        // Add progress with normal memory usage
        detector.progress_history.push_back(ProgressDataPoint {
            timestamp: chrono::Utc::now(),
            progress: 0.1,
            active_actions: 1,
            completed_actions: 1,
            state: "Executing".to_string(),
            resource_usage: ProgressResourceUsage {
                cpu_ms: 100,
                memory_bytes: 1024 * 1024,
                actions_per_minute: 1.0,
            },
        });
        detector.progress_history.push_back(ProgressDataPoint {
            timestamp: chrono::Utc::now(),
            progress: 0.2,
            active_actions: 1,
            completed_actions: 2,
            state: "Executing".to_string(),
            resource_usage: ProgressResourceUsage {
                cpu_ms: 200,
                memory_bytes: 1024 * 1024,
                actions_per_minute: 1.0,
            },
        });

        let result = detector.detect_resource_stall(&state_machine).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_resource_stall_detection_with_memory_growth() {
        let mut detector = StallDetector::new(10).unwrap();
        let state_machine = create_test_state_machine();

        // Add progress with memory growth but no progress
        detector.progress_history.push_back(ProgressDataPoint {
            timestamp: chrono::Utc::now(),
            progress: 0.1,
            active_actions: 1,
            completed_actions: 1,
            state: "Executing".to_string(),
            resource_usage: ProgressResourceUsage {
                cpu_ms: 100,
                memory_bytes: 1024 * 1024,
                actions_per_minute: 1.0,
            },
        });
        detector.progress_history.push_back(ProgressDataPoint {
            timestamp: chrono::Utc::now(),
            progress: 0.1, // No progress
            active_actions: 1,
            completed_actions: 1,
            state: "Executing".to_string(),
            resource_usage: ProgressResourceUsage {
                cpu_ms: 200,
                memory_bytes: 3 * 1024 * 1024, // 3x memory growth
                actions_per_minute: 1.0,
            },
        });

        let result = detector.detect_resource_stall(&state_machine).unwrap();
        assert!(result.is_some());
        let (issue, intervention, _) = result.unwrap();
        assert_eq!(issue.issue_type, "RESOURCE_STALL");
        assert_eq!(
            intervention.intervention_type,
            InterventionType::ReduceResources
        );
    }

    // ==================== Record Progress Tests ====================

    #[test]
    fn test_record_progress() {
        let mut detector = StallDetector::new(5).unwrap(); // Small window size
        let state_machine = create_test_state_machine();

        // Record progress multiple times
        for _ in 0..3 {
            detector.record_progress(&state_machine).unwrap();
        }

        // Should have recorded progress
        assert!(detector.progress_history.len() > 0);
        // Progress history should not exceed the configured window
        assert!(detector.progress_history.len() <= detector.config.progress_window_size);
    }

    // ==================== Get Current Stall Tests ====================

    #[test]
    fn test_get_current_stall() {
        let mut detector = StallDetector::new(10).unwrap();

        // Initially no stall
        assert!(detector.get_current_stall().is_none());

        // Set a stall
        detector.current_stall = Some(StallDetectionResult {
            stall_detected: true,
            stall_type: Some(StallType::TimeoutStall),
            confidence: 0.9,
            time_since_progress_ms: 50000,
            issues: vec![],
            interventions: vec![],
            should_escalate: false,
        });

        let stall = detector.get_current_stall().unwrap();
        assert!(stall.stall_detected);
        assert_eq!(stall.stall_type, Some(StallType::TimeoutStall));
    }
}
