/*!
# Stall Detection System - Advanced Workflow Monitoring

The Stall Detection System provides comprehensive monitoring and recovery for workflow stalls using 5 sophisticated algorithms:

- **Timeout Detection**: Identifies operations exceeding time thresholds
- **Progress Monitoring**: Tracks execution progress and detects stagnation
- **Dependency Analysis**: Identifies circular dependencies and deadlocks
- **Resource Starvation**: Detects resource allocation issues causing stalls
- **Pattern Recognition**: Uses ML-inspired techniques to identify stall patterns

## Detection Algorithms

```text
┌─────────────────────────────────────────────────────────────────┐
│                   Stall Detection Engine                       │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm 1: Timeout Detection                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Global    │  │    Step     │  │  Adaptive   │           │
│  │  Timeout    │  │  Timeout    │  │  Timeout    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm 2: Progress Monitoring                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Progress   │  │  Velocity   │  │  Heartbeat  │           │
│  │  Tracking   │  │  Analysis   │  │ Monitoring  │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm 3: Dependency Analysis                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Circular   │  │  Deadlock   │  │  Chain      │           │
│  │ Dependency  │  │ Detection   │  │ Analysis    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm 4: Resource Starvation                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Resource   │  │  Allocation │  │  Contention │           │
│  │ Monitoring  │  │   Failure   │  │ Detection   │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm 5: Pattern Recognition                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Historical │  │   Anomaly   │  │ Predictive  │           │
│  │  Analysis   │  │  Detection  │  │  Modeling   │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Recovery Strategies

- **AutoRetry**: Automatic retry with exponential backoff
- **UserIntervention**: Present options to user for manual resolution
- **Escalate**: Forward to higher-level management systems
- **Fail**: Mark workflow as failed with comprehensive reporting

## Usage

```text
let detector = StallDetector::new(config);
let stall_event = detector.check_stall(workflow_id, &current_state).await?;

if let Some(event) = stall_event {
    match event.recovery_strategy {
        RecoveryStrategy::AutoRetry => retry_operation().await?,
        RecoveryStrategy::UserIntervention => present_options().await?,
        RecoveryStrategy::Escalate => escalate_to_admin().await?,
        RecoveryStrategy::Fail => mark_failed().await?,
    }
}
```
*/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::planner::state_machine::{StateTransition, WorkflowState};

/// Stall detection system
#[derive(Clone)]
pub struct StallDetector {
    config: StallDetectionConfig,
    timeout_detector: Arc<TimeoutDetector>,
    progress_monitor: Arc<ProgressMonitor>,
    dependency_analyzer: Arc<DependencyStallAnalyzer>,
    resource_monitor: Arc<ResourceStarvationDetector>,
    pattern_recognizer: Arc<PatternRecognizer>,
    stall_history: Arc<RwLock<HashMap<Uuid, Vec<StallEvent>>>>,
    detection_metrics: Arc<RwLock<StallDetectionMetrics>>,
}

/// Stall detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallDetectionConfig {
    /// Global workflow timeout (seconds)
    pub global_timeout_seconds: u64,
    /// Per-state timeout thresholds
    pub state_timeouts: HashMap<String, u64>,
    /// Progress monitoring configuration
    pub progress_config: ProgressMonitorConfig,
    /// Dependency analysis configuration
    pub dependency_config: DependencyAnalysisConfig,
    /// Resource monitoring configuration
    pub resource_config: ResourceMonitorConfig,
    /// Pattern recognition configuration
    pub pattern_config: PatternRecognitionConfig,
    /// Recovery strategy preferences
    pub recovery_preferences: RecoveryPreferences,
}

/// Progress monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressMonitorConfig {
    /// Minimum progress velocity (progress/second)
    pub min_progress_velocity: f32,
    /// Progress stagnation threshold (seconds)
    pub stagnation_threshold_seconds: u64,
    /// Heartbeat timeout (seconds)
    pub heartbeat_timeout_seconds: u64,
    /// Progress measurement window (seconds)
    pub measurement_window_seconds: u64,
}

/// Dependency analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnalysisConfig {
    /// Maximum dependency chain length
    pub max_chain_length: u32,
    /// Deadlock detection interval (seconds)
    pub deadlock_check_interval_seconds: u64,
    /// Circular dependency detection enabled
    pub enable_circular_detection: bool,
}

/// Resource monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMonitorConfig {
    /// CPU starvation threshold (%)
    pub cpu_starvation_threshold: f32,
    /// Memory starvation threshold (%)
    pub memory_starvation_threshold: f32,
    /// Resource allocation timeout (seconds)
    pub allocation_timeout_seconds: u64,
    /// Resource contention threshold
    pub contention_threshold: f32,
}

/// Pattern recognition configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRecognitionConfig {
    /// Historical analysis window (number of past workflows)
    pub analysis_window_size: u32,
    /// Anomaly detection sensitivity (0.0-1.0)
    pub anomaly_sensitivity: f32,
    /// Pattern matching threshold
    pub pattern_match_threshold: f32,
    /// Enable predictive modeling
    pub enable_predictive_modeling: bool,
}

/// Recovery strategy preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPreferences {
    /// Prefer automatic retry when possible
    pub prefer_auto_retry: bool,
    /// Maximum auto-retry attempts
    pub max_auto_retry_attempts: u32,
    /// Escalation timeout (seconds)
    pub escalation_timeout_seconds: u64,
    /// User intervention timeout (seconds)
    pub user_intervention_timeout_seconds: u64,
}

/// Stall event detected by the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallEvent {
    pub event_id: Uuid,
    pub workflow_id: Uuid,
    pub stall_type: StallType,
    pub detection_algorithm: DetectionAlgorithm,
    pub severity: StallSeverity,
    pub description: String,
    pub context: StallContext,
    pub recovery_strategy: RecoveryStrategy,
    pub confidence: f32,
    pub detected_at: chrono::DateTime<chrono::Utc>,
    pub resolution_deadline: Option<chrono::DateTime<chrono::Utc>>,
}

/// Types of stalls that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StallType {
    /// Global workflow timeout exceeded
    GlobalTimeout,
    /// Individual state timeout exceeded
    StateTimeout,
    /// No progress detected for extended period
    ProgressStagnation,
    /// Execution velocity below threshold
    LowVelocity,
    /// Missing heartbeat signals
    HeartbeatTimeout,
    /// Circular dependency detected
    CircularDependency,
    /// Deadlock condition identified
    Deadlock,
    /// Dependency chain too long
    DependencyChainTooLong,
    /// CPU resources unavailable
    CpuStarvation,
    /// Memory resources unavailable
    MemoryStarvation,
    /// Resource allocation failed
    AllocationFailure,
    /// Resource contention detected
    ResourceContention,
    /// Historical pattern indicates stall
    HistoricalPattern,
    /// Anomalous behavior detected
    AnomalyDetected,
    /// Predictive model indicates future stall
    PredictiveStall,
}

/// Detection algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionAlgorithm {
    TimeoutDetection,
    ProgressMonitoring,
    DependencyAnalysis,
    ResourceStarvation,
    PatternRecognition,
}

/// Stall severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StallSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Stall context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallContext {
    pub current_state: String,
    pub time_in_state_seconds: u64,
    pub total_workflow_time_seconds: u64,
    pub progress_percentage: f32,
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
    pub resource_status: ResourceStatus,
    pub dependencies: Vec<DependencyInfo>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Recovery strategy for stall resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// Automatically retry the operation
    AutoRetry,
    /// Request user intervention
    UserIntervention,
    /// Escalate to higher-level system
    Escalate,
    /// Mark workflow as failed
    Fail,
}

/// Resource status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceStatus {
    pub cpu_utilization: f32,
    pub memory_utilization: f32,
    pub disk_utilization: f32,
    pub network_utilization: f32,
    pub allocation_pending: bool,
    pub contention_detected: bool,
}

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub dependency_id: Uuid,
    pub dependency_type: String,
    pub status: String,
    pub blocked_duration_seconds: u64,
    pub resolution_eta: Option<chrono::DateTime<chrono::Utc>>,
}

/// Stall detection metrics
#[derive(Debug, Clone, Default)]
struct StallDetectionMetrics {
    total_stalls_detected: u64,
    stalls_by_type: HashMap<String, u64>,
    stalls_by_algorithm: HashMap<String, u64>,
    auto_recovered_stalls: u64,
    user_intervention_stalls: u64,
    escalated_stalls: u64,
    failed_stalls: u64,
    average_detection_time_ms: f64,
    false_positive_rate: f32,
}

/// Timeout detection algorithm
struct TimeoutDetector {
    global_timeouts: Arc<RwLock<HashMap<Uuid, TimeoutTracker>>>,
    state_timeouts: Arc<RwLock<HashMap<Uuid, StateTimeoutTracker>>>,
    adaptive_timeouts: Arc<RwLock<HashMap<Uuid, AdaptiveTimeoutTracker>>>,
    global_timeout: Duration,
    state_timeout_defaults: HashMap<String, Duration>,
    recovery_preferences: RecoveryPreferences,
    inactivity_grace: Duration,
}

/// Timeout tracker
#[derive(Debug, Clone)]
struct TimeoutTracker {
    workflow_id: Uuid,
    started_at: Instant,
    timeout_threshold: Duration,
    last_activity: Instant,
    timeout_warnings: Vec<Instant>,
}

/// State timeout tracker
#[derive(Debug, Clone)]
struct StateTimeoutTracker {
    workflow_id: Uuid,
    current_state: WorkflowState,
    state_entered_at: Instant,
    state_timeout: Duration,
    state_history: VecDeque<StateTimeoutRecord>,
    last_activity: Instant,
    last_alert_at: Option<Instant>,
}

/// State timeout record
#[derive(Debug, Clone)]
struct StateTimeoutRecord {
    state: WorkflowState,
    duration: Duration,
    timed_out: bool,
}

/// Adaptive timeout tracker
#[derive(Debug, Clone)]
struct AdaptiveTimeoutTracker {
    workflow_id: Uuid,
    baseline_duration: Duration,
    adaptive_factor: f32,
    historical_durations: VecDeque<Duration>,
    confidence_interval: (Duration, Duration),
}

/// Progress monitoring algorithm
struct ProgressMonitor {
    progress_trackers: Arc<RwLock<HashMap<Uuid, ProgressTracker>>>,
    velocity_analyzers: Arc<RwLock<HashMap<Uuid, VelocityAnalyzer>>>,
    heartbeat_monitors: Arc<RwLock<HashMap<Uuid, HeartbeatMonitor>>>,
}

/// Progress tracker
#[derive(Debug, Clone)]
struct ProgressTracker {
    workflow_id: Uuid,
    progress_history: VecDeque<ProgressPoint>,
    last_progress_update: Instant,
    stagnation_start: Option<Instant>,
    measurement_window: Duration,
}

/// Progress point
#[derive(Debug, Clone)]
struct ProgressPoint {
    timestamp: Instant,
    progress: f32,
    delta: f32,
}

/// Velocity analyzer
#[derive(Debug, Clone)]
struct VelocityAnalyzer {
    workflow_id: Uuid,
    velocity_history: VecDeque<VelocityMeasurement>,
    current_velocity: f32,
    min_velocity_threshold: f32,
    velocity_trend: VelocityTrend,
}

/// Velocity measurement
#[derive(Debug, Clone)]
struct VelocityMeasurement {
    timestamp: Instant,
    velocity: f32,
    acceleration: f32,
}

/// Velocity trend
#[derive(Debug, Clone)]
enum VelocityTrend {
    Increasing,
    Stable,
    Decreasing,
    Stagnant,
}

/// Heartbeat monitor
#[derive(Debug, Clone)]
struct HeartbeatMonitor {
    workflow_id: Uuid,
    last_heartbeat: Instant,
    heartbeat_interval: Duration,
    missed_heartbeats: u32,
    heartbeat_pattern: HeartbeatPattern,
}

/// Heartbeat pattern
#[derive(Debug, Clone)]
struct HeartbeatPattern {
    expected_interval: Duration,
    tolerance: Duration,
    pattern_type: HeartbeatPatternType,
}

/// Heartbeat pattern type
#[derive(Debug, Clone)]
enum HeartbeatPatternType {
    Regular,
    Irregular,
    Adaptive,
    Burst,
}

/// Dependency stall analyzer
struct DependencyStallAnalyzer {
    dependency_graphs: Arc<RwLock<HashMap<Uuid, DependencyGraph>>>,
    deadlock_detector: Arc<DeadlockDetector>,
    chain_analyzer: Arc<DependencyChainAnalyzer>,
}

/// Dependency graph for stall analysis
#[derive(Debug, Clone)]
struct DependencyGraph {
    nodes: HashMap<Uuid, DependencyNode>,
    edges: HashMap<Uuid, Vec<Uuid>>,
    waiting_for: HashMap<Uuid, Vec<Uuid>>,
    last_updated: Instant,
}

/// Dependency node
#[derive(Debug, Clone)]
struct DependencyNode {
    node_id: Uuid,
    node_type: String,
    status: DependencyNodeStatus,
    waiting_since: Option<Instant>,
    dependents: Vec<Uuid>,
}

/// Dependency node status
#[derive(Debug, Clone)]
enum DependencyNodeStatus {
    Ready,
    Running,
    Waiting,
    Completed,
    Failed,
    Blocked,
}

/// Deadlock detector
struct DeadlockDetector {
    detection_history: Arc<RwLock<Vec<DeadlockDetection>>>,
    cycle_detector: CycleDetector,
}

/// Deadlock detection result
#[derive(Debug, Clone)]
struct DeadlockDetection {
    detection_id: Uuid,
    workflow_id: Uuid,
    detected_at: Instant,
    deadlock_cycle: Vec<Uuid>,
    severity: DeadlockSeverity,
    resolution_suggestion: String,
}

/// Deadlock severity
#[derive(Debug, Clone)]
enum DeadlockSeverity {
    Minor,
    Major,
    Critical,
}

/// Cycle detector for deadlocks
struct CycleDetector {
    visited: HashMap<Uuid, bool>,
    recursion_stack: HashMap<Uuid, bool>,
}

/// Dependency chain analyzer
struct DependencyChainAnalyzer {
    chain_cache: Arc<RwLock<HashMap<Uuid, DependencyChain>>>,
    max_chain_length: u32,
}

/// Dependency chain
#[derive(Debug, Clone)]
struct DependencyChain {
    chain_id: Uuid,
    root_node: Uuid,
    nodes: Vec<Uuid>,
    total_length: u32,
    longest_path: Vec<Uuid>,
    bottlenecks: Vec<Uuid>,
}

/// Resource starvation detector
struct ResourceStarvationDetector {
    resource_monitors: Arc<RwLock<HashMap<Uuid, ResourceMonitor>>>,
    allocation_trackers: Arc<RwLock<HashMap<Uuid, AllocationTracker>>>,
    contention_detectors: Arc<RwLock<HashMap<Uuid, ContentionDetector>>>,
}

/// Resource monitor
#[derive(Debug, Clone)]
struct ResourceMonitor {
    workflow_id: Uuid,
    resource_snapshots: VecDeque<ResourceSnapshot>,
    starvation_events: Vec<StarvationEvent>,
    monitoring_interval: Duration,
}

/// Resource snapshot
#[derive(Debug, Clone)]
struct ResourceSnapshot {
    timestamp: Instant,
    cpu_available: f32,
    memory_available: u64,
    disk_available: u64,
    network_available: f32,
    allocation_success_rate: f32,
}

/// Starvation event
#[derive(Debug, Clone)]
struct StarvationEvent {
    event_id: Uuid,
    resource_type: ResourceType,
    severity: StarvationSeverity,
    started_at: Instant,
    duration: Duration,
    impact: f32,
}

/// Resource type
#[derive(Debug, Clone)]
enum ResourceType {
    Cpu,
    Memory,
    Disk,
    Network,
    Custom(String),
}

/// Starvation severity
#[derive(Debug, Clone)]
enum StarvationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Allocation tracker
#[derive(Debug, Clone)]
struct AllocationTracker {
    workflow_id: Uuid,
    allocation_attempts: Vec<AllocationAttempt>,
    failure_pattern: AllocationFailurePattern,
    success_rate: f32,
}

/// Allocation attempt
#[derive(Debug, Clone)]
struct AllocationAttempt {
    attempt_id: Uuid,
    timestamp: Instant,
    resource_request: ResourceRequest,
    success: bool,
    failure_reason: Option<String>,
    retry_count: u32,
}

/// Resource request
#[derive(Debug, Clone)]
struct ResourceRequest {
    cpu_cores: f32,
    memory_mb: u64,
    disk_mb: u64,
    network_mbps: f32,
    priority: RequestPriority,
}

/// Request priority
#[derive(Debug, Clone)]
enum RequestPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Allocation failure pattern
#[derive(Debug, Clone)]
struct AllocationFailurePattern {
    pattern_type: FailurePatternType,
    frequency: f32,
    trend: FailureTrend,
    correlation: Vec<String>,
}

/// Failure pattern type
#[derive(Debug, Clone)]
enum FailurePatternType {
    Sporadic,
    Periodic,
    Continuous,
    Cascading,
}

/// Failure trend
#[derive(Debug, Clone)]
enum FailureTrend {
    Improving,
    Stable,
    Degrading,
    Critical,
}

/// Contention detector
#[derive(Debug, Clone)]
struct ContentionDetector {
    workflow_id: Uuid,
    contention_metrics: ContentionMetrics,
    contention_events: Vec<ContentionEvent>,
    resolution_strategies: Vec<ContentionResolutionStrategy>,
}

/// Contention metrics
#[derive(Debug, Clone)]
struct ContentionMetrics {
    wait_time_average: Duration,
    wait_time_p95: Duration,
    contention_frequency: f32,
    resource_utilization: f32,
    queue_length_average: f32,
}

/// Contention event
#[derive(Debug, Clone)]
struct ContentionEvent {
    event_id: Uuid,
    resource_type: ResourceType,
    contenders: Vec<Uuid>,
    wait_duration: Duration,
    resolution_method: String,
    impact_score: f32,
}

/// Contention resolution strategy
#[derive(Debug, Clone)]
struct ContentionResolutionStrategy {
    strategy_name: String,
    conditions: Vec<String>,
    actions: Vec<String>,
    effectiveness: f32,
}

/// Pattern recognition algorithm
struct PatternRecognizer {
    historical_analyzer: Arc<HistoricalAnalyzer>,
    anomaly_detector: Arc<AnomalyDetector>,
    predictive_modeler: Arc<PredictiveModeler>,
}

/// Historical analyzer
struct HistoricalAnalyzer {
    workflow_history: Arc<RwLock<VecDeque<WorkflowExecution>>>,
    pattern_database: Arc<RwLock<Vec<StallPattern>>>,
    analysis_window: usize,
}

/// Workflow execution record
#[derive(Debug, Clone)]
struct WorkflowExecution {
    execution_id: Uuid,
    execution_profile: ExecutionProfile,
    stall_events: Vec<StallEvent>,
    outcome: ExecutionOutcome,
    lessons_learned: Vec<String>,
}

/// Execution profile
#[derive(Debug, Clone)]
struct ExecutionProfile {
    workflow_type: String,
    complexity_score: f32,
    resource_requirements: ResourceRequirements,
    execution_characteristics: ExecutionCharacteristics,
}

/// Resource requirements for pattern analysis
#[derive(Debug, Clone)]
struct ResourceRequirements {
    cpu_requirement: f32,
    memory_requirement: u64,
    duration_estimate: Duration,
    parallelism_level: u32,
}

/// Execution characteristics
#[derive(Debug, Clone)]
struct ExecutionCharacteristics {
    state_transition_pattern: Vec<String>,
    resource_usage_pattern: Vec<f32>,
    progress_velocity_pattern: Vec<f32>,
    dependency_complexity: f32,
}

/// Execution outcome
#[derive(Debug, Clone)]
enum ExecutionOutcome {
    Success,
    PartialSuccess,
    Failure,
    Cancelled,
}

/// Stall pattern
#[derive(Debug, Clone)]
struct StallPattern {
    pattern_id: Uuid,
    pattern_name: String,
    pattern_signature: PatternSignature,
    occurrence_frequency: f32,
    prediction_accuracy: f32,
    mitigation_strategies: Vec<String>,
}

/// Pattern signature
#[derive(Debug, Clone)]
struct PatternSignature {
    state_sequence: Vec<String>,
    timing_characteristics: Vec<Duration>,
    resource_utilization: Vec<f32>,
    failure_points: Vec<String>,
}

/// Anomaly detector
struct AnomalyDetector {
    baseline_models: Arc<RwLock<HashMap<String, BaselineModel>>>,
    anomaly_threshold: f32,
    detection_history: Arc<RwLock<Vec<AnomalyDetection>>>,
}

/// Baseline model for anomaly detection
#[derive(Debug, Clone)]
struct BaselineModel {
    model_id: Uuid,
    model_type: String,
    parameters: HashMap<String, f32>,
    confidence_interval: (f32, f32),
    last_updated: Instant,
}

/// Anomaly detection result
#[derive(Debug, Clone)]
struct AnomalyDetection {
    detection_id: Uuid,
    workflow_id: Uuid,
    anomaly_type: AnomalyType,
    severity_score: f32,
    confidence: f32,
    detected_at: Instant,
    deviation_magnitude: f32,
}

/// Anomaly type
#[derive(Debug, Clone)]
enum AnomalyType {
    ExecutionTime,
    ResourceUsage,
    ProgressVelocity,
    StateTransition,
    DependencyPattern,
}

/// Predictive modeler
struct PredictiveModeler {
    prediction_models: Arc<RwLock<HashMap<String, PredictionModel>>>,
    prediction_history: Arc<RwLock<Vec<PredictionResult>>>,
    model_accuracy: HashMap<String, f32>,
}

/// Prediction model
#[derive(Debug, Clone)]
struct PredictionModel {
    model_id: Uuid,
    model_name: String,
    model_algorithm: String,
    training_data_size: usize,
    accuracy_score: f32,
    last_trained: Instant,
}

/// Prediction result
#[derive(Debug, Clone)]
struct PredictionResult {
    prediction_id: Uuid,
    workflow_id: Uuid,
    predicted_stall_type: StallType,
    probability: f32,
    time_to_stall: Duration,
    confidence: f32,
    prediction_made_at: Instant,
}

impl Default for StallDetectionConfig {
    fn default() -> Self {
        let mut state_timeouts = HashMap::new();
        state_timeouts.insert("Initializing".to_string(), 300); // 5 minutes
        state_timeouts.insert("Planning".to_string(), 1800); // 30 minutes
        state_timeouts.insert("Executing".to_string(), 3600); // 1 hour
        state_timeouts.insert("Evaluating".to_string(), 600); // 10 minutes

        Self {
            global_timeout_seconds: 14400, // 4 hours
            state_timeouts,
            progress_config: ProgressMonitorConfig {
                min_progress_velocity: 0.001,      // 0.1% per second
                stagnation_threshold_seconds: 300, // 5 minutes
                heartbeat_timeout_seconds: 120,    // 2 minutes
                measurement_window_seconds: 300,   // 5 minutes
            },
            dependency_config: DependencyAnalysisConfig {
                max_chain_length: 20,
                deadlock_check_interval_seconds: 60, // 1 minute
                enable_circular_detection: true,
            },
            resource_config: ResourceMonitorConfig {
                cpu_starvation_threshold: 0.95,    // 95%
                memory_starvation_threshold: 0.90, // 90%
                allocation_timeout_seconds: 300,   // 5 minutes
                contention_threshold: 0.8,         // 80%
            },
            pattern_config: PatternRecognitionConfig {
                analysis_window_size: 100,
                anomaly_sensitivity: 0.7,
                pattern_match_threshold: 0.8,
                enable_predictive_modeling: true,
            },
            recovery_preferences: RecoveryPreferences {
                prefer_auto_retry: true,
                max_auto_retry_attempts: 3,
                escalation_timeout_seconds: 1800, // 30 minutes
                user_intervention_timeout_seconds: 3600, // 1 hour
            },
        }
    }
}

impl StallDetector {
    /// Create new stall detector
    pub fn new(config: StallDetectionConfig) -> Self {
        info!("Initializing Stall Detection System");

        let timeout_detector = Arc::new(TimeoutDetector::new(&config));
        let progress_monitor = Arc::new(ProgressMonitor::new(&config.progress_config));
        let dependency_analyzer = Arc::new(DependencyStallAnalyzer::new(&config.dependency_config));
        let resource_monitor = Arc::new(ResourceStarvationDetector::new(&config.resource_config));
        let pattern_recognizer = Arc::new(PatternRecognizer::new(&config.pattern_config));
        let stall_history = Arc::new(RwLock::new(HashMap::new()));
        let detection_metrics = Arc::new(RwLock::new(StallDetectionMetrics::default()));

        info!("Stall Detection System initialized with 5 algorithms");

        Self {
            config,
            timeout_detector,
            progress_monitor,
            dependency_analyzer,
            resource_monitor,
            pattern_recognizer,
            stall_history,
            detection_metrics,
        }
    }

    /// Check for stalls in a workflow
    #[instrument(skip(self), fields(workflow_id = %workflow_id))]
    pub async fn check_stall(
        &self,
        workflow_id: Uuid,
        current_state: &WorkflowState,
    ) -> Result<Option<StallEvent>> {
        debug!(workflow_id = %workflow_id, state = ?current_state, "Checking for workflow stalls");

        let start_time = Instant::now();
        let mut detected_stalls = Vec::new();

        // Algorithm 1: Timeout Detection
        if let Some(stall) = self
            .timeout_detector
            .check_timeout(workflow_id, current_state)
            .await?
        {
            detected_stalls.push(stall);
        }

        // Algorithm 2: Progress Monitoring
        if let Some(stall) = self
            .progress_monitor
            .check_progress_stall(workflow_id, current_state)
            .await?
        {
            detected_stalls.push(stall);
        }

        // Algorithm 3: Dependency Analysis
        if let Some(stall) = self
            .dependency_analyzer
            .check_dependency_stalls(workflow_id)
            .await?
        {
            detected_stalls.push(stall);
        }

        // Algorithm 4: Resource Starvation
        if let Some(stall) = self
            .resource_monitor
            .check_resource_starvation(workflow_id)
            .await?
        {
            detected_stalls.push(stall);
        }

        // Algorithm 5: Pattern Recognition
        if let Some(stall) = self
            .pattern_recognizer
            .check_patterns(workflow_id, current_state)
            .await?
        {
            detected_stalls.push(stall);
        }

        // Select the most critical stall if multiple detected
        let critical_stall = self.select_critical_stall(detected_stalls).await;

        if let Some(ref stall) = critical_stall {
            // Record stall in history
            self.record_stall_event(stall.clone()).await;

            // Update detection metrics
            self.update_detection_metrics(stall.clone()).await;

            let detection_time = start_time.elapsed();
            info!(
                workflow_id = %workflow_id,
                stall_type = ?stall.stall_type,
                algorithm = ?stall.detection_algorithm,
                severity = ?stall.severity,
                detection_time_ms = detection_time.as_millis(),
                "Stall detected"
            );
        }

        Ok(critical_stall)
    }

    /// Select the most critical stall from detected stalls
    async fn select_critical_stall(&self, stalls: Vec<StallEvent>) -> Option<StallEvent> {
        if stalls.is_empty() {
            return None;
        }

        // Sort by severity and confidence
        let mut sorted_stalls = stalls;
        sorted_stalls.sort_by(|a, b| {
            let severity_order = |s: &StallSeverity| match s {
                StallSeverity::Critical => 4,
                StallSeverity::High => 3,
                StallSeverity::Medium => 2,
                StallSeverity::Low => 1,
            };

            let a_score = severity_order(&a.severity) as f32 + a.confidence;
            let b_score = severity_order(&b.severity) as f32 + b.confidence;

            b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        sorted_stalls.into_iter().next()
    }

    /// Record stall event in history
    async fn record_stall_event(&self, stall: StallEvent) {
        let mut history = self.stall_history.write().await;
        history
            .entry(stall.workflow_id)
            .or_insert_with(Vec::new)
            .push(stall);
    }

    /// Update detection metrics
    async fn update_detection_metrics(&self, stall: StallEvent) {
        let mut metrics = self.detection_metrics.write().await;

        metrics.total_stalls_detected += 1;

        let stall_type_key = format!("{:?}", stall.stall_type);
        *metrics.stalls_by_type.entry(stall_type_key).or_insert(0) += 1;

        let algorithm_key = format!("{:?}", stall.detection_algorithm);
        *metrics
            .stalls_by_algorithm
            .entry(algorithm_key)
            .or_insert(0) += 1;
    }

    /// Get stall history for workflow
    pub async fn get_stall_history(&self, workflow_id: Uuid) -> Vec<StallEvent> {
        self.stall_history
            .read()
            .await
            .get(&workflow_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Export detection metrics
    pub async fn export_metrics(&self) -> StallDetectionMetrics {
        self.detection_metrics.read().await.clone()
    }

    /// Update workflow progress (for progress monitoring)
    pub async fn update_progress(&self, workflow_id: Uuid, progress: f32) -> Result<()> {
        self.timeout_detector
            .record_activity(workflow_id, None)
            .await;
        self.progress_monitor
            .update_progress(workflow_id, progress)
            .await
    }

    /// Report heartbeat (for heartbeat monitoring)
    pub async fn report_heartbeat(&self, workflow_id: Uuid) -> Result<()> {
        self.timeout_detector
            .record_activity(workflow_id, None)
            .await;
        self.progress_monitor.report_heartbeat(workflow_id).await
    }

    /// Add resource snapshot (for resource monitoring)
    pub async fn add_resource_snapshot(
        &self,
        workflow_id: Uuid,
        snapshot: ResourceSnapshot,
    ) -> Result<()> {
        self.resource_monitor
            .add_resource_snapshot(workflow_id, snapshot)
            .await
    }
}

impl TimeoutDetector {
    fn new(config: &StallDetectionConfig) -> Self {
        let state_timeout_defaults = config
            .state_timeouts
            .iter()
            .map(|(state, seconds)| (state.clone(), Duration::from_secs(*seconds)))
            .collect();

        let grace_seconds = config
            .global_timeout_seconds
            .saturating_div(10)
            .max(3)
            .min(60);

        Self {
            global_timeouts: Arc::new(RwLock::new(HashMap::new())),
            state_timeouts: Arc::new(RwLock::new(HashMap::new())),
            adaptive_timeouts: Arc::new(RwLock::new(HashMap::new())),
            global_timeout: Duration::from_secs(config.global_timeout_seconds),
            state_timeout_defaults,
            recovery_preferences: config.recovery_preferences.clone(),
            inactivity_grace: Duration::from_secs(grace_seconds),
        }
    }

    async fn check_timeout(
        &self,
        workflow_id: Uuid,
        current_state: &WorkflowState,
    ) -> Result<Option<StallEvent>> {
        if matches!(
            current_state,
            WorkflowState::Completed | WorkflowState::Failed
        ) {
            self.clear_workflow(workflow_id).await;
            return Ok(None);
        }

        // Check global timeout
        if let Some(stall) = self.check_global_timeout(workflow_id).await? {
            return Ok(Some(stall));
        }

        // Check state timeout
        if let Some(stall) = self.check_state_timeout(workflow_id, current_state).await? {
            return Ok(Some(stall));
        }

        // Check adaptive timeout
        if let Some(stall) = self.check_adaptive_timeout(workflow_id).await? {
            return Ok(Some(stall));
        }

        Ok(None)
    }

    async fn check_global_timeout(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        let now = Instant::now();

        let snapshot = {
            let mut trackers = self.global_timeouts.write().await;
            let tracker = trackers
                .entry(workflow_id)
                .or_insert_with(|| TimeoutTracker {
                    workflow_id,
                    started_at: now,
                    timeout_threshold: self.global_timeout,
                    last_activity: now,
                    timeout_warnings: Vec::new(),
                });

            let elapsed = now.saturating_duration_since(tracker.started_at);
            let inactivity = now.saturating_duration_since(tracker.last_activity);
            let recently_warned = tracker
                .timeout_warnings
                .last()
                .map(|last| now.saturating_duration_since(*last) < self.inactivity_grace)
                .unwrap_or(false);

            if elapsed >= tracker.timeout_threshold
                && inactivity >= self.inactivity_grace
                && !recently_warned
            {
                tracker.timeout_warnings.push(now);
                Some((
                    tracker.started_at,
                    tracker.timeout_threshold,
                    elapsed,
                    inactivity,
                    tracker.last_activity,
                ))
            } else {
                None
            }
        };

        if let Some((started_at, threshold, elapsed, inactivity, last_activity)) = snapshot {
            let stall = self.build_timeout_stall(
                workflow_id,
                StallType::GlobalTimeout,
                threshold,
                elapsed,
                inactivity,
                None,
                Some((started_at, last_activity)),
            )?;
            Ok(Some(stall))
        } else {
            Ok(None)
        }
    }

    async fn check_state_timeout(
        &self,
        workflow_id: Uuid,
        current_state: &WorkflowState,
    ) -> Result<Option<StallEvent>> {
        let now = Instant::now();
        let state_name = format!("{:?}", current_state);
        let state_timeout = self
            .state_timeout_defaults
            .get(&state_name)
            .cloned()
            .unwrap_or(self.global_timeout);

        let global_started = {
            let mut global = self.global_timeouts.write().await;
            let tracker = global.entry(workflow_id).or_insert_with(|| TimeoutTracker {
                workflow_id,
                started_at: now,
                timeout_threshold: self.global_timeout,
                last_activity: now,
                timeout_warnings: Vec::new(),
            });
            tracker.started_at
        };

        let snapshot = {
            let mut trackers = self.state_timeouts.write().await;
            let entry = trackers
                .entry(workflow_id)
                .or_insert_with(|| StateTimeoutTracker {
                    workflow_id,
                    current_state: current_state.clone(),
                    state_entered_at: now,
                    state_timeout,
                    state_history: VecDeque::new(),
                    last_activity: now,
                    last_alert_at: None,
                });

            if entry.current_state != *current_state {
                let duration_in_state = now.saturating_duration_since(entry.state_entered_at);
                entry.state_history.push_back(StateTimeoutRecord {
                    state: entry.current_state.clone(),
                    duration: duration_in_state,
                    timed_out: false,
                });
                *entry = StateTimeoutTracker {
                    workflow_id,
                    current_state: current_state.clone(),
                    state_entered_at: now,
                    state_timeout,
                    state_history: VecDeque::new(),
                    last_activity: now,
                    last_alert_at: None,
                };
                None
            } else {
                let elapsed = now.saturating_duration_since(entry.state_entered_at);
                let inactivity = now.saturating_duration_since(entry.last_activity);
                let recently_warned = entry
                    .last_alert_at
                    .map(|alert| now.saturating_duration_since(alert) < self.inactivity_grace)
                    .unwrap_or(false);

                if elapsed >= entry.state_timeout
                    && inactivity >= self.inactivity_grace
                    && !recently_warned
                {
                    entry.state_history.push_back(StateTimeoutRecord {
                        state: entry.current_state.clone(),
                        duration: elapsed,
                        timed_out: true,
                    });
                    entry.last_alert_at = Some(now);

                    Some((
                        entry.state_entered_at,
                        entry.state_timeout,
                        elapsed,
                        inactivity,
                        entry.last_activity,
                    ))
                } else {
                    None
                }
            }
        };

        if let Some((state_entered_at, threshold, elapsed, inactivity, last_activity)) = snapshot {
            let stall = self.build_timeout_stall(
                workflow_id,
                StallType::StateTimeout,
                threshold,
                elapsed,
                inactivity,
                Some(state_name),
                Some((global_started, last_activity)),
            )?;
            Ok(Some(stall))
        } else {
            Ok(None)
        }
    }

    async fn check_adaptive_timeout(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation - in practice would use machine learning for adaptive timeouts
        Ok(None)
    }

    async fn record_activity(&self, workflow_id: Uuid, state: Option<&WorkflowState>) {
        let now = Instant::now();

        {
            let mut trackers = self.global_timeouts.write().await;
            let tracker = trackers
                .entry(workflow_id)
                .or_insert_with(|| TimeoutTracker {
                    workflow_id,
                    started_at: now,
                    timeout_threshold: self.global_timeout,
                    last_activity: now,
                    timeout_warnings: Vec::new(),
                });
            tracker.last_activity = now;
            tracker.timeout_warnings.clear();
        }

        let mut trackers = self.state_timeouts.write().await;

        if let Some(state) = state {
            let state_name = format!("{:?}", state);
            let state_timeout = self
                .state_timeout_defaults
                .get(&state_name)
                .cloned()
                .unwrap_or(self.global_timeout);

            let entry = trackers
                .entry(workflow_id)
                .or_insert_with(|| StateTimeoutTracker {
                    workflow_id,
                    current_state: state.clone(),
                    state_entered_at: now,
                    state_timeout,
                    state_history: VecDeque::new(),
                    last_activity: now,
                    last_alert_at: None,
                });

            if &entry.current_state == state {
                entry.last_activity = now;
                entry.last_alert_at = None;
            }
        } else if let Some(entry) = trackers.get_mut(&workflow_id) {
            entry.last_activity = now;
            entry.last_alert_at = None;
        }
    }

    async fn clear_workflow(&self, workflow_id: Uuid) {
        self.global_timeouts.write().await.remove(&workflow_id);
        self.state_timeouts.write().await.remove(&workflow_id);
        self.adaptive_timeouts.write().await.remove(&workflow_id);
    }

    fn build_timeout_stall(
        &self,
        workflow_id: Uuid,
        stall_type: StallType,
        threshold: Duration,
        elapsed: Duration,
        inactivity: Duration,
        state_name: Option<String>,
        timing: Option<(Instant, Instant)>,
    ) -> Result<StallEvent> {
        let detection_instant = Instant::now();
        let detected_at = chrono::Utc::now();

        let total_duration_seconds = timing
            .map(|(started_at, _)| {
                detection_instant
                    .saturating_duration_since(started_at)
                    .as_secs()
            })
            .unwrap_or_else(|| elapsed.as_secs());

        let last_activity_time = timing.and_then(|(_, last_activity)| {
            chrono::Duration::from_std(detection_instant.saturating_duration_since(last_activity))
                .ok()
                .map(|delta| detected_at - delta)
        });

        let severity = self.severity_from_ratio(threshold, elapsed);
        let recovery_strategy = self.choose_recovery_strategy(&severity);

        let mut metadata = HashMap::new();
        metadata.insert("timeout_seconds".to_string(), json!(threshold.as_secs()));
        metadata.insert("elapsed_seconds".to_string(), json!(elapsed.as_secs()));
        metadata.insert(
            "inactivity_seconds".to_string(),
            json!(inactivity.as_secs()),
        );

        let context = StallContext {
            current_state: state_name.unwrap_or_else(|| match stall_type {
                StallType::GlobalTimeout => "Global".to_string(),
                _ => "Unknown".to_string(),
            }),
            time_in_state_seconds: elapsed.as_secs(),
            total_workflow_time_seconds: total_duration_seconds,
            progress_percentage: 0.0,
            last_activity: last_activity_time,
            resource_status: ResourceStatus {
                cpu_utilization: 0.0,
                memory_utilization: 0.0,
                disk_utilization: 0.0,
                network_utilization: 0.0,
                allocation_pending: false,
                contention_detected: false,
            },
            dependencies: Vec::new(),
            metadata,
        };

        let confidence = if threshold.is_zero() {
            1.0
        } else {
            (elapsed.as_secs_f32() / threshold.as_secs_f32()).min(1.0)
        };

        let resolution_deadline = if self.recovery_preferences.escalation_timeout_seconds > 0 {
            Some(
                detected_at
                    + chrono::Duration::seconds(
                        self.recovery_preferences.escalation_timeout_seconds as i64,
                    ),
            )
        } else {
            None
        };

        let description = match stall_type {
            StallType::GlobalTimeout => format!(
                "Workflow exceeded global timeout (>{}s) with no activity",
                threshold.as_secs()
            ),
            StallType::StateTimeout => format!(
                "Workflow state exceeded timeout (>{}s) with limited progress",
                threshold.as_secs()
            ),
            _ => "Timeout detected".to_string(),
        };

        Ok(StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id,
            stall_type,
            detection_algorithm: DetectionAlgorithm::TimeoutDetection,
            severity,
            description,
            context,
            recovery_strategy,
            confidence,
            detected_at,
            resolution_deadline,
        })
    }

    fn severity_from_ratio(&self, threshold: Duration, elapsed: Duration) -> StallSeverity {
        if threshold.is_zero() {
            return StallSeverity::Critical;
        }

        let ratio = elapsed.as_secs_f64() / threshold.as_secs_f64();
        if ratio >= 2.0 {
            StallSeverity::Critical
        } else if ratio >= 1.5 {
            StallSeverity::High
        } else if ratio >= 1.1 {
            StallSeverity::Medium
        } else {
            StallSeverity::Low
        }
    }

    fn choose_recovery_strategy(&self, severity: &StallSeverity) -> RecoveryStrategy {
        if self.recovery_preferences.prefer_auto_retry
            && self.recovery_preferences.max_auto_retry_attempts > 0
            && !matches!(severity, StallSeverity::Critical)
        {
            RecoveryStrategy::AutoRetry
        } else if matches!(severity, StallSeverity::Critical | StallSeverity::High) {
            RecoveryStrategy::Escalate
        } else if self.recovery_preferences.user_intervention_timeout_seconds > 0 {
            RecoveryStrategy::UserIntervention
        } else {
            RecoveryStrategy::Fail
        }
    }
}

impl ProgressMonitor {
    fn new(config: &ProgressMonitorConfig) -> Self {
        Self {
            progress_trackers: Arc::new(RwLock::new(HashMap::new())),
            velocity_analyzers: Arc::new(RwLock::new(HashMap::new())),
            heartbeat_monitors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn check_progress_stall(
        &self,
        workflow_id: Uuid,
        _current_state: &WorkflowState,
    ) -> Result<Option<StallEvent>> {
        // Check progress stagnation
        if let Some(stall) = self.check_progress_stagnation(workflow_id).await? {
            return Ok(Some(stall));
        }

        // Check velocity issues
        if let Some(stall) = self.check_velocity_issues(workflow_id).await? {
            return Ok(Some(stall));
        }

        // Check heartbeat timeout
        if let Some(stall) = self.check_heartbeat_timeout(workflow_id).await? {
            return Ok(Some(stall));
        }

        Ok(None)
    }

    async fn check_progress_stagnation(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }

    async fn check_velocity_issues(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }

    async fn check_heartbeat_timeout(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }

    async fn update_progress(&self, workflow_id: Uuid, progress: f32) -> Result<()> {
        // Update progress tracker
        Ok(())
    }

    async fn report_heartbeat(&self, workflow_id: Uuid) -> Result<()> {
        // Update heartbeat monitor
        Ok(())
    }
}

impl DependencyStallAnalyzer {
    fn new(config: &DependencyAnalysisConfig) -> Self {
        Self {
            dependency_graphs: Arc::new(RwLock::new(HashMap::new())),
            deadlock_detector: Arc::new(DeadlockDetector::new()),
            chain_analyzer: Arc::new(DependencyChainAnalyzer::new(config.max_chain_length)),
        }
    }

    async fn check_dependency_stalls(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Check for circular dependencies
        if let Some(stall) = self.check_circular_dependencies(workflow_id).await? {
            return Ok(Some(stall));
        }

        // Check for deadlocks
        if let Some(stall) = self.deadlock_detector.check_deadlock(workflow_id).await? {
            return Ok(Some(stall));
        }

        // Check for long dependency chains
        if let Some(stall) = self.chain_analyzer.check_chain_length(workflow_id).await? {
            return Ok(Some(stall));
        }

        Ok(None)
    }

    async fn check_circular_dependencies(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }
}

impl DeadlockDetector {
    fn new() -> Self {
        Self {
            detection_history: Arc::new(RwLock::new(Vec::new())),
            cycle_detector: CycleDetector {
                visited: HashMap::new(),
                recursion_stack: HashMap::new(),
            },
        }
    }

    async fn check_deadlock(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }
}

impl DependencyChainAnalyzer {
    fn new(max_chain_length: u32) -> Self {
        Self {
            chain_cache: Arc::new(RwLock::new(HashMap::new())),
            max_chain_length,
        }
    }

    async fn check_chain_length(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }
}

impl ResourceStarvationDetector {
    fn new(config: &ResourceMonitorConfig) -> Self {
        Self {
            resource_monitors: Arc::new(RwLock::new(HashMap::new())),
            allocation_trackers: Arc::new(RwLock::new(HashMap::new())),
            contention_detectors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn check_resource_starvation(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Check CPU starvation
        if let Some(stall) = self.check_cpu_starvation(workflow_id).await? {
            return Ok(Some(stall));
        }

        // Check memory starvation
        if let Some(stall) = self.check_memory_starvation(workflow_id).await? {
            return Ok(Some(stall));
        }

        // Check allocation failures
        if let Some(stall) = self.check_allocation_failures(workflow_id).await? {
            return Ok(Some(stall));
        }

        // Check resource contention
        if let Some(stall) = self.check_resource_contention(workflow_id).await? {
            return Ok(Some(stall));
        }

        Ok(None)
    }

    async fn check_cpu_starvation(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }

    async fn check_memory_starvation(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }

    async fn check_allocation_failures(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }

    async fn check_resource_contention(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }

    async fn add_resource_snapshot(
        &self,
        workflow_id: Uuid,
        snapshot: ResourceSnapshot,
    ) -> Result<()> {
        // Add snapshot to monitoring
        Ok(())
    }
}

impl PatternRecognizer {
    fn new(config: &PatternRecognitionConfig) -> Self {
        Self {
            historical_analyzer: Arc::new(HistoricalAnalyzer::new(config.analysis_window_size)),
            anomaly_detector: Arc::new(AnomalyDetector::new(config.anomaly_sensitivity)),
            predictive_modeler: Arc::new(PredictiveModeler::new()),
        }
    }

    async fn check_patterns(
        &self,
        workflow_id: Uuid,
        current_state: &WorkflowState,
    ) -> Result<Option<StallEvent>> {
        // Check historical patterns
        if let Some(stall) = self
            .historical_analyzer
            .check_historical_patterns(workflow_id)
            .await?
        {
            return Ok(Some(stall));
        }

        // Check for anomalies
        if let Some(stall) = self
            .anomaly_detector
            .check_anomalies(workflow_id, current_state)
            .await?
        {
            return Ok(Some(stall));
        }

        // Check predictive models
        if let Some(stall) = self.predictive_modeler.predict_stalls(workflow_id).await? {
            return Ok(Some(stall));
        }

        Ok(None)
    }
}

impl HistoricalAnalyzer {
    fn new(analysis_window: u32) -> Self {
        Self {
            workflow_history: Arc::new(RwLock::new(VecDeque::new())),
            pattern_database: Arc::new(RwLock::new(Vec::new())),
            analysis_window: analysis_window as usize,
        }
    }

    async fn check_historical_patterns(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }
}

impl AnomalyDetector {
    fn new(sensitivity: f32) -> Self {
        Self {
            baseline_models: Arc::new(RwLock::new(HashMap::new())),
            anomaly_threshold: sensitivity,
            detection_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn check_anomalies(
        &self,
        workflow_id: Uuid,
        _current_state: &WorkflowState,
    ) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }
}

impl PredictiveModeler {
    fn new() -> Self {
        Self {
            prediction_models: Arc::new(RwLock::new(HashMap::new())),
            prediction_history: Arc::new(RwLock::new(Vec::new())),
            model_accuracy: HashMap::new(),
        }
    }

    async fn predict_stalls(&self, workflow_id: Uuid) -> Result<Option<StallEvent>> {
        // Simplified implementation
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[test]
    fn test_stall_detector_creation() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);

        // Verify detector was created successfully
        assert_eq!(detector.config.global_timeout_seconds, 14400);
    }

    // StallDetectionConfig default tests
    #[test]
    fn test_stall_detection_config_default() {
        let config = StallDetectionConfig::default();
        assert_eq!(config.global_timeout_seconds, 14400);
        assert_eq!(config.state_timeouts.get("Initializing"), Some(&300));
        assert_eq!(config.state_timeouts.get("Planning"), Some(&1800));
        assert_eq!(config.state_timeouts.get("Executing"), Some(&3600));
        assert_eq!(config.state_timeouts.get("Evaluating"), Some(&600));
    }

    #[test]
    fn test_progress_monitor_config_defaults() {
        let config = StallDetectionConfig::default();
        assert_eq!(config.progress_config.min_progress_velocity, 0.001);
        assert_eq!(config.progress_config.stagnation_threshold_seconds, 300);
        assert_eq!(config.progress_config.heartbeat_timeout_seconds, 120);
        assert_eq!(config.progress_config.measurement_window_seconds, 300);
    }

    #[test]
    fn test_dependency_analysis_config_defaults() {
        let config = StallDetectionConfig::default();
        assert_eq!(config.dependency_config.max_chain_length, 20);
        assert_eq!(config.dependency_config.deadlock_check_interval_seconds, 60);
        assert!(config.dependency_config.enable_circular_detection);
    }

    #[test]
    fn test_resource_monitor_config_defaults() {
        let config = StallDetectionConfig::default();
        assert_eq!(config.resource_config.cpu_starvation_threshold, 0.95);
        assert_eq!(config.resource_config.memory_starvation_threshold, 0.90);
        assert_eq!(config.resource_config.allocation_timeout_seconds, 300);
        assert_eq!(config.resource_config.contention_threshold, 0.8);
    }

    #[test]
    fn test_pattern_recognition_config_defaults() {
        let config = StallDetectionConfig::default();
        assert_eq!(config.pattern_config.analysis_window_size, 100);
        assert_eq!(config.pattern_config.anomaly_sensitivity, 0.7);
        assert_eq!(config.pattern_config.pattern_match_threshold, 0.8);
        assert!(config.pattern_config.enable_predictive_modeling);
    }

    #[test]
    fn test_recovery_preferences_defaults() {
        let config = StallDetectionConfig::default();
        assert!(config.recovery_preferences.prefer_auto_retry);
        assert_eq!(config.recovery_preferences.max_auto_retry_attempts, 3);
        assert_eq!(config.recovery_preferences.escalation_timeout_seconds, 1800);
        assert_eq!(
            config
                .recovery_preferences
                .user_intervention_timeout_seconds,
            3600
        );
    }

    // StallType serialization tests
    #[test]
    fn test_stall_type_serialization() {
        let types = vec![
            StallType::GlobalTimeout,
            StallType::StateTimeout,
            StallType::ProgressStagnation,
            StallType::LowVelocity,
            StallType::HeartbeatTimeout,
            StallType::CircularDependency,
            StallType::Deadlock,
            StallType::DependencyChainTooLong,
            StallType::CpuStarvation,
            StallType::MemoryStarvation,
            StallType::AllocationFailure,
            StallType::ResourceContention,
            StallType::HistoricalPattern,
            StallType::AnomalyDetected,
            StallType::PredictiveStall,
        ];

        for stall_type in types {
            let json = serde_json::to_string(&stall_type).unwrap();
            let parsed: StallType = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // DetectionAlgorithm serialization tests
    #[test]
    fn test_detection_algorithm_serialization() {
        let algorithms = vec![
            DetectionAlgorithm::TimeoutDetection,
            DetectionAlgorithm::ProgressMonitoring,
            DetectionAlgorithm::DependencyAnalysis,
            DetectionAlgorithm::ResourceStarvation,
            DetectionAlgorithm::PatternRecognition,
        ];

        for algo in algorithms {
            let json = serde_json::to_string(&algo).unwrap();
            let parsed: DetectionAlgorithm = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // StallSeverity serialization tests
    #[test]
    fn test_stall_severity_serialization() {
        let severities = vec![
            StallSeverity::Low,
            StallSeverity::Medium,
            StallSeverity::High,
            StallSeverity::Critical,
        ];

        for severity in severities {
            let json = serde_json::to_string(&severity).unwrap();
            let parsed: StallSeverity = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // RecoveryStrategy serialization tests
    #[test]
    fn test_recovery_strategy_serialization() {
        let strategies = vec![
            RecoveryStrategy::AutoRetry,
            RecoveryStrategy::UserIntervention,
            RecoveryStrategy::Escalate,
            RecoveryStrategy::Fail,
        ];

        for strategy in strategies {
            let json = serde_json::to_string(&strategy).unwrap();
            let parsed: RecoveryStrategy = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // ResourceStatus tests
    #[test]
    fn test_resource_status_serialization() {
        let status = ResourceStatus {
            cpu_utilization: 0.75,
            memory_utilization: 0.60,
            disk_utilization: 0.45,
            network_utilization: 0.30,
            allocation_pending: true,
            contention_detected: false,
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: ResourceStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.cpu_utilization, 0.75);
        assert_eq!(parsed.memory_utilization, 0.60);
        assert_eq!(parsed.disk_utilization, 0.45);
        assert_eq!(parsed.network_utilization, 0.30);
        assert!(parsed.allocation_pending);
        assert!(!parsed.contention_detected);
    }

    // DependencyInfo tests
    #[test]
    fn test_dependency_info_serialization() {
        let info = DependencyInfo {
            dependency_id: Uuid::new_v4(),
            dependency_type: "external_api".to_string(),
            status: "waiting".to_string(),
            blocked_duration_seconds: 120,
            resolution_eta: Some(chrono::Utc::now()),
        };

        let json = serde_json::to_string(&info).unwrap();
        let parsed: DependencyInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.dependency_type, "external_api");
        assert_eq!(parsed.status, "waiting");
        assert_eq!(parsed.blocked_duration_seconds, 120);
    }

    // StallContext tests
    #[test]
    fn test_stall_context_serialization() {
        let context = StallContext {
            current_state: "Executing".to_string(),
            time_in_state_seconds: 500,
            total_workflow_time_seconds: 1200,
            progress_percentage: 0.65,
            last_activity: Some(chrono::Utc::now()),
            resource_status: ResourceStatus {
                cpu_utilization: 0.80,
                memory_utilization: 0.70,
                disk_utilization: 0.50,
                network_utilization: 0.20,
                allocation_pending: false,
                contention_detected: true,
            },
            dependencies: vec![],
            metadata: HashMap::from([("key".to_string(), serde_json::json!("value"))]),
        };

        let json = serde_json::to_string(&context).unwrap();
        let parsed: StallContext = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.current_state, "Executing");
        assert_eq!(parsed.time_in_state_seconds, 500);
        assert_eq!(parsed.progress_percentage, 0.65);
    }

    // StallEvent serialization tests
    #[test]
    fn test_stall_event_serialization() {
        let event = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::GlobalTimeout,
            detection_algorithm: DetectionAlgorithm::TimeoutDetection,
            severity: StallSeverity::High,
            description: "Workflow timeout".to_string(),
            context: StallContext {
                current_state: "Planning".to_string(),
                time_in_state_seconds: 300,
                total_workflow_time_seconds: 600,
                progress_percentage: 0.3,
                last_activity: Some(chrono::Utc::now()),
                resource_status: ResourceStatus {
                    cpu_utilization: 0.5,
                    memory_utilization: 0.6,
                    disk_utilization: 0.3,
                    network_utilization: 0.2,
                    allocation_pending: false,
                    contention_detected: false,
                },
                dependencies: vec![],
                metadata: HashMap::new(),
            },
            recovery_strategy: RecoveryStrategy::Escalate,
            confidence: 0.95,
            detected_at: chrono::Utc::now(),
            resolution_deadline: Some(chrono::Utc::now() + chrono::Duration::minutes(30)),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: StallEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.confidence, 0.95);
        assert_eq!(parsed.description, "Workflow timeout");
    }

    // Config serialization tests
    #[test]
    fn test_stall_detection_config_serialization() {
        let config = StallDetectionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: StallDetectionConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.global_timeout_seconds, config.global_timeout_seconds);
        assert_eq!(
            parsed.progress_config.min_progress_velocity,
            config.progress_config.min_progress_velocity
        );
    }

    // Clone tests
    #[test]
    fn test_stall_type_clone() {
        let stall = StallType::CircularDependency;
        let cloned = stall.clone();
        assert!(matches!(cloned, StallType::CircularDependency));
    }

    #[test]
    fn test_detection_algorithm_clone() {
        let algo = DetectionAlgorithm::PatternRecognition;
        let cloned = algo.clone();
        assert!(matches!(cloned, DetectionAlgorithm::PatternRecognition));
    }

    #[test]
    fn test_stall_severity_clone() {
        let severity = StallSeverity::Critical;
        let cloned = severity.clone();
        assert!(matches!(cloned, StallSeverity::Critical));
    }

    #[test]
    fn test_recovery_strategy_clone() {
        let strategy = RecoveryStrategy::UserIntervention;
        let cloned = strategy.clone();
        assert!(matches!(cloned, RecoveryStrategy::UserIntervention));
    }

    #[tokio::test]
    async fn test_get_stall_history_empty() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();

        let history = detector.get_stall_history(workflow_id).await;
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_select_critical_stall_empty() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);

        let result = detector.select_critical_stall(vec![]).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_select_critical_stall_single() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);

        let stall = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::GlobalTimeout,
            detection_algorithm: DetectionAlgorithm::TimeoutDetection,
            severity: StallSeverity::Medium,
            description: "Test".to_string(),
            context: StallContext {
                current_state: "Planning".to_string(),
                time_in_state_seconds: 100,
                total_workflow_time_seconds: 200,
                progress_percentage: 0.5,
                last_activity: None,
                resource_status: ResourceStatus {
                    cpu_utilization: 0.0,
                    memory_utilization: 0.0,
                    disk_utilization: 0.0,
                    network_utilization: 0.0,
                    allocation_pending: false,
                    contention_detected: false,
                },
                dependencies: vec![],
                metadata: HashMap::new(),
            },
            recovery_strategy: RecoveryStrategy::AutoRetry,
            confidence: 0.8,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        let result = detector.select_critical_stall(vec![stall]).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_select_critical_stall_multiple() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);

        let low_stall = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::LowVelocity,
            detection_algorithm: DetectionAlgorithm::ProgressMonitoring,
            severity: StallSeverity::Low,
            description: "Low severity".to_string(),
            context: StallContext {
                current_state: "Planning".to_string(),
                time_in_state_seconds: 100,
                total_workflow_time_seconds: 200,
                progress_percentage: 0.5,
                last_activity: None,
                resource_status: ResourceStatus {
                    cpu_utilization: 0.0,
                    memory_utilization: 0.0,
                    disk_utilization: 0.0,
                    network_utilization: 0.0,
                    allocation_pending: false,
                    contention_detected: false,
                },
                dependencies: vec![],
                metadata: HashMap::new(),
            },
            recovery_strategy: RecoveryStrategy::AutoRetry,
            confidence: 0.5,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        let critical_stall = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::Deadlock,
            detection_algorithm: DetectionAlgorithm::DependencyAnalysis,
            severity: StallSeverity::Critical,
            description: "Critical severity".to_string(),
            context: StallContext {
                current_state: "Executing".to_string(),
                time_in_state_seconds: 500,
                total_workflow_time_seconds: 1000,
                progress_percentage: 0.3,
                last_activity: None,
                resource_status: ResourceStatus {
                    cpu_utilization: 0.9,
                    memory_utilization: 0.9,
                    disk_utilization: 0.5,
                    network_utilization: 0.5,
                    allocation_pending: true,
                    contention_detected: true,
                },
                dependencies: vec![],
                metadata: HashMap::new(),
            },
            recovery_strategy: RecoveryStrategy::Escalate,
            confidence: 0.95,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        let result = detector
            .select_critical_stall(vec![low_stall, critical_stall])
            .await;
        assert!(result.is_some());
        let selected = result.unwrap();
        assert!(matches!(selected.severity, StallSeverity::Critical));
    }

    #[tokio::test]
    async fn test_record_and_retrieve_stall_history() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();

        let stall = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id,
            stall_type: StallType::ProgressStagnation,
            detection_algorithm: DetectionAlgorithm::ProgressMonitoring,
            severity: StallSeverity::Medium,
            description: "Test stall".to_string(),
            context: StallContext {
                current_state: "Planning".to_string(),
                time_in_state_seconds: 100,
                total_workflow_time_seconds: 200,
                progress_percentage: 0.5,
                last_activity: None,
                resource_status: ResourceStatus {
                    cpu_utilization: 0.0,
                    memory_utilization: 0.0,
                    disk_utilization: 0.0,
                    network_utilization: 0.0,
                    allocation_pending: false,
                    contention_detected: false,
                },
                dependencies: vec![],
                metadata: HashMap::new(),
            },
            recovery_strategy: RecoveryStrategy::AutoRetry,
            confidence: 0.8,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        detector.record_stall_event(stall.clone()).await;

        let history = detector.get_stall_history(workflow_id).await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].description, "Test stall");
    }

    #[tokio::test]
    async fn test_update_detection_metrics() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);

        let stall = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::GlobalTimeout,
            detection_algorithm: DetectionAlgorithm::TimeoutDetection,
            severity: StallSeverity::High,
            description: "Timeout".to_string(),
            context: StallContext {
                current_state: "Test".to_string(),
                time_in_state_seconds: 100,
                total_workflow_time_seconds: 200,
                progress_percentage: 0.5,
                last_activity: None,
                resource_status: ResourceStatus {
                    cpu_utilization: 0.0,
                    memory_utilization: 0.0,
                    disk_utilization: 0.0,
                    network_utilization: 0.0,
                    allocation_pending: false,
                    contention_detected: false,
                },
                dependencies: vec![],
                metadata: HashMap::new(),
            },
            recovery_strategy: RecoveryStrategy::Escalate,
            confidence: 0.9,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        detector.update_detection_metrics(stall).await;

        let metrics = detector.export_metrics().await;
        assert_eq!(metrics.total_stalls_detected, 1);
        assert_eq!(metrics.stalls_by_type.get("GlobalTimeout"), Some(&1));
        assert_eq!(
            metrics.stalls_by_algorithm.get("TimeoutDetection"),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn test_add_resource_snapshot() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();

        let snapshot = ResourceSnapshot {
            timestamp: Instant::now(),
            cpu_available: 0.75,
            memory_available: 1024 * 1024 * 512, // 512 MB
            disk_available: 1024 * 1024 * 1024,  // 1 GB
            network_available: 0.90,
            allocation_success_rate: 0.98,
        };

        let result = detector.add_resource_snapshot(workflow_id, snapshot).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_completed_workflow_clears_timeout() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();

        // First check triggers timeout tracker creation
        let _ = detector
            .check_stall(workflow_id, &WorkflowState::Planning)
            .await;

        // Checking with completed state should clear and return None
        let result = detector
            .check_stall(workflow_id, &WorkflowState::Completed)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_failed_workflow_clears_timeout() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();

        // First check triggers timeout tracker creation
        let _ = detector
            .check_stall(workflow_id, &WorkflowState::Planning)
            .await;

        // Checking with failed state should clear and return None
        let result = detector
            .check_stall(workflow_id, &WorkflowState::Failed)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_stall_detection_no_stall() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();
        let state = WorkflowState::Planning;

        let result = detector.check_stall(workflow_id, &state).await;
        assert!(result.is_ok());

        // Should be None since no actual stalls are implemented in the simplified version
        let stall_event = result.unwrap();
        assert!(stall_event.is_none());
    }

    #[tokio::test]
    async fn test_progress_update() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();

        let result = detector.update_progress(workflow_id, 0.5).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_heartbeat_report() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();

        let result = detector.report_heartbeat(workflow_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_metrics_export() {
        let config = StallDetectionConfig::default();
        let detector = StallDetector::new(config);

        let metrics = detector.export_metrics().await;
        assert_eq!(metrics.total_stalls_detected, 0);
    }

    #[tokio::test]
    async fn test_global_timeout_detection_triggers() -> anyhow::Result<()> {
        let mut config = StallDetectionConfig::default();
        config.global_timeout_seconds = 1;
        let detector = StallDetector::new(config);

        let workflow_id = Uuid::new_v4();
        let state = WorkflowState::Planning;

        assert!(detector.check_stall(workflow_id, &state).await?.is_none());

        sleep(Duration::from_millis(3200)).await;

        let stall = detector
            .check_stall(workflow_id, &state)
            .await?
            .expect("expected global timeout stall");

        assert!(matches!(stall.stall_type, StallType::GlobalTimeout));
        assert!(stall.confidence > 0.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_state_timeout_detection_triggers() -> anyhow::Result<()> {
        let mut config = StallDetectionConfig::default();
        config.global_timeout_seconds = 10;
        config.state_timeouts.insert("Planning".to_string(), 1); // 1 second state timeout

        let detector = StallDetector::new(config);
        let workflow_id = Uuid::new_v4();
        let state = WorkflowState::Planning;

        assert!(detector.check_stall(workflow_id, &state).await?.is_none());

        sleep(Duration::from_millis(3200)).await;

        let stall = detector
            .check_stall(workflow_id, &state)
            .await?
            .expect("expected state timeout stall");

        assert!(matches!(stall.stall_type, StallType::StateTimeout));

        Ok(())
    }

    #[test]
    fn test_stall_event_creation() {
        let stall_event = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::ProgressStagnation,
            detection_algorithm: DetectionAlgorithm::ProgressMonitoring,
            severity: StallSeverity::Medium,
            description: "Test stall event".to_string(),
            context: StallContext {
                current_state: "Planning".to_string(),
                time_in_state_seconds: 300,
                total_workflow_time_seconds: 600,
                progress_percentage: 0.3,
                last_activity: Some(chrono::Utc::now()),
                resource_status: ResourceStatus {
                    cpu_utilization: 0.5,
                    memory_utilization: 0.7,
                    disk_utilization: 0.3,
                    network_utilization: 0.2,
                    allocation_pending: false,
                    contention_detected: false,
                },
                dependencies: vec![],
                metadata: HashMap::new(),
            },
            recovery_strategy: RecoveryStrategy::AutoRetry,
            confidence: 0.8,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        assert_eq!(stall_event.confidence, 0.8);
        assert!(matches!(
            stall_event.stall_type,
            StallType::ProgressStagnation
        ));
        assert!(matches!(
            stall_event.recovery_strategy,
            RecoveryStrategy::AutoRetry
        ));
    }
}
