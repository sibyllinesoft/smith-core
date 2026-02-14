/*!
# Menu System - User Intervention Interface

The Menu System provides sophisticated user intervention capabilities for complex workflow decisions:

- **Interactive Menus**: Dynamic menu generation based on workflow context
- **Contextual Options**: Smart option filtering based on current situation
- **Decision Recording**: Comprehensive logging of user decisions and rationale
- **Escalation Workflows**: Structured escalation paths for complex decisions
- **Approval Workflows**: Multi-stage approval processes for critical operations

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                      Menu System                               │
├─────────────────────────────────────────────────────────────────┤
│  Menu Generation Engine                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Context    │  │   Option    │  │  Dynamic    │           │
│  │  Analysis   │  │ Generation  │  │  Filtering  │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  User Interaction Framework                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ Interactive │  │  Decision   │  │  Approval   │           │
│  │   Prompts   │  │  Capture    │  │  Workflow   │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Decision Recording & Analytics                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Decision   │  │  Pattern    │  │ Learning    │           │
│  │  History    │  │ Analysis    │  │  System     │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Escalation & Notification                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ Escalation  │  │ Notification│  │  Response   │           │
│  │   Routes    │  │   System    │  │  Tracking   │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Intervention Types

- **Decision Points**: Choose between multiple valid approaches
- **Failure Recovery**: Select recovery strategy for failed operations
- **Resource Conflicts**: Resolve resource allocation conflicts
- **Security Approvals**: Approve high-risk operations
- **Strategy Adjustments**: Modify execution strategy mid-workflow

## Usage

```text
let menu_system = MenuSystem::new();
let intervention_result = menu_system.request_intervention(
    workflow_id,
    &stall_event
).await?;

match intervention_result.decision {
    UserDecision::Continue => resume_workflow().await?,
    UserDecision::Retry => retry_operation().await?,
    UserDecision::Escalate => escalate_to_admin().await?,
    UserDecision::Cancel => cancel_workflow().await?,
}
```
*/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::planner::stall_detection::StallEvent;

/// Menu system for user intervention
#[derive(Clone)]
pub struct MenuSystem {
    menu_generator: Arc<MenuGenerator>,
    interaction_handler: Arc<InteractionHandler>,
    decision_recorder: Arc<DecisionRecorder>,
    escalation_manager: Arc<EscalationManager>,
    notification_system: Arc<NotificationSystem>,
    active_interventions: Arc<RwLock<HashMap<Uuid, ActiveIntervention>>>,
    intervention_history: Arc<RwLock<Vec<InterventionEvent>>>,
}

/// Menu generation engine
pub(crate) struct MenuGenerator {
    pub(crate) context_analyzer: Arc<ContextAnalyzer>,
    pub(crate) option_generator: Arc<OptionGenerator>,
    pub(crate) menu_templates: Arc<RwLock<HashMap<String, MenuTemplate>>>,
    pub(crate) personalization_engine: Arc<PersonalizationEngine>,
}

/// User interaction handler
pub(crate) struct InteractionHandler {
    pub(crate) interaction_channels: Arc<RwLock<HashMap<Uuid, InteractionChannel>>>,
    pub(crate) response_validators: Arc<RwLock<Vec<ResponseValidator>>>,
    pub(crate) timeout_manager: Arc<TimeoutManager>,
}

/// Decision recording system
pub(crate) struct DecisionRecorder {
    pub(crate) decision_history: Arc<RwLock<Vec<UserDecision>>>,
    pub(crate) pattern_analyzer: Arc<DecisionPatternAnalyzer>,
    pub(crate) learning_system: Arc<LearningSystem>,
}

/// Escalation management
pub(crate) struct EscalationManager {
    pub(crate) escalation_paths: Arc<RwLock<HashMap<String, EscalationPath>>>,
    pub(crate) approval_workflows: Arc<RwLock<HashMap<String, ApprovalWorkflow>>>,
    pub(crate) stakeholder_registry: Arc<StakeholderRegistry>,
}

/// Notification system
pub(crate) struct NotificationSystem {
    pub(crate) notification_channels: Arc<RwLock<Vec<NotificationChannel>>>,
    pub(crate) delivery_tracker: Arc<DeliveryTracker>,
    pub(crate) preference_manager: Arc<PreferenceManager>,
}

/// User intervention option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInterventionOption {
    pub option_id: Uuid,
    pub title: String,
    pub description: String,
    pub option_type: OptionType,
    pub risk_level: RiskLevel,
    pub estimated_impact: EstimatedImpact,
    pub prerequisites: Vec<String>,
    pub consequences: Vec<String>,
    pub recommended: bool,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Intervention result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterventionResult {
    pub intervention_id: Uuid,
    pub workflow_id: Uuid,
    pub decision: UserDecision,
    pub selected_options: Vec<Uuid>,
    pub user_feedback: Option<String>,
    pub continue_execution: bool,
    pub decision_confidence: f32,
    pub response_time_seconds: u64,
    pub decided_at: chrono::DateTime<chrono::Utc>,
}

/// User decision types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserDecision {
    /// Continue with current approach
    Continue,
    /// Retry the failed operation
    Retry,
    /// Skip the problematic step
    Skip,
    /// Use alternative approach
    Alternative { approach: String },
    /// Escalate to higher authority
    Escalate { reason: String },
    /// Cancel the entire workflow
    Cancel { reason: String },
    /// Modify parameters and continue
    Modify {
        parameters: HashMap<String, serde_json::Value>,
    },
    /// Manual intervention required
    ManualIntervention { instructions: String },
}

/// Option types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptionType {
    /// Continue current operation
    Continue,
    /// Retry with same parameters
    Retry,
    /// Retry with different parameters
    RetryModified,
    /// Skip current step
    Skip,
    /// Use alternative implementation
    Alternative,
    /// Escalate decision
    Escalate,
    /// Cancel workflow
    Cancel,
    /// Manual override
    ManualOverride,
    /// Resource reallocation
    ResourceReallocation,
    /// Security approval
    SecurityApproval,
}

/// Risk levels for options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Estimated impact of intervention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimatedImpact {
    pub time_impact_minutes: i32,
    pub resource_impact: f32,
    pub success_probability: f32,
    pub side_effects: Vec<String>,
    pub rollback_difficulty: RollbackDifficulty,
}

/// Rollback difficulty
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackDifficulty {
    Easy,
    Medium,
    Hard,
    Impossible,
}

/// Active intervention tracking
#[derive(Debug)]
struct ActiveIntervention {
    intervention_id: Uuid,
    workflow_id: Uuid,
    started_at: chrono::DateTime<chrono::Utc>,
    timeout_at: chrono::DateTime<chrono::Utc>,
    intervention_type: InterventionType,
    context: InterventionContext,
    response_channel: Option<oneshot::Sender<InterventionResult>>,
    escalation_triggered: bool,
}

/// Intervention types
#[derive(Debug, Clone)]
enum InterventionType {
    StallResolution,
    DecisionPoint,
    FailureRecovery,
    ResourceConflict,
    SecurityApproval,
    StrategyAdjustment,
}

/// Intervention context
#[derive(Debug, Clone)]
pub(crate) struct InterventionContext {
    workflow_state: String,
    problem_description: String,
    available_options: Vec<UserInterventionOption>,
    time_pressure: TimePressure,
    stakeholders: Vec<String>,
    business_impact: BusinessImpact,
}

/// Time pressure levels
#[derive(Debug, Clone)]
enum TimePressure {
    Low,
    Medium,
    High,
    Critical,
}

/// Business impact assessment
#[derive(Debug, Clone)]
struct BusinessImpact {
    financial_impact: f32,
    customer_impact: f32,
    operational_impact: f32,
    reputation_impact: f32,
    compliance_impact: f32,
}

/// Intervention event for history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterventionEvent {
    pub event_id: Uuid,
    pub workflow_id: Uuid,
    pub intervention_type: String,
    pub trigger_reason: String,
    pub options_presented: Vec<UserInterventionOption>,
    pub user_decision: UserDecision,
    pub outcome: InterventionOutcome,
    pub response_time_seconds: u64,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

/// Intervention outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterventionOutcome {
    Resolved,
    Escalated,
    Timeout,
    Cancelled,
    Failed,
}

/// Menu template
#[derive(Debug, Clone)]
pub(crate) struct MenuTemplate {
    template_id: Uuid,
    template_name: String,
    trigger_conditions: Vec<String>,
    option_templates: Vec<OptionTemplate>,
    personalization_rules: Vec<PersonalizationRule>,
}

/// Option template
#[derive(Debug, Clone)]
struct OptionTemplate {
    option_type: OptionType,
    title_template: String,
    description_template: String,
    condition_rules: Vec<String>,
    risk_assessment: RiskAssessmentRule,
    impact_calculation: ImpactCalculationRule,
}

/// Personalization rule
#[derive(Debug, Clone)]
struct PersonalizationRule {
    rule_name: String,
    user_conditions: Vec<String>,
    modifications: Vec<String>,
    priority_adjustments: HashMap<String, f32>,
}

/// Risk assessment rule
#[derive(Debug, Clone)]
struct RiskAssessmentRule {
    factors: Vec<RiskFactor>,
    calculation_method: String,
    thresholds: HashMap<String, f32>,
}

/// Risk factor
#[derive(Debug, Clone)]
struct RiskFactor {
    factor_name: String,
    weight: f32,
    calculation: String,
}

/// Impact calculation rule
#[derive(Debug, Clone)]
struct ImpactCalculationRule {
    time_calculation: String,
    resource_calculation: String,
    success_probability_calculation: String,
    side_effect_analysis: Vec<String>,
}

/// Context analyzer
pub(crate) struct ContextAnalyzer {
    pub(crate) analysis_rules: Arc<RwLock<Vec<AnalysisRule>>>,
    pub(crate) context_cache: Arc<RwLock<HashMap<String, AnalysisResult>>>,
}

/// Analysis rule
#[derive(Debug, Clone)]
pub(crate) struct AnalysisRule {
    rule_id: Uuid,
    rule_name: String,
    conditions: Vec<String>,
    analysis_functions: Vec<String>,
    weight: f32,
}

/// Analysis result
#[derive(Debug, Clone)]
pub(crate) struct AnalysisResult {
    context_type: String,
    complexity_score: f32,
    urgency_score: f32,
    risk_score: f32,
    stakeholder_impact: f32,
    recommendations: Vec<String>,
}

/// Option generator
pub(crate) struct OptionGenerator {
    pub(crate) generation_strategies: Arc<RwLock<Vec<GenerationStrategy>>>,
    pub(crate) option_cache: Arc<RwLock<HashMap<String, Vec<UserInterventionOption>>>>,
}

/// Generation strategy
#[derive(Debug, Clone)]
pub(crate) struct GenerationStrategy {
    strategy_name: String,
    applicability_conditions: Vec<String>,
    option_generators: Vec<OptionGeneratorFunction>,
    filtering_rules: Vec<FilteringRule>,
}

/// Option generator function
#[derive(Debug, Clone)]
pub(crate) struct OptionGeneratorFunction {
    function_name: String,
    parameters: HashMap<String, serde_json::Value>,
    output_template: OptionTemplate,
}

/// Filtering rule
#[derive(Debug, Clone)]
pub(crate) struct FilteringRule {
    rule_name: String,
    conditions: Vec<String>,
    action: FilteringAction,
}

/// Filtering action
#[derive(Debug, Clone)]
pub(crate) enum FilteringAction {
    Include,
    Exclude,
    Modify,
    Prioritize,
}

/// Personalization engine
pub(crate) struct PersonalizationEngine {
    pub(crate) user_profiles: Arc<RwLock<HashMap<String, UserProfile>>>,
    pub(crate) preference_models: Arc<RwLock<HashMap<String, PreferenceModel>>>,
    pub(crate) adaptation_rules: Arc<RwLock<Vec<AdaptationRule>>>,
}

/// User profile
#[derive(Debug, Clone)]
pub(crate) struct UserProfile {
    user_id: String,
    experience_level: ExperienceLevel,
    role: String,
    preferences: UserPreferences,
    decision_history: Vec<DecisionHistoryEntry>,
    performance_metrics: UserPerformanceMetrics,
}

/// Experience level
#[derive(Debug, Clone)]
pub(crate) enum ExperienceLevel {
    Novice,
    Intermediate,
    Expert,
    Master,
}

/// User preferences
#[derive(Debug, Clone)]
pub(crate) struct UserPreferences {
    preferred_interaction_style: InteractionStyle,
    risk_tolerance: f32,
    detail_level: DetailLevel,
    notification_preferences: NotificationPreferences,
    timeout_preferences: TimeoutPreferences,
}

/// Interaction style
#[derive(Debug, Clone)]
pub(crate) enum InteractionStyle {
    Minimal,
    Standard,
    Detailed,
    Guided,
}

/// Detail level
#[derive(Debug, Clone)]
pub(crate) enum DetailLevel {
    Summary,
    Standard,
    Detailed,
    Comprehensive,
}

/// Notification preferences
#[derive(Debug, Clone)]
pub(crate) struct NotificationPreferences {
    channels: Vec<String>,
    urgency_thresholds: HashMap<String, f32>,
    quiet_hours: Option<QuietHours>,
}

/// Quiet hours
#[derive(Debug, Clone)]
pub(crate) struct QuietHours {
    start_hour: u8,
    end_hour: u8,
    timezone: String,
    exceptions: Vec<String>,
}

/// Timeout preferences
#[derive(Debug, Clone)]
pub(crate) struct TimeoutPreferences {
    default_timeout_minutes: u32,
    escalation_timeout_minutes: u32,
    auto_escalate: bool,
}

/// Decision history entry
#[derive(Debug, Clone)]
pub(crate) struct DecisionHistoryEntry {
    decision_id: Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
    context_type: String,
    decision: UserDecision,
    outcome: InterventionOutcome,
    confidence: f32,
    response_time_seconds: u64,
}

/// User performance metrics
#[derive(Debug, Clone)]
struct UserPerformanceMetrics {
    average_response_time_seconds: f64,
    decision_accuracy: f32,
    escalation_rate: f32,
    satisfaction_score: f32,
    expertise_growth_rate: f32,
}

/// Preference model
#[derive(Debug, Clone)]
pub(crate) struct PreferenceModel {
    model_id: Uuid,
    user_id: String,
    model_type: String,
    parameters: HashMap<String, f32>,
    accuracy_score: f32,
    last_updated: chrono::DateTime<chrono::Utc>,
}

/// Adaptation rule
#[derive(Debug, Clone)]
pub(crate) struct AdaptationRule {
    rule_id: Uuid,
    trigger_conditions: Vec<String>,
    adaptations: Vec<Adaptation>,
    learning_weight: f32,
}

/// Adaptation
#[derive(Debug, Clone)]
struct Adaptation {
    adaptation_type: AdaptationType,
    parameters: HashMap<String, serde_json::Value>,
    confidence: f32,
}

/// Adaptation type
#[derive(Debug, Clone)]
enum AdaptationType {
    OptionReordering,
    DetailAdjustment,
    TimeoutModification,
    ChannelSelection,
    EscalationThreshold,
}

/// Interaction channel
#[derive(Debug, Clone)]
pub(crate) struct InteractionChannel {
    channel_id: Uuid,
    channel_type: ChannelType,
    user_id: String,
    active: bool,
    response_handlers: Vec<ResponseHandler>,
}

/// Channel type
#[derive(Debug, Clone)]
enum ChannelType {
    WebInterface,
    MobileApp,
    Email,
    Slack,
    Teams,
    Webhook,
    Terminal,
}

/// Response handler
#[derive(Debug, Clone)]
struct ResponseHandler {
    handler_id: Uuid,
    intervention_id: Uuid,
    timeout: Duration,
    validation_rules: Vec<ValidationRule>,
}

/// Response validator
#[derive(Debug, Clone)]
pub(crate) struct ResponseValidator {
    validator_id: Uuid,
    validation_rules: Vec<ValidationRule>,
    error_messages: HashMap<String, String>,
}

/// Validation rule
#[derive(Debug, Clone)]
struct ValidationRule {
    rule_name: String,
    rule_type: ValidationType,
    parameters: HashMap<String, serde_json::Value>,
    error_message: String,
}

/// Validation type
#[derive(Debug, Clone)]
enum ValidationType {
    Required,
    Format,
    Range,
    Dependencies,
    Authorization,
    BusinessLogic,
}

/// Timeout manager
pub(crate) struct TimeoutManager {
    pub(crate) timeout_policies: Arc<RwLock<HashMap<String, TimeoutPolicy>>>,
    pub(crate) active_timeouts: Arc<RwLock<HashMap<Uuid, TimeoutTracker>>>,
}

/// Timeout policy
#[derive(Debug, Clone)]
pub(crate) struct TimeoutPolicy {
    policy_name: String,
    default_timeout: Duration,
    escalation_timeouts: Vec<Duration>,
    timeout_actions: Vec<TimeoutAction>,
}

/// Timeout action
#[derive(Debug, Clone)]
pub(crate) struct TimeoutAction {
    action_type: TimeoutActionType,
    parameters: HashMap<String, serde_json::Value>,
    conditions: Vec<String>,
}

/// Timeout action type
#[derive(Debug, Clone)]
pub(crate) enum TimeoutActionType {
    Escalate,
    UseDefault,
    Cancel,
    Notify,
    Extend,
}

/// Timeout tracker
#[derive(Debug, Clone)]
pub(crate) struct TimeoutTracker {
    intervention_id: Uuid,
    started_at: chrono::DateTime<chrono::Utc>,
    timeout_at: chrono::DateTime<chrono::Utc>,
    warnings_sent: Vec<chrono::DateTime<chrono::Utc>>,
    escalated: bool,
}

/// Decision pattern analyzer
pub(crate) struct DecisionPatternAnalyzer {
    pub(crate) pattern_database: Arc<RwLock<Vec<DecisionPattern>>>,
    pub(crate) analysis_algorithms: Arc<RwLock<Vec<AnalysisAlgorithm>>>,
}

/// Decision pattern
#[derive(Debug, Clone)]
pub(crate) struct DecisionPattern {
    pub(crate) pattern_id: Uuid,
    pub(crate) pattern_name: String,
    pub(crate) context_signature: ContextSignature,
    pub(crate) decision_sequence: Vec<UserDecision>,
    pub(crate) success_rate: f32,
    pub(crate) confidence: f32,
}

/// Context signature
#[derive(Debug, Clone)]
struct ContextSignature {
    workflow_type: String,
    problem_type: String,
    risk_level: RiskLevel,
    time_pressure: TimePressure,
    stakeholder_types: Vec<String>,
}

/// Analysis algorithm
#[derive(Debug, Clone)]
pub(crate) struct AnalysisAlgorithm {
    pub(crate) algorithm_name: String,
    pub(crate) algorithm_type: AnalysisType,
    pub(crate) parameters: HashMap<String, f32>,
    pub(crate) accuracy_metrics: AccuracyMetrics,
}

/// Analysis type
#[derive(Debug, Clone)]
pub(crate) enum AnalysisType {
    Clustering,
    Classification,
    Regression,
    SequenceAnalysis,
    AnomalyDetection,
}

/// Accuracy metrics
#[derive(Debug, Clone)]
pub(crate) struct AccuracyMetrics {
    pub(crate) precision: f32,
    pub(crate) recall: f32,
    pub(crate) f1_score: f32,
    pub(crate) confidence_interval: (f32, f32),
}

/// Learning system
pub(crate) struct LearningSystem {
    pub(crate) learning_models: Arc<RwLock<HashMap<String, LearningModel>>>,
    pub(crate) feedback_processor: Arc<FeedbackProcessor>,
    pub(crate) model_updater: Arc<ModelUpdater>,
}

/// Learning model
#[derive(Debug, Clone)]
pub(crate) struct LearningModel {
    pub(crate) model_id: Uuid,
    pub(crate) model_name: String,
    pub(crate) model_type: LearningModelType,
    pub(crate) training_data: Vec<TrainingExample>,
    pub(crate) performance_metrics: ModelPerformanceMetrics,
}

/// Learning model type
#[derive(Debug, Clone)]
pub(crate) enum LearningModelType {
    DecisionTree,
    RandomForest,
    NeuralNetwork,
    ReinforcementLearning,
    Bayesian,
}

/// Training example
#[derive(Debug, Clone)]
pub(crate) struct TrainingExample {
    pub(crate) example_id: Uuid,
    pub(crate) features: HashMap<String, f32>,
    pub(crate) label: String,
    pub(crate) weight: f32,
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
}

/// Model performance metrics
#[derive(Debug, Clone)]
pub(crate) struct ModelPerformanceMetrics {
    pub(crate) accuracy: f32,
    pub(crate) precision: f32,
    pub(crate) recall: f32,
    pub(crate) f1_score: f32,
    pub(crate) training_loss: f32,
    pub(crate) validation_loss: f32,
}

/// Feedback processor
pub(crate) struct FeedbackProcessor {
    pub(crate) feedback_queue: Arc<RwLock<Vec<UserFeedback>>>,
    pub(crate) processing_rules: Arc<RwLock<Vec<ProcessingRule>>>,
}

/// User feedback
#[derive(Debug, Clone)]
pub(crate) struct UserFeedback {
    pub(crate) feedback_id: Uuid,
    pub(crate) intervention_id: Uuid,
    pub(crate) user_id: String,
    pub(crate) feedback_type: FeedbackType,
    pub(crate) content: String,
    pub(crate) rating: Option<f32>,
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
}

/// Feedback type
#[derive(Debug, Clone)]
pub(crate) enum FeedbackType {
    Satisfaction,
    Difficulty,
    Suggestion,
    Complaint,
    Praise,
}

/// Processing rule
#[derive(Debug, Clone)]
pub(crate) struct ProcessingRule {
    rule_name: String,
    trigger_conditions: Vec<String>,
    processing_actions: Vec<ProcessingAction>,
}

/// Processing action
#[derive(Debug, Clone)]
struct ProcessingAction {
    action_type: ProcessingActionType,
    parameters: HashMap<String, serde_json::Value>,
}

/// Processing action type
#[derive(Debug, Clone)]
enum ProcessingActionType {
    UpdateModel,
    AdjustWeights,
    CreateTrainingExample,
    TriggerRetraining,
    GenerateInsight,
}

/// Model updater
pub(crate) struct ModelUpdater {
    pub(crate) update_strategies: Arc<RwLock<Vec<UpdateStrategy>>>,
    pub(crate) update_scheduler: Arc<UpdateScheduler>,
}

/// Update strategy
#[derive(Debug, Clone)]
pub(crate) struct UpdateStrategy {
    strategy_name: String,
    trigger_conditions: Vec<String>,
    update_algorithm: String,
    validation_criteria: Vec<String>,
}

/// Update scheduler
pub(crate) struct UpdateScheduler {
    pub(crate) scheduled_updates: Arc<RwLock<Vec<ScheduledUpdate>>>,
    pub(crate) update_policies: Arc<RwLock<HashMap<String, UpdatePolicy>>>,
}

/// Scheduled update
#[derive(Debug, Clone)]
pub(crate) struct ScheduledUpdate {
    update_id: Uuid,
    model_id: Uuid,
    scheduled_time: chrono::DateTime<chrono::Utc>,
    update_type: UpdateType,
    priority: UpdatePriority,
}

/// Update type
#[derive(Debug, Clone)]
enum UpdateType {
    Incremental,
    Batch,
    FullRetrain,
    ParameterTuning,
}

/// Update priority
#[derive(Debug, Clone)]
enum UpdatePriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Update policy
#[derive(Debug, Clone)]
pub(crate) struct UpdatePolicy {
    policy_name: String,
    update_frequency: Duration,
    minimum_data_points: usize,
    performance_threshold: f32,
    rollback_criteria: Vec<String>,
}

/// Escalation path
#[derive(Debug, Clone)]
pub(crate) struct EscalationPath {
    path_id: Uuid,
    path_name: String,
    trigger_conditions: Vec<String>,
    escalation_levels: Vec<EscalationLevel>,
    notification_templates: HashMap<String, NotificationTemplate>,
}

/// Escalation level
#[derive(Debug, Clone)]
pub(crate) struct EscalationLevel {
    level_number: u32,
    level_name: String,
    timeout: Duration,
    stakeholders: Vec<String>,
    required_approvals: u32,
    escalation_criteria: Vec<String>,
}

/// Approval workflow
#[derive(Debug, Clone)]
pub(crate) struct ApprovalWorkflow {
    workflow_id: Uuid,
    workflow_name: String,
    approval_stages: Vec<ApprovalStage>,
    parallel_approvals: bool,
    consensus_required: bool,
}

/// Approval stage
#[derive(Debug, Clone)]
pub(crate) struct ApprovalStage {
    stage_id: Uuid,
    stage_name: String,
    approvers: Vec<String>,
    required_approvals: u32,
    timeout: Duration,
    approval_criteria: Vec<String>,
}

/// Stakeholder registry
pub(crate) struct StakeholderRegistry {
    pub(crate) stakeholders: Arc<RwLock<HashMap<String, Stakeholder>>>,
    pub(crate) role_definitions: Arc<RwLock<HashMap<String, RoleDefinition>>>,
}

/// Stakeholder
#[derive(Debug, Clone)]
pub(crate) struct Stakeholder {
    stakeholder_id: String,
    name: String,
    role: String,
    contact_info: ContactInfo,
    availability: Availability,
    expertise_areas: Vec<String>,
    authority_level: AuthorityLevel,
}

/// Contact information
#[derive(Debug, Clone)]
pub(crate) struct ContactInfo {
    email: Option<String>,
    phone: Option<String>,
    slack_id: Option<String>,
    teams_id: Option<String>,
    preferred_channel: String,
}

/// Availability
#[derive(Debug, Clone)]
pub(crate) struct Availability {
    timezone: String,
    working_hours: WorkingHours,
    on_call_schedule: Option<OnCallSchedule>,
    vacation_dates: Vec<VacationPeriod>,
}

/// Working hours
#[derive(Debug, Clone)]
struct WorkingHours {
    monday: Option<DayHours>,
    tuesday: Option<DayHours>,
    wednesday: Option<DayHours>,
    thursday: Option<DayHours>,
    friday: Option<DayHours>,
    saturday: Option<DayHours>,
    sunday: Option<DayHours>,
}

/// Day hours
#[derive(Debug, Clone)]
struct DayHours {
    start_hour: u8,
    end_hour: u8,
    break_periods: Vec<BreakPeriod>,
}

/// Break period
#[derive(Debug, Clone)]
struct BreakPeriod {
    start_hour: u8,
    start_minute: u8,
    end_hour: u8,
    end_minute: u8,
}

/// On-call schedule
#[derive(Debug, Clone)]
struct OnCallSchedule {
    rotation_type: RotationType,
    schedule_entries: Vec<OnCallEntry>,
}

/// Rotation type
#[derive(Debug, Clone)]
enum RotationType {
    Weekly,
    Daily,
    Custom,
}

/// On-call entry
#[derive(Debug, Clone)]
struct OnCallEntry {
    start_date: chrono::NaiveDate,
    end_date: chrono::NaiveDate,
    primary: bool,
    escalation_order: u32,
}

/// Vacation period
#[derive(Debug, Clone)]
struct VacationPeriod {
    start_date: chrono::NaiveDate,
    end_date: chrono::NaiveDate,
    vacation_type: VacationType,
}

/// Vacation type
#[derive(Debug, Clone)]
enum VacationType {
    Vacation,
    SickLeave,
    PersonalTime,
    Training,
    Conference,
}

/// Authority level
#[derive(Debug, Clone)]
pub(crate) enum AuthorityLevel {
    Viewer,
    Operator,
    Approver,
    Admin,
    Executive,
}

/// Role definition
#[derive(Debug, Clone)]
pub(crate) struct RoleDefinition {
    role_name: String,
    permissions: Vec<String>,
    responsibilities: Vec<String>,
    escalation_authority: EscalationAuthority,
    approval_limits: ApprovalLimits,
}

/// Escalation authority
#[derive(Debug, Clone)]
struct EscalationAuthority {
    can_escalate: bool,
    escalation_levels: Vec<String>,
    auto_escalation_rules: Vec<String>,
}

/// Approval limits
#[derive(Debug, Clone)]
struct ApprovalLimits {
    financial_limit: Option<f32>,
    risk_level_limit: Option<RiskLevel>,
    time_limit: Option<Duration>,
    scope_limits: Vec<String>,
}

/// Notification channel
#[derive(Debug, Clone)]
pub(crate) struct NotificationChannel {
    channel_id: Uuid,
    channel_type: ChannelType,
    configuration: ChannelConfiguration,
    delivery_guarantees: DeliveryGuarantees,
    rate_limits: RateLimits,
}

/// Channel configuration
#[derive(Debug, Clone)]
struct ChannelConfiguration {
    endpoint: String,
    authentication: AuthenticationConfig,
    message_format: MessageFormat,
    retry_policy: RetryPolicy,
}

/// Authentication config
#[derive(Debug, Clone)]
struct AuthenticationConfig {
    auth_type: AuthenticationType,
    credentials: HashMap<String, String>,
    token_refresh: Option<TokenRefreshConfig>,
}

/// Authentication type
#[derive(Debug, Clone)]
enum AuthenticationType {
    None,
    ApiKey,
    OAuth2,
    BasicAuth,
    Custom,
}

/// Token refresh config
#[derive(Debug, Clone)]
struct TokenRefreshConfig {
    refresh_endpoint: String,
    refresh_interval: Duration,
    refresh_threshold: Duration,
}

/// Message format
#[derive(Debug, Clone)]
enum MessageFormat {
    Plain,
    Html,
    Markdown,
    Json,
    Custom(String),
}

/// Retry policy
#[derive(Debug, Clone)]
struct RetryPolicy {
    max_retries: u32,
    initial_delay: Duration,
    max_delay: Duration,
    backoff_multiplier: f32,
}

/// Delivery guarantees
#[derive(Debug, Clone)]
struct DeliveryGuarantees {
    guarantee_level: GuaranteeLevel,
    acknowledgment_required: bool,
    timeout: Duration,
    duplicate_detection: bool,
}

/// Guarantee level
#[derive(Debug, Clone)]
enum GuaranteeLevel {
    BestEffort,
    AtLeastOnce,
    ExactlyOnce,
}

/// Rate limits
#[derive(Debug, Clone)]
struct RateLimits {
    messages_per_minute: u32,
    messages_per_hour: u32,
    burst_limit: u32,
    backoff_strategy: BackoffStrategy,
}

/// Backoff strategy
#[derive(Debug, Clone)]
enum BackoffStrategy {
    Linear,
    Exponential,
    Fibonacci,
    Custom(String),
}

/// Delivery tracker
pub(crate) struct DeliveryTracker {
    pub(crate) delivery_records: Arc<RwLock<HashMap<Uuid, DeliveryRecord>>>,
    pub(crate) delivery_metrics: Arc<RwLock<DeliveryMetrics>>,
}

/// Delivery record
#[derive(Debug, Clone)]
pub(crate) struct DeliveryRecord {
    record_id: Uuid,
    message_id: Uuid,
    channel_id: Uuid,
    recipient: String,
    sent_at: chrono::DateTime<chrono::Utc>,
    delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    delivery_status: DeliveryStatus,
    retry_count: u32,
}

/// Delivery status
#[derive(Debug, Clone)]
enum DeliveryStatus {
    Pending,
    Sent,
    Delivered,
    Acknowledged,
    Failed,
    Cancelled,
}

/// Delivery metrics
#[derive(Debug, Clone)]
pub(crate) struct DeliveryMetrics {
    pub(crate) total_messages: u64,
    pub(crate) successful_deliveries: u64,
    pub(crate) failed_deliveries: u64,
    pub(crate) average_delivery_time: Duration,
    pub(crate) delivery_rate_by_channel: HashMap<String, f32>,
}

/// Preference manager
pub(crate) struct PreferenceManager {
    pub(crate) user_preferences: Arc<RwLock<HashMap<String, NotificationPreferences>>>,
    pub(crate) global_preferences: Arc<RwLock<GlobalNotificationPreferences>>,
}

/// Global notification preferences
#[derive(Debug, Clone)]
pub(crate) struct GlobalNotificationPreferences {
    pub(crate) default_channels: Vec<String>,
    pub(crate) emergency_channels: Vec<String>,
    pub(crate) quiet_hours_policy: QuietHoursPolicy,
    pub(crate) escalation_preferences: EscalationPreferences,
}

/// Quiet hours policy
#[derive(Debug, Clone)]
pub(crate) struct QuietHoursPolicy {
    pub(crate) enforce_quiet_hours: bool,
    pub(crate) emergency_override: bool,
    pub(crate) time_zones: Vec<String>,
    pub(crate) exceptions: Vec<String>,
}

/// Escalation preferences
#[derive(Debug, Clone)]
pub(crate) struct EscalationPreferences {
    pub(crate) auto_escalate: bool,
    pub(crate) escalation_delay: Duration,
    pub(crate) escalation_channels: Vec<String>,
    pub(crate) notification_frequency: Duration,
}

/// Notification template
#[derive(Debug, Clone)]
struct NotificationTemplate {
    template_id: Uuid,
    template_name: String,
    subject_template: String,
    body_template: String,
    variables: Vec<TemplateVariable>,
    localization: HashMap<String, LocalizedTemplate>,
}

/// Template variable
#[derive(Debug, Clone)]
struct TemplateVariable {
    variable_name: String,
    variable_type: VariableType,
    default_value: Option<String>,
    required: bool,
}

/// Variable type
#[derive(Debug, Clone)]
enum VariableType {
    String,
    Number,
    Date,
    Boolean,
    Object,
}

/// Localized template
#[derive(Debug, Clone)]
struct LocalizedTemplate {
    language_code: String,
    subject: String,
    body: String,
    formatting_rules: Vec<FormattingRule>,
}

/// Formatting rule
#[derive(Debug, Clone)]
struct FormattingRule {
    rule_name: String,
    pattern: String,
    replacement: String,
    conditions: Vec<String>,
}

impl MenuSystem {
    /// Create new menu system
    pub fn new() -> Self {
        info!("Initializing Menu System");

        let menu_generator = Arc::new(MenuGenerator::new());
        let interaction_handler = Arc::new(InteractionHandler::new());
        let decision_recorder = Arc::new(DecisionRecorder::new());
        let escalation_manager = Arc::new(EscalationManager::new());
        let notification_system = Arc::new(NotificationSystem::new());
        let active_interventions = Arc::new(RwLock::new(HashMap::new()));
        let intervention_history = Arc::new(RwLock::new(Vec::new()));

        info!("Menu System initialized successfully");

        Self {
            menu_generator,
            interaction_handler,
            decision_recorder,
            escalation_manager,
            notification_system,
            active_interventions,
            intervention_history,
        }
    }

    /// Request user intervention for a stall
    #[instrument(skip(self), fields(workflow_id = %workflow_id))]
    pub async fn request_intervention(
        &self,
        workflow_id: Uuid,
        stall_event: &StallEvent,
    ) -> Result<InterventionResult> {
        info!(
            workflow_id = %workflow_id,
            stall_type = ?stall_event.stall_type,
            "Requesting user intervention"
        );

        let intervention_id = Uuid::new_v4();
        let start_time = chrono::Utc::now();

        // Analyze context and generate menu options
        let intervention_options = self
            .menu_generator
            .generate_intervention_options(workflow_id, stall_event)
            .await?;

        // Create intervention context
        let intervention_context = InterventionContext {
            workflow_state: stall_event.context.current_state.clone(),
            problem_description: stall_event.description.clone(),
            available_options: intervention_options.clone(),
            time_pressure: self.assess_time_pressure(stall_event),
            stakeholders: self.identify_stakeholders(workflow_id, stall_event).await?,
            business_impact: self
                .assess_business_impact(workflow_id, stall_event)
                .await?,
        };

        // Calculate timeout
        let timeout_duration = self.calculate_intervention_timeout(&intervention_context);
        let timeout_at = start_time + chrono::Duration::from_std(timeout_duration)?;

        // Create active intervention
        let (response_tx, response_rx) = oneshot::channel();
        let active_intervention = ActiveIntervention {
            intervention_id,
            workflow_id,
            started_at: start_time,
            timeout_at,
            intervention_type: InterventionType::StallResolution,
            context: intervention_context,
            response_channel: Some(response_tx),
            escalation_triggered: false,
        };

        // Store active intervention
        self.active_interventions
            .write()
            .await
            .insert(intervention_id, active_intervention);

        // Send notifications to stakeholders
        self.notification_system
            .send_intervention_notification(intervention_id, &intervention_options)
            .await?;

        // Wait for response or timeout
        let intervention_result = match tokio::time::timeout(timeout_duration, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                warn!(intervention_id = %intervention_id, "Intervention response channel closed");
                self.handle_intervention_timeout(intervention_id).await?
            }
            Err(_) => {
                warn!(intervention_id = %intervention_id, "Intervention timed out");
                self.handle_intervention_timeout(intervention_id).await?
            }
        };

        // Record intervention event
        self.record_intervention_event(intervention_id, &intervention_result)
            .await?;

        // Clean up active intervention
        self.active_interventions
            .write()
            .await
            .remove(&intervention_id);

        let response_time = (chrono::Utc::now() - start_time).num_seconds() as u64;
        info!(
            workflow_id = %workflow_id,
            intervention_id = %intervention_id,
            decision = ?intervention_result.decision,
            response_time_seconds = response_time,
            "User intervention completed"
        );

        Ok(intervention_result)
    }

    /// Handle manual user response to intervention
    pub async fn respond_to_intervention(
        &self,
        intervention_id: Uuid,
        selected_options: Vec<Uuid>,
        user_feedback: Option<String>,
    ) -> Result<()> {
        debug!(intervention_id = %intervention_id, "Processing user response");

        // Get active intervention
        let mut active_interventions = self.active_interventions.write().await;
        let active_intervention = active_interventions
            .get_mut(&intervention_id)
            .ok_or_else(|| anyhow::anyhow!("Intervention not found: {}", intervention_id))?;

        // Validate selected options
        let valid_options = self
            .validate_selected_options(
                &selected_options,
                &active_intervention.context.available_options,
            )
            .await?;

        if !valid_options {
            return Err(anyhow::anyhow!("Invalid option selection"));
        }

        // Determine decision based on selected options
        let decision = self
            .determine_decision_from_options(&selected_options, &active_intervention.context)
            .await?;

        // Create intervention result
        let intervention_result = InterventionResult {
            intervention_id,
            workflow_id: active_intervention.workflow_id,
            decision,
            selected_options,
            user_feedback,
            continue_execution: self.should_continue_execution(&active_intervention.context)?,
            decision_confidence: 0.8, // Simplified confidence calculation
            response_time_seconds: (chrono::Utc::now() - active_intervention.started_at)
                .num_seconds() as u64,
            decided_at: chrono::Utc::now(),
        };

        // Send response through channel
        if let Some(response_channel) = active_intervention.response_channel.take() {
            let _ = response_channel.send(intervention_result);
        }

        Ok(())
    }

    /// Get intervention history for workflow
    pub async fn get_intervention_history(&self, workflow_id: Uuid) -> Vec<InterventionEvent> {
        self.intervention_history
            .read()
            .await
            .iter()
            .filter(|event| event.workflow_id == workflow_id)
            .cloned()
            .collect()
    }

    /// Get active interventions
    pub async fn get_active_interventions(&self) -> Vec<Uuid> {
        self.active_interventions
            .read()
            .await
            .keys()
            .cloned()
            .collect()
    }

    /// Assess time pressure for intervention
    fn assess_time_pressure(&self, stall_event: &StallEvent) -> TimePressure {
        match stall_event.severity {
            crate::planner::stall_detection::StallSeverity::Critical => TimePressure::Critical,
            crate::planner::stall_detection::StallSeverity::High => TimePressure::High,
            crate::planner::stall_detection::StallSeverity::Medium => TimePressure::Medium,
            crate::planner::stall_detection::StallSeverity::Low => TimePressure::Low,
        }
    }

    /// Identify stakeholders for intervention
    async fn identify_stakeholders(
        &self,
        _workflow_id: Uuid,
        _stall_event: &StallEvent,
    ) -> Result<Vec<String>> {
        // Simplified implementation
        Ok(vec!["workflow_owner".to_string(), "tech_lead".to_string()])
    }

    /// Assess business impact
    async fn assess_business_impact(
        &self,
        _workflow_id: Uuid,
        stall_event: &StallEvent,
    ) -> Result<BusinessImpact> {
        let base_impact = match stall_event.severity {
            crate::planner::stall_detection::StallSeverity::Critical => 0.9,
            crate::planner::stall_detection::StallSeverity::High => 0.7,
            crate::planner::stall_detection::StallSeverity::Medium => 0.4,
            crate::planner::stall_detection::StallSeverity::Low => 0.2,
        };

        Ok(BusinessImpact {
            financial_impact: base_impact,
            customer_impact: base_impact * 0.8,
            operational_impact: base_impact * 1.2,
            reputation_impact: base_impact * 0.6,
            compliance_impact: base_impact * 0.5,
        })
    }

    /// Calculate intervention timeout
    fn calculate_intervention_timeout(&self, context: &InterventionContext) -> Duration {
        let base_timeout = Duration::from_secs(1800); // 30 minutes

        match context.time_pressure {
            TimePressure::Critical => base_timeout / 6, // 5 minutes
            TimePressure::High => base_timeout / 3,     // 10 minutes
            TimePressure::Medium => base_timeout / 2,   // 15 minutes
            TimePressure::Low => base_timeout,          // 30 minutes
        }
    }

    /// Handle intervention timeout
    async fn handle_intervention_timeout(
        &self,
        intervention_id: Uuid,
    ) -> Result<InterventionResult> {
        warn!(intervention_id = %intervention_id, "Handling intervention timeout");

        // Get intervention context
        let active_interventions = self.active_interventions.read().await;
        let active_intervention = active_interventions
            .get(&intervention_id)
            .ok_or_else(|| anyhow::anyhow!("Intervention not found: {}", intervention_id))?;

        // Trigger escalation
        let escalation_result = self
            .escalation_manager
            .escalate_intervention(intervention_id, &active_intervention.context)
            .await?;

        // Create timeout intervention result
        let intervention_result = InterventionResult {
            intervention_id,
            workflow_id: active_intervention.workflow_id,
            decision: UserDecision::Escalate {
                reason: "Intervention timed out".to_string(),
            },
            selected_options: vec![],
            user_feedback: Some("Automatic escalation due to timeout".to_string()),
            continue_execution: false,
            decision_confidence: 0.3, // Low confidence for timeout
            response_time_seconds: (chrono::Utc::now() - active_intervention.started_at)
                .num_seconds() as u64,
            decided_at: chrono::Utc::now(),
        };

        Ok(intervention_result)
    }

    /// Validate selected options
    async fn validate_selected_options(
        &self,
        selected_options: &[Uuid],
        available_options: &[UserInterventionOption],
    ) -> Result<bool> {
        // Check that all selected options are available
        for selected_id in selected_options {
            if !available_options
                .iter()
                .any(|opt| opt.option_id == *selected_id)
            {
                return Ok(false);
            }
        }

        // Additional validation logic can be added here
        Ok(true)
    }

    /// Determine decision from selected options
    async fn determine_decision_from_options(
        &self,
        selected_options: &[Uuid],
        context: &InterventionContext,
    ) -> Result<UserDecision> {
        if selected_options.is_empty() {
            return Ok(UserDecision::Cancel {
                reason: "No options selected".to_string(),
            });
        }

        // Get the first selected option and determine decision
        let selected_option = context
            .available_options
            .iter()
            .find(|opt| opt.option_id == selected_options[0])
            .ok_or_else(|| anyhow::anyhow!("Selected option not found"))?;

        let decision = match selected_option.option_type {
            OptionType::Continue => UserDecision::Continue,
            OptionType::Retry => UserDecision::Retry,
            OptionType::RetryModified => UserDecision::Retry, // Simplified
            OptionType::Skip => UserDecision::Skip,
            OptionType::Alternative => UserDecision::Alternative {
                approach: "Alternative approach".to_string(),
            },
            OptionType::Escalate => UserDecision::Escalate {
                reason: "User requested escalation".to_string(),
            },
            OptionType::Cancel => UserDecision::Cancel {
                reason: "User cancelled workflow".to_string(),
            },
            _ => UserDecision::Continue, // Default
        };

        Ok(decision)
    }

    /// Determine if execution should continue
    fn should_continue_execution(&self, context: &InterventionContext) -> Result<bool> {
        // Simplified logic - in practice would be more sophisticated
        match context.time_pressure {
            TimePressure::Critical => Ok(false), // Stop for critical issues
            _ => Ok(true),                       // Continue for other cases
        }
    }

    /// Record intervention event
    async fn record_intervention_event(
        &self,
        intervention_id: Uuid,
        result: &InterventionResult,
    ) -> Result<()> {
        let active_interventions = self.active_interventions.read().await;
        let active_intervention = active_interventions
            .get(&intervention_id)
            .ok_or_else(|| anyhow::anyhow!("Intervention not found: {}", intervention_id))?;

        let intervention_event = InterventionEvent {
            event_id: Uuid::new_v4(),
            workflow_id: result.workflow_id,
            intervention_type: format!("{:?}", active_intervention.intervention_type),
            trigger_reason: active_intervention.context.problem_description.clone(),
            options_presented: active_intervention.context.available_options.clone(),
            user_decision: result.decision.clone(),
            outcome: if result.continue_execution {
                InterventionOutcome::Resolved
            } else {
                InterventionOutcome::Escalated
            },
            response_time_seconds: result.response_time_seconds,
            occurred_at: result.decided_at,
        };

        self.intervention_history
            .write()
            .await
            .push(intervention_event);

        // Record decision for learning
        self.decision_recorder.record_decision(result).await?;

        Ok(())
    }
}

impl From<InterventionResult> for InterventionEvent {
    fn from(result: InterventionResult) -> Self {
        // This is a conversion helper - the actual implementation would be more complete
        Self {
            event_id: Uuid::new_v4(),
            workflow_id: result.workflow_id,
            intervention_type: "StallResolution".to_string(),
            trigger_reason: "Workflow stall detected".to_string(),
            options_presented: vec![], // Would be populated from context
            user_decision: result.decision,
            outcome: if result.continue_execution {
                InterventionOutcome::Resolved
            } else {
                InterventionOutcome::Escalated
            },
            response_time_seconds: result.response_time_seconds,
            occurred_at: result.decided_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::stall_detection::{
        DetectionAlgorithm, ResourceStatus, StallContext, StallSeverity, StallType,
    };

    #[test]
    fn test_menu_system_creation() {
        let menu_system = MenuSystem::new();

        // Verify menu system was created successfully
        assert!(menu_system.active_interventions.try_read().is_ok());
    }

    // Serialization tests for UserDecision
    #[test]
    fn test_user_decision_continue_serialization() {
        let decision = UserDecision::Continue;
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: UserDecision = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, UserDecision::Continue));
    }

    #[test]
    fn test_user_decision_retry_serialization() {
        let decision = UserDecision::Retry;
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: UserDecision = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, UserDecision::Retry));
    }

    #[test]
    fn test_user_decision_skip_serialization() {
        let decision = UserDecision::Skip;
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: UserDecision = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, UserDecision::Skip));
    }

    #[test]
    fn test_user_decision_alternative_serialization() {
        let decision = UserDecision::Alternative {
            approach: "new approach".to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: UserDecision = serde_json::from_str(&json).unwrap();
        if let UserDecision::Alternative { approach } = parsed {
            assert_eq!(approach, "new approach");
        } else {
            panic!("Expected Alternative variant");
        }
    }

    #[test]
    fn test_user_decision_escalate_serialization() {
        let decision = UserDecision::Escalate {
            reason: "urgent issue".to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: UserDecision = serde_json::from_str(&json).unwrap();
        if let UserDecision::Escalate { reason } = parsed {
            assert_eq!(reason, "urgent issue");
        } else {
            panic!("Expected Escalate variant");
        }
    }

    #[test]
    fn test_user_decision_cancel_serialization() {
        let decision = UserDecision::Cancel {
            reason: "user requested".to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: UserDecision = serde_json::from_str(&json).unwrap();
        if let UserDecision::Cancel { reason } = parsed {
            assert_eq!(reason, "user requested");
        } else {
            panic!("Expected Cancel variant");
        }
    }

    #[test]
    fn test_user_decision_modify_serialization() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), serde_json::json!("value"));
        let decision = UserDecision::Modify { parameters: params };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: UserDecision = serde_json::from_str(&json).unwrap();
        if let UserDecision::Modify { parameters } = parsed {
            assert!(parameters.contains_key("key"));
        } else {
            panic!("Expected Modify variant");
        }
    }

    #[test]
    fn test_user_decision_manual_intervention_serialization() {
        let decision = UserDecision::ManualIntervention {
            instructions: "check server".to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: UserDecision = serde_json::from_str(&json).unwrap();
        if let UserDecision::ManualIntervention { instructions } = parsed {
            assert_eq!(instructions, "check server");
        } else {
            panic!("Expected ManualIntervention variant");
        }
    }

    // OptionType serialization tests
    #[test]
    fn test_option_type_serialization() {
        let types = vec![
            OptionType::Continue,
            OptionType::Retry,
            OptionType::RetryModified,
            OptionType::Skip,
            OptionType::Alternative,
            OptionType::Escalate,
            OptionType::Cancel,
            OptionType::ManualOverride,
            OptionType::ResourceReallocation,
            OptionType::SecurityApproval,
        ];

        for option_type in types {
            let json = serde_json::to_string(&option_type).unwrap();
            let parsed: OptionType = serde_json::from_str(&json).unwrap();
            // Just verify round-trip works
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // RiskLevel serialization tests
    #[test]
    fn test_risk_level_serialization() {
        let levels = vec![
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ];

        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let parsed: RiskLevel = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // RollbackDifficulty serialization tests
    #[test]
    fn test_rollback_difficulty_serialization() {
        let difficulties = vec![
            RollbackDifficulty::Easy,
            RollbackDifficulty::Medium,
            RollbackDifficulty::Hard,
            RollbackDifficulty::Impossible,
        ];

        for difficulty in difficulties {
            let json = serde_json::to_string(&difficulty).unwrap();
            let parsed: RollbackDifficulty = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // InterventionOutcome serialization tests
    #[test]
    fn test_intervention_outcome_serialization() {
        let outcomes = vec![
            InterventionOutcome::Resolved,
            InterventionOutcome::Escalated,
            InterventionOutcome::Timeout,
            InterventionOutcome::Cancelled,
            InterventionOutcome::Failed,
        ];

        for outcome in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            let parsed: InterventionOutcome = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // EstimatedImpact tests
    #[test]
    fn test_estimated_impact_serialization() {
        let impact = EstimatedImpact {
            time_impact_minutes: 30,
            resource_impact: 0.5,
            success_probability: 0.8,
            side_effects: vec!["effect1".to_string(), "effect2".to_string()],
            rollback_difficulty: RollbackDifficulty::Medium,
        };

        let json = serde_json::to_string(&impact).unwrap();
        let parsed: EstimatedImpact = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.time_impact_minutes, 30);
        assert_eq!(parsed.resource_impact, 0.5);
        assert_eq!(parsed.success_probability, 0.8);
        assert_eq!(parsed.side_effects.len(), 2);
    }

    // UserInterventionOption tests
    #[test]
    fn test_user_intervention_option_serialization() {
        let option = UserInterventionOption {
            option_id: Uuid::new_v4(),
            title: "Test Option".to_string(),
            description: "Test description".to_string(),
            option_type: OptionType::Retry,
            risk_level: RiskLevel::Low,
            estimated_impact: EstimatedImpact {
                time_impact_minutes: 5,
                resource_impact: 0.1,
                success_probability: 0.9,
                side_effects: vec![],
                rollback_difficulty: RollbackDifficulty::Easy,
            },
            prerequisites: vec!["prereq1".to_string()],
            consequences: vec!["consequence1".to_string()],
            recommended: true,
            metadata: HashMap::new(),
        };

        let json = serde_json::to_string(&option).unwrap();
        let parsed: UserInterventionOption = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.title, "Test Option");
        assert_eq!(parsed.description, "Test description");
        assert!(parsed.recommended);
    }

    // InterventionResult tests
    #[test]
    fn test_intervention_result_serialization() {
        let result = InterventionResult {
            intervention_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            decision: UserDecision::Continue,
            selected_options: vec![Uuid::new_v4()],
            user_feedback: Some("Test feedback".to_string()),
            continue_execution: true,
            decision_confidence: 0.85,
            response_time_seconds: 120,
            decided_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: InterventionResult = serde_json::from_str(&json).unwrap();

        assert!(parsed.continue_execution);
        assert_eq!(parsed.decision_confidence, 0.85);
        assert_eq!(parsed.response_time_seconds, 120);
    }

    // InterventionEvent tests
    #[test]
    fn test_intervention_event_serialization() {
        let event = InterventionEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            intervention_type: "StallResolution".to_string(),
            trigger_reason: "Test reason".to_string(),
            options_presented: vec![],
            user_decision: UserDecision::Continue,
            outcome: InterventionOutcome::Resolved,
            response_time_seconds: 60,
            occurred_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: InterventionEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.intervention_type, "StallResolution");
        assert_eq!(parsed.trigger_reason, "Test reason");
        assert_eq!(parsed.response_time_seconds, 60);
    }

    // From<InterventionResult> for InterventionEvent test
    #[test]
    fn test_intervention_result_to_event_conversion() {
        let result = InterventionResult {
            intervention_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            decision: UserDecision::Retry,
            selected_options: vec![],
            user_feedback: None,
            continue_execution: true,
            decision_confidence: 0.9,
            response_time_seconds: 45,
            decided_at: chrono::Utc::now(),
        };

        let event: InterventionEvent = result.into();
        assert_eq!(event.intervention_type, "StallResolution");
        assert!(matches!(event.outcome, InterventionOutcome::Resolved));
        assert_eq!(event.response_time_seconds, 45);
    }

    #[test]
    fn test_intervention_result_to_event_escalated() {
        let result = InterventionResult {
            intervention_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            decision: UserDecision::Escalate {
                reason: "test".to_string(),
            },
            selected_options: vec![],
            user_feedback: None,
            continue_execution: false, // Not continuing means escalated
            decision_confidence: 0.5,
            response_time_seconds: 30,
            decided_at: chrono::Utc::now(),
        };

        let event: InterventionEvent = result.into();
        assert!(matches!(event.outcome, InterventionOutcome::Escalated));
    }

    // Timeout calculation tests for different pressure levels
    #[test]
    fn test_timeout_calculation_critical() {
        let menu_system = MenuSystem::new();
        let context = InterventionContext {
            workflow_state: "Planning".to_string(),
            problem_description: "Test".to_string(),
            available_options: vec![],
            time_pressure: TimePressure::Critical,
            stakeholders: vec![],
            business_impact: BusinessImpact {
                financial_impact: 0.9,
                customer_impact: 0.9,
                operational_impact: 0.9,
                reputation_impact: 0.9,
                compliance_impact: 0.9,
            },
        };

        let timeout = menu_system.calculate_intervention_timeout(&context);
        assert_eq!(timeout, Duration::from_secs(300)); // 5 minutes for critical
    }

    #[test]
    fn test_timeout_calculation_medium() {
        let menu_system = MenuSystem::new();
        let context = InterventionContext {
            workflow_state: "Planning".to_string(),
            problem_description: "Test".to_string(),
            available_options: vec![],
            time_pressure: TimePressure::Medium,
            stakeholders: vec![],
            business_impact: BusinessImpact {
                financial_impact: 0.5,
                customer_impact: 0.5,
                operational_impact: 0.5,
                reputation_impact: 0.5,
                compliance_impact: 0.5,
            },
        };

        let timeout = menu_system.calculate_intervention_timeout(&context);
        assert_eq!(timeout, Duration::from_secs(900)); // 15 minutes for medium
    }

    #[test]
    fn test_timeout_calculation_low() {
        let menu_system = MenuSystem::new();
        let context = InterventionContext {
            workflow_state: "Planning".to_string(),
            problem_description: "Test".to_string(),
            available_options: vec![],
            time_pressure: TimePressure::Low,
            stakeholders: vec![],
            business_impact: BusinessImpact {
                financial_impact: 0.2,
                customer_impact: 0.2,
                operational_impact: 0.2,
                reputation_impact: 0.2,
                compliance_impact: 0.2,
            },
        };

        let timeout = menu_system.calculate_intervention_timeout(&context);
        assert_eq!(timeout, Duration::from_secs(1800)); // 30 minutes for low
    }

    // Test should_continue_execution
    #[test]
    fn test_should_continue_execution_critical() {
        let menu_system = MenuSystem::new();
        let context = InterventionContext {
            workflow_state: "Planning".to_string(),
            problem_description: "Test".to_string(),
            available_options: vec![],
            time_pressure: TimePressure::Critical,
            stakeholders: vec![],
            business_impact: BusinessImpact {
                financial_impact: 0.9,
                customer_impact: 0.9,
                operational_impact: 0.9,
                reputation_impact: 0.9,
                compliance_impact: 0.9,
            },
        };

        let result = menu_system.should_continue_execution(&context).unwrap();
        assert!(!result); // Critical should not continue
    }

    #[test]
    fn test_should_continue_execution_low() {
        let menu_system = MenuSystem::new();
        let context = InterventionContext {
            workflow_state: "Planning".to_string(),
            problem_description: "Test".to_string(),
            available_options: vec![],
            time_pressure: TimePressure::Low,
            stakeholders: vec![],
            business_impact: BusinessImpact {
                financial_impact: 0.2,
                customer_impact: 0.2,
                operational_impact: 0.2,
                reputation_impact: 0.2,
                compliance_impact: 0.2,
            },
        };

        let result = menu_system.should_continue_execution(&context).unwrap();
        assert!(result); // Low should continue
    }

    // Test time pressure assessment for all severity levels
    #[test]
    fn test_time_pressure_assessment_all_severities() {
        let menu_system = MenuSystem::new();

        // Test all severity levels
        let severities = vec![
            (StallSeverity::Critical, TimePressure::Critical),
            (StallSeverity::High, TimePressure::High),
            (StallSeverity::Medium, TimePressure::Medium),
            (StallSeverity::Low, TimePressure::Low),
        ];

        for (severity, expected_pressure) in severities {
            let stall = StallEvent {
                event_id: Uuid::new_v4(),
                workflow_id: Uuid::new_v4(),
                stall_type: StallType::ProgressStagnation,
                detection_algorithm: DetectionAlgorithm::ProgressMonitoring,
                severity,
                description: "Test".to_string(),
                context: StallContext {
                    current_state: "Test".to_string(),
                    time_in_state_seconds: 100,
                    total_workflow_time_seconds: 200,
                    progress_percentage: 0.5,
                    last_activity: Some(chrono::Utc::now()),
                    resource_status: ResourceStatus {
                        cpu_utilization: 0.5,
                        memory_utilization: 0.5,
                        disk_utilization: 0.5,
                        network_utilization: 0.5,
                        allocation_pending: false,
                        contention_detected: false,
                    },
                    dependencies: vec![],
                    metadata: HashMap::new(),
                },
                recovery_strategy:
                    crate::planner::stall_detection::RecoveryStrategy::UserIntervention,
                confidence: 0.8,
                detected_at: chrono::Utc::now(),
                resolution_deadline: None,
            };

            let pressure = menu_system.assess_time_pressure(&stall);
            // Check that the pressure matches expected based on Debug format
            let pressure_str = format!("{:?}", pressure);
            let expected_str = format!("{:?}", expected_pressure);
            assert_eq!(pressure_str, expected_str);
        }
    }

    #[tokio::test]
    async fn test_get_active_interventions_empty() {
        let menu_system = MenuSystem::new();
        let active = menu_system.get_active_interventions().await;
        assert!(active.is_empty());
    }

    #[tokio::test]
    async fn test_get_intervention_history_empty() {
        let menu_system = MenuSystem::new();
        let history = menu_system.get_intervention_history(Uuid::new_v4()).await;
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_determine_decision_from_empty_options() {
        let menu_system = MenuSystem::new();
        let context = InterventionContext {
            workflow_state: "Test".to_string(),
            problem_description: "Test".to_string(),
            available_options: vec![],
            time_pressure: TimePressure::Low,
            stakeholders: vec![],
            business_impact: BusinessImpact {
                financial_impact: 0.1,
                customer_impact: 0.1,
                operational_impact: 0.1,
                reputation_impact: 0.1,
                compliance_impact: 0.1,
            },
        };

        let decision = menu_system
            .determine_decision_from_options(&[], &context)
            .await
            .unwrap();
        if let UserDecision::Cancel { reason } = decision {
            assert_eq!(reason, "No options selected");
        } else {
            panic!("Expected Cancel decision for empty options");
        }
    }

    #[tokio::test]
    async fn test_determine_decision_from_option_types() {
        let menu_system = MenuSystem::new();

        // Test each option type mapping
        let test_cases = vec![
            (OptionType::Continue, "Continue"),
            (OptionType::Retry, "Retry"),
            (OptionType::RetryModified, "Retry"),
            (OptionType::Skip, "Skip"),
            (OptionType::Alternative, "Alternative"),
            (OptionType::Escalate, "Escalate"),
            (OptionType::Cancel, "Cancel"),
            (OptionType::ManualOverride, "Continue"),
            (OptionType::ResourceReallocation, "Continue"),
            (OptionType::SecurityApproval, "Continue"),
        ];

        for (option_type, expected_variant) in test_cases {
            let option_id = Uuid::new_v4();
            let option = UserInterventionOption {
                option_id,
                title: "Test".to_string(),
                description: "Test".to_string(),
                option_type,
                risk_level: RiskLevel::Low,
                estimated_impact: EstimatedImpact {
                    time_impact_minutes: 5,
                    resource_impact: 0.1,
                    success_probability: 0.9,
                    side_effects: vec![],
                    rollback_difficulty: RollbackDifficulty::Easy,
                },
                prerequisites: vec![],
                consequences: vec![],
                recommended: false,
                metadata: HashMap::new(),
            };

            let context = InterventionContext {
                workflow_state: "Test".to_string(),
                problem_description: "Test".to_string(),
                available_options: vec![option],
                time_pressure: TimePressure::Low,
                stakeholders: vec![],
                business_impact: BusinessImpact {
                    financial_impact: 0.1,
                    customer_impact: 0.1,
                    operational_impact: 0.1,
                    reputation_impact: 0.1,
                    compliance_impact: 0.1,
                },
            };

            let decision = menu_system
                .determine_decision_from_options(&[option_id], &context)
                .await
                .unwrap();
            let decision_str = format!("{:?}", decision);
            assert!(
                decision_str.contains(expected_variant),
                "Expected {} in {:?}",
                expected_variant,
                decision
            );
        }
    }

    #[tokio::test]
    async fn test_identify_stakeholders() {
        let menu_system = MenuSystem::new();
        let stall = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::ProgressStagnation,
            detection_algorithm: DetectionAlgorithm::ProgressMonitoring,
            severity: StallSeverity::Medium,
            description: "Test".to_string(),
            context: StallContext {
                current_state: "Test".to_string(),
                time_in_state_seconds: 100,
                total_workflow_time_seconds: 200,
                progress_percentage: 0.5,
                last_activity: Some(chrono::Utc::now()),
                resource_status: ResourceStatus {
                    cpu_utilization: 0.5,
                    memory_utilization: 0.5,
                    disk_utilization: 0.5,
                    network_utilization: 0.5,
                    allocation_pending: false,
                    contention_detected: false,
                },
                dependencies: vec![],
                metadata: HashMap::new(),
            },
            recovery_strategy: crate::planner::stall_detection::RecoveryStrategy::UserIntervention,
            confidence: 0.8,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        let stakeholders = menu_system
            .identify_stakeholders(Uuid::new_v4(), &stall)
            .await
            .unwrap();
        assert!(!stakeholders.is_empty());
        assert!(stakeholders.contains(&"workflow_owner".to_string()));
        assert!(stakeholders.contains(&"tech_lead".to_string()));
    }

    #[tokio::test]
    async fn test_assess_business_impact() {
        let menu_system = MenuSystem::new();

        // Test business impact calculation for different severities
        let severities = vec![
            (StallSeverity::Critical, 0.9),
            (StallSeverity::High, 0.7),
            (StallSeverity::Medium, 0.4),
            (StallSeverity::Low, 0.2),
        ];

        for (severity, expected_base) in severities {
            let stall = StallEvent {
                event_id: Uuid::new_v4(),
                workflow_id: Uuid::new_v4(),
                stall_type: StallType::ProgressStagnation,
                detection_algorithm: DetectionAlgorithm::ProgressMonitoring,
                severity,
                description: "Test".to_string(),
                context: StallContext {
                    current_state: "Test".to_string(),
                    time_in_state_seconds: 100,
                    total_workflow_time_seconds: 200,
                    progress_percentage: 0.5,
                    last_activity: Some(chrono::Utc::now()),
                    resource_status: ResourceStatus {
                        cpu_utilization: 0.5,
                        memory_utilization: 0.5,
                        disk_utilization: 0.5,
                        network_utilization: 0.5,
                        allocation_pending: false,
                        contention_detected: false,
                    },
                    dependencies: vec![],
                    metadata: HashMap::new(),
                },
                recovery_strategy:
                    crate::planner::stall_detection::RecoveryStrategy::UserIntervention,
                confidence: 0.8,
                detected_at: chrono::Utc::now(),
                resolution_deadline: None,
            };

            let impact = menu_system
                .assess_business_impact(Uuid::new_v4(), &stall)
                .await
                .unwrap();
            assert_eq!(impact.financial_impact, expected_base);
        }
    }

    // UserDecision clone test
    #[test]
    fn test_user_decision_clone() {
        let decision = UserDecision::Alternative {
            approach: "test".to_string(),
        };
        let cloned = decision.clone();
        if let UserDecision::Alternative { approach } = cloned {
            assert_eq!(approach, "test");
        } else {
            panic!("Clone failed");
        }
    }

    // OptionType clone test
    #[test]
    fn test_option_type_clone() {
        let opt = OptionType::SecurityApproval;
        let cloned = opt.clone();
        assert!(matches!(cloned, OptionType::SecurityApproval));
    }

    // RiskLevel clone test
    #[test]
    fn test_risk_level_clone() {
        let risk = RiskLevel::Critical;
        let cloned = risk.clone();
        assert!(matches!(cloned, RiskLevel::Critical));
    }

    // InterventionOutcome clone test
    #[test]
    fn test_intervention_outcome_clone() {
        let outcome = InterventionOutcome::Timeout;
        let cloned = outcome.clone();
        assert!(matches!(cloned, InterventionOutcome::Timeout));
    }

    // RollbackDifficulty clone test
    #[test]
    fn test_rollback_difficulty_clone() {
        let difficulty = RollbackDifficulty::Impossible;
        let cloned = difficulty.clone();
        assert!(matches!(cloned, RollbackDifficulty::Impossible));
    }

    #[tokio::test]
    async fn test_intervention_option_generation() {
        let menu_system = MenuSystem::new();

        let stall_event = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::ProgressStagnation,
            detection_algorithm: DetectionAlgorithm::ProgressMonitoring,
            severity: StallSeverity::Medium,
            description: "Test stall".to_string(),
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
                metadata: std::collections::HashMap::new(),
            },
            recovery_strategy: crate::planner::stall_detection::RecoveryStrategy::UserIntervention,
            confidence: 0.8,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        let options = menu_system
            .menu_generator
            .generate_intervention_options(Uuid::new_v4(), &stall_event)
            .await
            .unwrap();

        assert!(!options.is_empty());
        assert!(options
            .iter()
            .any(|opt| matches!(opt.option_type, OptionType::Retry)));
        assert!(options
            .iter()
            .any(|opt| matches!(opt.option_type, OptionType::Skip)));
        assert!(options
            .iter()
            .any(|opt| matches!(opt.option_type, OptionType::Escalate)));
        assert!(options
            .iter()
            .any(|opt| matches!(opt.option_type, OptionType::Cancel)));
    }

    #[test]
    fn test_time_pressure_assessment() {
        let menu_system = MenuSystem::new();

        let critical_stall = StallEvent {
            event_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            stall_type: StallType::ProgressStagnation,
            detection_algorithm: DetectionAlgorithm::ProgressMonitoring,
            severity: StallSeverity::Critical,
            description: "Critical stall".to_string(),
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
                metadata: std::collections::HashMap::new(),
            },
            recovery_strategy: crate::planner::stall_detection::RecoveryStrategy::UserIntervention,
            confidence: 0.8,
            detected_at: chrono::Utc::now(),
            resolution_deadline: None,
        };

        let time_pressure = menu_system.assess_time_pressure(&critical_stall);
        assert!(matches!(time_pressure, TimePressure::Critical));
    }

    #[test]
    fn test_timeout_calculation() {
        let menu_system = MenuSystem::new();

        let context = InterventionContext {
            workflow_state: "Planning".to_string(),
            problem_description: "Test problem".to_string(),
            available_options: vec![],
            time_pressure: TimePressure::High,
            stakeholders: vec![],
            business_impact: BusinessImpact {
                financial_impact: 0.5,
                customer_impact: 0.4,
                operational_impact: 0.6,
                reputation_impact: 0.3,
                compliance_impact: 0.2,
            },
        };

        let timeout = menu_system.calculate_intervention_timeout(&context);
        assert!(timeout < Duration::from_secs(1800)); // Should be less than 30 minutes for high pressure
    }

    #[tokio::test]
    async fn test_option_validation() {
        let menu_system = MenuSystem::new();

        let option1 = UserInterventionOption {
            option_id: Uuid::new_v4(),
            title: "Option 1".to_string(),
            description: "Test option".to_string(),
            option_type: OptionType::Retry,
            risk_level: RiskLevel::Low,
            estimated_impact: EstimatedImpact {
                time_impact_minutes: 5,
                resource_impact: 0.1,
                success_probability: 0.8,
                side_effects: vec![],
                rollback_difficulty: RollbackDifficulty::Easy,
            },
            prerequisites: vec![],
            consequences: vec![],
            recommended: true,
            metadata: std::collections::HashMap::new(),
        };

        let available_options = vec![option1.clone()];
        let selected_options = vec![option1.option_id];

        let valid = menu_system
            .validate_selected_options(&selected_options, &available_options)
            .await
            .unwrap();
        assert!(valid);

        // Test invalid selection
        let invalid_selection = vec![Uuid::new_v4()];
        let invalid = menu_system
            .validate_selected_options(&invalid_selection, &available_options)
            .await
            .unwrap();
        assert!(!invalid);
    }
}
