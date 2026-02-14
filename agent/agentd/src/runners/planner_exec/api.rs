// api.rs - NATS-based API integration for planner-executor communication

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use smith_bus::{subjects::*, Consumer, Publisher, SmithBus};
use smith_protocol::{ExecutionStatus, Intent, IntentResult};

use crate::runners::planner_exec::{
    schemas::{
        ActionResult, ExecutionSummary, PlannerExecParams, ResourceUsage, WorkflowAction,
        WorkflowStatus, WorkflowType,
    },
    state_machine::{StateMachine, WorkflowState},
    telemetry::{EventType, ResourceUtilization, Severity, TelemetryCollector},
};

/// NATS-based API for planner-executor communication
pub struct PlannerExecAPI {
    bus: Arc<SmithBus>,
    publisher: Arc<Publisher>,
    active_workflows: Arc<RwLock<HashMap<String, WorkflowSession>>>,
    event_sender: mpsc::UnboundedSender<APIEvent>,
    config: APIConfig,
}

/// Configuration for the planner-executor API
#[derive(Debug, Clone)]
pub struct APIConfig {
    pub max_concurrent_workflows: usize,
    pub workflow_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub result_retention: Duration,
    pub enable_streaming: bool,
    pub compression_enabled: bool,
}

/// Active workflow session
#[derive(Debug)]
struct WorkflowSession {
    session_id: String,
    workflow_type: WorkflowType,
    state_machine: StateMachine,
    telemetry: TelemetryCollector,
    created_at: std::time::Instant,
    last_activity: std::time::Instant,
    result_channel: mpsc::UnboundedSender<WorkflowUpdate>,
}

/// API events for internal communication
#[derive(Debug, Clone, Serialize)]
pub enum APIEvent {
    WorkflowStarted {
        session_id: String,
        workflow_type: WorkflowType,
    },
    WorkflowCompleted {
        session_id: String,
        summary: ExecutionSummary,
    },
    WorkflowFailed {
        session_id: String,
        error: String,
    },
    ActionExecuted {
        session_id: String,
        action_id: String,
        result: ActionResult,
    },
    StateTransition {
        session_id: String,
        from_state: WorkflowState,
        to_state: WorkflowState,
    },
    UserIntervention {
        session_id: String,
        intervention_type: String,
    },
    SystemError {
        session_id: String,
        error: String,
    },
    HealthCheck {
        component: String,
        status: HealthStatus,
    },
}

/// Health status for system components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Workflow update for streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowUpdate {
    pub session_id: String,
    pub timestamp: u64,
    pub update_type: UpdateType,
    pub payload: serde_json::Value,
}

/// Types of workflow updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateType {
    StateChanged,
    ActionStarted,
    ActionCompleted,
    ProgressUpdate,
    ErrorOccurred,
    UserRequired,
    MetricsUpdate,
    LogMessage,
}

/// API request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum APIRequest {
    StartWorkflow {
        session_id: String,
        params: PlannerExecParams,
        streaming: bool,
    },
    StopWorkflow {
        session_id: String,
        force: bool,
    },
    PauseWorkflow {
        session_id: String,
    },
    ResumeWorkflow {
        session_id: String,
    },
    GetWorkflowStatus {
        session_id: String,
    },
    ListActiveWorkflows,
    GetWorkflowHistory {
        session_id: String,
        include_telemetry: bool,
    },
    HealthCheck {
        component: Option<String>,
    },
    GetMetrics {
        session_id: Option<String>,
        format: String,
    },
    UserIntervention {
        session_id: String,
        action: String,
        parameters: HashMap<String, String>,
    },
}

/// API response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum APIResponse {
    WorkflowStarted {
        session_id: String,
        stream_subject: Option<String>,
    },
    WorkflowStopped {
        session_id: String,
        summary: Option<ExecutionSummary>,
    },
    WorkflowStatus {
        session_id: String,
        state: WorkflowState,
        progress: f64,
        current_action: Option<String>,
        metadata: HashMap<String, String>,
    },
    ActiveWorkflows {
        workflows: Vec<WorkflowInfo>,
    },
    WorkflowHistory {
        session_id: String,
        events: Vec<serde_json::Value>,
        telemetry: Option<serde_json::Value>,
    },
    HealthStatus {
        component: String,
        status: HealthStatus,
        details: HashMap<String, String>,
    },
    Metrics {
        data: String,
        format: String,
    },
    InterventionResult {
        session_id: String,
        success: bool,
        message: String,
    },
    Error {
        code: String,
        message: String,
        details: Option<HashMap<String, String>>,
    },
}

/// Workflow information for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInfo {
    pub session_id: String,
    pub workflow_type: WorkflowType,
    pub state: WorkflowState,
    pub progress: f64,
    pub created_at: u64,
    pub last_activity: u64,
    pub duration_ms: u64,
}

impl Default for APIConfig {
    fn default() -> Self {
        Self {
            max_concurrent_workflows: 100,
            workflow_timeout: Duration::from_secs(3600), // 1 hour
            heartbeat_interval: Duration::from_secs(30),
            result_retention: Duration::from_secs(86400), // 24 hours
            enable_streaming: true,
            compression_enabled: true,
        }
    }
}

/// Convert telemetry ResourceUtilization to schemas ResourceUsage
fn convert_resource_utilization(util: &ResourceUtilization) -> ResourceUsage {
    ResourceUsage {
        cpu_ms: (util.avg_cpu_percent * 1000.0) as u64, // Rough approximation
        memory_bytes: (util.peak_memory_mb * 1024.0 * 1024.0) as u64,
        fs_operations: 0, // Not tracked in ResourceUtilization
        network_requests: (util.network_io_mb * 10.0) as u64, // Rough approximation
    }
}

impl PlannerExecAPI {
    /// Create a new planner-executor API instance
    pub async fn new(
        bus: Arc<SmithBus>,
        config: APIConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let publisher = Arc::new(bus.publisher());
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let api = Self {
            bus: bus.clone(),
            publisher,
            active_workflows: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            config,
        };

        // Start background tasks
        api.start_background_tasks(event_receiver).await?;

        info!(
            "Planner-Executor API initialized with config: {:?}",
            api.config
        );
        Ok(api)
    }

    /// Start the API request handler
    pub async fn start_request_handler(&self) -> Result<(), Box<dyn std::error::Error>> {
        let consumer = self
            .bus
            .consumer(
                "planner_exec_requests",
                smith_bus::ConsumerConfig {
                    name: "planner_exec_api".to_string(),
                    consumer_group: None,
                    max_deliver: 3,
                    ack_wait: Duration::from_secs(30),
                    max_age: None,
                    start_sequence: smith_bus::ConsumerStartSequence::Latest,
                    worker_count: 1,
                },
            )
            .await?;

        let api = self.clone();
        tokio::spawn(async move {
            api.handle_requests(consumer).await;
        });

        info!("Started planner-executor API request handler");
        Ok(())
    }

    /// Handle incoming API requests
    async fn handle_requests(&self, mut consumer: Consumer) {
        loop {
            match consumer.next_message::<serde_json::Value>().await {
                Ok(Some(message)) => {
                    let api = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = api.process_request_message(message).await {
                            error!("Failed to process API request: {}", e);
                        }
                    });
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => {
                    error!("Error receiving message: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Process a single API request message
    async fn process_request_message(
        &self,
        message: smith_bus::Message<serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request: APIRequest = serde_json::from_value(message.payload.clone())?;
        let response = self.handle_api_request(request).await;

        // Send response - reply handling would need to be implemented
        // through request/response pattern or additional message headers

        // Acknowledge message
        message.ack().await?;
        Ok(())
    }

    /// Handle an API request and generate response
    async fn handle_api_request(&self, request: APIRequest) -> APIResponse {
        debug!("Handling API request: {:?}", request);

        match request {
            APIRequest::StartWorkflow {
                session_id,
                params,
                streaming,
            } => {
                match self
                    .start_workflow(session_id.clone(), params, streaming)
                    .await
                {
                    Ok(stream_subject) => APIResponse::WorkflowStarted {
                        session_id,
                        stream_subject,
                    },
                    Err(e) => APIResponse::Error {
                        code: "WORKFLOW_START_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }
            }

            APIRequest::StopWorkflow { session_id, force } => {
                match self.stop_workflow(&session_id, force).await {
                    Ok(summary) => APIResponse::WorkflowStopped {
                        session_id,
                        summary,
                    },
                    Err(e) => APIResponse::Error {
                        code: "WORKFLOW_STOP_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }
            }

            APIRequest::PauseWorkflow { session_id } => {
                match self.pause_workflow(&session_id).await {
                    Ok(_) => APIResponse::WorkflowStatus {
                        session_id: session_id.clone(),
                        state: WorkflowState::Paused,
                        progress: 0.0, // Will be updated by actual implementation
                        current_action: None,
                        metadata: HashMap::new(),
                    },
                    Err(e) => APIResponse::Error {
                        code: "WORKFLOW_PAUSE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }
            }

            APIRequest::ResumeWorkflow { session_id } => {
                match self.resume_workflow(&session_id).await {
                    Ok(_) => APIResponse::WorkflowStatus {
                        session_id: session_id.clone(),
                        state: WorkflowState::Executing,
                        progress: 0.0, // Will be updated by actual implementation
                        current_action: None,
                        metadata: HashMap::new(),
                    },
                    Err(e) => APIResponse::Error {
                        code: "WORKFLOW_RESUME_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }
            }

            APIRequest::GetWorkflowStatus { session_id } => {
                match self.get_workflow_status(&session_id).await {
                    Ok(status) => status,
                    Err(e) => APIResponse::Error {
                        code: "WORKFLOW_STATUS_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }
            }

            APIRequest::ListActiveWorkflows => match self.list_active_workflows().await {
                Ok(workflows) => APIResponse::ActiveWorkflows { workflows },
                Err(e) => APIResponse::Error {
                    code: "LIST_WORKFLOWS_FAILED".to_string(),
                    message: e.to_string(),
                    details: None,
                },
            },

            APIRequest::GetWorkflowHistory {
                session_id,
                include_telemetry,
            } => {
                match self
                    .get_workflow_history(&session_id, include_telemetry)
                    .await
                {
                    Ok((events, telemetry)) => APIResponse::WorkflowHistory {
                        session_id,
                        events,
                        telemetry,
                    },
                    Err(e) => APIResponse::Error {
                        code: "WORKFLOW_HISTORY_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }
            }

            APIRequest::HealthCheck { component } => self.get_health_status(component).await,

            APIRequest::GetMetrics { session_id, format } => {
                match self.get_metrics(session_id, &format).await {
                    Ok(data) => APIResponse::Metrics { data, format },
                    Err(e) => APIResponse::Error {
                        code: "METRICS_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }
            }

            APIRequest::UserIntervention {
                session_id,
                action,
                parameters,
            } => {
                match self
                    .handle_user_intervention(&session_id, &action, parameters)
                    .await
                {
                    Ok(message) => APIResponse::InterventionResult {
                        session_id,
                        success: true,
                        message,
                    },
                    Err(e) => APIResponse::InterventionResult {
                        session_id,
                        success: false,
                        message: e.to_string(),
                    },
                }
            }
        }
    }

    /// Start a new workflow
    async fn start_workflow(
        &self,
        session_id: String,
        params: PlannerExecParams,
        streaming: bool,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        // Check concurrent workflow limit
        let workflows = self.active_workflows.read().await;
        if workflows.len() >= self.config.max_concurrent_workflows {
            return Err("Maximum concurrent workflows exceeded".into());
        }
        drop(workflows);

        // Create state machine and telemetry
        let state_machine = StateMachine::new(params.workflow_id.clone(), params.clone())?;
        let telemetry =
            TelemetryCollector::new(session_id.clone(), Some(params.workflow_type.clone()));

        // Create result channel for streaming
        let (result_sender, mut result_receiver) = mpsc::unbounded_channel();
        let stream_subject = if streaming {
            Some(format!("smith.planner_exec.streams.{}", session_id))
        } else {
            None
        };

        // Create workflow session
        let session = WorkflowSession {
            session_id: session_id.clone(),
            workflow_type: params.workflow_type.clone(),
            state_machine,
            telemetry,
            created_at: std::time::Instant::now(),
            last_activity: std::time::Instant::now(),
            result_channel: result_sender,
        };

        // Add to active workflows
        let mut workflows = self.active_workflows.write().await;
        workflows.insert(session_id.clone(), session);
        drop(workflows);

        // Start streaming task if enabled
        if let Some(subject) = &stream_subject {
            let publisher = self.publisher.clone();
            let subject = subject.clone();
            tokio::spawn(async move {
                while let Some(update) = result_receiver.recv().await {
                    if let Ok(data) = serde_json::to_vec(&update) {
                        if let Err(e) = publisher.publish(subject.clone(), &update).await {
                            error!("Failed to publish workflow update: {}", e);
                        }
                    }
                }
            });
        }

        // Emit workflow started event
        let _ = self.event_sender.send(APIEvent::WorkflowStarted {
            session_id: session_id.clone(),
            workflow_type: params.workflow_type,
        });

        info!(
            "Started workflow {} with streaming: {}",
            session_id, streaming
        );
        Ok(stream_subject)
    }

    /// Stop a workflow
    async fn stop_workflow(
        &self,
        session_id: &str,
        force: bool,
    ) -> Result<Option<ExecutionSummary>, Box<dyn std::error::Error>> {
        let mut workflows = self.active_workflows.write().await;

        if let Some(session) = workflows.remove(session_id) {
            drop(workflows);

            // Generate final summary from telemetry
            let telemetry_report = session.telemetry.generate_report().await;
            let summary = ExecutionSummary {
                workflow_id: session.state_machine.workflow_id.clone(),
                session_id: session.session_id.clone(),
                workflow_type: session.workflow_type,
                goal: session.state_machine.params.goal.clone(),
                status: match session.state_machine.current_state() {
                    WorkflowState::Completed => WorkflowStatus::Completed,
                    WorkflowState::Failed(_) => WorkflowStatus::Failed,
                    _ => WorkflowStatus::Cancelled,
                },
                actions: session.state_machine.completed_actions.clone(),
                duration_ms: session.created_at.elapsed().as_millis() as u64,
                total_duration: session.created_at.elapsed(),
                total_actions: telemetry_report.total_actions as u32,
                successful_actions: telemetry_report.successful_actions as u32,
                failed_actions: telemetry_report.failed_actions as u32,
                final_state: match session.state_machine.current_state() {
                    WorkflowState::Completed => WorkflowStatus::Completed,
                    WorkflowState::Failed(_) => WorkflowStatus::Failed,
                    WorkflowState::Paused => WorkflowStatus::Paused,
                    WorkflowState::Executing => WorkflowStatus::Executing,
                    WorkflowState::Planning => WorkflowStatus::Planning,
                    WorkflowState::Initializing => WorkflowStatus::Initializing,
                },
                error_message: None,
                resource_usage: convert_resource_utilization(
                    &telemetry_report.resource_utilization,
                ),
                success_criteria_met: vec![], // TODO: Extract from state machine
                lessons_learned: session.state_machine.lessons_learned.clone(),
                recommendations: telemetry_report.recommendations,
                final_output: None, // TODO: Extract final output if available
            };

            // Emit workflow completed event
            let _ = self.event_sender.send(APIEvent::WorkflowCompleted {
                session_id: session_id.to_string(),
                summary: summary.clone(),
            });

            info!("Stopped workflow {} (force: {})", session_id, force);
            Ok(Some(summary))
        } else {
            Err(format!("Workflow {} not found", session_id).into())
        }
    }

    /// Pause a workflow
    async fn pause_workflow(&self, session_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let workflows = self.active_workflows.read().await;

        if let Some(session) = workflows.get(session_id) {
            // In a real implementation, this would pause the state machine
            info!("Paused workflow {}", session_id);
            Ok(())
        } else {
            Err(format!("Workflow {} not found", session_id).into())
        }
    }

    /// Resume a workflow
    async fn resume_workflow(&self, session_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let workflows = self.active_workflows.read().await;

        if let Some(session) = workflows.get(session_id) {
            // In a real implementation, this would resume the state machine
            info!("Resumed workflow {}", session_id);
            Ok(())
        } else {
            Err(format!("Workflow {} not found", session_id).into())
        }
    }

    /// Get workflow status
    async fn get_workflow_status(
        &self,
        session_id: &str,
    ) -> Result<APIResponse, Box<dyn std::error::Error>> {
        let workflows = self.active_workflows.read().await;

        if let Some(session) = workflows.get(session_id) {
            let mut metadata = HashMap::new();
            metadata.insert(
                "created_at".to_string(),
                session.created_at.elapsed().as_secs().to_string(),
            );
            metadata.insert(
                "last_activity".to_string(),
                session.last_activity.elapsed().as_secs().to_string(),
            );

            Ok(APIResponse::WorkflowStatus {
                session_id: session_id.to_string(),
                state: session.state_machine.current_state().clone(),
                progress: session.state_machine.progress(),
                current_action: session.state_machine.current_action().map(|a| a.id.clone()),
                metadata,
            })
        } else {
            Err(format!("Workflow {} not found", session_id).into())
        }
    }

    /// List active workflows
    async fn list_active_workflows(&self) -> Result<Vec<WorkflowInfo>, Box<dyn std::error::Error>> {
        let workflows = self.active_workflows.read().await;
        let mut result = Vec::new();

        for (session_id, session) in workflows.iter() {
            let info = WorkflowInfo {
                session_id: session_id.clone(),
                workflow_type: session.workflow_type.clone(),
                state: session.state_machine.current_state().clone(),
                progress: session.state_machine.progress(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - session.created_at.elapsed().as_secs(),
                last_activity: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - session.last_activity.elapsed().as_secs(),
                duration_ms: session.created_at.elapsed().as_millis() as u64,
            };
            result.push(info);
        }

        Ok(result)
    }

    /// Get workflow history
    async fn get_workflow_history(
        &self,
        session_id: &str,
        include_telemetry: bool,
    ) -> Result<(Vec<serde_json::Value>, Option<serde_json::Value>), Box<dyn std::error::Error>>
    {
        let workflows = self.active_workflows.read().await;

        if let Some(session) = workflows.get(session_id) {
            let events = session
                .state_machine
                .get_execution_history()
                .iter()
                .map(|event| serde_json::to_value(event).unwrap_or_default())
                .collect();

            let telemetry = if include_telemetry {
                let report = session.telemetry.generate_report().await;
                Some(serde_json::to_value(&report)?)
            } else {
                None
            };

            Ok((events, telemetry))
        } else {
            Err(format!("Workflow {} not found", session_id).into())
        }
    }

    /// Get health status
    async fn get_health_status(&self, component: Option<String>) -> APIResponse {
        let mut details = HashMap::new();
        details.insert(
            "active_workflows".to_string(),
            self.active_workflows.read().await.len().to_string(),
        );
        details.insert("uptime".to_string(), "healthy".to_string());

        APIResponse::HealthStatus {
            component: component.unwrap_or_else(|| "planner_exec_api".to_string()),
            status: HealthStatus::Healthy,
            details,
        }
    }

    /// Get metrics
    async fn get_metrics(
        &self,
        session_id: Option<String>,
        format: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let workflows = self.active_workflows.read().await;

        if let Some(sid) = session_id {
            // Get metrics for specific workflow
            if let Some(session) = workflows.get(&sid) {
                match format {
                    "json" => {
                        let report = session.telemetry.generate_report().await;
                        Ok(serde_json::to_string_pretty(&report)?)
                    }
                    "prometheus" => {
                        session
                            .telemetry
                            .export_telemetry(
                                crate::runners::planner_exec::telemetry::ExportFormat::Prometheus,
                            )
                            .await
                    }
                    _ => Err("Unsupported format".into()),
                }
            } else {
                Err(format!("Workflow {} not found", sid).into())
            }
        } else {
            // Get aggregate metrics
            let total_workflows = workflows.len();
            let aggregate_metrics = serde_json::json!({
                "total_active_workflows": total_workflows,
                "api_status": "healthy",
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });

            Ok(serde_json::to_string_pretty(&aggregate_metrics)?)
        }
    }

    /// Handle user intervention
    async fn handle_user_intervention(
        &self,
        session_id: &str,
        action: &str,
        parameters: HashMap<String, String>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let workflows = self.active_workflows.read().await;

        if let Some(_session) = workflows.get(session_id) {
            // Emit user intervention event
            let _ = self.event_sender.send(APIEvent::UserIntervention {
                session_id: session_id.to_string(),
                intervention_type: action.to_string(),
            });

            info!(
                "User intervention {} applied to workflow {}",
                action, session_id
            );
            Ok(format!("Intervention '{}' applied successfully", action))
        } else {
            Err(format!("Workflow {} not found", session_id).into())
        }
    }

    /// Start background tasks
    async fn start_background_tasks(
        &self,
        mut event_receiver: mpsc::UnboundedReceiver<APIEvent>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Event processing task
        let publisher = self.publisher.clone();
        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                if let Ok(data) = serde_json::to_vec(&event) {
                    let subject = "smith.planner_exec.events";
                    if let Err(e) = publisher.publish(subject.to_string(), &event).await {
                        error!("Failed to publish API event: {}", e);
                    }
                }
            }
        });

        // Cleanup task for expired workflows
        let workflows = self.active_workflows.clone();
        let timeout = self.config.workflow_timeout;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                let mut to_remove = Vec::new();
                {
                    let workflows_read = workflows.read().await;
                    for (session_id, session) in workflows_read.iter() {
                        if session.last_activity.elapsed() > timeout {
                            to_remove.push(session_id.clone());
                        }
                    }
                }

                if !to_remove.is_empty() {
                    let mut workflows_write = workflows.write().await;
                    for session_id in to_remove {
                        workflows_write.remove(&session_id);
                        warn!("Removed expired workflow: {}", session_id);
                    }
                }
            }
        });

        Ok(())
    }
}

impl Clone for PlannerExecAPI {
    fn clone(&self) -> Self {
        Self {
            bus: self.bus.clone(),
            publisher: self.publisher.clone(),
            active_workflows: self.active_workflows.clone(),
            event_sender: self.event_sender.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== APIConfig Tests ====================

    #[test]
    fn test_api_config_default() {
        let config = APIConfig::default();
        assert_eq!(config.max_concurrent_workflows, 100);
        assert_eq!(config.workflow_timeout, Duration::from_secs(3600));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.result_retention, Duration::from_secs(86400));
        assert!(config.enable_streaming);
        assert!(config.compression_enabled);
    }

    #[test]
    fn test_api_config_clone() {
        let config = APIConfig {
            max_concurrent_workflows: 50,
            workflow_timeout: Duration::from_secs(1800),
            heartbeat_interval: Duration::from_secs(15),
            result_retention: Duration::from_secs(43200),
            enable_streaming: false,
            compression_enabled: false,
        };
        let cloned = config.clone();
        assert_eq!(cloned.max_concurrent_workflows, 50);
        assert_eq!(cloned.workflow_timeout, Duration::from_secs(1800));
        assert!(!cloned.enable_streaming);
    }

    #[test]
    fn test_api_config_debug() {
        let config = APIConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("max_concurrent_workflows"));
        assert!(debug_str.contains("workflow_timeout"));
    }

    // ==================== HealthStatus Tests ====================

    #[test]
    fn test_health_status_healthy() {
        let status = HealthStatus::Healthy;
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(serialized.contains("Healthy"));
    }

    #[test]
    fn test_health_status_degraded() {
        let status = HealthStatus::Degraded;
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(serialized.contains("Degraded"));
    }

    #[test]
    fn test_health_status_unhealthy() {
        let status = HealthStatus::Unhealthy;
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(serialized.contains("Unhealthy"));
    }

    #[test]
    fn test_health_status_unknown() {
        let status = HealthStatus::Unknown;
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(serialized.contains("Unknown"));
    }

    #[test]
    fn test_health_status_roundtrip() {
        for status in [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
            HealthStatus::Unknown,
        ] {
            let serialized = serde_json::to_string(&status).unwrap();
            let deserialized: HealthStatus = serde_json::from_str(&serialized).unwrap();
            // Just verify it roundtrips without panicking
            let _ = format!("{:?}", deserialized);
        }
    }

    // ==================== UpdateType Tests ====================

    #[test]
    fn test_update_type_serialization() {
        let update_types = [
            UpdateType::StateChanged,
            UpdateType::ActionStarted,
            UpdateType::ActionCompleted,
            UpdateType::ProgressUpdate,
            UpdateType::ErrorOccurred,
            UpdateType::UserRequired,
            UpdateType::MetricsUpdate,
            UpdateType::LogMessage,
        ];

        for update_type in update_types {
            let serialized = serde_json::to_string(&update_type).unwrap();
            let deserialized: UpdateType = serde_json::from_str(&serialized).unwrap();
            let _ = format!("{:?}", deserialized);
        }
    }

    // ==================== WorkflowUpdate Tests ====================

    #[test]
    fn test_workflow_update_creation() {
        let update = WorkflowUpdate {
            session_id: "test-session-123".to_string(),
            timestamp: 1234567890,
            update_type: UpdateType::StateChanged,
            payload: serde_json::json!({"state": "executing"}),
        };
        assert_eq!(update.session_id, "test-session-123");
        assert_eq!(update.timestamp, 1234567890);
    }

    #[test]
    fn test_workflow_update_serialization() {
        let update = WorkflowUpdate {
            session_id: "session-abc".to_string(),
            timestamp: 9876543210,
            update_type: UpdateType::ProgressUpdate,
            payload: serde_json::json!({"progress": 0.75}),
        };
        let serialized = serde_json::to_string(&update).unwrap();
        let deserialized: WorkflowUpdate = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.session_id, "session-abc");
        assert_eq!(deserialized.timestamp, 9876543210);
    }

    // ==================== APIRequest Tests ====================

    #[tokio::test]
    async fn test_api_request_start_workflow() {
        let request = APIRequest::StartWorkflow {
            session_id: "test-session".to_string(),
            params: PlannerExecParams {
                workflow_id: "test-workflow-123".to_string(),
                goal: "Test workflow".to_string(),
                workflow_type: WorkflowType::Simple,
                max_steps: 10,
                timeout_ms: Some(3600000),
                context: HashMap::new(),
                allowed_capabilities: vec![],
                resource_limits: crate::runners::planner_exec::schemas::ResourceLimits::default(),
                preferences: crate::runners::planner_exec::schemas::ExecutionPreferences::default(),
            },
            streaming: true,
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            APIRequest::StartWorkflow {
                session_id,
                streaming,
                ..
            } => {
                assert_eq!(session_id, "test-session");
                assert!(streaming);
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_api_request_stop_workflow() {
        let request = APIRequest::StopWorkflow {
            session_id: "session-to-stop".to_string(),
            force: true,
        };
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIRequest::StopWorkflow { session_id, force } => {
                assert_eq!(session_id, "session-to-stop");
                assert!(force);
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_api_request_pause_workflow() {
        let request = APIRequest::PauseWorkflow {
            session_id: "session-to-pause".to_string(),
        };
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIRequest::PauseWorkflow { session_id } => {
                assert_eq!(session_id, "session-to-pause");
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_api_request_resume_workflow() {
        let request = APIRequest::ResumeWorkflow {
            session_id: "session-to-resume".to_string(),
        };
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIRequest::ResumeWorkflow { session_id } => {
                assert_eq!(session_id, "session-to-resume");
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_api_request_get_status() {
        let request = APIRequest::GetWorkflowStatus {
            session_id: "status-session".to_string(),
        };
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIRequest::GetWorkflowStatus { session_id } => {
                assert_eq!(session_id, "status-session");
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_api_request_list_active() {
        let request = APIRequest::ListActiveWorkflows;
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, APIRequest::ListActiveWorkflows));
    }

    #[test]
    fn test_api_request_get_history() {
        let request = APIRequest::GetWorkflowHistory {
            session_id: "history-session".to_string(),
            include_telemetry: true,
        };
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIRequest::GetWorkflowHistory {
                session_id,
                include_telemetry,
            } => {
                assert_eq!(session_id, "history-session");
                assert!(include_telemetry);
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_api_request_health_check() {
        let request = APIRequest::HealthCheck {
            component: Some("executor".to_string()),
        };
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIRequest::HealthCheck { component } => {
                assert_eq!(component, Some("executor".to_string()));
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_api_request_get_metrics() {
        let request = APIRequest::GetMetrics {
            session_id: Some("metrics-session".to_string()),
            format: "json".to_string(),
        };
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIRequest::GetMetrics { session_id, format } => {
                assert_eq!(session_id, Some("metrics-session".to_string()));
                assert_eq!(format, "json");
            }
            _ => panic!("Unexpected request type"),
        }
    }

    #[test]
    fn test_api_request_user_intervention() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "value".to_string());
        let request = APIRequest::UserIntervention {
            session_id: "intervention-session".to_string(),
            action: "approve".to_string(),
            parameters: params.clone(),
        };
        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: APIRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIRequest::UserIntervention {
                session_id,
                action,
                parameters,
            } => {
                assert_eq!(session_id, "intervention-session");
                assert_eq!(action, "approve");
                assert_eq!(parameters.get("key"), Some(&"value".to_string()));
            }
            _ => panic!("Unexpected request type"),
        }
    }

    // ==================== APIResponse Tests ====================

    #[test]
    fn test_api_response_workflow_started() {
        let response = APIResponse::WorkflowStarted {
            session_id: "started-session".to_string(),
            stream_subject: Some("smith.planner.streams.test".to_string()),
        };
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: APIResponse = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIResponse::WorkflowStarted {
                session_id,
                stream_subject,
            } => {
                assert_eq!(session_id, "started-session");
                assert!(stream_subject.is_some());
            }
            _ => panic!("Unexpected response type"),
        }
    }

    #[test]
    fn test_api_response_workflow_stopped() {
        let response = APIResponse::WorkflowStopped {
            session_id: "stopped-session".to_string(),
            summary: None,
        };
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: APIResponse = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIResponse::WorkflowStopped {
                session_id,
                summary,
            } => {
                assert_eq!(session_id, "stopped-session");
                assert!(summary.is_none());
            }
            _ => panic!("Unexpected response type"),
        }
    }

    #[test]
    fn test_api_response_workflow_status() {
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), "value".to_string());
        let response = APIResponse::WorkflowStatus {
            session_id: "status-session".to_string(),
            state: WorkflowState::Executing,
            progress: 0.75,
            current_action: Some("action-123".to_string()),
            metadata,
        };
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: APIResponse = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIResponse::WorkflowStatus {
                session_id,
                progress,
                ..
            } => {
                assert_eq!(session_id, "status-session");
                assert_eq!(progress, 0.75);
            }
            _ => panic!("Unexpected response type"),
        }
    }

    #[test]
    fn test_api_response_active_workflows() {
        let workflows = vec![WorkflowInfo {
            session_id: "workflow-1".to_string(),
            workflow_type: WorkflowType::Simple,
            state: WorkflowState::Executing,
            progress: 0.5,
            created_at: 1000,
            last_activity: 2000,
            duration_ms: 1000,
        }];
        let response = APIResponse::ActiveWorkflows { workflows };
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: APIResponse = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIResponse::ActiveWorkflows { workflows } => {
                assert_eq!(workflows.len(), 1);
                assert_eq!(workflows[0].session_id, "workflow-1");
            }
            _ => panic!("Unexpected response type"),
        }
    }

    #[test]
    fn test_api_response_error() {
        let mut details = HashMap::new();
        details.insert("field".to_string(), "invalid".to_string());
        let response = APIResponse::Error {
            code: "VALIDATION_ERROR".to_string(),
            message: "Invalid parameters".to_string(),
            details: Some(details),
        };
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: APIResponse = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIResponse::Error {
                code,
                message,
                details,
            } => {
                assert_eq!(code, "VALIDATION_ERROR");
                assert_eq!(message, "Invalid parameters");
                assert!(details.is_some());
            }
            _ => panic!("Unexpected response type"),
        }
    }

    #[test]
    fn test_api_response_health_status() {
        let mut details = HashMap::new();
        details.insert("uptime".to_string(), "1234".to_string());
        let response = APIResponse::HealthStatus {
            component: "executor".to_string(),
            status: HealthStatus::Healthy,
            details,
        };
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: APIResponse = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIResponse::HealthStatus { component, .. } => {
                assert_eq!(component, "executor");
            }
            _ => panic!("Unexpected response type"),
        }
    }

    #[test]
    fn test_api_response_metrics() {
        let response = APIResponse::Metrics {
            data: "{\"cpu\": 50}".to_string(),
            format: "json".to_string(),
        };
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: APIResponse = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIResponse::Metrics { data, format } => {
                assert!(data.contains("cpu"));
                assert_eq!(format, "json");
            }
            _ => panic!("Unexpected response type"),
        }
    }

    #[test]
    fn test_api_response_intervention_result() {
        let response = APIResponse::InterventionResult {
            session_id: "intervention-session".to_string(),
            success: true,
            message: "Action completed".to_string(),
        };
        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: APIResponse = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            APIResponse::InterventionResult {
                session_id,
                success,
                message,
            } => {
                assert_eq!(session_id, "intervention-session");
                assert!(success);
                assert_eq!(message, "Action completed");
            }
            _ => panic!("Unexpected response type"),
        }
    }

    // ==================== WorkflowInfo Tests ====================

    #[tokio::test]
    async fn test_workflow_info_serialization() {
        let info = WorkflowInfo {
            session_id: "test-session".to_string(),
            workflow_type: WorkflowType::ResearchAndPlanning,
            state: WorkflowState::Executing,
            progress: 0.5,
            created_at: 1234567890,
            last_activity: 1234567900,
            duration_ms: 10000,
        };

        let serialized = serde_json::to_string(&info).unwrap();
        let deserialized: WorkflowInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.session_id, "test-session");
        assert_eq!(deserialized.progress, 0.5);
        assert_eq!(deserialized.created_at, 1234567890);
        assert_eq!(deserialized.last_activity, 1234567900);
        assert_eq!(deserialized.duration_ms, 10000);
    }

    #[test]
    fn test_workflow_info_all_states() {
        let states = [
            WorkflowState::Initializing,
            WorkflowState::Planning,
            WorkflowState::Executing,
            WorkflowState::Paused,
            WorkflowState::Completed,
        ];

        for state in states {
            let info = WorkflowInfo {
                session_id: "state-test".to_string(),
                workflow_type: WorkflowType::Simple,
                state: state.clone(),
                progress: 0.0,
                created_at: 0,
                last_activity: 0,
                duration_ms: 0,
            };
            let serialized = serde_json::to_string(&info).unwrap();
            let deserialized: WorkflowInfo = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized.session_id, "state-test");
        }
    }

    // ==================== APIEvent Tests ====================

    #[test]
    fn test_api_event_workflow_started() {
        let event = APIEvent::WorkflowStarted {
            session_id: "event-session".to_string(),
            workflow_type: WorkflowType::ResearchAndPlanning,
        };
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("WorkflowStarted"));
        assert!(serialized.contains("event-session"));
    }

    #[test]
    fn test_api_event_workflow_failed() {
        let event = APIEvent::WorkflowFailed {
            session_id: "failed-session".to_string(),
            error: "Test error".to_string(),
        };
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("WorkflowFailed"));
        assert!(serialized.contains("Test error"));
    }

    #[test]
    fn test_api_event_state_transition() {
        let event = APIEvent::StateTransition {
            session_id: "transition-session".to_string(),
            from_state: WorkflowState::Planning,
            to_state: WorkflowState::Executing,
        };
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("StateTransition"));
    }

    #[test]
    fn test_api_event_user_intervention() {
        let event = APIEvent::UserIntervention {
            session_id: "user-session".to_string(),
            intervention_type: "approval".to_string(),
        };
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("UserIntervention"));
        assert!(serialized.contains("approval"));
    }

    #[test]
    fn test_api_event_system_error() {
        let event = APIEvent::SystemError {
            session_id: "error-session".to_string(),
            error: "System failure".to_string(),
        };
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("SystemError"));
    }

    #[test]
    fn test_api_event_health_check() {
        let event = APIEvent::HealthCheck {
            component: "nats".to_string(),
            status: HealthStatus::Healthy,
        };
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("HealthCheck"));
        assert!(serialized.contains("nats"));
    }

    #[test]
    fn test_api_event_clone() {
        let event = APIEvent::WorkflowStarted {
            session_id: "clone-test".to_string(),
            workflow_type: WorkflowType::Simple,
        };
        let cloned = event.clone();
        let serialized = serde_json::to_string(&cloned).unwrap();
        assert!(serialized.contains("clone-test"));
    }

    // ==================== convert_resource_utilization Tests ====================

    #[test]
    fn test_convert_resource_utilization() {
        let util = ResourceUtilization {
            avg_memory_mb: 128.0,
            peak_memory_mb: 256.0,
            avg_cpu_percent: 50.0,
            peak_cpu_percent: 80.0,
            network_io_mb: 10.0,
            disk_io_mb: 5.0,
            execution_efficiency: 0.95,
        };
        let usage = convert_resource_utilization(&util);
        assert_eq!(usage.cpu_ms, 50000); // 50.0 * 1000
        assert_eq!(usage.memory_bytes, 268435456); // 256 * 1024 * 1024
        assert_eq!(usage.network_requests, 100); // 10.0 * 10
        assert_eq!(usage.fs_operations, 0);
    }

    #[test]
    fn test_convert_resource_utilization_zero() {
        let util = ResourceUtilization {
            avg_memory_mb: 0.0,
            peak_memory_mb: 0.0,
            avg_cpu_percent: 0.0,
            peak_cpu_percent: 0.0,
            network_io_mb: 0.0,
            disk_io_mb: 0.0,
            execution_efficiency: 0.0,
        };
        let usage = convert_resource_utilization(&util);
        assert_eq!(usage.cpu_ms, 0);
        assert_eq!(usage.memory_bytes, 0);
        assert_eq!(usage.network_requests, 0);
    }

    #[test]
    fn test_convert_resource_utilization_high_values() {
        let util = ResourceUtilization {
            avg_memory_mb: 512.0,
            peak_memory_mb: 1024.0,
            avg_cpu_percent: 100.0,
            peak_cpu_percent: 100.0,
            network_io_mb: 100.0,
            disk_io_mb: 50.0,
            execution_efficiency: 1.0,
        };
        let usage = convert_resource_utilization(&util);
        assert_eq!(usage.cpu_ms, 100000);
        assert_eq!(usage.memory_bytes, 1073741824); // 1GB
        assert_eq!(usage.network_requests, 1000);
    }
}
