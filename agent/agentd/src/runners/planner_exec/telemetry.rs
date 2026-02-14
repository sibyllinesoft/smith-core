// telemetry.rs - Comprehensive observability and metrics collection for planner-executor

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::runners::planner_exec::schemas::{
    ActionResult, ActionStatus, RiskLevel, WorkflowAction, WorkflowType,
};

/// Telemetry collector for planner-executor workflows
#[derive(Debug)]
pub struct TelemetryCollector {
    metrics: Arc<RwLock<MetricsStorage>>,
    session_id: String,
    workflow_type: Option<WorkflowType>,
    start_time: Instant,
}

/// Storage for collected metrics and events
#[derive(Debug, Default)]
struct MetricsStorage {
    counters: HashMap<String, u64>,
    gauges: HashMap<String, f64>,
    histograms: HashMap<String, Vec<f64>>,
    events: Vec<TelemetryEvent>,
    state_transitions: Vec<StateTransition>,
    performance_metrics: PerformanceMetrics,
    error_tracking: ErrorTracking,
}

/// Individual telemetry event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub timestamp: u64,
    pub event_type: EventType,
    pub session_id: String,
    pub component: String,
    pub message: String,
    pub metadata: HashMap<String, String>,
    pub severity: Severity,
}

/// Types of telemetry events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    WorkflowStart,
    WorkflowComplete,
    WorkflowFailed,
    ActionExecuted,
    StateTransition,
    StallDetected,
    UserIntervention,
    SecurityViolation,
    ResourceLimit,
    PerformanceWarning,
    SystemError,
    Custom(String),
}

/// Event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// State transition tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub timestamp: u64,
    pub from_state: String,
    pub to_state: String,
    pub trigger: String,
    pub duration_ms: u64,
    pub metadata: HashMap<String, String>,
}

/// Performance metrics aggregation
#[derive(Debug, Default)]
struct PerformanceMetrics {
    action_durations: HashMap<String, Vec<Duration>>,
    memory_usage: Vec<(u64, usize)>,  // timestamp, bytes
    cpu_usage: Vec<(u64, f64)>,       // timestamp, percentage
    throughput: HashMap<String, u64>, // operations per type
    queue_depths: Vec<(u64, usize)>,  // timestamp, queue size
}

/// Error tracking and categorization
#[derive(Debug, Default)]
struct ErrorTracking {
    error_counts: HashMap<String, u64>,
    error_patterns: Vec<ErrorPattern>,
    recovery_attempts: Vec<RecoveryAttempt>,
    mttr_metrics: Vec<Duration>, // Mean Time To Recovery
}

/// Error pattern detection
#[derive(Debug, Clone)]
struct ErrorPattern {
    pattern_id: String,
    frequency: u64,
    last_occurrence: u64,
    impact_level: RiskLevel,
    suggested_mitigation: String,
}

/// Recovery attempt tracking
#[derive(Debug, Clone)]
struct RecoveryAttempt {
    timestamp: u64,
    error_type: String,
    recovery_strategy: String,
    success: bool,
    duration: Duration,
}

/// Telemetry export formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Prometheus,
    OpenTelemetry,
    InfluxDB,
    Custom(String),
}

/// Comprehensive telemetry report
#[derive(Debug, Serialize, Deserialize)]
pub struct TelemetryReport {
    pub session_id: String,
    pub workflow_type: Option<WorkflowType>,
    pub duration_ms: u64,
    pub total_actions: u64,
    pub successful_actions: u64,
    pub failed_actions: u64,
    pub state_transitions: u64,
    pub performance_summary: PerformanceSummary,
    pub error_summary: ErrorSummary,
    pub resource_utilization: ResourceUtilization,
    pub recommendations: Vec<String>,
    pub events: Vec<TelemetryEvent>,
}

/// Performance metrics summary
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub avg_action_duration_ms: f64,
    pub max_action_duration_ms: f64,
    pub min_action_duration_ms: f64,
    pub p95_action_duration_ms: f64,
    pub throughput_actions_per_sec: f64,
    pub peak_memory_usage_mb: f64,
    pub avg_cpu_usage_percent: f64,
    pub peak_queue_depth: usize,
}

/// Error analysis summary
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorSummary {
    pub total_errors: u64,
    pub error_rate_percent: f64,
    pub most_common_error: Option<String>,
    pub avg_recovery_time_ms: f64,
    pub successful_recoveries: u64,
    pub failed_recoveries: u64,
    pub detected_patterns: Vec<String>,
}

/// Resource utilization tracking
#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceUtilization {
    pub avg_memory_mb: f64,
    pub peak_memory_mb: f64,
    pub avg_cpu_percent: f64,
    pub peak_cpu_percent: f64,
    pub network_io_mb: f64,
    pub disk_io_mb: f64,
    pub execution_efficiency: f64, // successful actions / total actions
}

impl TelemetryCollector {
    /// Create a new telemetry collector
    pub fn new(session_id: String, workflow_type: Option<WorkflowType>) -> Self {
        debug!("Creating telemetry collector for session: {}", session_id);

        Self {
            metrics: Arc::new(RwLock::new(MetricsStorage::default())),
            session_id,
            workflow_type,
            start_time: Instant::now(),
        }
    }

    /// Record a telemetry event
    pub async fn record_event(
        &self,
        event_type: EventType,
        component: &str,
        message: &str,
        metadata: HashMap<String, String>,
        severity: Severity,
    ) {
        let event = TelemetryEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            event_type: event_type.clone(),
            session_id: self.session_id.clone(),
            component: component.to_string(),
            message: message.to_string(),
            metadata,
            severity: severity.clone(),
        };

        // Log the event
        match severity {
            Severity::Debug => debug!("[{}] {}: {}", component, message, self.session_id),
            Severity::Info => info!("[{}] {}: {}", component, message, self.session_id),
            Severity::Warning => warn!("[{}] {}: {}", component, message, self.session_id),
            Severity::Error | Severity::Critical => {
                error!("[{}] {}: {}", component, message, self.session_id)
            }
        }

        let mut metrics = self.metrics.write().await;
        metrics.events.push(event);

        // Update counters based on event type
        match event_type {
            EventType::ActionExecuted => {
                *metrics
                    .counters
                    .entry("actions_executed".to_string())
                    .or_insert(0) += 1;
            }
            EventType::StallDetected => {
                *metrics
                    .counters
                    .entry("stalls_detected".to_string())
                    .or_insert(0) += 1;
            }
            EventType::SecurityViolation => {
                *metrics
                    .counters
                    .entry("security_violations".to_string())
                    .or_insert(0) += 1;
            }
            EventType::SystemError => {
                *metrics
                    .counters
                    .entry("system_errors".to_string())
                    .or_insert(0) += 1;
            }
            _ => {}
        }
    }

    /// Record action execution metrics
    pub async fn record_action_execution(
        &self,
        action: &WorkflowAction,
        result: &ActionResult,
        duration: Duration,
    ) {
        let mut metadata = HashMap::new();
        metadata.insert("action_id".to_string(), action.id.clone());
        metadata.insert("action_type".to_string(), action.action_type.to_string());
        metadata.insert("duration_ms".to_string(), duration.as_millis().to_string());
        metadata.insert("status".to_string(), format!("{:?}", result.status));

        let (event_type, severity) = match result.status {
            ActionStatus::Completed => (EventType::ActionExecuted, Severity::Info),
            ActionStatus::Failed => (EventType::ActionExecuted, Severity::Error),
            ActionStatus::Skipped => (EventType::ActionExecuted, Severity::Warning),
            _ => (EventType::ActionExecuted, Severity::Debug),
        };

        self.record_event(
            event_type,
            "action_executor",
            &format!(
                "Action {} executed with status {:?}",
                action.id, result.status
            ),
            metadata,
            severity,
        )
        .await;

        // Update performance metrics
        let mut metrics = self.metrics.write().await;
        metrics
            .performance_metrics
            .action_durations
            .entry(action.action_type.to_string())
            .or_insert_with(Vec::new)
            .push(duration);

        *metrics
            .performance_metrics
            .throughput
            .entry(action.action_type.to_string())
            .or_insert(0) += 1;
    }

    /// Record state transition
    pub async fn record_state_transition(
        &self,
        from_state: &str,
        to_state: &str,
        trigger: &str,
        duration: Duration,
        metadata: HashMap<String, String>,
    ) {
        let transition = StateTransition {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            from_state: from_state.to_string(),
            to_state: to_state.to_string(),
            trigger: trigger.to_string(),
            duration_ms: duration.as_millis() as u64,
            metadata: metadata.clone(),
        };

        let mut event_metadata = metadata;
        event_metadata.insert("from_state".to_string(), from_state.to_string());
        event_metadata.insert("to_state".to_string(), to_state.to_string());
        event_metadata.insert("trigger".to_string(), trigger.to_string());

        self.record_event(
            EventType::StateTransition,
            "state_machine",
            &format!("State transition: {} -> {}", from_state, to_state),
            event_metadata,
            Severity::Info,
        )
        .await;

        let mut metrics = self.metrics.write().await;
        metrics.state_transitions.push(transition);
    }

    /// Record resource usage
    pub async fn record_resource_usage(
        &self,
        memory_mb: f64,
        cpu_percent: f64,
        queue_depth: usize,
    ) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut metrics = self.metrics.write().await;
        metrics
            .performance_metrics
            .memory_usage
            .push((timestamp, memory_mb as usize));
        metrics
            .performance_metrics
            .cpu_usage
            .push((timestamp, cpu_percent));
        metrics
            .performance_metrics
            .queue_depths
            .push((timestamp, queue_depth));

        // Update gauges
        metrics
            .gauges
            .insert("current_memory_mb".to_string(), memory_mb);
        metrics
            .gauges
            .insert("current_cpu_percent".to_string(), cpu_percent);
        metrics
            .gauges
            .insert("current_queue_depth".to_string(), queue_depth as f64);
    }

    /// Record error and recovery attempt
    pub async fn record_error_recovery(
        &self,
        error_type: &str,
        recovery_strategy: &str,
        success: bool,
        duration: Duration,
    ) {
        let recovery = RecoveryAttempt {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            error_type: error_type.to_string(),
            recovery_strategy: recovery_strategy.to_string(),
            success,
            duration,
        };

        let mut metadata = HashMap::new();
        metadata.insert("error_type".to_string(), error_type.to_string());
        metadata.insert(
            "recovery_strategy".to_string(),
            recovery_strategy.to_string(),
        );
        metadata.insert("success".to_string(), success.to_string());
        metadata.insert("duration_ms".to_string(), duration.as_millis().to_string());

        let severity = if success {
            Severity::Info
        } else {
            Severity::Warning
        };

        self.record_event(
            EventType::Custom("error_recovery".to_string()),
            "recovery_system",
            &format!(
                "Recovery attempt for {}: {}",
                error_type,
                if success { "SUCCESS" } else { "FAILED" }
            ),
            metadata,
            severity,
        )
        .await;

        let mut metrics = self.metrics.write().await;
        metrics.error_tracking.recovery_attempts.push(recovery);

        if success {
            metrics.error_tracking.mttr_metrics.push(duration);
        }

        *metrics
            .error_tracking
            .error_counts
            .entry(error_type.to_string())
            .or_insert(0) += 1;
    }

    /// Generate comprehensive telemetry report
    pub async fn generate_report(&self) -> TelemetryReport {
        let metrics = self.metrics.read().await;
        let total_duration = self.start_time.elapsed();

        let total_actions = metrics
            .counters
            .get("actions_executed")
            .copied()
            .unwrap_or(0);
        let successful_actions = metrics
            .events
            .iter()
            .filter(|e| {
                matches!(e.event_type, EventType::ActionExecuted)
                    && e.metadata
                        .get("status")
                        .map_or(false, |s| s.contains("Completed"))
            })
            .count() as u64;
        let failed_actions = total_actions - successful_actions;

        TelemetryReport {
            session_id: self.session_id.clone(),
            workflow_type: self.workflow_type.clone(),
            duration_ms: total_duration.as_millis() as u64,
            total_actions,
            successful_actions,
            failed_actions,
            state_transitions: metrics.state_transitions.len() as u64,
            performance_summary: self.calculate_performance_summary(&metrics).await,
            error_summary: self.calculate_error_summary(&metrics).await,
            resource_utilization: self.calculate_resource_utilization(&metrics).await,
            recommendations: self.generate_recommendations(&metrics).await,
            events: metrics.events.clone(),
        }
    }

    /// Export telemetry data in specified format
    pub async fn export_telemetry(
        &self,
        format: ExportFormat,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let report = self.generate_report().await;

        match format {
            ExportFormat::Json => Ok(serde_json::to_string_pretty(&report)?),
            ExportFormat::Prometheus => Ok(self.export_prometheus_format(&report).await),
            ExportFormat::OpenTelemetry => Ok(self.export_otel_format(&report).await),
            ExportFormat::InfluxDB => Ok(self.export_influxdb_format(&report).await),
            ExportFormat::Custom(format_name) => {
                warn!(
                    "Custom format '{}' not implemented, using JSON",
                    format_name
                );
                Ok(serde_json::to_string_pretty(&report)?)
            }
        }
    }

    // Private helper methods

    async fn calculate_performance_summary(&self, metrics: &MetricsStorage) -> PerformanceSummary {
        let all_durations: Vec<f64> = metrics
            .performance_metrics
            .action_durations
            .values()
            .flatten()
            .map(|d| d.as_millis() as f64)
            .collect();

        let (avg_duration, max_duration, min_duration, p95_duration) = if all_durations.is_empty() {
            (0.0, 0.0, 0.0, 0.0)
        } else {
            let avg = all_durations.iter().sum::<f64>() / all_durations.len() as f64;
            let max = all_durations.iter().copied().fold(0.0f64, f64::max);
            let min = all_durations.iter().copied().fold(f64::MAX, f64::min);

            let mut sorted = all_durations.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p95_idx = (sorted.len() as f64 * 0.95) as usize;
            let p95 = sorted.get(p95_idx).copied().unwrap_or(0.0);

            (avg, max, min, p95)
        };

        let total_duration = self.start_time.elapsed().as_secs_f64();
        let throughput = if total_duration > 0.0 {
            all_durations.len() as f64 / total_duration
        } else {
            0.0
        };

        let peak_memory = metrics
            .performance_metrics
            .memory_usage
            .iter()
            .map(|(_, mem)| *mem as f64)
            .fold(0.0f64, f64::max);

        let avg_cpu = if metrics.performance_metrics.cpu_usage.is_empty() {
            0.0
        } else {
            metrics
                .performance_metrics
                .cpu_usage
                .iter()
                .map(|(_, cpu)| *cpu)
                .sum::<f64>()
                / metrics.performance_metrics.cpu_usage.len() as f64
        };

        let peak_queue_depth = metrics
            .performance_metrics
            .queue_depths
            .iter()
            .map(|(_, depth)| *depth)
            .max()
            .unwrap_or(0);

        PerformanceSummary {
            avg_action_duration_ms: avg_duration,
            max_action_duration_ms: max_duration,
            min_action_duration_ms: min_duration,
            p95_action_duration_ms: p95_duration,
            throughput_actions_per_sec: throughput,
            peak_memory_usage_mb: peak_memory,
            avg_cpu_usage_percent: avg_cpu,
            peak_queue_depth,
        }
    }

    async fn calculate_error_summary(&self, metrics: &MetricsStorage) -> ErrorSummary {
        let total_errors = metrics.error_tracking.error_counts.values().sum();
        let total_actions = metrics
            .counters
            .get("actions_executed")
            .copied()
            .unwrap_or(0);

        let error_rate = if total_actions > 0 {
            (total_errors as f64 / total_actions as f64) * 100.0
        } else {
            0.0
        };

        let most_common_error = metrics
            .error_tracking
            .error_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(error_type, _)| error_type.clone());

        let avg_recovery_time = if metrics.error_tracking.mttr_metrics.is_empty() {
            0.0
        } else {
            let total_recovery_time: Duration = metrics.error_tracking.mttr_metrics.iter().sum();
            total_recovery_time.as_millis() as f64
                / metrics.error_tracking.mttr_metrics.len() as f64
        };

        let successful_recoveries = metrics
            .error_tracking
            .recovery_attempts
            .iter()
            .filter(|attempt| attempt.success)
            .count() as u64;

        let failed_recoveries =
            metrics.error_tracking.recovery_attempts.len() as u64 - successful_recoveries;

        let detected_patterns = metrics
            .error_tracking
            .error_patterns
            .iter()
            .map(|pattern| pattern.pattern_id.clone())
            .collect();

        ErrorSummary {
            total_errors,
            error_rate_percent: error_rate,
            most_common_error,
            avg_recovery_time_ms: avg_recovery_time,
            successful_recoveries,
            failed_recoveries,
            detected_patterns,
        }
    }

    async fn calculate_resource_utilization(
        &self,
        metrics: &MetricsStorage,
    ) -> ResourceUtilization {
        let avg_memory = if metrics.performance_metrics.memory_usage.is_empty() {
            0.0
        } else {
            metrics
                .performance_metrics
                .memory_usage
                .iter()
                .map(|(_, mem)| *mem as f64)
                .sum::<f64>()
                / metrics.performance_metrics.memory_usage.len() as f64
        };

        let peak_memory = metrics
            .performance_metrics
            .memory_usage
            .iter()
            .map(|(_, mem)| *mem as f64)
            .fold(0.0f64, f64::max);

        let avg_cpu = if metrics.performance_metrics.cpu_usage.is_empty() {
            0.0
        } else {
            metrics
                .performance_metrics
                .cpu_usage
                .iter()
                .map(|(_, cpu)| *cpu)
                .sum::<f64>()
                / metrics.performance_metrics.cpu_usage.len() as f64
        };

        let peak_cpu = metrics
            .performance_metrics
            .cpu_usage
            .iter()
            .map(|(_, cpu)| *cpu)
            .fold(0.0f64, f64::max);

        let total_actions = metrics
            .counters
            .get("actions_executed")
            .copied()
            .unwrap_or(0);
        let successful_actions = metrics
            .events
            .iter()
            .filter(|e| {
                matches!(e.event_type, EventType::ActionExecuted)
                    && e.metadata
                        .get("status")
                        .map_or(false, |s| s.contains("Completed"))
            })
            .count() as u64;

        let execution_efficiency = if total_actions > 0 {
            successful_actions as f64 / total_actions as f64
        } else {
            0.0
        };

        ResourceUtilization {
            avg_memory_mb: avg_memory,
            peak_memory_mb: peak_memory,
            avg_cpu_percent: avg_cpu,
            peak_cpu_percent: peak_cpu,
            network_io_mb: 0.0, // TODO: Implement network I/O tracking
            disk_io_mb: 0.0,    // TODO: Implement disk I/O tracking
            execution_efficiency,
        }
    }

    async fn generate_recommendations(&self, metrics: &MetricsStorage) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Performance recommendations
        let avg_memory = metrics
            .gauges
            .get("current_memory_mb")
            .copied()
            .unwrap_or(0.0);
        if avg_memory > 1000.0 {
            recommendations
                .push("Consider optimizing memory usage - current usage exceeds 1GB".to_string());
        }

        let avg_cpu = metrics
            .gauges
            .get("current_cpu_percent")
            .copied()
            .unwrap_or(0.0);
        if avg_cpu > 80.0 {
            recommendations
                .push("High CPU usage detected - consider scaling or optimization".to_string());
        }

        // Error rate recommendations
        let total_errors = metrics.error_tracking.error_counts.values().sum::<u64>();
        let total_actions = metrics
            .counters
            .get("actions_executed")
            .copied()
            .unwrap_or(0);
        if total_actions > 0 && (total_errors as f64 / total_actions as f64) > 0.1 {
            recommendations
                .push("High error rate (>10%) - review action implementations".to_string());
        }

        // Stall detection recommendations
        let stalls = metrics
            .counters
            .get("stalls_detected")
            .copied()
            .unwrap_or(0);
        if stalls > 5 {
            recommendations.push(
                "Multiple stalls detected - review workflow logic and dependencies".to_string(),
            );
        }

        if recommendations.is_empty() {
            recommendations.push("System performance is within normal parameters".to_string());
        }

        recommendations
    }

    async fn export_prometheus_format(&self, report: &TelemetryReport) -> String {
        format!(
            r#"# HELP planner_exec_duration_seconds Total workflow duration
# TYPE planner_exec_duration_seconds gauge
planner_exec_duration_seconds{{session_id="{}"}} {}

# HELP planner_exec_actions_total Total number of actions executed
# TYPE planner_exec_actions_total counter
planner_exec_actions_total{{session_id="{}"}} {}

# HELP planner_exec_actions_success_rate Success rate of actions
# TYPE planner_exec_actions_success_rate gauge
planner_exec_actions_success_rate{{session_id="{}"}} {}

# HELP planner_exec_memory_usage_bytes Peak memory usage
# TYPE planner_exec_memory_usage_bytes gauge
planner_exec_memory_usage_bytes{{session_id="{}"}} {}

# HELP planner_exec_cpu_usage_percent Average CPU usage
# TYPE planner_exec_cpu_usage_percent gauge
planner_exec_cpu_usage_percent{{session_id="{}"}} {}
"#,
            report.session_id,
            report.duration_ms as f64 / 1000.0,
            report.session_id,
            report.total_actions,
            report.session_id,
            if report.total_actions > 0 {
                report.successful_actions as f64 / report.total_actions as f64
            } else {
                0.0
            },
            report.session_id,
            report.resource_utilization.peak_memory_mb * 1024.0 * 1024.0,
            report.session_id,
            report.resource_utilization.avg_cpu_percent,
        )
    }

    async fn export_otel_format(&self, report: &TelemetryReport) -> String {
        // Simplified OpenTelemetry-style JSON format
        serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "planner-executor"}},
                        {"key": "service.version", "value": {"stringValue": "1.0.0"}},
                        {"key": "session.id", "value": {"stringValue": report.session_id}}
                    ]
                },
                "spans": report.events.iter().map(|event| {
                    serde_json::json!({
                        "traceId": format!("{:016x}{:016x}", 0u64, event.timestamp),
                        "spanId": format!("{:016x}", event.timestamp),
                        "name": format!("{:?}", event.event_type),
                        "startTimeUnixNano": event.timestamp * 1_000_000,
                        "endTimeUnixNano": (event.timestamp + 1) * 1_000_000,
                        "attributes": event.metadata.iter().map(|(k, v)| {
                            serde_json::json!({
                                "key": k,
                                "value": {"stringValue": v}
                            })
                        }).collect::<Vec<_>>()
                    })
                }).collect::<Vec<_>>()
            }]
        })
        .to_string()
    }

    async fn export_influxdb_format(&self, report: &TelemetryReport) -> String {
        let mut lines = Vec::new();

        // Main workflow metrics
        lines.push(format!(
            "planner_exec,session_id={} duration_ms={},total_actions={},successful_actions={},failed_actions={} {}",
            report.session_id,
            report.duration_ms,
            report.total_actions,
            report.successful_actions,
            report.failed_actions,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        // Performance metrics
        lines.push(format!(
            "planner_exec_performance,session_id={} avg_action_duration_ms={},throughput_per_sec={},peak_memory_mb={},avg_cpu_percent={} {}",
            report.session_id,
            report.performance_summary.avg_action_duration_ms,
            report.performance_summary.throughput_actions_per_sec,
            report.performance_summary.peak_memory_usage_mb,
            report.performance_summary.avg_cpu_usage_percent,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_telemetry_collector_creation() {
        let collector =
            TelemetryCollector::new("test-session".to_string(), Some(WorkflowType::Simple));

        assert_eq!(collector.session_id, "test-session");
        assert_eq!(collector.workflow_type, Some(WorkflowType::Simple));
    }

    #[tokio::test]
    async fn test_event_recording() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let mut metadata = HashMap::new();
        metadata.insert("test_key".to_string(), "test_value".to_string());

        collector
            .record_event(
                EventType::WorkflowStart,
                "test_component",
                "Test message",
                metadata,
                Severity::Info,
            )
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].component, "test_component");
        assert_eq!(report.events[0].message, "Test message");
    }

    #[tokio::test]
    async fn test_performance_metrics() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Record some resource usage
        collector.record_resource_usage(100.0, 50.0, 5).await;
        collector.record_resource_usage(150.0, 60.0, 3).await;

        let report = collector.generate_report().await;
        assert!(report.resource_utilization.peak_memory_mb >= 150.0);
        assert!(report.resource_utilization.avg_cpu_percent > 0.0);
    }

    #[tokio::test]
    async fn test_export_formats() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Test JSON export
        let json_export = collector
            .export_telemetry(ExportFormat::Json)
            .await
            .unwrap();
        assert!(json_export.contains("test-session"));

        // Test Prometheus export
        let prometheus_export = collector
            .export_telemetry(ExportFormat::Prometheus)
            .await
            .unwrap();
        assert!(prometheus_export.contains("planner_exec_duration_seconds"));

        // Test InfluxDB export
        let influx_export = collector
            .export_telemetry(ExportFormat::InfluxDB)
            .await
            .unwrap();
        assert!(influx_export.contains("planner_exec,session_id=test-session"));
    }

    #[tokio::test]
    async fn test_error_tracking() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector
            .record_error_recovery(
                "timeout_error",
                "retry_with_backoff",
                true,
                Duration::from_millis(500),
            )
            .await;

        collector
            .record_error_recovery(
                "network_error",
                "circuit_breaker",
                false,
                Duration::from_millis(1000),
            )
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.error_summary.successful_recoveries, 1);
        assert_eq!(report.error_summary.failed_recoveries, 1);
        assert!(report.error_summary.avg_recovery_time_ms > 0.0);
    }

    #[tokio::test]
    async fn test_recommendations_generation() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Simulate high resource usage to trigger recommendations
        collector.record_resource_usage(2000.0, 90.0, 10).await;

        let report = collector.generate_report().await;
        assert!(!report.recommendations.is_empty());
        assert!(report.recommendations.iter().any(|r| r.contains("memory")));
        assert!(report.recommendations.iter().any(|r| r.contains("CPU")));
    }

    // ==================== EventType Serialization Tests ====================

    #[test]
    fn test_event_type_workflow_start_serialization() {
        let event_type = EventType::WorkflowStart;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("WorkflowStart"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::WorkflowStart));
    }

    #[test]
    fn test_event_type_workflow_complete_serialization() {
        let event_type = EventType::WorkflowComplete;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("WorkflowComplete"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::WorkflowComplete));
    }

    #[test]
    fn test_event_type_workflow_failed_serialization() {
        let event_type = EventType::WorkflowFailed;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("WorkflowFailed"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::WorkflowFailed));
    }

    #[test]
    fn test_event_type_action_executed_serialization() {
        let event_type = EventType::ActionExecuted;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("ActionExecuted"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::ActionExecuted));
    }

    #[test]
    fn test_event_type_state_transition_serialization() {
        let event_type = EventType::StateTransition;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("StateTransition"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::StateTransition));
    }

    #[test]
    fn test_event_type_stall_detected_serialization() {
        let event_type = EventType::StallDetected;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("StallDetected"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::StallDetected));
    }

    #[test]
    fn test_event_type_user_intervention_serialization() {
        let event_type = EventType::UserIntervention;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("UserIntervention"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::UserIntervention));
    }

    #[test]
    fn test_event_type_security_violation_serialization() {
        let event_type = EventType::SecurityViolation;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("SecurityViolation"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::SecurityViolation));
    }

    #[test]
    fn test_event_type_resource_limit_serialization() {
        let event_type = EventType::ResourceLimit;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("ResourceLimit"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::ResourceLimit));
    }

    #[test]
    fn test_event_type_performance_warning_serialization() {
        let event_type = EventType::PerformanceWarning;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("PerformanceWarning"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::PerformanceWarning));
    }

    #[test]
    fn test_event_type_system_error_serialization() {
        let event_type = EventType::SystemError;
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("SystemError"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventType::SystemError));
    }

    #[test]
    fn test_event_type_custom_serialization() {
        let event_type = EventType::Custom("custom_event".to_string());
        let json = serde_json::to_string(&event_type).unwrap();
        assert!(json.contains("Custom"));
        assert!(json.contains("custom_event"));
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        if let EventType::Custom(name) = parsed {
            assert_eq!(name, "custom_event");
        } else {
            panic!("Expected Custom event type");
        }
    }

    // ==================== Severity Serialization Tests ====================

    #[test]
    fn test_severity_debug_serialization() {
        let severity = Severity::Debug;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("Debug"));
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Severity::Debug));
    }

    #[test]
    fn test_severity_info_serialization() {
        let severity = Severity::Info;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("Info"));
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Severity::Info));
    }

    #[test]
    fn test_severity_warning_serialization() {
        let severity = Severity::Warning;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("Warning"));
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Severity::Warning));
    }

    #[test]
    fn test_severity_error_serialization() {
        let severity = Severity::Error;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("Error"));
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Severity::Error));
    }

    #[test]
    fn test_severity_critical_serialization() {
        let severity = Severity::Critical;
        let json = serde_json::to_string(&severity).unwrap();
        assert!(json.contains("Critical"));
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Severity::Critical));
    }

    // ==================== ExportFormat Serialization Tests ====================

    #[test]
    fn test_export_format_json_serialization() {
        let format = ExportFormat::Json;
        let json = serde_json::to_string(&format).unwrap();
        assert!(json.contains("Json"));
        let parsed: ExportFormat = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ExportFormat::Json));
    }

    #[test]
    fn test_export_format_prometheus_serialization() {
        let format = ExportFormat::Prometheus;
        let json = serde_json::to_string(&format).unwrap();
        assert!(json.contains("Prometheus"));
        let parsed: ExportFormat = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ExportFormat::Prometheus));
    }

    #[test]
    fn test_export_format_opentelemetry_serialization() {
        let format = ExportFormat::OpenTelemetry;
        let json = serde_json::to_string(&format).unwrap();
        assert!(json.contains("OpenTelemetry"));
        let parsed: ExportFormat = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ExportFormat::OpenTelemetry));
    }

    #[test]
    fn test_export_format_influxdb_serialization() {
        let format = ExportFormat::InfluxDB;
        let json = serde_json::to_string(&format).unwrap();
        assert!(json.contains("InfluxDB"));
        let parsed: ExportFormat = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ExportFormat::InfluxDB));
    }

    #[test]
    fn test_export_format_custom_serialization() {
        let format = ExportFormat::Custom("my_format".to_string());
        let json = serde_json::to_string(&format).unwrap();
        assert!(json.contains("Custom"));
        assert!(json.contains("my_format"));
        let parsed: ExportFormat = serde_json::from_str(&json).unwrap();
        if let ExportFormat::Custom(name) = parsed {
            assert_eq!(name, "my_format");
        } else {
            panic!("Expected Custom format");
        }
    }

    // ==================== StateTransition Serialization Tests ====================

    #[test]
    fn test_state_transition_serialization() {
        let transition = StateTransition {
            timestamp: 1234567890,
            from_state: "Planning".to_string(),
            to_state: "Executing".to_string(),
            trigger: "plan_complete".to_string(),
            duration_ms: 1500,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&transition).unwrap();
        assert!(json.contains("1234567890"));
        assert!(json.contains("Planning"));
        assert!(json.contains("Executing"));
        let parsed: StateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.from_state, "Planning");
        assert_eq!(parsed.to_state, "Executing");
        assert_eq!(parsed.duration_ms, 1500);
    }

    // ==================== TelemetryEvent Serialization Tests ====================

    #[test]
    fn test_telemetry_event_serialization() {
        let mut metadata = HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        let event = TelemetryEvent {
            timestamp: 1234567890,
            event_type: EventType::ActionExecuted,
            session_id: "session-123".to_string(),
            component: "test_component".to_string(),
            message: "Test message".to_string(),
            metadata,
            severity: Severity::Info,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("session-123"));
        assert!(json.contains("test_component"));
        assert!(json.contains("Test message"));
        let parsed: TelemetryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "session-123");
        assert_eq!(parsed.message, "Test message");
    }

    // ==================== PerformanceSummary Serialization Tests ====================

    #[test]
    fn test_performance_summary_serialization() {
        let summary = PerformanceSummary {
            avg_action_duration_ms: 150.5,
            max_action_duration_ms: 500.0,
            min_action_duration_ms: 10.0,
            p95_action_duration_ms: 450.0,
            throughput_actions_per_sec: 10.5,
            peak_memory_usage_mb: 256.0,
            avg_cpu_usage_percent: 45.5,
            peak_queue_depth: 15,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("150.5"));
        assert!(json.contains("256"));
        let parsed: PerformanceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.avg_action_duration_ms, 150.5);
        assert_eq!(parsed.peak_queue_depth, 15);
    }

    // ==================== ErrorSummary Serialization Tests ====================

    #[test]
    fn test_error_summary_serialization() {
        let summary = ErrorSummary {
            total_errors: 5,
            error_rate_percent: 2.5,
            most_common_error: Some("timeout".to_string()),
            avg_recovery_time_ms: 250.0,
            successful_recoveries: 4,
            failed_recoveries: 1,
            detected_patterns: vec!["pattern1".to_string(), "pattern2".to_string()],
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("5"));
        assert!(json.contains("timeout"));
        let parsed: ErrorSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_errors, 5);
        assert_eq!(parsed.most_common_error, Some("timeout".to_string()));
        assert_eq!(parsed.detected_patterns.len(), 2);
    }

    // ==================== ResourceUtilization Serialization Tests ====================

    #[test]
    fn test_resource_utilization_serialization() {
        let utilization = ResourceUtilization {
            avg_memory_mb: 128.5,
            peak_memory_mb: 256.0,
            avg_cpu_percent: 35.5,
            peak_cpu_percent: 85.0,
            network_io_mb: 10.5,
            disk_io_mb: 25.0,
            execution_efficiency: 0.95,
        };
        let json = serde_json::to_string(&utilization).unwrap();
        assert!(json.contains("128.5"));
        assert!(json.contains("0.95"));
        let parsed: ResourceUtilization = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.avg_memory_mb, 128.5);
        assert_eq!(parsed.execution_efficiency, 0.95);
    }

    // ==================== TelemetryReport Serialization Tests ====================

    #[test]
    fn test_telemetry_report_serialization() {
        let report = TelemetryReport {
            session_id: "test-session".to_string(),
            workflow_type: Some(WorkflowType::Simple),
            duration_ms: 5000,
            total_actions: 10,
            successful_actions: 9,
            failed_actions: 1,
            state_transitions: 5,
            performance_summary: PerformanceSummary {
                avg_action_duration_ms: 150.0,
                max_action_duration_ms: 500.0,
                min_action_duration_ms: 10.0,
                p95_action_duration_ms: 450.0,
                throughput_actions_per_sec: 2.0,
                peak_memory_usage_mb: 128.0,
                avg_cpu_usage_percent: 40.0,
                peak_queue_depth: 5,
            },
            error_summary: ErrorSummary {
                total_errors: 1,
                error_rate_percent: 10.0,
                most_common_error: None,
                avg_recovery_time_ms: 0.0,
                successful_recoveries: 0,
                failed_recoveries: 0,
                detected_patterns: vec![],
            },
            resource_utilization: ResourceUtilization {
                avg_memory_mb: 64.0,
                peak_memory_mb: 128.0,
                avg_cpu_percent: 30.0,
                peak_cpu_percent: 60.0,
                network_io_mb: 0.0,
                disk_io_mb: 0.0,
                execution_efficiency: 0.9,
            },
            recommendations: vec!["Test recommendation".to_string()],
            events: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("test-session"));
        assert!(json.contains("5000"));
        let parsed: TelemetryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "test-session");
        assert_eq!(parsed.total_actions, 10);
    }

    // ==================== Additional Collector Tests ====================

    #[tokio::test]
    async fn test_multiple_event_recording() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        for i in 0..5 {
            let mut metadata = HashMap::new();
            metadata.insert("index".to_string(), i.to_string());
            collector
                .record_event(
                    EventType::ActionExecuted,
                    "test_component",
                    &format!("Event {}", i),
                    metadata,
                    Severity::Info,
                )
                .await;
        }

        let report = collector.generate_report().await;
        assert_eq!(report.events.len(), 5);
    }

    #[tokio::test]
    async fn test_multiple_resource_recordings() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Record multiple resource samples
        collector.record_resource_usage(100.0, 30.0, 2).await;
        collector.record_resource_usage(150.0, 40.0, 3).await;
        collector.record_resource_usage(200.0, 50.0, 5).await;

        let report = collector.generate_report().await;
        assert!(report.resource_utilization.peak_memory_mb >= 200.0);
        assert!(report.resource_utilization.avg_cpu_percent > 0.0);
    }

    #[tokio::test]
    async fn test_mixed_event_severities() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector
            .record_event(
                EventType::WorkflowStart,
                "test",
                "Debug message",
                HashMap::new(),
                Severity::Debug,
            )
            .await;

        collector
            .record_event(
                EventType::ActionExecuted,
                "test",
                "Info message",
                HashMap::new(),
                Severity::Info,
            )
            .await;

        collector
            .record_event(
                EventType::PerformanceWarning,
                "test",
                "Warning message",
                HashMap::new(),
                Severity::Warning,
            )
            .await;

        collector
            .record_event(
                EventType::SecurityViolation,
                "test",
                "Critical message",
                HashMap::new(),
                Severity::Critical,
            )
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.events.len(), 4);
    }

    #[tokio::test]
    async fn test_opentelemetry_export() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector
            .record_event(
                EventType::WorkflowStart,
                "test_component",
                "Test event",
                HashMap::new(),
                Severity::Info,
            )
            .await;

        let otel_export = collector
            .export_telemetry(ExportFormat::OpenTelemetry)
            .await
            .unwrap();

        assert!(otel_export.contains("resourceSpans"));
        assert!(otel_export.contains("planner-executor"));
    }

    #[tokio::test]
    async fn test_custom_export_format() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let custom_export = collector
            .export_telemetry(ExportFormat::Custom("custom_format".to_string()))
            .await
            .unwrap();

        // Custom format falls back to JSON
        assert!(custom_export.contains("test-session"));
    }

    #[tokio::test]
    async fn test_workflow_type_tracking() {
        let collector = TelemetryCollector::new(
            "test-session".to_string(),
            Some(WorkflowType::ResearchAndPlanning),
        );

        let report = collector.generate_report().await;
        assert_eq!(
            report.workflow_type,
            Some(WorkflowType::ResearchAndPlanning)
        );
    }

    #[tokio::test]
    async fn test_empty_report() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let report = collector.generate_report().await;

        // Report should have defaults
        assert_eq!(report.session_id, "test-session");
        assert_eq!(report.total_actions, 0);
        assert_eq!(report.events.len(), 0);
        // duration_ms may be 0 for immediate report generation
    }

    #[tokio::test]
    async fn test_error_counter_increment() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector
            .record_event(
                EventType::SystemError,
                "test_component",
                "Error occurred",
                HashMap::new(),
                Severity::Error,
            )
            .await;

        collector
            .record_event(
                EventType::SystemError,
                "test_component",
                "Another error",
                HashMap::new(),
                Severity::Error,
            )
            .await;

        // Errors are tracked via events
        let report = collector.generate_report().await;
        assert_eq!(report.events.len(), 2);
    }

    // ==================== State Transition Tests ====================

    #[tokio::test]
    async fn test_state_transition_recording() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let mut metadata = HashMap::new();
        metadata.insert("trigger_reason".to_string(), "plan_complete".to_string());

        collector
            .record_state_transition(
                "Planning",
                "Executing",
                "oracle_complete",
                Duration::from_millis(500),
                metadata,
            )
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.state_transitions, 1);
        // State transition also creates an event
        assert!(!report.events.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_state_transitions() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector
            .record_state_transition(
                "Initializing",
                "Planning",
                "init_complete",
                Duration::from_millis(100),
                HashMap::new(),
            )
            .await;

        collector
            .record_state_transition(
                "Planning",
                "Executing",
                "plan_complete",
                Duration::from_millis(200),
                HashMap::new(),
            )
            .await;

        collector
            .record_state_transition(
                "Executing",
                "Completed",
                "all_actions_done",
                Duration::from_millis(1000),
                HashMap::new(),
            )
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.state_transitions, 3);
    }

    // ==================== Action Execution Tests ====================

    #[tokio::test]
    async fn test_action_execution_recording_completed() {
        use crate::runners::planner_exec::schemas::{
            ActionError, ActionMetadata, ActionResult, ActionStatus, ActionType,
            ExecutionEnvironment, ResourceUsage, WorkflowAction,
        };

        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            serde_json::json!({"path": "/test/file.txt"}),
            "Read test file".to_string(),
        );

        let result = ActionResult {
            action_id: action.id.clone(),
            status: ActionStatus::Completed,
            output: Some(serde_json::json!({"content": "file contents"})),
            error: None,
            metadata: ActionMetadata {
                retry_count: 0,
                resource_usage: ResourceUsage::default(),
                environment: ExecutionEnvironment {
                    executor_id: "exec-1".to_string(),
                    sandbox_mode: "landlock".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };

        collector
            .record_action_execution(&action, &result, Duration::from_millis(150))
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.total_actions, 1);
    }

    #[tokio::test]
    async fn test_action_execution_recording_failed() {
        use crate::runners::planner_exec::schemas::{
            ActionError, ActionMetadata, ActionResult, ActionStatus, ActionType,
            ExecutionEnvironment, ResourceUsage, WorkflowAction,
        };

        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let action = WorkflowAction::new(
            ActionType::Http("http.fetch.v1".to_string()),
            serde_json::json!({"url": "https://example.com"}),
            "Fetch data".to_string(),
        );

        let result = ActionResult {
            action_id: action.id.clone(),
            status: ActionStatus::Failed,
            output: None,
            error: Some(ActionError {
                code: "TIMEOUT".to_string(),
                message: "Request timed out".to_string(),
                details: None,
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

        collector
            .record_action_execution(&action, &result, Duration::from_millis(5000))
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.total_actions, 1);
    }

    #[tokio::test]
    async fn test_action_execution_recording_skipped() {
        use crate::runners::planner_exec::schemas::{
            ActionMetadata, ActionResult, ActionStatus, ActionType, ExecutionEnvironment,
            ResourceUsage, WorkflowAction,
        };

        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let action = WorkflowAction::new(
            ActionType::Analysis("analysis.v1".to_string()),
            serde_json::json!({}),
            "Analyze results".to_string(),
        );

        let result = ActionResult {
            action_id: action.id.clone(),
            status: ActionStatus::Skipped,
            output: None,
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

        collector
            .record_action_execution(&action, &result, Duration::from_millis(10))
            .await;

        let report = collector.generate_report().await;
        assert!(!report.events.is_empty());
    }

    // ==================== Error Recovery Tests ====================

    #[tokio::test]
    async fn test_multiple_error_recoveries() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Record multiple recovery attempts with different strategies
        collector
            .record_error_recovery("network_error", "retry", true, Duration::from_millis(100))
            .await;

        collector
            .record_error_recovery("timeout_error", "backoff", true, Duration::from_millis(500))
            .await;

        collector
            .record_error_recovery(
                "auth_error",
                "refresh_token",
                false,
                Duration::from_millis(200),
            )
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.error_summary.successful_recoveries, 2);
        assert_eq!(report.error_summary.failed_recoveries, 1);
        assert!(report.error_summary.avg_recovery_time_ms > 0.0);
    }

    #[tokio::test]
    async fn test_error_recovery_no_successful() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // All failures
        collector
            .record_error_recovery("fatal_error", "restart", false, Duration::from_millis(1000))
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.error_summary.successful_recoveries, 0);
        assert_eq!(report.error_summary.failed_recoveries, 1);
        // avg_recovery_time should be 0 since no successful recoveries
        assert_eq!(report.error_summary.avg_recovery_time_ms, 0.0);
    }

    // ==================== Event Type Counter Tests ====================

    #[tokio::test]
    async fn test_stall_detection_counter() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector
            .record_event(
                EventType::StallDetected,
                "stall_detector",
                "Stall detected",
                HashMap::new(),
                Severity::Warning,
            )
            .await;

        collector
            .record_event(
                EventType::StallDetected,
                "stall_detector",
                "Another stall",
                HashMap::new(),
                Severity::Warning,
            )
            .await;

        let report = collector.generate_report().await;
        // Stall events should be counted and appear in recommendations if > 5
        assert_eq!(report.events.len(), 2);
    }

    #[tokio::test]
    async fn test_security_violation_counter() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector
            .record_event(
                EventType::SecurityViolation,
                "guard",
                "Path traversal attempt",
                HashMap::new(),
                Severity::Error,
            )
            .await;

        let report = collector.generate_report().await;
        assert!(!report.events.is_empty());
    }

    #[tokio::test]
    async fn test_resource_limit_event() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let mut metadata = HashMap::new();
        metadata.insert("limit_type".to_string(), "memory".to_string());
        metadata.insert("current".to_string(), "1024".to_string());
        metadata.insert("max".to_string(), "512".to_string());

        collector
            .record_event(
                EventType::ResourceLimit,
                "resource_monitor",
                "Memory limit exceeded",
                metadata,
                Severity::Warning,
            )
            .await;

        let report = collector.generate_report().await;
        assert_eq!(report.events.len(), 1);
        assert!(report.events[0].metadata.contains_key("limit_type"));
    }

    // ==================== Performance Summary Edge Cases ====================

    #[tokio::test]
    async fn test_performance_summary_no_actions() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let report = collector.generate_report().await;

        // With no actions, durations should be 0
        assert_eq!(report.performance_summary.avg_action_duration_ms, 0.0);
        assert_eq!(report.performance_summary.max_action_duration_ms, 0.0);
        assert_eq!(report.performance_summary.min_action_duration_ms, 0.0);
        assert_eq!(report.performance_summary.p95_action_duration_ms, 0.0);
    }

    #[tokio::test]
    async fn test_performance_summary_no_resource_data() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let report = collector.generate_report().await;

        // With no resource recordings, values should be 0
        assert_eq!(report.resource_utilization.avg_memory_mb, 0.0);
        assert_eq!(report.resource_utilization.peak_memory_mb, 0.0);
        assert_eq!(report.resource_utilization.avg_cpu_percent, 0.0);
        assert_eq!(report.resource_utilization.peak_cpu_percent, 0.0);
    }

    #[tokio::test]
    async fn test_execution_efficiency_zero_actions() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        let report = collector.generate_report().await;

        // With 0 total actions, efficiency should be 0
        assert_eq!(report.resource_utilization.execution_efficiency, 0.0);
    }

    // ==================== Recommendations Logic Tests ====================

    #[tokio::test]
    async fn test_recommendations_normal_usage() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Normal usage - no high values
        collector.record_resource_usage(100.0, 30.0, 2).await;

        let report = collector.generate_report().await;
        assert!(!report.recommendations.is_empty());
        // Should have the "within normal parameters" recommendation
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.contains("normal parameters")));
    }

    #[tokio::test]
    async fn test_recommendations_high_memory() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // High memory usage (>1000 MB)
        collector.record_resource_usage(1500.0, 30.0, 2).await;

        let report = collector.generate_report().await;
        assert!(report.recommendations.iter().any(|r| r.contains("memory")));
    }

    #[tokio::test]
    async fn test_recommendations_high_cpu() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // High CPU usage (>80%)
        collector.record_resource_usage(100.0, 95.0, 2).await;

        let report = collector.generate_report().await;
        assert!(report.recommendations.iter().any(|r| r.contains("CPU")));
    }

    #[tokio::test]
    async fn test_recommendations_many_stalls() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Record more than 5 stalls
        for i in 0..6 {
            collector
                .record_event(
                    EventType::StallDetected,
                    "stall_detector",
                    &format!("Stall {}", i),
                    HashMap::new(),
                    Severity::Warning,
                )
                .await;
        }

        let report = collector.generate_report().await;
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.contains("stalls") || r.contains("Multiple stalls")));
    }

    // ==================== Export Format Tests ====================

    #[tokio::test]
    async fn test_prometheus_export_format_details() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Record some data
        collector.record_resource_usage(256.0, 45.0, 5).await;

        let prometheus_export = collector
            .export_telemetry(ExportFormat::Prometheus)
            .await
            .unwrap();

        // Check for expected Prometheus metrics
        assert!(prometheus_export.contains("planner_exec_duration_seconds"));
        assert!(prometheus_export.contains("planner_exec_actions_total"));
        assert!(prometheus_export.contains("planner_exec_actions_success_rate"));
        assert!(prometheus_export.contains("planner_exec_memory_usage_bytes"));
        assert!(prometheus_export.contains("planner_exec_cpu_usage_percent"));
        assert!(prometheus_export.contains("session_id=\"test-session\""));
    }

    #[tokio::test]
    async fn test_influxdb_export_format_details() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector.record_resource_usage(128.0, 35.0, 3).await;

        let influx_export = collector
            .export_telemetry(ExportFormat::InfluxDB)
            .await
            .unwrap();

        // Check for InfluxDB line protocol format
        assert!(influx_export.contains("planner_exec,session_id=test-session"));
        assert!(influx_export.contains("planner_exec_performance,session_id=test-session"));
        assert!(influx_export.contains("duration_ms="));
        assert!(influx_export.contains("total_actions="));
    }

    #[tokio::test]
    async fn test_opentelemetry_export_format_details() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        collector
            .record_event(
                EventType::WorkflowStart,
                "orchestrator",
                "Workflow started",
                HashMap::new(),
                Severity::Info,
            )
            .await;

        let otel_export = collector
            .export_telemetry(ExportFormat::OpenTelemetry)
            .await
            .unwrap();

        // Check for OpenTelemetry JSON structure
        assert!(otel_export.contains("resourceSpans"));
        assert!(otel_export.contains("service.name"));
        assert!(otel_export.contains("planner-executor"));
        assert!(otel_export.contains("spans"));
    }

    // ==================== Complex Workflow Type Tests ====================

    #[tokio::test]
    async fn test_workflow_type_complex_orchestration() {
        let collector = TelemetryCollector::new(
            "complex-session".to_string(),
            Some(WorkflowType::ComplexOrchestration),
        );

        let report = collector.generate_report().await;
        assert_eq!(
            report.workflow_type,
            Some(WorkflowType::ComplexOrchestration)
        );
    }

    #[tokio::test]
    async fn test_workflow_type_none() {
        let collector = TelemetryCollector::new("generic-session".to_string(), None);

        let report = collector.generate_report().await;
        assert!(report.workflow_type.is_none());
    }

    // ==================== Gauge Updates Tests ====================

    #[tokio::test]
    async fn test_gauge_updates() {
        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Record initial values
        collector.record_resource_usage(100.0, 20.0, 3).await;

        // Record updated values
        collector.record_resource_usage(200.0, 40.0, 5).await;

        // The gauge should reflect the latest values
        let report = collector.generate_report().await;
        assert!(report.resource_utilization.peak_memory_mb >= 200.0);
    }

    // ==================== Error Rate Tests ====================

    #[tokio::test]
    async fn test_error_rate_calculation() {
        use crate::runners::planner_exec::schemas::{
            ActionMetadata, ActionResult, ActionStatus, ActionType, ExecutionEnvironment,
            ResourceUsage, WorkflowAction,
        };

        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Record multiple actions with some failures
        for i in 0..10 {
            let action = WorkflowAction::new(
                ActionType::FileSystem("fs.read.v1".to_string()),
                serde_json::json!({}),
                format!("Action {}", i),
            );

            let status = if i < 8 {
                ActionStatus::Completed
            } else {
                ActionStatus::Failed
            };

            let result = ActionResult {
                action_id: action.id.clone(),
                status,
                output: None,
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

            collector
                .record_action_execution(&action, &result, Duration::from_millis(100))
                .await;
        }

        let report = collector.generate_report().await;
        assert_eq!(report.total_actions, 10);
    }

    // ==================== Performance Timing Tests ====================

    #[tokio::test]
    async fn test_performance_timing_with_varying_durations() {
        use crate::runners::planner_exec::schemas::{
            ActionMetadata, ActionResult, ActionStatus, ActionType, ExecutionEnvironment,
            ResourceUsage, WorkflowAction,
        };

        let collector = TelemetryCollector::new("test-session".to_string(), None);

        // Record actions with varying durations
        let durations = [50, 100, 150, 200, 500, 1000, 2000];
        for (i, &duration_ms) in durations.iter().enumerate() {
            let action = WorkflowAction::new(
                ActionType::FileSystem("fs.read.v1".to_string()),
                serde_json::json!({}),
                format!("Action {}", i),
            );

            let result = ActionResult {
                action_id: action.id.clone(),
                status: ActionStatus::Completed,
                output: None,
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

            collector
                .record_action_execution(&action, &result, Duration::from_millis(duration_ms))
                .await;
        }

        let report = collector.generate_report().await;
        assert!(report.performance_summary.max_action_duration_ms >= 2000.0);
        assert!(report.performance_summary.min_action_duration_ms <= 50.0);
        // Average should be somewhere in between
        assert!(report.performance_summary.avg_action_duration_ms > 50.0);
        assert!(report.performance_summary.avg_action_duration_ms < 2000.0);
    }
}
