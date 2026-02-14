//! # Telemetry Collection System
//!
//! Comprehensive telemetry and metrics collection for the planner-executor controller.
//! Supports multi-format export (JSON, CSV, Prometheus) and real-time streaming.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │   Collectors    │───▶│  TelemetryHub    │───▶│   Exporters     │
//! │                 │    │                  │    │                 │
//! │ ∙ Workflow      │    │ ∙ Aggregation    │    │ ∙ JSON          │
//! │ ∙ Performance   │    │ ∙ Buffering      │    │ ∙ CSV           │
//! │ ∙ Security      │    │ ∙ Filtering      │    │ ∙ Prometheus    │
//! │ ∙ Resource      │    │ ∙ Real-time      │    │ ∙ NATS Stream   │
//! │ ∙ User          │    │                  │    │                 │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//! ```
//!
//! ## Key Features
//!
//! - **Multi-dimensional Metrics**: Workflow performance, security events, resource usage
//! - **Real-time Collection**: Sub-second metric collection and streaming
//! - **Flexible Export**: JSON, CSV, Prometheus, and NATS streaming formats
//! - **Intelligent Buffering**: Memory-efficient with configurable retention
//! - **Anomaly Detection**: Statistical analysis for performance degradation
//! - **Custom Dashboards**: Pre-built visualizations for operational monitoring

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::planner::executor_adapter::ExecutionResult;
use crate::planner::oracle::ExecutionPlan;
use crate::planner::{Goal, WorkflowState};

/// Configuration for telemetry collection system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Collection interval in milliseconds
    pub collection_interval_ms: u64,
    /// Maximum buffer size for each metric type
    pub buffer_size: usize,
    /// Retention period for historical data
    pub retention_period: Duration,
    /// Export formats to enable
    pub export_formats: Vec<ExportFormat>,
    /// Real-time streaming configuration
    pub streaming: StreamingConfig,
    /// Anomaly detection thresholds
    pub anomaly_detection: AnomalyDetectionConfig,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            collection_interval_ms: 1000, // 1 second
            buffer_size: 10000,
            retention_period: Duration::from_secs(24 * 60 * 60), // 24 hours
            export_formats: vec![ExportFormat::Json, ExportFormat::Prometheus],
            streaming: StreamingConfig::default(),
            anomaly_detection: AnomalyDetectionConfig::default(),
        }
    }
}

/// Supported export formats
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Prometheus,
    NatsStream,
}

/// Streaming configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    pub enabled: bool,
    pub buffer_size: usize,
    pub flush_interval_ms: u64,
    pub nats_subject: String,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: 1000,
            flush_interval_ms: 5000, // 5 seconds
            nats_subject: "smith.telemetry.planner".to_string(),
        }
    }
}

/// Anomaly detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionConfig {
    pub enabled: bool,
    pub window_size: usize,
    pub std_dev_threshold: f64,
    pub min_samples: usize,
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_size: 100,
            std_dev_threshold: 2.0,
            min_samples: 10,
        }
    }
}

/// Main telemetry collection hub
pub struct TelemetryCollector {
    config: TelemetryConfig,
    workflow_collector: Arc<WorkflowMetricsCollector>,
    performance_collector: Arc<PerformanceMetricsCollector>,
    security_collector: Arc<SecurityMetricsCollector>,
    resource_collector: Arc<ResourceMetricsCollector>,
    user_collector: Arc<UserInteractionCollector>,
    exporters: Arc<RwLock<HashMap<ExportFormat, Box<dyn MetricsExporter + Send + Sync>>>>,
    telemetry_hub: Arc<TelemetryHub>,
    collection_handle: Option<tokio::task::JoinHandle<()>>,
}

impl TelemetryCollector {
    /// Create new telemetry collector
    pub async fn new(config: TelemetryConfig) -> Result<Self, TelemetryError> {
        let workflow_collector = Arc::new(WorkflowMetricsCollector::new(config.buffer_size));
        let performance_collector = Arc::new(PerformanceMetricsCollector::new(config.buffer_size));
        let security_collector = Arc::new(SecurityMetricsCollector::new(config.buffer_size));
        let resource_collector = Arc::new(ResourceMetricsCollector::new(config.buffer_size));
        let user_collector = Arc::new(UserInteractionCollector::new(config.buffer_size));

        let telemetry_hub = Arc::new(TelemetryHub::new(config.clone()).await?);

        let mut exporters: HashMap<ExportFormat, Box<dyn MetricsExporter + Send + Sync>> =
            HashMap::new();

        for format in &config.export_formats {
            let exporter: Box<dyn MetricsExporter + Send + Sync> = match format {
                ExportFormat::Json => Box::new(JsonExporter::new()),
                ExportFormat::Csv => Box::new(CsvExporter::new()),
                ExportFormat::Prometheus => Box::new(PrometheusExporter::new()),
                ExportFormat::NatsStream => {
                    Box::new(NatsStreamExporter::new(config.streaming.nats_subject.clone()).await?)
                }
            };
            exporters.insert(format.clone(), exporter);
        }

        Ok(Self {
            config,
            workflow_collector,
            performance_collector,
            security_collector,
            resource_collector,
            user_collector,
            exporters: Arc::new(RwLock::new(exporters)),
            telemetry_hub,
            collection_handle: None,
        })
    }

    /// Start telemetry collection
    #[instrument(skip(self))]
    pub async fn start_collection(&mut self) -> Result<(), TelemetryError> {
        info!("Starting telemetry collection");

        let config = self.config.clone();
        let workflow_collector = Arc::clone(&self.workflow_collector);
        let performance_collector = Arc::clone(&self.performance_collector);
        let security_collector = Arc::clone(&self.security_collector);
        let resource_collector = Arc::clone(&self.resource_collector);
        let user_collector = Arc::clone(&self.user_collector);
        let telemetry_hub = Arc::clone(&self.telemetry_hub);

        let handle = tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(config.collection_interval_ms));

            loop {
                interval.tick().await;

                // Collect metrics from all collectors
                let workflow_metrics = workflow_collector.collect_current_metrics().await;
                let performance_metrics = performance_collector.collect_current_metrics().await;
                let security_metrics = security_collector.collect_current_metrics().await;
                let resource_metrics = resource_collector.collect_current_metrics().await;
                let user_metrics = user_collector.collect_current_metrics().await;

                // Aggregate and process through hub
                let aggregate_metrics = AggregateMetrics {
                    timestamp: SystemTime::now(),
                    workflow: workflow_metrics,
                    performance: performance_metrics,
                    security: security_metrics,
                    resource: resource_metrics,
                    user_interaction: user_metrics,
                };

                if let Err(e) = telemetry_hub.process_metrics(aggregate_metrics).await {
                    error!("Failed to process metrics: {}", e);
                }
            }
        });

        self.collection_handle = Some(handle);
        Ok(())
    }

    /// Stop telemetry collection
    #[instrument(skip(self))]
    pub async fn stop_collection(&mut self) {
        if let Some(handle) = self.collection_handle.take() {
            handle.abort();
            info!("Telemetry collection stopped");
        }
    }

    /// Record workflow event
    #[instrument(skip(self))]
    pub async fn record_workflow_event(&self, event: WorkflowEvent) {
        self.workflow_collector.record_event(event).await;
    }

    /// Record performance metric
    #[instrument(skip(self))]
    pub async fn record_performance_metric(&self, metric: PerformanceMetric) {
        self.performance_collector.record_metric(metric).await;
    }

    /// Record security event
    #[instrument(skip(self))]
    pub async fn record_security_event(&self, event: SecurityEvent) {
        self.security_collector.record_event(event).await;
    }

    /// Record resource usage
    #[instrument(skip(self))]
    pub async fn record_resource_usage(&self, usage: ResourceUsage) {
        self.resource_collector.record_usage(usage).await;
    }

    /// Record user interaction
    #[instrument(skip(self))]
    pub async fn record_user_interaction(&self, interaction: UserInteraction) {
        self.user_collector.record_interaction(interaction).await;
    }

    /// Export metrics in specified format
    #[instrument(skip(self))]
    pub async fn export_metrics(&self, format: ExportFormat) -> Result<String, TelemetryError> {
        let exporters = self.exporters.read().await;
        if let Some(exporter) = exporters.get(&format) {
            let metrics = self.telemetry_hub.get_current_metrics().await;
            exporter.export(&metrics).await
        } else {
            Err(TelemetryError::ExporterNotFound(format))
        }
    }

    /// Get current metrics summary
    pub async fn get_metrics_summary(&self) -> MetricsSummary {
        self.telemetry_hub.get_metrics_summary().await
    }

    /// Get anomaly detection results
    pub async fn get_anomalies(&self) -> Vec<AnomalyReport> {
        self.telemetry_hub.get_detected_anomalies().await
    }
}

/// In-memory collector that tracks workflow submissions, transitions, and completion stats.
pub struct WorkflowMetricsCollector {
    events: Arc<RwLock<VecDeque<WorkflowEvent>>>,
    buffer_size: usize,
    state_transitions: Arc<RwLock<HashMap<Uuid, Vec<StateTransition>>>>,
    goal_metrics: Arc<RwLock<HashMap<Uuid, GoalMetrics>>>,
}

impl WorkflowMetricsCollector {
    /// Create a collector with a fixed event buffer and per-workflow aggregates.
    pub fn new(buffer_size: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            buffer_size,
            state_transitions: Arc::new(RwLock::new(HashMap::new())),
            goal_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a workflow event and update any derived metrics (transitions, goals, etc.).
    pub async fn record_event(&self, event: WorkflowEvent) {
        let mut events = self.events.write().await;
        if events.len() >= self.buffer_size {
            events.pop_front();
        }
        events.push_back(event.clone());

        // Update specialized collections
        match event.event_type {
            WorkflowEventType::StateTransition { from, to, .. } => {
                let mut transitions = self.state_transitions.write().await;
                transitions
                    .entry(event.workflow_id)
                    .or_insert_with(Vec::new)
                    .push(StateTransition {
                        from,
                        to,
                        timestamp: event.timestamp,
                        duration: None, // Calculate based on previous transition
                    });
            }
            WorkflowEventType::GoalSubmitted { goal } => {
                let mut metrics = self.goal_metrics.write().await;
                metrics.insert(
                    event.workflow_id,
                    GoalMetrics {
                        goal: goal.clone(),
                        submitted_at: event.timestamp,
                        planning_duration: None,
                        execution_duration: None,
                        total_duration: None,
                        success: None,
                    },
                );
            }
            WorkflowEventType::GoalCompleted { success, .. } => {
                let mut metrics = self.goal_metrics.write().await;
                if let Some(goal_metrics) = metrics.get_mut(&event.workflow_id) {
                    goal_metrics.success = Some(success);
                    if let Ok(duration) = event.timestamp.duration_since(goal_metrics.submitted_at)
                    {
                        goal_metrics.total_duration = Some(duration);
                    }
                }
            }
            _ => {}
        }
    }

    /// Produce a snapshot of workflow KPIs derived from the buffered events.
    pub async fn collect_current_metrics(&self) -> WorkflowMetrics {
        let events = self.events.read().await;
        let state_transitions = self.state_transitions.read().await;
        let goal_metrics = self.goal_metrics.read().await;

        let total_workflows = goal_metrics.len();
        let active_workflows = goal_metrics
            .values()
            .filter(|m| m.success.is_none())
            .count();
        let successful_workflows = goal_metrics
            .values()
            .filter(|m| m.success == Some(true))
            .count();
        let failed_workflows = goal_metrics
            .values()
            .filter(|m| m.success == Some(false))
            .count();

        let avg_completion_time = goal_metrics
            .values()
            .filter_map(|m| m.total_duration)
            .collect::<Vec<_>>();
        let average_completion_time = if !avg_completion_time.is_empty() {
            Some(avg_completion_time.iter().sum::<Duration>() / avg_completion_time.len() as u32)
        } else {
            None
        };

        WorkflowMetrics {
            total_workflows,
            active_workflows,
            successful_workflows,
            failed_workflows,
            average_completion_time,
            state_distribution: calculate_state_distribution(&state_transitions),
            recent_events: events.iter().rev().take(10).cloned().collect(),
        }
    }
}

/// Tracks latency and throughput metrics for planner activity and tool calls.
pub struct PerformanceMetricsCollector {
    metrics: Arc<RwLock<VecDeque<PerformanceMetric>>>,
    buffer_size: usize,
    latency_tracker: Arc<RwLock<LatencyTracker>>,
    throughput_tracker: Arc<RwLock<ThroughputTracker>>,
}

impl PerformanceMetricsCollector {
    /// Create a performance collector with bounded buffers and rolling trackers.
    pub fn new(buffer_size: usize) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            buffer_size,
            latency_tracker: Arc::new(RwLock::new(LatencyTracker::new())),
            throughput_tracker: Arc::new(RwLock::new(ThroughputTracker::new())),
        }
    }

    /// Record a performance metric and update the rolling latency/throughput stats.
    pub async fn record_metric(&self, metric: PerformanceMetric) {
        let mut metrics = self.metrics.write().await;
        if metrics.len() >= self.buffer_size {
            metrics.pop_front();
        }
        metrics.push_back(metric.clone());

        // Update specialized trackers
        match &metric.metric_type {
            PerformanceMetricType::Latency {
                operation,
                duration,
            } => {
                let mut tracker = self.latency_tracker.write().await;
                tracker.record_latency(operation.clone(), *duration);
            }
            PerformanceMetricType::Throughput { operation, count } => {
                let mut tracker = self.throughput_tracker.write().await;
                tracker.record_throughput(operation.clone(), *count, metric.timestamp);
            }
            _ => {}
        }
    }

    /// Aggregate recent samples and derived stats into a single snapshot.
    pub async fn collect_current_metrics(&self) -> PerformanceMetrics {
        let metrics = self.metrics.read().await;
        let latency_tracker = self.latency_tracker.read().await;
        let throughput_tracker = self.throughput_tracker.read().await;

        PerformanceMetrics {
            latency_stats: latency_tracker.get_statistics(),
            throughput_stats: throughput_tracker.get_statistics(),
            recent_metrics: metrics.iter().rev().take(100).cloned().collect(),
            anomalies: detect_performance_anomalies(&metrics),
        }
    }
}

/// Collects security events, policy violations, and threat levels for workflows.
pub struct SecurityMetricsCollector {
    events: Arc<RwLock<VecDeque<SecurityEvent>>>,
    buffer_size: usize,
    threat_levels: Arc<RwLock<HashMap<String, ThreatLevel>>>,
    policy_violations: Arc<RwLock<Vec<PolicyViolation>>>,
}

impl SecurityMetricsCollector {
    /// Build a security collector with bounded buffers.
    pub fn new(buffer_size: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            buffer_size,
            threat_levels: Arc::new(RwLock::new(HashMap::new())),
            policy_violations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Store a security event and update derived counts/violations.
    pub async fn record_event(&self, event: SecurityEvent) {
        let mut events = self.events.write().await;
        if events.len() >= self.buffer_size {
            events.pop_front();
        }
        events.push_back(event.clone());

        // Update specialized collections
        match &event.event_type {
            SecurityEventType::ThreatDetected { threat_type, level } => {
                let mut threat_levels = self.threat_levels.write().await;
                threat_levels.insert(threat_type.clone(), *level);
            }
            SecurityEventType::PolicyViolation { policy, details } => {
                let mut violations = self.policy_violations.write().await;
                violations.push(PolicyViolation {
                    policy: policy.clone(),
                    details: details.clone(),
                    timestamp: event.timestamp,
                    severity: event.severity,
                });
            }
            _ => {}
        }
    }

    /// Gather the latest security posture (events, violations, threat levels).
    pub async fn collect_current_metrics(&self) -> SecurityMetrics {
        let events = self.events.read().await;
        let threat_levels = self.threat_levels.read().await;
        let policy_violations = self.policy_violations.read().await;

        SecurityMetrics {
            total_events: events.len(),
            threat_level_distribution: threat_levels.clone(),
            recent_violations: policy_violations.iter().rev().take(10).cloned().collect(),
            security_score: calculate_security_score(&events),
            recent_events: events.iter().rev().take(20).cloned().collect(),
        }
    }
}

/// Tracks CPU/memory/disk usage and alert thresholds for the planner executor.
pub struct ResourceMetricsCollector {
    usage_history: Arc<RwLock<VecDeque<ResourceUsage>>>,
    buffer_size: usize,
    peak_usage: Arc<RwLock<ResourceUsage>>,
    resource_alerts: Arc<RwLock<Vec<ResourceAlert>>>,
}

impl ResourceMetricsCollector {
    /// Initialize a collector with historical usage buffers and alert storage.
    pub fn new(buffer_size: usize) -> Self {
        Self {
            usage_history: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            buffer_size,
            peak_usage: Arc::new(RwLock::new(ResourceUsage::default())),
            resource_alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Record a resource usage sample and evaluate alert thresholds.
    pub async fn record_usage(&self, usage: ResourceUsage) {
        let mut history = self.usage_history.write().await;
        if history.len() >= self.buffer_size {
            history.pop_front();
        }
        history.push_back(usage.clone());

        // Update peak usage
        let mut peak = self.peak_usage.write().await;
        if usage.cpu_usage > peak.cpu_usage {
            peak.cpu_usage = usage.cpu_usage;
        }
        if usage.memory_usage > peak.memory_usage {
            peak.memory_usage = usage.memory_usage;
        }
        if usage.disk_io > peak.disk_io {
            peak.disk_io = usage.disk_io;
        }
        if usage.network_io > peak.network_io {
            peak.network_io = usage.network_io;
        }

        // Check for resource alerts
        if usage.cpu_usage > 80.0 || usage.memory_usage > 80.0 {
            let mut alerts = self.resource_alerts.write().await;
            alerts.push(ResourceAlert {
                alert_type: if usage.cpu_usage > 80.0 {
                    ResourceAlertType::HighCpuUsage
                } else {
                    ResourceAlertType::HighMemoryUsage
                },
                usage: usage.clone(),
                timestamp: usage.timestamp,
            });
        }
    }

    /// Produce resource utilization summaries along with active alerts.
    pub async fn collect_current_metrics(&self) -> ResourceMetrics {
        let history = self.usage_history.read().await;
        let peak = self.peak_usage.read().await;
        let alerts = self.resource_alerts.read().await;

        let current_usage = history.back().cloned().unwrap_or_default();
        let average_usage = if !history.is_empty() {
            ResourceUsage {
                timestamp: current_usage.timestamp,
                cpu_usage: history.iter().map(|u| u.cpu_usage).sum::<f64>() / history.len() as f64,
                memory_usage: history.iter().map(|u| u.memory_usage).sum::<f64>()
                    / history.len() as f64,
                disk_io: history.iter().map(|u| u.disk_io).sum::<f64>() / history.len() as f64,
                network_io: history.iter().map(|u| u.network_io).sum::<f64>()
                    / history.len() as f64,
            }
        } else {
            ResourceUsage::default()
        };

        ResourceMetrics {
            current_usage,
            average_usage,
            peak_usage: peak.clone(),
            recent_alerts: alerts.iter().rev().take(5).cloned().collect(),
            usage_trend: calculate_usage_trend(&history),
        }
    }
}

/// Captures interaction metadata to highlight high-traffic contexts and UX regressions.
pub struct UserInteractionCollector {
    interactions: Arc<RwLock<VecDeque<UserInteraction>>>,
    buffer_size: usize,
    interaction_patterns: Arc<RwLock<HashMap<String, InteractionPattern>>>,
}

impl UserInteractionCollector {
    /// Create a collector with a bounded interaction buffer.
    pub fn new(buffer_size: usize) -> Self {
        Self {
            interactions: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            buffer_size,
            interaction_patterns: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a user interaction and update the rolling pattern analysis.
    pub async fn record_interaction(&self, interaction: UserInteraction) {
        let mut interactions = self.interactions.write().await;
        if interactions.len() >= self.buffer_size {
            interactions.pop_front();
        }
        interactions.push_back(interaction.clone());

        // Update interaction patterns
        let mut patterns = self.interaction_patterns.write().await;
        let pattern_key = format!("{}_{}", interaction.interaction_type, interaction.context);
        patterns
            .entry(pattern_key)
            .and_modify(|p| {
                p.count += 1;
                p.last_seen = interaction.timestamp;
            })
            .or_insert_with(|| InteractionPattern {
                count: 1,
                first_seen: interaction.timestamp,
                last_seen: interaction.timestamp,
                average_duration: interaction.duration,
            });
    }

    /// Summarize interaction counts, hotspots, and anomalies.
    pub async fn collect_current_metrics(&self) -> UserInteractionMetrics {
        let interactions = self.interactions.read().await;
        let patterns = self.interaction_patterns.read().await;

        UserInteractionMetrics {
            total_interactions: interactions.len(),
            interaction_patterns: patterns.clone(),
            recent_interactions: interactions.iter().rev().take(10).cloned().collect(),
            user_engagement_score: calculate_engagement_score(&interactions),
        }
    }
}

/// Central telemetry hub responsible for aggregating collector output and driving exporters.
pub struct TelemetryHub {
    config: TelemetryConfig,
    current_metrics: Arc<RwLock<Option<AggregateMetrics>>>,
    metrics_history: Arc<RwLock<VecDeque<AggregateMetrics>>>,
    anomaly_detector: Arc<AnomalyDetector>,
    streaming_sender: Option<mpsc::Sender<AggregateMetrics>>,
}

impl TelemetryHub {
    /// Construct a telemetry hub based on the runtime configuration.
    pub async fn new(config: TelemetryConfig) -> Result<Self, TelemetryError> {
        let anomaly_detector = Arc::new(AnomalyDetector::new(config.anomaly_detection.clone()));

        let streaming_sender = if config.streaming.enabled {
            let (tx, rx) = mpsc::channel(config.streaming.buffer_size);

            // Start streaming task
            let streaming_config = config.streaming.clone();
            tokio::spawn(async move {
                Self::run_streaming_task(rx, streaming_config).await;
            });

            Some(tx)
        } else {
            None
        };

        let buffer_size = config.buffer_size;

        Ok(Self {
            config,
            current_metrics: Arc::new(RwLock::new(None)),
            metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            anomaly_detector,
            streaming_sender,
        })
    }

    /// Accept a new aggregate snapshot, update history, run anomaly detection, and emit streams.
    pub async fn process_metrics(&self, metrics: AggregateMetrics) -> Result<(), TelemetryError> {
        // Update current metrics
        {
            let mut current = self.current_metrics.write().await;
            *current = Some(metrics.clone());
        }

        // Add to history
        {
            let mut history = self.metrics_history.write().await;
            if history.len() >= self.config.buffer_size {
                history.pop_front();
            }
            history.push_back(metrics.clone());
        }

        // Anomaly detection
        if let Err(e) = self.anomaly_detector.analyze_metrics(&metrics).await {
            warn!("Anomaly detection failed: {}", e);
        }

        // Stream if enabled
        if let Some(ref sender) = self.streaming_sender {
            if let Err(e) = sender.try_send(metrics) {
                warn!("Failed to send metrics to streaming buffer: {}", e);
            }
        }

        Ok(())
    }

    /// Return the most recently processed aggregate metrics, if any.
    pub async fn get_current_metrics(&self) -> Option<AggregateMetrics> {
        self.current_metrics.read().await.clone()
    }

    /// Provide summary metadata about buffered metrics (history size, timestamps, anomalies).
    pub async fn get_metrics_summary(&self) -> MetricsSummary {
        let current = self.current_metrics.read().await;
        let history = self.metrics_history.read().await;

        MetricsSummary {
            current_metrics: current.clone(),
            history_size: history.len(),
            oldest_timestamp: history.front().map(|m| m.timestamp),
            newest_timestamp: history.back().map(|m| m.timestamp),
            anomaly_count: self.anomaly_detector.get_anomaly_count().await,
        }
    }

    /// Retrieve the latest anomaly reports produced by the detector.
    pub async fn get_detected_anomalies(&self) -> Vec<AnomalyReport> {
        self.anomaly_detector.get_recent_anomalies().await
    }

    async fn run_streaming_task(mut rx: mpsc::Receiver<AggregateMetrics>, config: StreamingConfig) {
        let mut buffer = Vec::with_capacity(config.buffer_size);
        let mut flush_interval = interval(Duration::from_millis(config.flush_interval_ms));

        loop {
            tokio::select! {
                metrics = rx.recv() => {
                    if let Some(metrics) = metrics {
                        buffer.push(metrics);

                        if buffer.len() >= config.buffer_size {
                            Self::flush_streaming_buffer(&mut buffer, &config).await;
                        }
                    } else {
                        break; // Channel closed
                    }
                }
                _ = flush_interval.tick() => {
                    if !buffer.is_empty() {
                        Self::flush_streaming_buffer(&mut buffer, &config).await;
                    }
                }
            }
        }
    }

    async fn flush_streaming_buffer(buffer: &mut Vec<AggregateMetrics>, config: &StreamingConfig) {
        if buffer.is_empty() {
            return;
        }

        // TODO: Implement NATS streaming
        debug!(
            "Flushing {} metrics to stream: {}",
            buffer.len(),
            config.nats_subject
        );
        buffer.clear();
    }
}

/// Sliding-window anomaly detector that analyzes aggregate metrics.
pub struct AnomalyDetector {
    config: AnomalyDetectionConfig,
    metric_windows: Arc<RwLock<HashMap<String, VecDeque<f64>>>>,
    detected_anomalies: Arc<RwLock<Vec<AnomalyReport>>>,
}

impl AnomalyDetector {
    /// Build an anomaly detector from configuration.
    pub fn new(config: AnomalyDetectionConfig) -> Self {
        Self {
            config,
            metric_windows: Arc::new(RwLock::new(HashMap::new())),
            detected_anomalies: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Inspect the latest aggregate metrics and capture any statistical anomalies.
    pub async fn analyze_metrics(&self, metrics: &AggregateMetrics) -> Result<(), TelemetryError> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut windows = self.metric_windows.write().await;
        let mut anomalies = self.detected_anomalies.write().await;

        // Analyze various metrics for anomalies
        let metric_values = vec![
            (
                "workflow_completion_rate",
                metrics.workflow.successful_workflows as f64
                    / metrics.workflow.total_workflows.max(1) as f64,
            ),
            ("avg_cpu_usage", metrics.resource.current_usage.cpu_usage),
            (
                "avg_memory_usage",
                metrics.resource.current_usage.memory_usage,
            ),
            ("security_score", metrics.security.security_score),
        ];

        for (metric_name, value) in metric_values {
            let window = windows
                .entry(metric_name.to_string())
                .or_insert_with(|| VecDeque::with_capacity(self.config.window_size));

            window.push_back(value);
            if window.len() > self.config.window_size {
                window.pop_front();
            }

            if window.len() >= self.config.min_samples {
                if let Some(anomaly) = self.detect_statistical_anomaly(metric_name, value, window) {
                    anomalies.push(anomaly);
                }
            }
        }

        // Keep only recent anomalies
        anomalies.retain(|a| {
            metrics
                .timestamp
                .duration_since(a.timestamp)
                .map(|d| d < Duration::from_secs(3600)) // 1 hour
                .unwrap_or(false)
        });

        Ok(())
    }

    fn detect_statistical_anomaly(
        &self,
        metric_name: &str,
        current_value: f64,
        window: &VecDeque<f64>,
    ) -> Option<AnomalyReport> {
        let mean = window.iter().sum::<f64>() / window.len() as f64;
        let variance =
            window.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / window.len() as f64;
        let std_dev = variance.sqrt();

        let z_score = (current_value - mean) / std_dev;

        if z_score.abs() > self.config.std_dev_threshold {
            Some(AnomalyReport {
                metric_name: metric_name.to_string(),
                current_value,
                expected_range: (mean - std_dev, mean + std_dev),
                z_score,
                severity: if z_score.abs() > 3.0 {
                    AnomalySeverity::High
                } else {
                    AnomalySeverity::Medium
                },
                timestamp: SystemTime::now(),
                description: format!(
                    "Metric '{}' value {} is {:.1} standard deviations from mean {:.2}",
                    metric_name, current_value, z_score, mean
                ),
            })
        } else {
            None
        }
    }

    /// Return the number of anomalies currently retained in memory.
    pub async fn get_anomaly_count(&self) -> usize {
        self.detected_anomalies.read().await.len()
    }

    /// Retrieve recent anomaly reports within the retention window.
    pub async fn get_recent_anomalies(&self) -> Vec<AnomalyReport> {
        self.detected_anomalies.read().await.clone()
    }
}

// Data structures and types

/// Represents an auditable event emitted during workflow execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEvent {
    pub workflow_id: Uuid,
    pub timestamp: SystemTime,
    pub event_type: WorkflowEventType,
    pub user_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Discriminates workflow events so collectors can react appropriately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowEventType {
    GoalSubmitted {
        goal: Goal,
    },
    PlanningStarted,
    PlanningCompleted {
        plan: ExecutionPlan,
    },
    ExecutionStarted,
    ExecutionCompleted {
        result: ExecutionResult,
    },
    StateTransition {
        from: WorkflowState,
        to: WorkflowState,
    },
    GoalCompleted {
        success: bool,
        duration: Duration,
    },
    ErrorOccurred {
        error: String,
    },
    UserInterventionRequested {
        reason: String,
    },
    UserInterventionCompleted {
        action: String,
    },
}

/// Tracks state transitions for a workflow along with timing metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: WorkflowState,
    pub to: WorkflowState,
    pub timestamp: SystemTime,
    pub duration: Option<Duration>,
}

/// Aggregated metrics for a single goal being processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalMetrics {
    pub goal: Goal,
    pub submitted_at: SystemTime,
    pub planning_duration: Option<Duration>,
    pub execution_duration: Option<Duration>,
    pub total_duration: Option<Duration>,
    pub success: Option<bool>,
}

/// Snapshot of workflow-level KPIs (counts, durations, recent history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowMetrics {
    pub total_workflows: usize,
    pub active_workflows: usize,
    pub successful_workflows: usize,
    pub failed_workflows: usize,
    pub average_completion_time: Option<Duration>,
    pub state_distribution: HashMap<WorkflowState, usize>,
    pub recent_events: Vec<WorkflowEvent>,
}

/// Raw performance measurement captured by the planner/executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetric {
    pub timestamp: SystemTime,
    pub metric_type: PerformanceMetricType,
    pub workflow_id: Option<Uuid>,
    pub value: f64,
    pub metadata: HashMap<String, String>,
}

/// Enumerates the different types of performance metrics that can be recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceMetricType {
    Latency {
        operation: String,
        duration: Duration,
    },
    Throughput {
        operation: String,
        count: u64,
    },
    MemoryUsage {
        peak_mb: f64,
        current_mb: f64,
    },
    CpuUsage {
        percentage: f64,
    },
    DiskIo {
        read_mbps: f64,
        write_mbps: f64,
    },
    NetworkIo {
        rx_mbps: f64,
        tx_mbps: f64,
    },
}

/// Rolling latency tracker keyed by operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyTracker {
    operation_latencies: HashMap<String, VecDeque<Duration>>,
}

impl LatencyTracker {
    /// Create an empty latency tracker.
    pub fn new() -> Self {
        Self {
            operation_latencies: HashMap::new(),
        }
    }

    /// Record a latency sample for the provided operation.
    pub fn record_latency(&mut self, operation: String, duration: Duration) {
        let latencies = self
            .operation_latencies
            .entry(operation)
            .or_insert_with(VecDeque::new);
        latencies.push_back(duration);
        if latencies.len() > 1000 {
            latencies.pop_front();
        }
    }

    /// Compute latency statistics (mean/percentiles) per operation.
    pub fn get_statistics(&self) -> HashMap<String, LatencyStats> {
        self.operation_latencies
            .iter()
            .map(|(op, latencies)| {
                let durations: Vec<Duration> = latencies.iter().cloned().collect();
                let stats = calculate_latency_stats(&durations);
                (op.clone(), stats)
            })
            .collect()
    }
}

/// Summary statistics describing latency distributions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub count: usize,
    pub mean: Duration,
    pub median: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub min: Duration,
    pub max: Duration,
}

/// Tracks rolling throughput measurements per operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputTracker {
    operation_counts: HashMap<String, VecDeque<(SystemTime, u64)>>,
}

impl ThroughputTracker {
    /// Create an empty throughput tracker.
    pub fn new() -> Self {
        Self {
            operation_counts: HashMap::new(),
        }
    }

    /// Record how many operations ran at a timestamp for a given operation label.
    pub fn record_throughput(&mut self, operation: String, count: u64, timestamp: SystemTime) {
        let counts = self
            .operation_counts
            .entry(operation)
            .or_insert_with(VecDeque::new);
        counts.push_back((timestamp, count));

        // Keep only last hour of data
        let cutoff = timestamp - Duration::from_secs(3600);
        while let Some(&(ts, _)) = counts.front() {
            if ts < cutoff {
                counts.pop_front();
            } else {
                break;
            }
        }
    }

    /// Convert raw counts into throughput statistics for each operation.
    pub fn get_statistics(&self) -> HashMap<String, ThroughputStats> {
        self.operation_counts
            .iter()
            .map(|(op, counts)| {
                let stats = calculate_throughput_stats(counts);
                (op.clone(), stats)
            })
            .collect()
    }
}

/// Summary throughput metrics (total, average, peak) for an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputStats {
    pub total_operations: u64,
    pub operations_per_second: f64,
    pub peak_ops_per_second: f64,
    pub average_ops_per_second: f64,
}

/// Bundled performance stats returned to dashboards/exporters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub latency_stats: HashMap<String, LatencyStats>,
    pub throughput_stats: HashMap<String, ThroughputStats>,
    pub recent_metrics: Vec<PerformanceMetric>,
    pub anomalies: Vec<String>,
}

/// Represents a security-related event emitted by admission or runtime guards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: SystemTime,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub workflow_id: Option<Uuid>,
    pub user_id: Option<String>,
    pub details: HashMap<String, String>,
}

/// Types of security events emitted by the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    ThreatDetected {
        threat_type: String,
        level: ThreatLevel,
    },
    PolicyViolation {
        policy: String,
        details: String,
    },
    AccessDenied {
        resource: String,
        reason: String,
    },
    PrivilegeEscalation {
        from: String,
        to: String,
    },
    SuspiciousActivity {
        activity: String,
        confidence: f64,
    },
    SecurityAudit {
        audit_type: String,
        result: String,
    },
}

/// Severity levels used for classifying security events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Threat level taxonomy for contextual alerts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ThreatLevel {
    Minimal,
    Low,
    Medium,
    High,
    Severe,
}

/// Describes a policy violation, including severity and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub policy: String,
    pub details: String,
    pub timestamp: SystemTime,
    pub severity: SecuritySeverity,
}

/// Aggregated security posture metrics and recent events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub total_events: usize,
    pub threat_level_distribution: HashMap<String, ThreatLevel>,
    pub recent_violations: Vec<PolicyViolation>,
    pub security_score: f64,
    pub recent_events: Vec<SecurityEvent>,
}

/// Snapshot of CPU/memory/disk/network consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub timestamp: SystemTime,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_io: f64,
    pub network_io: f64,
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            timestamp: SystemTime::now(),
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_io: 0.0,
            network_io: 0.0,
        }
    }
}

// Note: Cannot implement Default for SystemTime (external type)
// Using SystemTime::now() directly instead

/// Alert produced when resource usage exceeds configured thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAlert {
    pub alert_type: ResourceAlertType,
    pub usage: ResourceUsage,
    pub timestamp: SystemTime,
}

/// Enumerates the categories of resource alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceAlertType {
    HighCpuUsage,
    HighMemoryUsage,
    HighDiskIo,
    HighNetworkIo,
}

/// Aggregate resource metrics including averages, peaks, and trend information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub current_usage: ResourceUsage,
    pub average_usage: ResourceUsage,
    pub peak_usage: ResourceUsage,
    pub recent_alerts: Vec<ResourceAlert>,
    pub usage_trend: UsageTrend,
}

/// Trend indicator showing how usage is evolving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsageTrend {
    Increasing,
    Decreasing,
    Stable,
}

/// Captures a single user interaction for telemetry purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInteraction {
    pub timestamp: SystemTime,
    pub interaction_type: String,
    pub context: String,
    pub duration: Duration,
    pub workflow_id: Option<Uuid>,
    pub user_id: String,
    pub metadata: HashMap<String, String>,
}

/// Simplified interaction pattern used for engagement reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionPattern {
    pub count: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub average_duration: Duration,
}

/// Overall metrics describing user engagement and interaction patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInteractionMetrics {
    pub total_interactions: usize,
    pub interaction_patterns: HashMap<String, InteractionPattern>,
    pub recent_interactions: Vec<UserInteraction>,
    pub user_engagement_score: f64,
}

/// Top-level aggregate metrics emitted during each collection cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateMetrics {
    pub timestamp: SystemTime,
    pub workflow: WorkflowMetrics,
    pub performance: PerformanceMetrics,
    pub security: SecurityMetrics,
    pub resource: ResourceMetrics,
    pub user_interaction: UserInteractionMetrics,
}

/// Lightweight summary derived from the metrics history buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub current_metrics: Option<AggregateMetrics>,
    pub history_size: usize,
    pub oldest_timestamp: Option<SystemTime>,
    pub newest_timestamp: Option<SystemTime>,
    pub anomaly_count: usize,
}

/// Structured anomaly report indicating which metric deviated and by how much.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub metric_name: String,
    pub current_value: f64,
    pub expected_range: (f64, f64),
    pub z_score: f64,
    pub severity: AnomalySeverity,
    pub timestamp: SystemTime,
    pub description: String,
}

/// Qualitative severity attached to anomalies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
}

// Export traits and implementations

#[async_trait::async_trait]
/// Trait implemented by exporters that serialize aggregated telemetry.
pub trait MetricsExporter: Send + Sync {
    async fn export(&self, metrics: &Option<AggregateMetrics>) -> Result<String, TelemetryError>;
}

/// Exporter that renders metrics as prettified JSON.
pub struct JsonExporter;

impl JsonExporter {
    /// Construct a JSON exporter.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl MetricsExporter for JsonExporter {
    async fn export(&self, metrics: &Option<AggregateMetrics>) -> Result<String, TelemetryError> {
        match metrics {
            Some(metrics) => serde_json::to_string_pretty(metrics)
                .map_err(|e| TelemetryError::ExportFailed(format!("JSON export failed: {}", e))),
            None => Ok("{}".to_string()),
        }
    }
}

/// Exporter that emits a simple CSV row for quick inspection.
pub struct CsvExporter;

impl CsvExporter {
    /// Construct a CSV exporter.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl MetricsExporter for CsvExporter {
    async fn export(&self, metrics: &Option<AggregateMetrics>) -> Result<String, TelemetryError> {
        match metrics {
            Some(metrics) => {
                let mut csv = String::new();
                csv.push_str("timestamp,total_workflows,active_workflows,cpu_usage,memory_usage,security_score\n");
                csv.push_str(&format!(
                    "{:?},{},{},{:.2},{:.2},{:.2}\n",
                    metrics.timestamp,
                    metrics.workflow.total_workflows,
                    metrics.workflow.active_workflows,
                    metrics.resource.current_usage.cpu_usage,
                    metrics.resource.current_usage.memory_usage,
                    metrics.security.security_score
                ));
                Ok(csv)
            }
            None => Ok("timestamp,total_workflows,active_workflows,cpu_usage,memory_usage,security_score\n".to_string()),
        }
    }
}

/// Exporter that formats metrics as Prometheus scrape output.
pub struct PrometheusExporter;

impl PrometheusExporter {
    /// Construct a Prometheus exporter.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl MetricsExporter for PrometheusExporter {
    async fn export(&self, metrics: &Option<AggregateMetrics>) -> Result<String, TelemetryError> {
        match metrics {
            Some(metrics) => {
                let mut prometheus = String::new();

                // Workflow metrics
                prometheus.push_str(&format!(
                    "# HELP smith_workflows_total Total number of workflows\n# TYPE smith_workflows_total counter\nsmith_workflows_total {}\n",
                    metrics.workflow.total_workflows
                ));
                prometheus.push_str(&format!(
                    "# HELP smith_workflows_active Active workflows\n# TYPE smith_workflows_active gauge\nsmith_workflows_active {}\n",
                    metrics.workflow.active_workflows
                ));

                // Resource metrics
                prometheus.push_str(&format!(
                    "# HELP smith_cpu_usage CPU usage percentage\n# TYPE smith_cpu_usage gauge\nsmith_cpu_usage {:.2}\n",
                    metrics.resource.current_usage.cpu_usage
                ));
                prometheus.push_str(&format!(
                    "# HELP smith_memory_usage Memory usage percentage\n# TYPE smith_memory_usage gauge\nsmith_memory_usage {:.2}\n",
                    metrics.resource.current_usage.memory_usage
                ));

                // Security metrics
                prometheus.push_str(&format!(
                    "# HELP smith_security_score Security score\n# TYPE smith_security_score gauge\nsmith_security_score {:.2}\n",
                    metrics.security.security_score
                ));

                Ok(prometheus)
            }
            None => Ok(String::new()),
        }
    }
}

/// Exporter that streams metrics over NATS JetStream (placeholder implementation).
pub struct NatsStreamExporter {
    subject: String,
    // TODO: Add NATS client
}

impl NatsStreamExporter {
    /// Construct a streaming exporter targeting the provided subject.
    pub async fn new(subject: String) -> Result<Self, TelemetryError> {
        Ok(Self { subject })
    }
}

#[async_trait::async_trait]
impl MetricsExporter for NatsStreamExporter {
    async fn export(&self, metrics: &Option<AggregateMetrics>) -> Result<String, TelemetryError> {
        match metrics {
            Some(metrics) => {
                let json = serde_json::to_string(metrics).map_err(|e| {
                    TelemetryError::ExportFailed(format!("NATS export failed: {}", e))
                })?;

                // TODO: Publish to NATS stream
                debug!("Would publish to NATS subject: {}", self.subject);

                Ok(json)
            }
            None => Ok("{}".to_string()),
        }
    }
}

// Error types

/// Error type used throughout the telemetry subsystem.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("Exporter not found for format: {0:?}")]
    ExporterNotFound(ExportFormat),

    #[error("Export failed: {0}")]
    ExportFailed(String),

    #[error("Telemetry collection failed: {0}")]
    CollectionFailed(String),

    #[error("Anomaly detection failed: {0}")]
    AnomalyDetectionFailed(String),

    #[error("Streaming setup failed: {0}")]
    StreamingFailed(String),
}

// Utility functions

fn calculate_state_distribution(
    state_transitions: &HashMap<Uuid, Vec<StateTransition>>,
) -> HashMap<WorkflowState, usize> {
    let mut distribution = HashMap::new();

    for transitions in state_transitions.values() {
        if let Some(last_transition) = transitions.last() {
            *distribution.entry(last_transition.to.clone()).or_insert(0) += 1;
        }
    }

    distribution
}

fn detect_performance_anomalies(_metrics: &VecDeque<PerformanceMetric>) -> Vec<String> {
    // TODO: Implement performance anomaly detection
    Vec::new()
}

fn calculate_security_score(events: &VecDeque<SecurityEvent>) -> f64 {
    if events.is_empty() {
        return 100.0;
    }

    let total_weight = events.len() as f64;
    let penalty_sum: f64 = events
        .iter()
        .map(|event| match event.severity {
            SecuritySeverity::Low => 1.0,
            SecuritySeverity::Medium => 5.0,
            SecuritySeverity::High => 20.0,
            SecuritySeverity::Critical => 50.0,
        })
        .sum();

    (100.0 - (penalty_sum / total_weight * 10.0)).max(0.0)
}

fn calculate_usage_trend(history: &VecDeque<ResourceUsage>) -> UsageTrend {
    if history.len() < 2 {
        return UsageTrend::Stable;
    }

    let recent_avg = history
        .iter()
        .rev()
        .take(5)
        .map(|u| u.cpu_usage + u.memory_usage)
        .sum::<f64>()
        / 5.0;

    let older_avg = history
        .iter()
        .rev()
        .skip(5)
        .take(5)
        .map(|u| u.cpu_usage + u.memory_usage)
        .sum::<f64>()
        / 5.0;

    let change_ratio = recent_avg / older_avg;

    if change_ratio > 1.1 {
        UsageTrend::Increasing
    } else if change_ratio < 0.9 {
        UsageTrend::Decreasing
    } else {
        UsageTrend::Stable
    }
}

fn calculate_engagement_score(interactions: &VecDeque<UserInteraction>) -> f64 {
    if interactions.is_empty() {
        return 0.0;
    }

    let total_duration: Duration = interactions.iter().map(|i| i.duration).sum();

    let avg_duration = total_duration.as_secs_f64() / interactions.len() as f64;

    // Score based on frequency and average duration
    let frequency_score = (interactions.len() as f64).min(100.0);
    let duration_score = (avg_duration / 60.0).min(100.0); // Normalize to minutes

    (frequency_score + duration_score) / 2.0
}

fn calculate_latency_stats(durations: &[Duration]) -> LatencyStats {
    if durations.is_empty() {
        return LatencyStats {
            count: 0,
            mean: Duration::ZERO,
            median: Duration::ZERO,
            p95: Duration::ZERO,
            p99: Duration::ZERO,
            min: Duration::ZERO,
            max: Duration::ZERO,
        };
    }

    let mut sorted = durations.to_vec();
    sorted.sort();

    let count = sorted.len();
    let mean = sorted.iter().sum::<Duration>() / count as u32;
    let median = sorted[count / 2];
    let p95 = sorted[(count as f64 * 0.95) as usize];
    let p99 = sorted[(count as f64 * 0.99) as usize];
    let min = sorted[0];
    let max = sorted[count - 1];

    LatencyStats {
        count,
        mean,
        median,
        p95,
        p99,
        min,
        max,
    }
}

fn calculate_throughput_stats(counts: &VecDeque<(SystemTime, u64)>) -> ThroughputStats {
    if counts.is_empty() {
        return ThroughputStats {
            total_operations: 0,
            operations_per_second: 0.0,
            peak_ops_per_second: 0.0,
            average_ops_per_second: 0.0,
        };
    }

    let total_operations = counts.iter().map(|(_, count)| count).sum();

    if counts.len() < 2 {
        return ThroughputStats {
            total_operations,
            operations_per_second: 0.0,
            peak_ops_per_second: 0.0,
            average_ops_per_second: 0.0,
        };
    }

    let time_span = counts
        .back()
        .unwrap()
        .0
        .duration_since(counts.front().unwrap().0)
        .unwrap_or(Duration::from_secs(1));

    let operations_per_second = total_operations as f64 / time_span.as_secs_f64();

    // Calculate peak by looking at sliding windows
    let mut peak_ops_per_second: f64 = 0.0;
    let counts_vec: Vec<_> = counts.iter().cloned().collect();
    for window in counts_vec.windows(2) {
        if let Ok(duration) = window[1].0.duration_since(window[0].0) {
            if duration.as_secs_f64() > 0.0 {
                let ops_per_sec = window[1].1 as f64 / duration.as_secs_f64();
                peak_ops_per_second = peak_ops_per_second.max(ops_per_sec);
            }
        }
    }

    ThroughputStats {
        total_operations,
        operations_per_second,
        peak_ops_per_second,
        average_ops_per_second: operations_per_second,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_telemetry_collector_creation() {
        let config = TelemetryConfig::default();
        let collector = TelemetryCollector::new(config).await;
        assert!(collector.is_ok());
    }

    #[tokio::test]
    async fn test_workflow_metrics_collection() {
        let collector = WorkflowMetricsCollector::new(100);

        let event = WorkflowEvent {
            workflow_id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            event_type: WorkflowEventType::GoalSubmitted {
                goal: Goal {
                    id: Uuid::new_v4(),
                    description: "Test goal".to_string(),
                    context: Some("Test context".to_string()),
                    priority: crate::planner::Priority::Medium,
                    constraints: Vec::new(),
                    success_criteria: Vec::new(),
                    metadata: HashMap::new(),
                    created_at: chrono::Utc::now(),
                },
            },
            user_id: Some("test_user".to_string()),
            metadata: HashMap::new(),
        };

        collector.record_event(event).await;
        let metrics = collector.collect_current_metrics().await;

        assert_eq!(metrics.total_workflows, 1);
        assert_eq!(metrics.active_workflows, 1);
    }

    #[tokio::test]
    async fn test_performance_metrics_collection() {
        let collector = PerformanceMetricsCollector::new(100);

        let metric = PerformanceMetric {
            timestamp: SystemTime::now(),
            metric_type: PerformanceMetricType::Latency {
                operation: "test_operation".to_string(),
                duration: Duration::from_millis(100),
            },
            workflow_id: Some(Uuid::new_v4()),
            value: 100.0,
            metadata: HashMap::new(),
        };

        collector.record_metric(metric).await;
        let metrics = collector.collect_current_metrics().await;

        assert_eq!(metrics.recent_metrics.len(), 1);
        assert!(metrics.latency_stats.contains_key("test_operation"));
    }

    #[tokio::test]
    async fn test_security_metrics_collection() {
        let collector = SecurityMetricsCollector::new(100);

        let event = SecurityEvent {
            timestamp: SystemTime::now(),
            event_type: SecurityEventType::ThreatDetected {
                threat_type: "test_threat".to_string(),
                level: ThreatLevel::Medium,
            },
            severity: SecuritySeverity::Medium,
            workflow_id: Some(Uuid::new_v4()),
            user_id: Some("test_user".to_string()),
            details: HashMap::new(),
        };

        collector.record_event(event).await;
        let metrics = collector.collect_current_metrics().await;

        assert_eq!(metrics.total_events, 1);
        assert!(metrics.security_score < 100.0);
    }

    #[tokio::test]
    async fn test_resource_metrics_collection() {
        let collector = ResourceMetricsCollector::new(100);

        let usage = ResourceUsage {
            timestamp: SystemTime::now(),
            cpu_usage: 75.5,
            memory_usage: 60.2,
            disk_io: 50.0,
            network_io: 25.0,
        };

        collector.record_usage(usage.clone()).await;
        let metrics = collector.collect_current_metrics().await;

        assert_eq!(metrics.current_usage.cpu_usage, 75.5);
        assert_eq!(metrics.peak_usage.cpu_usage, 75.5);
    }

    #[tokio::test]
    async fn test_anomaly_detection() {
        let config = AnomalyDetectionConfig {
            enabled: true,
            window_size: 10,
            std_dev_threshold: 2.0,
            min_samples: 5,
        };

        let detector = AnomalyDetector::new(config);

        // Create metrics with an obvious anomaly
        let normal_metrics = AggregateMetrics {
            timestamp: SystemTime::now(),
            workflow: WorkflowMetrics {
                total_workflows: 10,
                active_workflows: 2,
                successful_workflows: 8,
                failed_workflows: 0,
                average_completion_time: Some(Duration::from_secs(60)),
                state_distribution: HashMap::new(),
                recent_events: Vec::new(),
            },
            performance: PerformanceMetrics {
                latency_stats: HashMap::new(),
                throughput_stats: HashMap::new(),
                recent_metrics: Vec::new(),
                anomalies: Vec::new(),
            },
            security: SecurityMetrics {
                total_events: 0,
                threat_level_distribution: HashMap::new(),
                recent_violations: Vec::new(),
                security_score: 95.0,
                recent_events: Vec::new(),
            },
            resource: ResourceMetrics {
                current_usage: ResourceUsage {
                    timestamp: SystemTime::now(),
                    cpu_usage: 50.0,
                    memory_usage: 60.0,
                    disk_io: 30.0,
                    network_io: 20.0,
                },
                average_usage: ResourceUsage::default(),
                peak_usage: ResourceUsage::default(),
                recent_alerts: Vec::new(),
                usage_trend: UsageTrend::Stable,
            },
            user_interaction: UserInteractionMetrics {
                total_interactions: 5,
                interaction_patterns: HashMap::new(),
                recent_interactions: Vec::new(),
                user_engagement_score: 75.0,
            },
        };

        // Feed normal data
        for _ in 0..6 {
            detector.analyze_metrics(&normal_metrics).await.unwrap();
        }

        // Feed anomalous data
        let mut anomalous_metrics = normal_metrics.clone();
        anomalous_metrics.resource.current_usage.cpu_usage = 150.0; // Impossible value
        anomalous_metrics.timestamp = SystemTime::now()
            .checked_add(Duration::from_secs(1))
            .unwrap();

        detector.analyze_metrics(&anomalous_metrics).await.unwrap();

        let anomalies = detector.get_recent_anomalies().await;
        assert!(!anomalies.is_empty());
    }

    #[tokio::test]
    async fn test_json_export() {
        let exporter = JsonExporter::new();

        let metrics = AggregateMetrics {
            timestamp: SystemTime::now(),
            workflow: WorkflowMetrics {
                total_workflows: 5,
                active_workflows: 2,
                successful_workflows: 3,
                failed_workflows: 0,
                average_completion_time: Some(Duration::from_secs(120)),
                state_distribution: HashMap::new(),
                recent_events: Vec::new(),
            },
            performance: PerformanceMetrics {
                latency_stats: HashMap::new(),
                throughput_stats: HashMap::new(),
                recent_metrics: Vec::new(),
                anomalies: Vec::new(),
            },
            security: SecurityMetrics {
                total_events: 0,
                threat_level_distribution: HashMap::new(),
                recent_violations: Vec::new(),
                security_score: 98.5,
                recent_events: Vec::new(),
            },
            resource: ResourceMetrics {
                current_usage: ResourceUsage {
                    timestamp: SystemTime::now(),
                    cpu_usage: 45.2,
                    memory_usage: 67.8,
                    disk_io: 12.5,
                    network_io: 8.3,
                },
                average_usage: ResourceUsage::default(),
                peak_usage: ResourceUsage::default(),
                recent_alerts: Vec::new(),
                usage_trend: UsageTrend::Stable,
            },
            user_interaction: UserInteractionMetrics {
                total_interactions: 12,
                interaction_patterns: HashMap::new(),
                recent_interactions: Vec::new(),
                user_engagement_score: 82.5,
            },
        };

        let result = exporter.export(&Some(metrics)).await;
        assert!(result.is_ok());

        let json_string = result.unwrap();
        assert!(json_string.contains("total_workflows"));
        assert!(json_string.contains("security_score"));
    }

    #[tokio::test]
    async fn test_telemetry_hub_processing() {
        let config = TelemetryConfig {
            streaming: StreamingConfig {
                enabled: false, // Disable streaming for test
                ..Default::default()
            },
            ..Default::default()
        };

        let hub = TelemetryHub::new(config).await.unwrap();

        let metrics = AggregateMetrics {
            timestamp: SystemTime::now(),
            workflow: WorkflowMetrics {
                total_workflows: 1,
                active_workflows: 1,
                successful_workflows: 0,
                failed_workflows: 0,
                average_completion_time: None,
                state_distribution: HashMap::new(),
                recent_events: Vec::new(),
            },
            performance: PerformanceMetrics {
                latency_stats: HashMap::new(),
                throughput_stats: HashMap::new(),
                recent_metrics: Vec::new(),
                anomalies: Vec::new(),
            },
            security: SecurityMetrics {
                total_events: 0,
                threat_level_distribution: HashMap::new(),
                recent_violations: Vec::new(),
                security_score: 100.0,
                recent_events: Vec::new(),
            },
            resource: ResourceMetrics {
                current_usage: ResourceUsage {
                    timestamp: SystemTime::now(),
                    cpu_usage: 25.0,
                    memory_usage: 40.0,
                    disk_io: 15.0,
                    network_io: 10.0,
                },
                average_usage: ResourceUsage::default(),
                peak_usage: ResourceUsage::default(),
                recent_alerts: Vec::new(),
                usage_trend: UsageTrend::Stable,
            },
            user_interaction: UserInteractionMetrics {
                total_interactions: 0,
                interaction_patterns: HashMap::new(),
                recent_interactions: Vec::new(),
                user_engagement_score: 0.0,
            },
        };

        let result = hub.process_metrics(metrics.clone()).await;
        assert!(result.is_ok());

        let current = hub.get_current_metrics().await;
        assert!(current.is_some());
        assert_eq!(current.unwrap().workflow.total_workflows, 1);

        let summary = hub.get_metrics_summary().await;
        assert_eq!(summary.history_size, 1);
    }
}
