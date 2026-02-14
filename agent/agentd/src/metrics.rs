use anyhow::{Context, Result};
use prometheus::{
    Counter, CounterVec, Encoder, Histogram, HistogramVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::Config;

/// Prometheus metrics exporter for executor monitoring
pub struct MetricsExporter {
    registry: Registry,
    metrics: Arc<RwLock<ExecutorMetrics>>,
}

/// Core metrics for the executor
pub struct ExecutorMetrics {
    // Intent processing metrics
    pub intents_admitted_total: CounterVec,
    pub intents_denied_total: CounterVec,
    pub admit_latency_ms: HistogramVec,
    pub run_latency_ms: HistogramVec,

    // Worker and queue metrics
    pub worker_queue_depth: IntGaugeVec,
    pub active_workers: IntGaugeVec,

    // Result publishing metrics
    pub results_publish_errors_total: Counter,
    pub results_published_total: CounterVec,
    pub results_finalize_latency_ms: HistogramVec,

    // Replay and security metrics
    pub replay_dropped_total: Counter,
    pub seccomp_violations_total: Counter,
    pub cgroup_oom_total: Counter,

    // NATS metrics
    pub nats_pull_latency_ms: Histogram,
    pub nats_connection_errors_total: Counter,

    // System metrics
    pub memory_usage_bytes: IntGauge,
    pub cpu_usage_percent: IntGauge,
}

impl MetricsExporter {
    /// Create new metrics exporter
    pub fn new(_config: &Config) -> Result<Self> {
        let registry = Registry::new();
        let metrics = Arc::new(RwLock::new(ExecutorMetrics::new(&registry)?));

        // Start metrics HTTP server if configured
        // TODO: Add metrics server configuration to config

        info!("Metrics exporter initialized");
        Ok(Self { registry, metrics })
    }

    /// Get current metrics as Prometheus text format
    pub async fn export_metrics(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();

        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .context("Failed to encode metrics")?;

        String::from_utf8(buffer).context("Failed to convert metrics to UTF-8")
    }

    /// Start HTTP metrics server on specified port
    pub async fn start_http_server(&self, port: u16) -> Result<()> {
        use tokio::net::TcpListener;

        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("Failed to bind metrics server to {}", addr))?;

        info!("Starting metrics HTTP server on {}", addr);

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let metrics = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_metrics_request(&mut stream, metrics).await {
                            warn!("Failed to handle metrics request: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to accept metrics connection: {}", e);
                }
            }
        }
    }

    /// Get metrics handle for updating counters
    pub fn metrics(&self) -> Arc<RwLock<ExecutorMetrics>> {
        self.metrics.clone()
    }
}

impl Clone for MetricsExporter {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl ExecutorMetrics {
    /// Create new executor metrics
    pub fn new(registry: &Registry) -> Result<Self> {
        // Intent processing metrics
        let intents_admitted_total = CounterVec::new(
            Opts::new(
                "executor_intents_admitted_total",
                "Total intents admitted for execution",
            )
            .namespace("smith"),
            &["capability"],
        )?;
        registry.register(Box::new(intents_admitted_total.clone()))?;

        let intents_denied_total = CounterVec::new(
            Opts::new("executor_intents_denied_total", "Total intents denied").namespace("smith"),
            &["capability", "code"],
        )?;
        registry.register(Box::new(intents_denied_total.clone()))?;

        let admit_latency_ms = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "executor_admit_latency_ms",
                "Admission pipeline latency",
            )
            .namespace("smith")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0]),
            &["capability"],
        )?;
        registry.register(Box::new(admit_latency_ms.clone()))?;

        let run_latency_ms = HistogramVec::new(
            prometheus::HistogramOpts::new("executor_run_latency_ms", "Intent execution latency")
                .namespace("smith")
                .buckets(vec![1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0]),
            &["capability"],
        )?;
        registry.register(Box::new(run_latency_ms.clone()))?;

        // Worker and queue metrics
        let worker_queue_depth = IntGaugeVec::new(
            Opts::new(
                "executor_worker_queue_depth",
                "Current queue depth per capability",
            )
            .namespace("smith"),
            &["capability"],
        )?;
        registry.register(Box::new(worker_queue_depth.clone()))?;

        let active_workers = IntGaugeVec::new(
            Opts::new("executor_active_workers", "Currently active workers").namespace("smith"),
            &["capability"],
        )?;
        registry.register(Box::new(active_workers.clone()))?;

        // Result publishing metrics
        let results_publish_errors_total = Counter::new(
            "executor_results_publish_errors_total",
            "Total errors publishing results to NATS",
        )?;
        registry.register(Box::new(results_publish_errors_total.clone()))?;

        let results_published_total = CounterVec::new(
            Opts::new(
                "executor_results_published_total",
                "Total results published",
            )
            .namespace("smith"),
            &["capability", "status"],
        )?;
        registry.register(Box::new(results_published_total.clone()))?;

        let results_finalize_latency_ms = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "executor_results_finalize_latency_ms",
                "Latency of result finalization (including publish)",
            )
            .namespace("smith")
            .buckets(vec![0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0]),
            &["capability"],
        )?;
        registry.register(Box::new(results_finalize_latency_ms.clone()))?;

        // Security metrics
        let replay_dropped_total = Counter::new(
            "executor_replay_dropped_total",
            "Total intents dropped due to replay detection",
        )?;
        registry.register(Box::new(replay_dropped_total.clone()))?;

        let seccomp_violations_total = Counter::new(
            "executor_seccomp_violations_total",
            "Total seccomp violations detected",
        )?;
        registry.register(Box::new(seccomp_violations_total.clone()))?;

        let cgroup_oom_total = Counter::new("executor_cgroup_oom_total", "Total cgroup OOM kills")?;
        registry.register(Box::new(cgroup_oom_total.clone()))?;

        // NATS metrics
        let nats_pull_latency_ms = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "executor_nats_pull_latency_ms",
                "NATS message pull latency",
            )
            .namespace("smith")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0]),
        )?;
        registry.register(Box::new(nats_pull_latency_ms.clone()))?;

        let nats_connection_errors_total = Counter::new(
            "executor_nats_connection_errors_total",
            "Total NATS connection errors",
        )?;
        registry.register(Box::new(nats_connection_errors_total.clone()))?;

        // System metrics
        let memory_usage_bytes = IntGauge::new(
            "executor_memory_usage_bytes",
            "Current memory usage in bytes",
        )?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;

        let cpu_usage_percent =
            IntGauge::new("executor_cpu_usage_percent", "Current CPU usage percentage")?;
        registry.register(Box::new(cpu_usage_percent.clone()))?;

        Ok(Self {
            intents_admitted_total,
            intents_denied_total,
            admit_latency_ms,
            run_latency_ms,
            worker_queue_depth,
            active_workers,
            results_publish_errors_total,
            results_published_total,
            results_finalize_latency_ms,
            replay_dropped_total,
            seccomp_violations_total,
            cgroup_oom_total,
            nats_pull_latency_ms,
            nats_connection_errors_total,
            memory_usage_bytes,
            cpu_usage_percent,
        })
    }

    /// Record intent admission
    pub fn record_admission(&self, capability: &str, latency_ms: f64) {
        self.intents_admitted_total
            .with_label_values(&[capability])
            .inc();

        self.admit_latency_ms
            .with_label_values(&[capability])
            .observe(latency_ms);
    }

    /// Record intent denial
    pub fn record_denial(&self, capability: &str, code: &str) {
        self.intents_denied_total
            .with_label_values(&[capability, code])
            .inc();
    }

    /// Record intent execution
    pub fn record_execution(&self, capability: &str, latency_ms: f64) {
        self.run_latency_ms
            .with_label_values(&[capability])
            .observe(latency_ms);
    }

    /// Update worker queue depth
    pub fn set_queue_depth(&self, capability: &str, depth: i64) {
        self.worker_queue_depth
            .with_label_values(&[capability])
            .set(depth);
    }

    /// Update active worker count
    pub fn set_active_workers(&self, capability: &str, count: i64) {
        self.active_workers
            .with_label_values(&[capability])
            .set(count);
    }

    /// Record result publication
    pub fn record_result_published(&self, capability: &str, status: &str) {
        self.results_published_total
            .with_label_values(&[capability, status])
            .inc();
    }

    /// Record result finalization latency
    pub fn record_result_finalize_latency(&self, capability: &str, latency_ms: f64) {
        self.results_finalize_latency_ms
            .with_label_values(&[capability])
            .observe(latency_ms);
    }

    /// Record result publication error
    pub fn record_result_error(&self) {
        self.results_publish_errors_total.inc();
    }

    /// Record replay detection
    pub fn record_replay_dropped(&self) {
        self.replay_dropped_total.inc();
    }

    /// Record seccomp violation
    pub fn record_seccomp_violation(&self) {
        self.seccomp_violations_total.inc();
    }

    /// Record cgroup OOM kill
    pub fn record_cgroup_oom(&self) {
        self.cgroup_oom_total.inc();
    }

    /// Record NATS pull latency
    pub fn record_nats_pull_latency(&self, latency_ms: f64) {
        self.nats_pull_latency_ms.observe(latency_ms);
    }

    /// Record NATS connection error
    pub fn record_nats_connection_error(&self) {
        self.nats_connection_errors_total.inc();
    }

    /// Update system metrics
    pub fn update_system_metrics(&self, memory_bytes: i64, cpu_percent: i64) {
        self.memory_usage_bytes.set(memory_bytes);
        self.cpu_usage_percent.set(cpu_percent);
    }
}

/// Handle HTTP request for metrics endpoint
async fn handle_metrics_request(
    stream: &mut tokio::net::TcpStream,
    metrics: MetricsExporter,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read request (basic HTTP parsing)
    let mut buffer = [0; 1024];
    let bytes_read = stream.read(&mut buffer).await?;

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);

    // Check if this is a GET request to /metrics
    if request.starts_with("GET /metrics") {
        // Generate metrics response
        let metrics_text = metrics.export_metrics().await?;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            metrics_text.len(),
            metrics_text
        );

        stream.write_all(response.as_bytes()).await?;
    } else {
        // Return 404 for other paths
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let registry = Registry::new();
        let metrics = ExecutorMetrics::new(&registry);
        assert!(metrics.is_ok(), "Metrics creation should succeed");
    }

    #[tokio::test]
    async fn test_metrics_export() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            !metrics_text.is_empty(),
            "Metrics export should return text"
        );
        assert!(
            metrics_text.contains("smith_executor"),
            "Should contain namespaced metrics"
        );
    }

    #[tokio::test]
    async fn test_metrics_recording() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_admission("fs.read", 1.5);
            m.record_denial("http.fetch", "POLICY_DENY");
            m.set_queue_depth("fs.read", 5);
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("intents_admitted_total"),
            "Should contain admission metrics"
        );
        assert!(
            metrics_text.contains("intents_denied_total"),
            "Should contain denial metrics"
        );
        assert!(
            metrics_text.contains("worker_queue_depth"),
            "Should contain queue depth metrics"
        );
    }

    #[tokio::test]
    async fn test_record_execution() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_execution("fs.read", 100.0);
            m.record_execution("fs.read", 200.0);
            m.record_execution("http.fetch", 50.0);
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("run_latency_ms"),
            "Should contain run latency metrics"
        );
    }

    #[tokio::test]
    async fn test_set_active_workers() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.set_active_workers("fs.read", 4);
            m.set_active_workers("http.fetch", 2);
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("active_workers"),
            "Should contain active workers metrics"
        );
    }

    #[tokio::test]
    async fn test_record_result_published() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_result_published("fs.read", "ok");
            m.record_result_published("fs.read", "error");
            m.record_result_published("http.fetch", "ok");
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("results_published_total"),
            "Should contain results published metrics"
        );
    }

    #[tokio::test]
    async fn test_record_result_finalize_latency() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_result_finalize_latency("fs.read", 5.0);
            m.record_result_finalize_latency("fs.read", 10.0);
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("results_finalize_latency_ms"),
            "Should contain result finalize latency metrics"
        );
    }

    #[tokio::test]
    async fn test_record_result_error() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_result_error();
            m.record_result_error();
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("results_publish_errors_total"),
            "Should contain result publish errors metrics"
        );
    }

    #[tokio::test]
    async fn test_record_replay_dropped() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_replay_dropped();
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("replay_dropped_total"),
            "Should contain replay dropped metrics"
        );
    }

    #[tokio::test]
    async fn test_record_seccomp_violation() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_seccomp_violation();
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("seccomp_violations_total"),
            "Should contain seccomp violations metrics"
        );
    }

    #[tokio::test]
    async fn test_record_cgroup_oom() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_cgroup_oom();
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("cgroup_oom_total"),
            "Should contain cgroup OOM metrics"
        );
    }

    #[tokio::test]
    async fn test_record_nats_pull_latency() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_nats_pull_latency(1.5);
            m.record_nats_pull_latency(2.0);
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("nats_pull_latency_ms"),
            "Should contain NATS pull latency metrics"
        );
    }

    #[tokio::test]
    async fn test_record_nats_connection_error() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_nats_connection_error();
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("nats_connection_errors_total"),
            "Should contain NATS connection errors metrics"
        );
    }

    #[tokio::test]
    async fn test_update_system_metrics() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.update_system_metrics(1024 * 1024 * 100, 50);
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("memory_usage_bytes"),
            "Should contain memory usage metrics"
        );
        assert!(
            metrics_text.contains("cpu_usage_percent"),
            "Should contain CPU usage metrics"
        );
    }

    #[tokio::test]
    async fn test_metrics_exporter_clone() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let cloned = exporter.clone();

        // Record on original
        {
            let metrics = exporter.metrics();
            let m = metrics.read().await;
            m.record_admission("fs.read", 1.0);
        }

        // Both should export the same data
        let text1 = exporter.export_metrics().await.unwrap();
        let text2 = cloned.export_metrics().await.unwrap();

        assert_eq!(text1, text2, "Cloned exporter should share registry");
    }

    #[tokio::test]
    async fn test_metrics_multiple_capabilities() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_admission("fs.read", 1.0);
            m.record_admission("http.fetch", 2.0);
            m.record_admission("shell.exec", 3.0);
            m.record_admission("git.clone", 4.0);
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(metrics_text.contains("fs.read"));
        assert!(metrics_text.contains("http.fetch"));
        assert!(metrics_text.contains("shell.exec"));
        assert!(metrics_text.contains("git.clone"));
    }

    #[tokio::test]
    async fn test_queue_depth_updates() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.set_queue_depth("fs.read", 10);
            m.set_queue_depth("fs.read", 5);
            m.set_queue_depth("fs.read", 0);
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("worker_queue_depth"),
            "Should track queue depth"
        );
    }

    #[tokio::test]
    async fn test_denial_with_different_codes() {
        let config = Config::default();
        let exporter = MetricsExporter::new(&config).unwrap();
        let metrics = exporter.metrics();

        {
            let m = metrics.read().await;
            m.record_denial("fs.read", "POLICY_DENY");
            m.record_denial("fs.read", "VALIDATION_ERROR");
            m.record_denial("http.fetch", "TIMEOUT");
            m.record_denial("shell.exec", "RESOURCE_LIMIT");
        }

        let metrics_text = exporter.export_metrics().await.unwrap();
        assert!(
            metrics_text.contains("intents_denied_total"),
            "Should track denials"
        );
    }
}
