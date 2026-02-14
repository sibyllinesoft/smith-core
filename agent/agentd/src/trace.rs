use anyhow::Result;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use uuid::Uuid;

/// OpenTelemetry tracing setup for distributed tracing
pub struct TracingSetup;

impl TracingSetup {
    /// Initialize OpenTelemetry tracing
    pub fn init() -> Result<()> {
        warn!("Full OpenTelemetry integration not implemented - using structured logging");
        info!("Tracing initialized with span context support");
        Ok(())
    }

    /// Shutdown tracing provider
    pub fn shutdown() -> Result<()> {
        info!("Tracing shutdown complete");
        Ok(())
    }
}

/// Executor-specific tracing spans for observability
pub struct ExecutorTracer;

impl ExecutorTracer {
    /// Create span for NATS message pull operation
    pub fn span_nats_pull(stream_name: &str, consumer_name: &str) -> ExecutorSpan {
        let span_id = Uuid::new_v4();
        let started_at = Instant::now();

        tracing::info!(
            operation = "nats_pull",
            span_id = %span_id,
            stream = stream_name,
            consumer = consumer_name,
            "Starting NATS pull operation"
        );

        ExecutorSpan::new("nats_pull", span_id, started_at)
    }

    /// Create span for intent admission pipeline
    pub fn span_intent_admission(intent_id: &str, capability: &str) -> ExecutorSpan {
        let span_id = Uuid::new_v4();
        let started_at = Instant::now();

        tracing::info!(
            operation = "intent_admission",
            span_id = %span_id,
            intent_id = intent_id,
            capability = capability,
            "Starting intent admission pipeline"
        );

        ExecutorSpan::new("intent_admission", span_id, started_at)
    }

    /// Create span for jail setup operation
    pub fn span_jail_setup(intent_id: &str, work_dir: &str) -> ExecutorSpan {
        let span_id = Uuid::new_v4();
        let started_at = Instant::now();

        tracing::info!(
            operation = "jail_setup",
            span_id = %span_id,
            intent_id = intent_id,
            work_dir = work_dir,
            "Starting jail setup"
        );

        ExecutorSpan::new("jail_setup", span_id, started_at)
    }

    /// Create span for intent execution (run operation)
    pub fn span_intent_run(intent_id: &str, capability: &str, runner: &str) -> ExecutorSpan {
        let span_id = Uuid::new_v4();
        let started_at = Instant::now();

        tracing::info!(
            operation = "intent_run",
            span_id = %span_id,
            intent_id = intent_id,
            capability = capability,
            runner = runner,
            "Starting intent execution"
        );

        ExecutorSpan::new("intent_run", span_id, started_at)
    }

    /// Create span for result publishing
    pub fn span_publish_result(intent_id: &str, result_status: &str) -> ExecutorSpan {
        let span_id = Uuid::new_v4();
        let started_at = Instant::now();

        tracing::info!(
            operation = "publish_result",
            span_id = %span_id,
            intent_id = intent_id,
            result_status = result_status,
            "Publishing intent result"
        );

        ExecutorSpan::new("publish_result", span_id, started_at)
    }
}

/// A span for tracking execution times and providing structured logging
pub struct ExecutorSpan {
    operation: String,
    span_id: Uuid,
    started_at: Instant,
    trace_id: Option<String>,
}

/// Type alias for admission spans (same as ExecutorSpan)
pub type AdmissionSpan = ExecutorSpan;

impl ExecutorSpan {
    fn new(operation: &str, span_id: Uuid, started_at: Instant) -> Self {
        Self {
            operation: operation.to_string(),
            span_id,
            started_at,
            trace_id: None,
        }
    }

    /// Set trace ID for distributed tracing correlation
    pub fn with_trace_id(mut self, trace_id: String) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    /// Record an event within this span
    pub fn record_event(&self, event: &str, attributes: &[(&str, &str)]) {
        let span_id_str = self.span_id.to_string();
        let mut fields = Vec::with_capacity(attributes.len() + 3);
        fields.push(("operation", self.operation.as_str()));
        fields.push(("span_id", &span_id_str));
        fields.push(("event", event));
        fields.extend_from_slice(attributes);

        tracing::info!(
            operation = self.operation.as_str(),
            span_id = %self.span_id,
            trace_id = self.trace_id.as_deref().unwrap_or(""),
            event = event,
            attributes = ?attributes,
            "Span event recorded"
        );
    }

    /// Record an error within this span
    pub fn record_error(&self, error: &str) {
        tracing::error!(
            operation = self.operation.as_str(),
            span_id = %self.span_id,
            trace_id = self.trace_id.as_deref().unwrap_or(""),
            error = error,
            "Span error recorded"
        );
    }

    /// Complete the span successfully
    pub fn finish_success(self) -> Duration {
        let duration = self.started_at.elapsed();

        tracing::info!(
            operation = self.operation.as_str(),
            span_id = %self.span_id,
            trace_id = self.trace_id.as_deref().unwrap_or(""),
            duration_ms = duration.as_millis(),
            status = "success",
            "Span completed successfully"
        );

        duration
    }

    /// Complete the span with an error
    pub fn finish_error(self, error: &str) -> Duration {
        let duration = self.started_at.elapsed();

        tracing::error!(
            operation = self.operation.as_str(),
            span_id = %self.span_id,
            trace_id = self.trace_id.as_deref().unwrap_or(""),
            duration_ms = duration.as_millis(),
            status = "error",
            error = error,
            "Span completed with error"
        );

        duration
    }

    /// Get the span ID for correlation
    pub fn span_id(&self) -> Uuid {
        self.span_id
    }

    /// Get duration so far
    pub fn duration(&self) -> Duration {
        self.started_at.elapsed()
    }
}

/// Create a trace ID for distributed tracing (simple implementation)
pub fn generate_trace_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let random = Uuid::new_v4().as_u128();
    format!("{:016x}{:032x}", timestamp, random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracing_setup() {
        let result = TracingSetup::init();
        assert!(result.is_ok());

        let result = TracingSetup::shutdown();
        assert!(result.is_ok());
    }

    #[test]
    fn test_span_creation() {
        let span = ExecutorTracer::span_nats_pull("test-stream", "test-consumer");
        assert_eq!(span.operation, "nats_pull");
        assert!(span.duration().as_millis() < 10); // Should be very recent
    }

    #[test]
    fn test_span_events() {
        let span = ExecutorTracer::span_intent_admission("test-intent", "fs.read");

        span.record_event("policy_evaluated", &[("result", "allow")]);
        span.record_error("validation failed");

        let duration = span.finish_error("processing failed");
        assert!(duration.as_millis() < 50); // Should complete quickly in test
    }

    #[test]
    fn test_trace_id_generation() {
        let trace_id = generate_trace_id();
        assert_eq!(trace_id.len(), 48); // 16 + 32 hex characters

        // Should be different each time
        let trace_id2 = generate_trace_id();
        assert_ne!(trace_id, trace_id2);
    }

    #[test]
    fn test_span_with_trace_id() {
        let trace_id = generate_trace_id();
        let span = ExecutorTracer::span_intent_run("test", "fs.read", "builtin")
            .with_trace_id(trace_id.clone());

        assert_eq!(span.trace_id, Some(trace_id));
        let _ = span.finish_success();
    }

    #[test]
    fn test_span_jail_setup() {
        let span = ExecutorTracer::span_jail_setup("intent-123", "/tmp/work");
        assert_eq!(span.operation, "jail_setup");

        let span_id = span.span_id();
        assert!(!span_id.is_nil());

        let duration = span.finish_success();
        assert!(duration.as_millis() < 50);
    }

    #[test]
    fn test_span_publish_result() {
        let span = ExecutorTracer::span_publish_result("intent-456", "ok");
        assert_eq!(span.operation, "publish_result");

        let duration = span.finish_error("publish failed");
        assert!(duration.as_millis() < 50);
    }

    #[test]
    fn test_span_finish_success() {
        let span = ExecutorTracer::span_nats_pull("stream", "consumer");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let duration = span.finish_success();
        assert!(duration.as_millis() >= 1);
    }

    #[test]
    fn test_span_duration() {
        let span = ExecutorTracer::span_intent_admission("test", "http.fetch");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let duration = span.duration();
        assert!(duration.as_millis() >= 1);
        let _ = span.finish_success();
    }
}
