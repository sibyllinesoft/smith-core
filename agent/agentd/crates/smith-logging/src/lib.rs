//! Structured logging infrastructure for Smith platform
//!
//! This crate provides high-performance, structured logging with NATS integration
//! for centralized log collection across all Smith platform services.
//!
//! # Features
//!
//! - **NATS Integration**: Emit logs directly to NATS subjects for centralized collection
//! - **Performance Optimized**: Asynchronous logging with batching and buffering
//! - **Structured Format**: JSON logs with consistent fields and correlation IDs
//! - **Configurable Filtering**: Per-module, per-level filtering with target-based rules
//! - **Graceful Fallback**: Console logging when NATS is unavailable
//! - **Rate Limiting**: Prevent log flooding with configurable rate limits
//!
//! # Usage
//!
//! ```rust,ignore
//! use smith_logging::{init_logging, LoggingLayer};
//! use smith_config::Config;
//!
//! // Initialize logging with NATS integration
//! let config = Config::development();
//! let _guard = init_logging(&config.logging, &config.nats, "smith-core").await?;
//!
//! // Use standard tracing macros
//! tracing::info!("Service started");
//! tracing::warn!("High memory usage detected");
//! tracing::error!("Database connection failed");
//! ```

use anyhow::{Context, Result};
use async_nats::Client as NatsClient;
use chrono::{DateTime, Utc};
use governor::{
    clock::DefaultClock, middleware::NoOpMiddleware, state::direct::NotKeyed, state::InMemoryState,
    Quota, RateLimiter,
};
use serde::{Deserialize, Serialize};
use smith_bus::subjects::builders::LogSubject;
use smith_config::{LoggingConfig, NatsConfig, NatsLoggingConfig};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{Event, Subscriber};
use tracing_subscriber::{
    layer::{Context as TracingContext, SubscriberExt},
    util::SubscriberInitExt,
    EnvFilter, Layer, Registry,
};
use uuid::Uuid;

pub mod error;
pub mod metrics;

pub use error::{LoggingError, LoggingResult};

/// Structured log entry for NATS transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp in RFC 3339 format
    pub timestamp: DateTime<Utc>,

    /// Log level (ERROR, WARN, INFO, DEBUG, TRACE)
    pub level: String,

    /// Service name (e.g., "smith-core", "smith-executor")
    pub service: String,

    /// Module target (e.g., "smith::planner")
    pub target: String,

    /// Log message
    pub message: String,

    /// Structured fields from the log event
    pub fields: HashMap<String, serde_json::Value>,

    /// Span information (if available)
    pub span: Option<SpanInfo>,

    /// Trace information (if enabled)
    pub trace: Option<TraceInfo>,

    /// Unique correlation ID for this log entry
    pub correlation_id: String,

    /// Node/instance identifier
    pub node_id: String,

    /// Additional metadata
    pub metadata: LogMetadata,
}

/// Span information for distributed tracing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanInfo {
    /// Span ID
    pub id: String,

    /// Parent span ID (if any)
    pub parent_id: Option<String>,

    /// Span name
    pub name: String,

    /// Span fields
    pub fields: HashMap<String, serde_json::Value>,
}

/// Trace information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInfo {
    /// Trace ID
    pub id: String,

    /// Trace context
    pub context: HashMap<String, String>,
}

/// Additional log metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMetadata {
    /// Source file (in debug builds)
    pub file: Option<String>,

    /// Source line (in debug builds)
    pub line: Option<u32>,

    /// Module path
    pub module_path: Option<String>,

    /// Thread ID
    pub thread_id: Option<String>,

    /// Performance category (if performance logging is enabled)
    pub performance_category: Option<String>,
}

/// NATS logging layer for tracing-subscriber
pub struct NatsLoggingLayer {
    /// Service name for this logger
    service_name: String,

    /// Configuration
    config: NatsLoggingConfig,

    /// Async sender for log entries
    log_sender: mpsc::UnboundedSender<LogEntry>,

    /// Rate limiter (optional)
    rate_limiter: Option<Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>>,

    /// Node ID for this instance
    node_id: String,
}

/// Background log processor that handles NATS publishing
struct LogProcessor {
    /// NATS client
    nats_client: NatsClient,

    /// Configuration
    config: NatsLoggingConfig,

    /// Log entry receiver
    log_receiver: mpsc::UnboundedReceiver<LogEntry>,

    /// Buffer for batching
    buffer: Vec<LogEntry>,

    /// Service name
    service_name: String,
}

/// Guard that ensures proper cleanup of logging infrastructure
pub struct LoggingGuard {
    /// Handle to the background processor
    _processor_handle: tokio::task::JoinHandle<Result<()>>,
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        // The processor handle will be cancelled when dropped
        tracing::debug!("Logging infrastructure shutting down");
    }
}

impl NatsLoggingLayer {
    /// Create a new NATS logging layer
    pub fn new(
        service_name: String,
        config: NatsLoggingConfig,
        nats_client: NatsClient,
    ) -> Result<(Self, LoggingGuard)> {
        let (log_sender, log_receiver) = mpsc::unbounded_channel();

        // Create rate limiter if configured
        let rate_limiter = if config.rate_limit > 0 {
            let quota = Quota::per_second(
                NonZeroU32::new(config.rate_limit as u32)
                    .context("Invalid rate limit configuration")?,
            );
            Some(Arc::new(RateLimiter::direct(quota)))
        } else {
            None
        };

        // Generate node ID
        let short_uuid = Uuid::new_v4().to_string();
        let node_id = format!(
            "{}_{}",
            hostname::get().unwrap_or_default().to_string_lossy(),
            &short_uuid[..8]
        );

        // Start background processor
        let processor = LogProcessor {
            nats_client,
            config: config.clone(),
            log_receiver,
            buffer: Vec::with_capacity(config.batch_size),
            service_name: service_name.clone(),
        };

        let processor_handle = tokio::spawn(async move { processor.run().await });

        let layer = Self {
            service_name,
            config,
            log_sender,
            rate_limiter,
            node_id,
        };

        let guard = LoggingGuard {
            _processor_handle: processor_handle,
        };

        Ok((layer, guard))
    }

    /// Check if this log event should be processed
    fn should_process(&self, event: &Event) -> bool {
        // Check level filter
        if let Some(ref level_filter) = self.config.level_filter {
            let event_level = event.metadata().level();
            let filter_level = match level_filter.as_str() {
                "error" => tracing::Level::ERROR,
                "warn" => tracing::Level::WARN,
                "info" => tracing::Level::INFO,
                "debug" => tracing::Level::DEBUG,
                "trace" => tracing::Level::TRACE,
                _ => return true, // Invalid filter, allow all
            };

            if *event_level > filter_level {
                return false;
            }
        }

        // Check target filters
        if !self.config.target_filters.is_empty() {
            let target = event.metadata().target();
            let matches = self
                .config
                .target_filters
                .iter()
                .any(|filter| target.starts_with(filter));
            if !matches {
                return false;
            }
        }

        // Check rate limit
        if let Some(ref rate_limiter) = self.rate_limiter {
            if rate_limiter.check().is_err() {
                return false;
            }
        }

        true
    }

    /// Convert tracing event to log entry
    fn event_to_log_entry<S>(&self, event: &Event, ctx: &TracingContext<'_, S>) -> LogEntry
    where
        S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        let metadata = event.metadata();

        // Extract fields from the event
        let mut field_visitor = FieldVisitor::new();
        event.record(&mut field_visitor);

        // Extract span information if enabled
        let span = if self.config.include_spans {
            ctx.event_span(event).map(|span_ref| {
                let span_metadata = span_ref.metadata();
                let mut span_fields = HashMap::new();

                // Extract span fields (simplified implementation)
                let span_name = span_metadata.name().to_string();
                span_fields.insert(
                    "span_name".to_string(),
                    serde_json::Value::String(span_name),
                );

                SpanInfo {
                    id: format!("{:x}", span_ref.id().into_u64()),
                    parent_id: span_ref
                        .parent()
                        .map(|p| format!("{:x}", p.id().into_u64())),
                    name: span_metadata.name().to_string(),
                    fields: span_fields,
                }
            })
        } else {
            None
        };

        // Generate correlation ID
        let correlation_id = Uuid::new_v4().to_string();

        // Create metadata
        let log_metadata = LogMetadata {
            file: if cfg!(debug_assertions) {
                metadata.file().map(|s| s.to_string())
            } else {
                None
            },
            line: if cfg!(debug_assertions) {
                metadata.line()
            } else {
                None
            },
            module_path: metadata.module_path().map(|s| s.to_string()),
            thread_id: Some(format!("{:?}", std::thread::current().id())),
            performance_category: field_visitor
                .fields
                .get("performance_category")
                .and_then(|v| v.as_str().map(|s| s.to_string())),
        };

        LogEntry {
            timestamp: Utc::now(),
            level: metadata.level().to_string().to_uppercase(),
            service: self.service_name.clone(),
            target: metadata.target().to_string(),
            message: field_visitor.message,
            fields: field_visitor.fields,
            span,
            trace: None, // TODO: Implement trace context extraction
            correlation_id,
            node_id: self.node_id.clone(),
            metadata: log_metadata,
        }
    }
}

impl<S> Layer<S> for NatsLoggingLayer
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: TracingContext<'_, S>) {
        // Check if we should process this event
        if !self.should_process(event) {
            return;
        }

        // Convert to log entry
        let log_entry = self.event_to_log_entry(event, &ctx);

        // Send to background processor (non-blocking)
        if self.log_sender.send(log_entry).is_err() {
            // Channel closed, processor is shutting down
            if self.config.fallback_to_console {
                eprintln!(
                    "NATS logging unavailable, log entry lost: {}",
                    event.metadata().target()
                );
            }
        }
    }
}

/// Field visitor for extracting structured data from log events
struct FieldVisitor {
    message: String,
    fields: HashMap<String, serde_json::Value>,
}

impl FieldVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            fields: HashMap::new(),
        }
    }
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let value_str = format!("{:?}", value);

        if field.name() == "message" {
            self.message = value_str;
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(value_str),
            );
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }
}

impl LogProcessor {
    /// Main processing loop
    async fn run(mut self) -> Result<()> {
        let mut batch_timer = if self.config.batch_enabled {
            Some(interval(Duration::from_millis(
                self.config.batch_timeout_ms,
            )))
        } else {
            None
        };

        loop {
            tokio::select! {
                // Receive log entry
                log_entry = self.log_receiver.recv() => {
                    match log_entry {
                        Some(entry) => {
                            if self.config.batch_enabled {
                                self.buffer.push(entry);
                                if self.buffer.len() >= self.config.batch_size {
                                    self.flush_buffer().await?;
                                }
                            } else {
                                self.publish_single(entry).await?;
                            }
                        }
                        None => {
                            // Channel closed, flush buffer and exit
                            if !self.buffer.is_empty() {
                                self.flush_buffer().await?;
                            }
                            break;
                        }
                    }
                }

                // Batch timeout
                _ = async {
                    if let Some(ref mut timer) = batch_timer {
                        timer.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    if !self.buffer.is_empty() {
                        self.flush_buffer().await?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Publish a single log entry
    async fn publish_single(&self, entry: LogEntry) -> Result<()> {
        let subject = self.get_subject_for_entry(&entry);
        let payload = serde_json::to_vec(&entry).context("Failed to serialize log entry")?;

        let timeout = Duration::from_millis(self.config.publish_timeout_ms);

        for attempt in 1..=self.config.max_retries {
            match tokio::time::timeout(
                timeout,
                self.nats_client
                    .publish(subject.clone(), payload.clone().into()),
            )
            .await
            {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => {
                    tracing::warn!(
                        "NATS publish failed (attempt {}/{}): {}",
                        attempt,
                        self.config.max_retries,
                        e
                    );
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        "NATS publish timeout (attempt {}/{})",
                        attempt,
                        self.config.max_retries
                    );
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
                    }
                }
            }
        }

        // All retries failed
        if self.config.fallback_to_console {
            eprintln!(
                "NATS logging failed, falling back to console: {}",
                entry.message
            );
        }

        Err(anyhow::anyhow!(
            "Failed to publish log entry after {} retries",
            self.config.max_retries
        ))
    }

    /// Flush the buffer by publishing all entries
    async fn flush_buffer(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let entries =
            std::mem::replace(&mut self.buffer, Vec::with_capacity(self.config.batch_size));

        // Publish entries in parallel (but limited concurrency)
        let chunk_size = 10; // Limit concurrent publishes
        for chunk in entries.chunks(chunk_size) {
            let tasks: Vec<_> = chunk
                .iter()
                .map(|entry| self.publish_single(entry.clone()))
                .collect();

            // Wait for all tasks in this chunk to complete
            let results = futures::future::join_all(tasks).await;

            // Log any errors (already handled in publish_single)
            for (i, result) in results.iter().enumerate() {
                if let Err(e) = result {
                    tracing::debug!("Failed to publish log entry {}: {}", i, e);
                }
            }
        }

        Ok(())
    }

    /// Get appropriate NATS subject for a log entry
    fn get_subject_for_entry(&self, entry: &LogEntry) -> String {
        match entry.level.as_str() {
            "ERROR" => LogSubject::error(&self.service_name),
            "WARN" | "INFO" | "DEBUG" | "TRACE" => {
                LogSubject::service(&self.service_name, &entry.level.to_lowercase())
            }
            _ => LogSubject::service(&self.service_name, &"unknown".to_string()),
        }
    }
}

/// Initialize logging with NATS integration
pub async fn init_logging(
    logging_config: &LoggingConfig,
    nats_config: &NatsConfig,
    service_name: &str,
) -> Result<Option<LoggingGuard>> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&logging_config.level));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
        .with_level(true);

    let registry = Registry::default().with(env_filter).with(fmt_layer);

    // Add NATS layer if enabled
    if logging_config.nats.enabled {
        // Connect to NATS
        let nats_client = async_nats::connect(&nats_config.url)
            .await
            .context("Failed to connect to NATS for logging")?;

        let (nats_layer, guard) = NatsLoggingLayer::new(
            service_name.to_string(),
            logging_config.nats.clone(),
            nats_client,
        )?;

        match registry.with(nats_layer).try_init() {
            Ok(()) => {
                tracing::info!(
                    "Logging initialized with NATS integration for service: {}",
                    service_name
                );
                Ok(Some(guard))
            }
            Err(err) => {
                tracing::warn!(
                    "Logging already initialized, skipping duplicate subscriber: {}",
                    err
                );
                // Drop guard so the background processor shuts down cleanly.
                drop(guard);
                Ok(None)
            }
        }
    } else {
        match registry.try_init() {
            Ok(()) => {
                tracing::info!(
                    "Logging initialized without NATS integration for service: {}",
                    service_name
                );
            }
            Err(err) => {
                tracing::warn!(
                    "Logging already initialized, skipping duplicate subscriber: {}",
                    err
                );
            }
        }
        Ok(None)
    }
}

/// Simplified initialization for testing
pub fn init_console_logging(level: &str) -> Result<()> {
    let env_filter = EnvFilter::new(level);
    let builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
        .with_level(true);

    // Ignore error if a subscriber is already set; this happens in test environments.
    let _ = builder.try_init();

    Ok(())
}

// Re-export for convenience
pub use tracing::{debug, error, info, trace, warn};
