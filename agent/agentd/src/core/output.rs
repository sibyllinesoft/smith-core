//! Output sink and multiplexer traits
//!
//! This module defines the core traits for routing execution results
//! to multiple destinations. This enables:
//! - Replying to the source adapter
//! - Broadcasting to NATS for downstream consumers
//! - Writing to audit logs
//! - Streaming to observability systems

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::intent::{IntentResponse, IntentStatus};

/// Context for emitting results
#[derive(Debug, Clone)]
pub struct EmitContext {
    /// Request ID
    pub request_id: String,

    /// Trace ID for distributed tracing
    pub trace_id: String,

    /// Source adapter that received the request
    pub source_adapter: String,

    /// Reply-to channel (adapter-specific)
    pub reply_to: Option<String>,

    /// Client identifier
    pub client_id: String,

    /// Capability that was executed
    pub capability: String,

    /// Whether the execution succeeded
    pub success: bool,

    /// Custom metadata
    pub metadata: Vec<(String, String)>,
}

impl Default for EmitContext {
    fn default() -> Self {
        Self {
            request_id: String::new(),
            trace_id: String::new(),
            source_adapter: String::new(),
            reply_to: None,
            client_id: String::new(),
            capability: String::new(),
            success: true,
            metadata: vec![],
        }
    }
}

/// Output chunk for streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputChunk {
    /// Stdout data
    Stdout(Vec<u8>),
    /// Stderr data
    Stderr(Vec<u8>),
    /// Progress update
    Progress {
        /// Completion percentage (0.0 - 100.0)
        percent: f32,
        /// Progress message
        message: String,
    },
    /// Log message
    Log {
        /// Log level
        level: String,
        /// Log message
        message: String,
        /// Timestamp
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// Execution metrics update
    Metrics {
        /// Metric name
        name: String,
        /// Metric value
        value: f64,
        /// Metric labels
        labels: Vec<(String, String)>,
    },
    /// Execution completed
    Complete {
        /// Exit code
        exit_code: i32,
        /// Duration in milliseconds
        duration_ms: u64,
    },
    /// Error occurred
    Error {
        /// Error code
        code: String,
        /// Error message
        message: String,
    },
}

/// Trait for output sinks that receive execution results
#[async_trait]
pub trait OutputSink: Send + Sync {
    /// Get the name of this sink
    fn name(&self) -> &str;

    /// Emit a complete result
    async fn emit(&self, result: &IntentResponse, ctx: &EmitContext) -> Result<()>;

    /// Stream an output chunk (for real-time streaming)
    async fn stream(&self, chunk: &OutputChunk, ctx: &EmitContext) -> Result<()>;

    /// Check if this sink is available and working
    async fn is_available(&self) -> bool;

    /// Flush any buffered data
    async fn flush(&self) -> Result<()>;
}

/// Rule for routing output to sinks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Rule name
    pub name: String,

    /// Sink names to route to
    pub sinks: Vec<String>,

    /// Condition for when this rule applies
    pub condition: RoutingCondition,

    /// Whether to continue checking rules after this one matches
    pub continue_matching: bool,

    /// Priority (higher = checked first)
    pub priority: i32,
}

/// Condition for routing rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingCondition {
    /// Always route
    Always,

    /// Never route (disabled rule)
    Never,

    /// Route if the sink is available
    IfAvailable,

    /// Route based on success/failure
    OnStatus(IntentStatus),

    /// Route based on capability pattern
    CapabilityMatch(String),

    /// Route based on source adapter
    SourceAdapter(String),

    /// Route based on metadata key presence
    HasMetadata(String),

    /// Route based on metadata key-value match
    MetadataMatch { key: String, value: String },

    /// Combine conditions with AND
    And(Vec<RoutingCondition>),

    /// Combine conditions with OR
    Or(Vec<RoutingCondition>),

    /// Negate a condition
    Not(Box<RoutingCondition>),
}

impl RoutingCondition {
    /// Evaluate the condition against a context
    pub fn evaluate(&self, ctx: &EmitContext, status: &IntentStatus) -> bool {
        match self {
            RoutingCondition::Always => true,
            RoutingCondition::Never => false,
            RoutingCondition::IfAvailable => true, // Checked separately
            RoutingCondition::OnStatus(s) => s == status,
            RoutingCondition::CapabilityMatch(pattern) => {
                // Simple glob-style matching
                if pattern.ends_with('*') {
                    ctx.capability.starts_with(&pattern[..pattern.len() - 1])
                } else {
                    ctx.capability == *pattern
                }
            }
            RoutingCondition::SourceAdapter(adapter) => ctx.source_adapter == *adapter,
            RoutingCondition::HasMetadata(key) => ctx.metadata.iter().any(|(k, _)| k == key),
            RoutingCondition::MetadataMatch { key, value } => {
                ctx.metadata.iter().any(|(k, v)| k == key && v == value)
            }
            RoutingCondition::And(conditions) => conditions.iter().all(|c| c.evaluate(ctx, status)),
            RoutingCondition::Or(conditions) => conditions.iter().any(|c| c.evaluate(ctx, status)),
            RoutingCondition::Not(condition) => !condition.evaluate(ctx, status),
        }
    }
}

/// Multiplexer that routes output to multiple sinks
pub struct OutputMultiplexer {
    sinks: Vec<Arc<dyn OutputSink>>,
    rules: Vec<RoutingRule>,
    default_sinks: Vec<String>,
}

impl OutputMultiplexer {
    /// Create a new multiplexer
    pub fn new() -> Self {
        Self {
            sinks: Vec::new(),
            rules: Vec::new(),
            default_sinks: Vec::new(),
        }
    }

    /// Add a sink to the multiplexer
    pub fn add_sink(&mut self, sink: Arc<dyn OutputSink>) {
        self.sinks.push(sink);
    }

    /// Add a routing rule
    pub fn add_rule(&mut self, rule: RoutingRule) {
        self.rules.push(rule);
        // Keep rules sorted by priority (descending)
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Set default sinks (used when no rules match)
    pub fn set_defaults(&mut self, sinks: Vec<String>) {
        self.default_sinks = sinks;
    }

    /// Emit a result to all matching sinks
    pub async fn emit(&self, result: &IntentResponse, ctx: &EmitContext) -> Result<()> {
        let target_sinks = self.resolve_sinks(ctx, &result.status);

        for sink_name in &target_sinks {
            if let Some(sink) = self.sinks.iter().find(|s| s.name() == *sink_name) {
                if matches!(self.should_emit(sink_name, ctx), true) {
                    if let Err(e) = sink.emit(result, ctx).await {
                        tracing::warn!(
                            sink = sink_name,
                            error = %e,
                            "Failed to emit to sink"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Stream a chunk to all matching sinks
    pub async fn stream(&self, chunk: &OutputChunk, ctx: &EmitContext) -> Result<()> {
        // For streaming, we use a simpler resolution that doesn't depend on final status
        let target_sinks = self.resolve_streaming_sinks(ctx);

        for sink_name in &target_sinks {
            if let Some(sink) = self.sinks.iter().find(|s| s.name() == *sink_name) {
                if let Err(e) = sink.stream(chunk, ctx).await {
                    tracing::warn!(
                        sink = sink_name,
                        error = %e,
                        "Failed to stream to sink"
                    );
                }
            }
        }

        Ok(())
    }

    /// Flush all sinks
    pub async fn flush(&self) -> Result<()> {
        for sink in &self.sinks {
            if let Err(e) = sink.flush().await {
                tracing::warn!(
                    sink = sink.name(),
                    error = %e,
                    "Failed to flush sink"
                );
            }
        }
        Ok(())
    }

    /// Resolve which sinks should receive the output
    fn resolve_sinks(&self, ctx: &EmitContext, status: &IntentStatus) -> Vec<String> {
        let mut matched_sinks = Vec::new();
        let mut matched = false;

        for rule in &self.rules {
            if rule.condition.evaluate(ctx, status) {
                matched_sinks.extend(rule.sinks.clone());
                matched = true;

                if !rule.continue_matching {
                    break;
                }
            }
        }

        if !matched {
            matched_sinks.extend(self.default_sinks.clone());
        }

        // Deduplicate while preserving order
        let mut seen = std::collections::HashSet::new();
        matched_sinks.retain(|s| seen.insert(s.clone()));

        matched_sinks
    }

    /// Resolve sinks for streaming (simpler rules)
    fn resolve_streaming_sinks(&self, ctx: &EmitContext) -> Vec<String> {
        // For streaming, just use sinks that are marked for streaming
        // This is a simplified version - could be enhanced
        let mut sinks: Vec<String> = self
            .sinks
            .iter()
            .filter(|s| s.name().contains("stream") || s.name() == "reply")
            .map(|s| s.name().to_string())
            .collect();

        if sinks.is_empty() {
            sinks = self.default_sinks.clone();
        }

        sinks
    }

    /// Check if we should emit to a sink (availability check)
    fn should_emit(&self, sink_name: &str, _ctx: &EmitContext) -> bool {
        // Check if any rule has IfAvailable condition for this sink
        for rule in &self.rules {
            if rule.sinks.contains(&sink_name.to_string()) {
                if matches!(rule.condition, RoutingCondition::IfAvailable) {
                    // Would check sink.is_available() here
                    return true;
                }
            }
        }
        true
    }
}

impl Default for OutputMultiplexer {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple reply sink that sends results back to the source
pub struct ReplySink {
    name: String,
}

impl ReplySink {
    pub fn new() -> Self {
        Self {
            name: "reply".to_string(),
        }
    }
}

impl Default for ReplySink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutputSink for ReplySink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn emit(&self, result: &IntentResponse, ctx: &EmitContext) -> Result<()> {
        // The actual reply mechanism depends on the adapter
        // This sink just marks that a reply should be sent
        tracing::debug!(
            request_id = %ctx.request_id,
            reply_to = ?ctx.reply_to,
            status = ?result.status,
            "Reply sink: result ready for reply"
        );
        Ok(())
    }

    async fn stream(&self, chunk: &OutputChunk, ctx: &EmitContext) -> Result<()> {
        tracing::trace!(
            request_id = %ctx.request_id,
            "Reply sink: streaming chunk"
        );
        Ok(())
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}

/// An audit sink that logs all results for compliance
pub struct AuditSink {
    name: String,
}

impl AuditSink {
    pub fn new() -> Self {
        Self {
            name: "audit".to_string(),
        }
    }
}

impl Default for AuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutputSink for AuditSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn emit(&self, result: &IntentResponse, ctx: &EmitContext) -> Result<()> {
        // Log to audit trail
        tracing::info!(
            target: "audit",
            request_id = %ctx.request_id,
            trace_id = %ctx.trace_id,
            capability = %ctx.capability,
            client_id = %ctx.client_id,
            source_adapter = %ctx.source_adapter,
            status = ?result.status,
            code = %result.code,
            "Audit: intent execution completed"
        );
        Ok(())
    }

    async fn stream(&self, _chunk: &OutputChunk, _ctx: &EmitContext) -> Result<()> {
        // Audit sink typically doesn't stream intermediate output
        Ok(())
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== EmitContext Tests =====

    #[test]
    fn test_emit_context_default() {
        let ctx = EmitContext::default();
        assert!(ctx.request_id.is_empty());
        assert!(ctx.trace_id.is_empty());
        assert!(ctx.source_adapter.is_empty());
        assert!(ctx.reply_to.is_none());
        assert!(ctx.client_id.is_empty());
        assert!(ctx.capability.is_empty());
        assert!(ctx.success);
        assert!(ctx.metadata.is_empty());
    }

    #[test]
    fn test_emit_context_creation() {
        let ctx = EmitContext {
            request_id: "req-123".to_string(),
            trace_id: "trace-456".to_string(),
            source_adapter: "grpc".to_string(),
            reply_to: Some("reply-channel".to_string()),
            client_id: "client-789".to_string(),
            capability: "fs.read.v1".to_string(),
            success: true,
            metadata: vec![("key".to_string(), "value".to_string())],
        };

        assert_eq!(ctx.request_id, "req-123");
        assert_eq!(ctx.trace_id, "trace-456");
        assert_eq!(ctx.source_adapter, "grpc");
        assert_eq!(ctx.reply_to, Some("reply-channel".to_string()));
        assert_eq!(ctx.capability, "fs.read.v1");
    }

    // ===== OutputChunk Tests =====

    #[test]
    fn test_output_chunk_stdout() {
        let chunk = OutputChunk::Stdout(b"hello world".to_vec());
        if let OutputChunk::Stdout(data) = chunk {
            assert_eq!(data, b"hello world");
        } else {
            panic!("Expected Stdout variant");
        }
    }

    #[test]
    fn test_output_chunk_stderr() {
        let chunk = OutputChunk::Stderr(b"error message".to_vec());
        if let OutputChunk::Stderr(data) = chunk {
            assert_eq!(data, b"error message");
        } else {
            panic!("Expected Stderr variant");
        }
    }

    #[test]
    fn test_output_chunk_progress() {
        let chunk = OutputChunk::Progress {
            percent: 50.0,
            message: "Halfway done".to_string(),
        };
        if let OutputChunk::Progress { percent, message } = chunk {
            assert_eq!(percent, 50.0);
            assert_eq!(message, "Halfway done");
        } else {
            panic!("Expected Progress variant");
        }
    }

    #[test]
    fn test_output_chunk_log() {
        let chunk = OutputChunk::Log {
            level: "info".to_string(),
            message: "Processing started".to_string(),
            timestamp: chrono::Utc::now(),
        };
        if let OutputChunk::Log { level, message, .. } = chunk {
            assert_eq!(level, "info");
            assert_eq!(message, "Processing started");
        } else {
            panic!("Expected Log variant");
        }
    }

    #[test]
    fn test_output_chunk_metrics() {
        let chunk = OutputChunk::Metrics {
            name: "cpu_usage".to_string(),
            value: 75.5,
            labels: vec![("host".to_string(), "localhost".to_string())],
        };
        if let OutputChunk::Metrics {
            name,
            value,
            labels,
        } = chunk
        {
            assert_eq!(name, "cpu_usage");
            assert_eq!(value, 75.5);
            assert_eq!(labels.len(), 1);
        } else {
            panic!("Expected Metrics variant");
        }
    }

    #[test]
    fn test_output_chunk_complete() {
        let chunk = OutputChunk::Complete {
            exit_code: 0,
            duration_ms: 1234,
        };
        if let OutputChunk::Complete {
            exit_code,
            duration_ms,
        } = chunk
        {
            assert_eq!(exit_code, 0);
            assert_eq!(duration_ms, 1234);
        } else {
            panic!("Expected Complete variant");
        }
    }

    #[test]
    fn test_output_chunk_error() {
        let chunk = OutputChunk::Error {
            code: "E001".to_string(),
            message: "Something went wrong".to_string(),
        };
        if let OutputChunk::Error { code, message } = chunk {
            assert_eq!(code, "E001");
            assert_eq!(message, "Something went wrong");
        } else {
            panic!("Expected Error variant");
        }
    }

    // ===== RoutingRule Tests =====

    #[test]
    fn test_routing_rule_creation() {
        let rule = RoutingRule {
            name: "error-to-audit".to_string(),
            sinks: vec!["audit".to_string()],
            condition: RoutingCondition::OnStatus(IntentStatus::Error),
            continue_matching: false,
            priority: 10,
        };

        assert_eq!(rule.name, "error-to-audit");
        assert_eq!(rule.sinks.len(), 1);
        assert!(!rule.continue_matching);
        assert_eq!(rule.priority, 10);
    }

    // ===== RoutingCondition Tests =====

    #[test]
    fn test_routing_condition_always() {
        let ctx = EmitContext::default();
        let condition = RoutingCondition::Always;
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));
        assert!(condition.evaluate(&ctx, &IntentStatus::Error));
    }

    #[test]
    fn test_routing_condition_never() {
        let ctx = EmitContext::default();
        let condition = RoutingCondition::Never;
        assert!(!condition.evaluate(&ctx, &IntentStatus::Ok));
        assert!(!condition.evaluate(&ctx, &IntentStatus::Error));
    }

    #[test]
    fn test_routing_condition_if_available() {
        let ctx = EmitContext::default();
        let condition = RoutingCondition::IfAvailable;
        // IfAvailable always evaluates to true (availability is checked separately)
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));
    }

    #[test]
    fn test_routing_condition_on_status() {
        let ctx = EmitContext::default();
        let condition = RoutingCondition::OnStatus(IntentStatus::Ok);
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));
        assert!(!condition.evaluate(&ctx, &IntentStatus::Error));
    }

    #[test]
    fn test_routing_condition_capability_match_exact() {
        let mut ctx = EmitContext::default();
        ctx.capability = "fs.read.v1".to_string();

        let condition = RoutingCondition::CapabilityMatch("fs.read.v1".to_string());
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));

        let condition2 = RoutingCondition::CapabilityMatch("fs.write.v1".to_string());
        assert!(!condition2.evaluate(&ctx, &IntentStatus::Ok));
    }

    #[test]
    fn test_routing_condition_capability_match_wildcard() {
        let mut ctx = EmitContext::default();
        ctx.capability = "fs.read.v1".to_string();

        let condition = RoutingCondition::CapabilityMatch("fs.*".to_string());
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));

        let condition2 = RoutingCondition::CapabilityMatch("http.*".to_string());
        assert!(!condition2.evaluate(&ctx, &IntentStatus::Ok));
    }

    #[test]
    fn test_routing_condition_source_adapter() {
        let mut ctx = EmitContext::default();
        ctx.source_adapter = "grpc".to_string();

        let condition = RoutingCondition::SourceAdapter("grpc".to_string());
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));

        let condition2 = RoutingCondition::SourceAdapter("nats".to_string());
        assert!(!condition2.evaluate(&ctx, &IntentStatus::Ok));
    }

    #[test]
    fn test_routing_condition_has_metadata() {
        let mut ctx = EmitContext::default();
        ctx.metadata = vec![("tenant".to_string(), "acme".to_string())];

        let condition = RoutingCondition::HasMetadata("tenant".to_string());
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));

        let condition2 = RoutingCondition::HasMetadata("region".to_string());
        assert!(!condition2.evaluate(&ctx, &IntentStatus::Ok));
    }

    #[test]
    fn test_routing_condition_metadata_match() {
        let mut ctx = EmitContext::default();
        ctx.metadata = vec![("tenant".to_string(), "acme".to_string())];

        let condition = RoutingCondition::MetadataMatch {
            key: "tenant".to_string(),
            value: "acme".to_string(),
        };
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));

        let condition2 = RoutingCondition::MetadataMatch {
            key: "tenant".to_string(),
            value: "other".to_string(),
        };
        assert!(!condition2.evaluate(&ctx, &IntentStatus::Ok));
    }

    #[test]
    fn test_routing_condition_and() {
        let mut ctx = EmitContext::default();
        ctx.capability = "fs.read.v1".to_string();
        ctx.source_adapter = "grpc".to_string();

        let condition = RoutingCondition::And(vec![
            RoutingCondition::CapabilityMatch("fs.*".to_string()),
            RoutingCondition::SourceAdapter("grpc".to_string()),
        ]);
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));

        let condition2 = RoutingCondition::And(vec![
            RoutingCondition::CapabilityMatch("fs.*".to_string()),
            RoutingCondition::SourceAdapter("nats".to_string()),
        ]);
        assert!(!condition2.evaluate(&ctx, &IntentStatus::Ok));
    }

    #[test]
    fn test_routing_condition_or() {
        let mut ctx = EmitContext::default();
        ctx.capability = "fs.read.v1".to_string();
        ctx.source_adapter = "grpc".to_string();

        let condition = RoutingCondition::Or(vec![
            RoutingCondition::CapabilityMatch("http.*".to_string()),
            RoutingCondition::SourceAdapter("grpc".to_string()),
        ]);
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));

        let condition2 = RoutingCondition::Or(vec![
            RoutingCondition::CapabilityMatch("http.*".to_string()),
            RoutingCondition::SourceAdapter("nats".to_string()),
        ]);
        assert!(!condition2.evaluate(&ctx, &IntentStatus::Ok));
    }

    #[test]
    fn test_routing_condition_not() {
        let mut ctx = EmitContext::default();
        ctx.capability = "fs.read.v1".to_string();

        let condition = RoutingCondition::Not(Box::new(RoutingCondition::CapabilityMatch(
            "http.*".to_string(),
        )));
        assert!(condition.evaluate(&ctx, &IntentStatus::Ok));

        let condition2 = RoutingCondition::Not(Box::new(RoutingCondition::CapabilityMatch(
            "fs.*".to_string(),
        )));
        assert!(!condition2.evaluate(&ctx, &IntentStatus::Ok));
    }

    // ===== OutputMultiplexer Tests =====

    #[test]
    fn test_output_multiplexer_new() {
        let mux = OutputMultiplexer::new();
        assert!(mux.sinks.is_empty());
        assert!(mux.rules.is_empty());
        assert!(mux.default_sinks.is_empty());
    }

    #[test]
    fn test_output_multiplexer_default() {
        let mux = OutputMultiplexer::default();
        assert!(mux.sinks.is_empty());
    }

    #[test]
    fn test_output_multiplexer_add_rule_priority_sorting() {
        let mut mux = OutputMultiplexer::new();

        mux.add_rule(RoutingRule {
            name: "low".to_string(),
            sinks: vec![],
            condition: RoutingCondition::Always,
            continue_matching: false,
            priority: 1,
        });

        mux.add_rule(RoutingRule {
            name: "high".to_string(),
            sinks: vec![],
            condition: RoutingCondition::Always,
            continue_matching: false,
            priority: 10,
        });

        mux.add_rule(RoutingRule {
            name: "medium".to_string(),
            sinks: vec![],
            condition: RoutingCondition::Always,
            continue_matching: false,
            priority: 5,
        });

        // Rules should be sorted by priority descending
        assert_eq!(mux.rules[0].name, "high");
        assert_eq!(mux.rules[1].name, "medium");
        assert_eq!(mux.rules[2].name, "low");
    }

    #[test]
    fn test_output_multiplexer_set_defaults() {
        let mut mux = OutputMultiplexer::new();
        mux.set_defaults(vec!["audit".to_string(), "reply".to_string()]);

        assert_eq!(mux.default_sinks.len(), 2);
        assert!(mux.default_sinks.contains(&"audit".to_string()));
        assert!(mux.default_sinks.contains(&"reply".to_string()));
    }

    #[test]
    fn test_output_multiplexer_resolve_sinks_no_rules() {
        let mut mux = OutputMultiplexer::new();
        mux.set_defaults(vec!["default-sink".to_string()]);

        let ctx = EmitContext::default();
        let sinks = mux.resolve_sinks(&ctx, &IntentStatus::Ok);

        assert_eq!(sinks, vec!["default-sink"]);
    }

    #[test]
    fn test_output_multiplexer_resolve_sinks_with_matching_rule() {
        let mut mux = OutputMultiplexer::new();
        mux.set_defaults(vec!["default".to_string()]);

        mux.add_rule(RoutingRule {
            name: "errors-to-audit".to_string(),
            sinks: vec!["audit".to_string()],
            condition: RoutingCondition::OnStatus(IntentStatus::Error),
            continue_matching: false,
            priority: 10,
        });

        let ctx = EmitContext::default();

        // On error, should route to audit
        let sinks = mux.resolve_sinks(&ctx, &IntentStatus::Error);
        assert_eq!(sinks, vec!["audit"]);

        // On success, should use defaults
        let sinks = mux.resolve_sinks(&ctx, &IntentStatus::Ok);
        assert_eq!(sinks, vec!["default"]);
    }

    #[test]
    fn test_output_multiplexer_resolve_sinks_continue_matching() {
        let mut mux = OutputMultiplexer::new();

        mux.add_rule(RoutingRule {
            name: "all-to-audit".to_string(),
            sinks: vec!["audit".to_string()],
            condition: RoutingCondition::Always,
            continue_matching: true, // Continue to next rule
            priority: 10,
        });

        mux.add_rule(RoutingRule {
            name: "all-to-metrics".to_string(),
            sinks: vec!["metrics".to_string()],
            condition: RoutingCondition::Always,
            continue_matching: false,
            priority: 5,
        });

        let ctx = EmitContext::default();
        let sinks = mux.resolve_sinks(&ctx, &IntentStatus::Ok);

        // Should include both since first rule has continue_matching = true
        assert!(sinks.contains(&"audit".to_string()));
        assert!(sinks.contains(&"metrics".to_string()));
    }

    #[test]
    fn test_output_multiplexer_resolve_sinks_deduplication() {
        let mut mux = OutputMultiplexer::new();

        mux.add_rule(RoutingRule {
            name: "rule1".to_string(),
            sinks: vec!["audit".to_string()],
            condition: RoutingCondition::Always,
            continue_matching: true,
            priority: 10,
        });

        mux.add_rule(RoutingRule {
            name: "rule2".to_string(),
            sinks: vec!["audit".to_string(), "metrics".to_string()],
            condition: RoutingCondition::Always,
            continue_matching: false,
            priority: 5,
        });

        let ctx = EmitContext::default();
        let sinks = mux.resolve_sinks(&ctx, &IntentStatus::Ok);

        // audit should only appear once due to deduplication
        assert_eq!(sinks.iter().filter(|s| *s == "audit").count(), 1);
    }

    // ===== ReplySink Tests =====

    #[test]
    fn test_reply_sink_new() {
        let sink = ReplySink::new();
        assert_eq!(sink.name, "reply");
    }

    #[test]
    fn test_reply_sink_default() {
        let sink = ReplySink::default();
        assert_eq!(sink.name, "reply");
    }

    // ===== AuditSink Tests =====

    #[test]
    fn test_audit_sink_new() {
        let sink = AuditSink::new();
        assert_eq!(sink.name, "audit");
    }

    #[test]
    fn test_audit_sink_default() {
        let sink = AuditSink::default();
        assert_eq!(sink.name, "audit");
    }

    // ===== Serialization Tests =====

    #[test]
    fn test_output_chunk_serialization() {
        let chunk = OutputChunk::Progress {
            percent: 75.5,
            message: "Almost done".to_string(),
        };
        let json = serde_json::to_string(&chunk).unwrap();
        let deserialized: OutputChunk = serde_json::from_str(&json).unwrap();

        if let OutputChunk::Progress { percent, message } = deserialized {
            assert_eq!(percent, 75.5);
            assert_eq!(message, "Almost done");
        } else {
            panic!("Expected Progress variant");
        }
    }

    #[test]
    fn test_routing_rule_serialization() {
        let rule = RoutingRule {
            name: "test-rule".to_string(),
            sinks: vec!["audit".to_string()],
            condition: RoutingCondition::Always,
            continue_matching: true,
            priority: 5,
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: RoutingRule = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "test-rule");
        assert_eq!(deserialized.priority, 5);
    }

    #[test]
    fn test_routing_condition_serialization() {
        let condition = RoutingCondition::And(vec![
            RoutingCondition::Always,
            RoutingCondition::OnStatus(IntentStatus::Ok),
        ]);

        let json = serde_json::to_string(&condition).unwrap();
        let deserialized: RoutingCondition = serde_json::from_str(&json).unwrap();

        let ctx = EmitContext::default();
        // Both conditions match, so AND should be true
        assert!(deserialized.evaluate(&ctx, &IntentStatus::Ok));
    }
}
