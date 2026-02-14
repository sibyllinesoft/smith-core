//! Observability configuration for OpenTelemetry-based tracing and monitoring
//!
//! This module provides configuration for the unified observability system
//! with OpenTelemetry traces, metrics, and logs, featuring PII redaction
//! and integration with ClickHouse, Phoenix, and HyperDX.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_true() -> bool {
    true
}

/// Redaction levels for PII and sensitive data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedactionLevel {
    /// Maximum redaction - only essential fields preserved, everything else hashed
    Strict,
    /// Balanced approach - preserve more context while still protecting sensitive data
    Balanced,
    /// Permissive mode - only redact obvious secrets (PII, credentials), keep conversational text
    Permissive,
}

impl Default for RedactionLevel {
    fn default() -> Self {
        RedactionLevel::Permissive
    }
}

/// Sampling strategies for OpenTelemetry traces
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SamplingStrategy {
    /// Always sample all traces
    AlwaysOn,
    /// Never sample traces (only for emergencies)
    AlwaysOff,
    /// Parent-based sampling with fallback
    ParentBased { fallback_ratio: f64 },
    /// Fixed ratio sampling
    Ratio(f64),
}

impl Default for SamplingStrategy {
    fn default() -> Self {
        SamplingStrategy::ParentBased {
            fallback_ratio: 0.1,
        }
    }
}

/// OpenTelemetry Collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    /// OTLP endpoint for receiving traces/metrics/logs
    pub otlp_endpoint: String,

    /// OTLP endpoint for HTTP (fallback)
    pub otlp_http_endpoint: String,

    /// ClickHouse configuration for trace storage
    pub clickhouse: ClickHouseConfig,

    /// Phoenix configuration for LLM/agent session replay
    pub phoenix: PhoenixConfig,

    /// HyperDX configuration for unified observability UI
    pub hyperdx: HyperDxConfig,

    /// Memory limits for the collector
    pub memory_limit_mib: u64,

    /// Batch processing configuration
    pub batch_timeout_ms: u64,
    pub batch_send_size: u32,
}

/// ClickHouse configuration for OLAP storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    /// ClickHouse connection URL
    pub url: String,

    /// Database name for observability data
    pub database: String,

    /// Username for ClickHouse connection
    pub username: String,

    /// Password for ClickHouse connection (should be from env var)
    pub password: String,

    /// Enable compression for better performance
    pub compression: bool,

    /// Table TTL in days
    pub ttl_days: u32,
}

/// Phoenix configuration for LLM/agent session replay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoenixConfig {
    /// Phoenix OTLP ingestion endpoint
    pub otlp_endpoint: String,

    /// Phoenix web UI endpoint
    pub web_endpoint: String,

    /// Enable Phoenix ingestion
    pub enabled: bool,
}

/// HyperDX configuration for unified observability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperDxConfig {
    /// HyperDX web UI endpoint
    pub web_endpoint: String,

    /// HyperDX API endpoint
    pub api_endpoint: String,

    /// Enable HyperDX integration
    pub enabled: bool,
}

/// Main observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Master kill-switch for all observability features
    pub enabled: bool,

    /// Redaction level for PII and sensitive data
    pub redaction_level: RedactionLevel,

    /// OpenTelemetry service configuration
    pub service_name: String,
    pub service_version: String,
    pub deployment_environment: String,

    /// Sampling configuration
    pub sampling: SamplingStrategy,

    /// Resource attributes to add to all telemetry
    pub resource_attributes: HashMap<String, String>,

    /// OpenTelemetry Collector configuration
    pub collector: CollectorConfig,

    /// Enable different telemetry types
    pub traces_enabled: bool,
    pub metrics_enabled: bool,
    pub logs_enabled: bool,

    /// NATS trace propagation configuration
    pub nats_propagation_enabled: bool,

    /// Session management configuration
    pub session_timeout_minutes: u64,

    /// Cost tracking configuration
    pub cost_tracking_enabled: bool,

    /// Performance monitoring thresholds
    pub performance_thresholds: PerformanceThresholds,

    /// Optional chat bridge configuration for task notifications
    #[serde(default)]
    pub chat_bridge_tasks: Option<TasksBridgeConfig>,
}

/// Configuration for routing spans to a Mattermost tasks channel via chat bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TasksBridgeConfig {
    /// Enable Mattermost task notifications
    pub enabled: bool,

    /// Mattermost connection details
    pub mattermost: MattermostBridgeSettings,

    /// Target channel configuration
    pub channel: MattermostChannelSettings,
}

impl Default for TasksBridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mattermost: MattermostBridgeSettings::default(),
            channel: MattermostChannelSettings::default(),
        }
    }
}

/// Mattermost bot configuration for chat bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MattermostBridgeSettings {
    /// Mattermost server base URL (e.g., <https://mattermost.example.com>)
    pub base_url: String,

    /// Personal access token for the bot user
    pub access_token: String,

    /// Prefer the Mattermost AI Agent bridge instead of the REST bot flow
    #[serde(default)]
    pub use_agent_bridge: bool,

    /// Optional Mattermost plugin identifier hosting the bridge endpoint
    #[serde(default)]
    pub plugin_id: Option<String>,

    /// Optional override for the bridge URL (defaults to the plugin bridge endpoint)
    #[serde(default)]
    pub bridge_url: Option<String>,

    /// Shared secret used when calling the bridge endpoint
    #[serde(default)]
    pub webhook_secret: Option<String>,

    /// Optional agent identifier scoped to this bridge
    #[serde(default)]
    pub agent_id: Option<String>,

    /// Optional adapter label used to identify this bridge instance
    #[serde(default)]
    pub label: Option<String>,

    /// Verify TLS certificates when connecting to Mattermost
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

impl Default for MattermostBridgeSettings {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8065".to_string(),
            access_token: String::new(),
            use_agent_bridge: false,
            plugin_id: None,
            bridge_url: None,
            webhook_secret: None,
            agent_id: None,
            label: Some("mattermost-tasks".to_string()),
            verify_tls: true,
        }
    }
}

/// Target Mattermost channel for task notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MattermostChannelSettings {
    /// Team ID that owns the channel
    pub team_id: String,

    /// Channel ID that should receive notifications
    pub channel_id: String,

    /// Optional channel display name
    #[serde(default)]
    pub channel_name: Option<String>,

    /// Optional prefix added ahead of the trace header message
    #[serde(default)]
    pub thread_prefix: Option<String>,
}

impl Default for MattermostChannelSettings {
    fn default() -> Self {
        Self {
            team_id: String::new(),
            channel_id: String::new(),
            channel_name: None,
            thread_prefix: Some("#tasks".to_string()),
        }
    }
}

/// Performance monitoring thresholds for alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceThresholds {
    /// Maximum allowed latency in milliseconds
    pub max_latency_ms: u64,

    /// Maximum token cost per operation in USD
    pub max_cost_usd: f64,

    /// Maximum memory usage in MB
    pub max_memory_mb: u64,

    /// CPU usage threshold percentage
    pub cpu_threshold_percent: f32,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: "http://localhost:4317".to_string(),
            otlp_http_endpoint: "http://localhost:4318".to_string(),
            clickhouse: ClickHouseConfig::default(),
            phoenix: PhoenixConfig::default(),
            hyperdx: HyperDxConfig::default(),
            memory_limit_mib: 512,
            batch_timeout_ms: 5000,
            batch_send_size: 512,
        }
    }
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8123".to_string(),
            database: "otel".to_string(),
            username: "default".to_string(),
            password: "".to_string(),
            compression: true,
            ttl_days: 30,
        }
    }
}

impl Default for PhoenixConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: "http://localhost:6006".to_string(),
            web_endpoint: "http://localhost:6006".to_string(),
            enabled: true,
        }
    }
}

impl Default for HyperDxConfig {
    fn default() -> Self {
        Self {
            web_endpoint: "http://localhost:8080".to_string(),
            api_endpoint: "http://localhost:8080/api".to_string(),
            enabled: true,
        }
    }
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            max_latency_ms: 30000, // 30 seconds
            max_cost_usd: 1.0,     // $1 per operation
            max_memory_mb: 1024,   // 1GB
            cpu_threshold_percent: 80.0,
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Safe default - must be explicitly enabled
            redaction_level: RedactionLevel::Permissive,
            service_name: "smith".to_string(),
            service_version: "0.1.0".to_string(),
            deployment_environment: "development".to_string(),
            sampling: SamplingStrategy::default(),
            resource_attributes: HashMap::new(),
            collector: CollectorConfig::default(),
            traces_enabled: true,
            metrics_enabled: true,
            logs_enabled: true,
            nats_propagation_enabled: true,
            session_timeout_minutes: 60,
            cost_tracking_enabled: true,
            performance_thresholds: PerformanceThresholds::default(),
            chat_bridge_tasks: None,
        }
    }
}

impl ObservabilityConfig {
    /// Validate observability configuration
    pub fn validate(&self) -> Result<()> {
        if self.service_name.is_empty() {
            return Err(anyhow::anyhow!("Service name cannot be empty"));
        }

        if self.service_version.is_empty() {
            return Err(anyhow::anyhow!("Service version cannot be empty"));
        }

        if self.deployment_environment.is_empty() {
            return Err(anyhow::anyhow!("Deployment environment cannot be empty"));
        }

        if self.session_timeout_minutes == 0 {
            return Err(anyhow::anyhow!("Session timeout cannot be zero"));
        }

        if self.session_timeout_minutes > 1440 {
            return Err(anyhow::anyhow!("Session timeout cannot exceed 24 hours"));
        }

        // Validate sampling strategy
        match &self.sampling {
            SamplingStrategy::Ratio(ratio) => {
                if *ratio < 0.0 || *ratio > 1.0 {
                    return Err(anyhow::anyhow!(
                        "Sampling ratio must be between 0.0 and 1.0"
                    ));
                }
            }
            SamplingStrategy::ParentBased { fallback_ratio } => {
                if *fallback_ratio < 0.0 || *fallback_ratio > 1.0 {
                    return Err(anyhow::anyhow!(
                        "Fallback sampling ratio must be between 0.0 and 1.0"
                    ));
                }
            }
            _ => {}
        }

        // Validate collector configuration
        self.collector
            .validate()
            .context("Collector configuration validation failed")?;

        // Validate performance thresholds
        self.performance_thresholds
            .validate()
            .context("Performance thresholds validation failed")?;

        if let Some(tasks) = &self.chat_bridge_tasks {
            if tasks.enabled {
                if tasks.mattermost.base_url.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "Mattermost base_url must be set when chat bridge tasks are enabled"
                    ));
                }
                if tasks.mattermost.use_agent_bridge {
                    let secret_empty = tasks
                        .mattermost
                        .webhook_secret
                        .as_ref()
                        .map(|secret| secret.trim().is_empty())
                        .unwrap_or(true);
                    if secret_empty {
                        return Err(anyhow::anyhow!(
                            "Mattermost webhook_secret must be set when use_agent_bridge is enabled"
                        ));
                    }
                } else if tasks.mattermost.access_token.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "Mattermost access_token must be set when chat bridge tasks are enabled"
                    ));
                }
                if tasks.channel.team_id.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "Mattermost team_id must be set for chat bridge tasks"
                    ));
                }
                if tasks.channel.channel_id.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "Mattermost channel_id must be set for chat bridge tasks"
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get development environment configuration
    pub fn development() -> Self {
        Self {
            enabled: false, // Start disabled even in dev for safety
            deployment_environment: "development".to_string(),
            sampling: SamplingStrategy::AlwaysOn, // Full sampling in dev
            collector: CollectorConfig {
                memory_limit_mib: 256,  // Lower memory for dev
                batch_timeout_ms: 1000, // Faster batching in dev
                ..CollectorConfig::default()
            },
            ..Self::default()
        }
    }

    /// Get production environment configuration
    pub fn production() -> Self {
        Self {
            enabled: false, // Must be explicitly enabled
            deployment_environment: "production".to_string(),
            redaction_level: RedactionLevel::Strict, // Maximum protection
            sampling: SamplingStrategy::ParentBased {
                fallback_ratio: 0.1,
            },
            collector: CollectorConfig {
                memory_limit_mib: 1024, // Higher memory for prod
                ..CollectorConfig::default()
            },
            performance_thresholds: PerformanceThresholds {
                max_latency_ms: 10000, // Stricter in prod
                ..PerformanceThresholds::default()
            },
            ..Self::default()
        }
    }

    /// Get testing environment configuration  
    pub fn testing() -> Self {
        Self {
            enabled: false, // Disabled during tests by default
            deployment_environment: "testing".to_string(),
            sampling: SamplingStrategy::AlwaysOff, // No sampling during tests
            traces_enabled: false,
            metrics_enabled: false,
            logs_enabled: false,
            ..Self::default()
        }
    }
}

impl CollectorConfig {
    pub fn validate(&self) -> Result<()> {
        if self.otlp_endpoint.is_empty() {
            return Err(anyhow::anyhow!("OTLP endpoint cannot be empty"));
        }

        if self.otlp_http_endpoint.is_empty() {
            return Err(anyhow::anyhow!("OTLP HTTP endpoint cannot be empty"));
        }

        if self.memory_limit_mib == 0 {
            return Err(anyhow::anyhow!("Memory limit cannot be zero"));
        }

        if self.memory_limit_mib < 64 {
            return Err(anyhow::anyhow!(
                "Memory limit too low, minimum 64 MiB required"
            ));
        }

        if self.batch_timeout_ms == 0 {
            return Err(anyhow::anyhow!("Batch timeout cannot be zero"));
        }

        if self.batch_send_size == 0 {
            return Err(anyhow::anyhow!("Batch send size cannot be zero"));
        }

        self.clickhouse
            .validate()
            .context("ClickHouse configuration validation failed")?;

        Ok(())
    }
}

impl ClickHouseConfig {
    pub fn validate(&self) -> Result<()> {
        if self.url.is_empty() {
            return Err(anyhow::anyhow!("ClickHouse URL cannot be empty"));
        }

        if self.database.is_empty() {
            return Err(anyhow::anyhow!("ClickHouse database cannot be empty"));
        }

        if self.username.is_empty() {
            return Err(anyhow::anyhow!("ClickHouse username cannot be empty"));
        }

        if self.ttl_days == 0 {
            return Err(anyhow::anyhow!("TTL cannot be zero"));
        }

        if self.ttl_days > 365 {
            tracing::warn!("TTL > 1 year may consume significant storage space");
        }

        Ok(())
    }
}

impl PerformanceThresholds {
    pub fn validate(&self) -> Result<()> {
        if self.max_latency_ms == 0 {
            return Err(anyhow::anyhow!("Maximum latency cannot be zero"));
        }

        if self.max_cost_usd < 0.0 {
            return Err(anyhow::anyhow!("Maximum cost cannot be negative"));
        }

        if self.max_memory_mb == 0 {
            return Err(anyhow::anyhow!("Maximum memory cannot be zero"));
        }

        if self.cpu_threshold_percent <= 0.0 || self.cpu_threshold_percent > 100.0 {
            return Err(anyhow::anyhow!("CPU threshold must be between 0 and 100"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_observability_config() {
        let config = ObservabilityConfig::default();

        // Should be disabled by default for safety
        assert!(!config.enabled);
        assert_eq!(config.redaction_level, RedactionLevel::Permissive);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_environment_configs() {
        let dev_config = ObservabilityConfig::development();
        let prod_config = ObservabilityConfig::production();
        let test_config = ObservabilityConfig::testing();

        assert!(dev_config.validate().is_ok());
        assert!(prod_config.validate().is_ok());
        assert!(test_config.validate().is_ok());

        // Development should allow full sampling
        assert_eq!(dev_config.sampling, SamplingStrategy::AlwaysOn);

        // Production should be strict on redaction
        assert_eq!(prod_config.redaction_level, RedactionLevel::Strict);

        // Testing should disable telemetry
        assert!(!test_config.traces_enabled);
        assert!(!test_config.metrics_enabled);
        assert!(!test_config.logs_enabled);
    }

    #[test]
    fn test_redaction_levels() {
        let strict = RedactionLevel::Strict;
        let balanced = RedactionLevel::Balanced;
        let permissive = RedactionLevel::Permissive;

        assert_ne!(strict, balanced);
        assert_ne!(balanced, permissive);
        assert_eq!(RedactionLevel::default(), RedactionLevel::Permissive);
    }

    #[test]
    fn test_sampling_validation() {
        let valid_config = ObservabilityConfig {
            sampling: SamplingStrategy::Ratio(0.5),
            ..ObservabilityConfig::default()
        };
        assert!(valid_config.validate().is_ok());

        let invalid_low = ObservabilityConfig {
            sampling: SamplingStrategy::Ratio(-0.1),
            ..ObservabilityConfig::default()
        };
        assert!(invalid_low.validate().is_err());

        let invalid_high = ObservabilityConfig {
            sampling: SamplingStrategy::Ratio(1.1),
            ..ObservabilityConfig::default()
        };
        assert!(invalid_high.validate().is_err());
    }

    #[test]
    fn test_performance_thresholds_validation() {
        let mut thresholds = PerformanceThresholds::default();

        // Valid thresholds
        assert!(thresholds.validate().is_ok());

        // Invalid CPU threshold
        thresholds.cpu_threshold_percent = 150.0;
        assert!(thresholds.validate().is_err());

        thresholds.cpu_threshold_percent = -10.0;
        assert!(thresholds.validate().is_err());

        // Invalid cost
        thresholds.cpu_threshold_percent = 80.0;
        thresholds.max_cost_usd = -1.0;
        assert!(thresholds.validate().is_err());
    }
}
