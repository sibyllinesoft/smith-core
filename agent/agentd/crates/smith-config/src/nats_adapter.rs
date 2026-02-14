//! NATS adapter configuration shared across services

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use crate::nats::duration_serde;

/// Shared adapter configuration for NATS services
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdapterConfig {
    pub security: SecurityConfig,
    pub topics: TopicConfig,
    pub performance: PerformanceConfig,
    pub queues: QueueConfig,
}

impl AdapterConfig {
    /// Production-friendly defaults tuned for higher throughput and fan-out.
    pub fn production() -> Self {
        Self {
            performance: PerformanceConfig {
                max_messages_per_second: 2000,
                target_latency_ms: 10,
                max_message_size: 512 * 1024,
                connection_pool_size: 8,
                enable_compression: false,
                batch_size: 25,
                flush_interval: Duration::from_millis(5),
                reconnect: ReconnectConfig {
                    max_attempts: 0,
                    initial_delay: Duration::from_millis(500),
                    max_delay: Duration::from_secs(5),
                    backoff_multiplier: 2.0,
                },
            },
            queues: QueueConfig {
                command_queue_size: 2_000,
                event_queue_size: 10_000,
                processing_queue_size: 5_000,
                drain_strategy: DrainStrategy::DropOldest,
            },
            ..Self::default()
        }
    }

    /// Development defaults emphasizing simplicity over performance.
    pub fn development() -> Self {
        Self::default()
    }

    /// Testing defaults that slow down throughput for easier assertions.
    pub fn testing() -> Self {
        let mut config = Self::default();
        config.performance.max_messages_per_second = 100;
        config.performance.batch_size = 5;
        config.performance.flush_interval = Duration::from_millis(25);
        config
    }

    /// Validate adapter configuration
    pub fn validate(&self) -> Result<()> {
        self.security
            .validate()
            .context("security configuration invalid")?;
        self.topics
            .validate()
            .context("topic configuration invalid")?;
        self.performance
            .validate()
            .context("performance configuration invalid")?;
        self.queues
            .validate()
            .context("queue configuration invalid")?;
        Ok(())
    }
}

/// Security configuration for adapter connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub require_authentication: bool,
    pub auth_token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub jwt_token: Option<String>,
    pub nkey_seed: Option<String>,
    pub tls: TlsConfig,
    pub subject_permissions: SubjectPermissions,
    pub allowed_ips: HashSet<String>,
    pub rate_limits: RateLimits,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_authentication: false,
            auth_token: None,
            username: None,
            password: None,
            jwt_token: None,
            nkey_seed: None,
            tls: TlsConfig::default(),
            subject_permissions: SubjectPermissions::default(),
            allowed_ips: HashSet::new(),
            rate_limits: RateLimits::default(),
        }
    }
}

/// TLS configuration that guards adapter connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub required: bool,
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub server_name: Option<String>,
    pub insecure_skip_verify: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required: false,
            ca_file: None,
            cert_file: None,
            key_file: None,
            server_name: None,
            insecure_skip_verify: false,
        }
    }
}

/// Fine-grained publish/subscribe allow/deny lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectPermissions {
    pub publish_allow: HashSet<String>,
    pub publish_deny: HashSet<String>,
    pub subscribe_allow: HashSet<String>,
    pub subscribe_deny: HashSet<String>,
}

impl Default for SubjectPermissions {
    fn default() -> Self {
        let mut publish_allow = HashSet::new();
        let mut subscribe_allow = HashSet::new();
        publish_allow.insert("claude-code-rs.>".to_string());
        subscribe_allow.insert("claude-code-rs.>".to_string());
        Self {
            publish_allow,
            publish_deny: HashSet::new(),
            subscribe_allow,
            subscribe_deny: HashSet::new(),
        }
    }
}

impl SubjectPermissions {
    /// Construct permissions that open both publish and subscribe for a prefix.
    pub fn wildcard(prefix: &str) -> Self {
        let mut publish_allow = HashSet::new();
        let mut subscribe_allow = HashSet::new();
        publish_allow.insert(format!("{}>", prefix));
        subscribe_allow.insert(format!("{}>", prefix));
        Self {
            publish_allow,
            publish_deny: HashSet::new(),
            subscribe_allow,
            subscribe_deny: HashSet::new(),
        }
    }

    /// Ensure at least one publish or subscribe pattern is whitelisted.
    fn validate(&self) -> Result<()> {
        if self.publish_allow.is_empty() && self.subscribe_allow.is_empty() {
            return Err(anyhow!(
                "at least one publish or subscribe allow pattern required"
            ));
        }
        Ok(())
    }
}

/// Basic throughput and payload guardrails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimits {
    pub messages_per_second: u64,
    pub bytes_per_second: u64,
    pub max_subscriptions: usize,
    pub max_payload_size: usize,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            messages_per_second: 1_000,
            bytes_per_second: 1024 * 1024,
            max_subscriptions: 100,
            max_payload_size: 1024 * 1024,
        }
    }
}

impl RateLimits {
    /// Ensure rate limits are non-zero and sized above minimum thresholds.
    fn validate(&self) -> Result<()> {
        if self.messages_per_second == 0 {
            return Err(anyhow!("messages_per_second must be greater than zero"));
        }
        if self.bytes_per_second == 0 {
            return Err(anyhow!("bytes_per_second must be greater than zero"));
        }
        if self.max_subscriptions == 0 {
            return Err(anyhow!("max_subscriptions must be greater than zero"));
        }
        if self.max_payload_size < 1024 {
            return Err(anyhow!("max_payload_size must be at least 1KB"));
        }
        Ok(())
    }
}

/// Topic configuration
/// Topic namespace and pattern configuration shared by adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicConfig {
    pub prefix: String,
    pub command_subject: String,
    pub event_subject: String,
    pub max_topic_length: usize,
    pub allowed_patterns: Vec<String>,
}

impl Default for TopicConfig {
    fn default() -> Self {
        Self {
            prefix: "claude-code-rs".to_string(),
            command_subject: "command".to_string(),
            event_subject: "event".to_string(),
            max_topic_length: 256,
            allowed_patterns: vec![r"^claude-code-rs\.(command|event)\.[a-z_]+$".to_string()],
        }
    }
}

/// Performance configuration
/// Adapter runtime performance tuning knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_messages_per_second: u64,
    pub target_latency_ms: u64,
    pub max_message_size: usize,
    pub connection_pool_size: usize,
    pub enable_compression: bool,
    pub batch_size: usize,
    #[serde(with = "duration_serde")]
    pub flush_interval: Duration,
    pub reconnect: ReconnectConfig,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_messages_per_second: 1_000,
            target_latency_ms: 20,
            max_message_size: 1024 * 1024,
            connection_pool_size: 4,
            enable_compression: false,
            batch_size: 10,
            flush_interval: Duration::from_millis(10),
            reconnect: ReconnectConfig::default(),
        }
    }
}

/// Reconnect strategy for adapter-managed NATS connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectConfig {
    pub max_attempts: u32,
    #[serde(with = "duration_serde")]
    pub initial_delay: Duration,
    #[serde(with = "duration_serde")]
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(2),
            backoff_multiplier: 2.0,
        }
    }
}

/// Queue configuration for adapter internals
/// Queue sizing and overflow strategy for adapter worker pools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    pub command_queue_size: usize,
    pub event_queue_size: usize,
    pub processing_queue_size: usize,
    pub drain_strategy: DrainStrategy,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            command_queue_size: 1_000,
            event_queue_size: 5_000,
            processing_queue_size: 2_000,
            drain_strategy: DrainStrategy::DropOldest,
        }
    }
}

impl QueueConfig {
    /// Ensure in-memory queue sizes are non-zero.
    fn validate(&self) -> Result<()> {
        if self.command_queue_size == 0 {
            return Err(anyhow!("command_queue_size must be greater than zero"));
        }
        if self.event_queue_size == 0 {
            return Err(anyhow!("event_queue_size must be greater than zero"));
        }
        if self.processing_queue_size == 0 {
            return Err(anyhow!("processing_queue_size must be greater than zero"));
        }
        Ok(())
    }
}

/// Determines how in-memory queues behave once capacity is hit.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DrainStrategy {
    #[default]
    DropOldest,
    DropNewest,
    Block,
    Error,
}

impl SecurityConfig {
    /// Verify authentication, TLS, and IP restrictions are coherent.
    pub fn validate(&self) -> Result<()> {
        if self.require_authentication
            && self.auth_token.is_none()
            && self.username.is_none()
            && self.jwt_token.is_none()
            && self.nkey_seed.is_none()
        {
            return Err(anyhow!(
                "authentication required but no credentials were provided"
            ));
        }

        if self.username.is_some() && self.password.is_none() {
            return Err(anyhow!(
                "username supplied but password missing for basic authentication"
            ));
        }

        if self.tls.required && !self.tls.enabled {
            return Err(anyhow!("TLS is marked as required but disabled"));
        }

        self.subject_permissions
            .validate()
            .context("subject permissions invalid")?;

        for ip in &self.allowed_ips {
            ip.parse::<IpAddr>()
                .with_context(|| format!("invalid allowed IP address: {ip}"))?;
        }

        self.rate_limits.validate().context("rate limits invalid")?;

        Ok(())
    }
}

impl TopicConfig {
    /// Validate prefix, pattern, and length constraints are sane.
    pub fn validate(&self) -> Result<()> {
        if self.prefix.trim().is_empty() {
            return Err(anyhow!("topic prefix cannot be empty"));
        }

        if self.max_topic_length < 10 {
            return Err(anyhow!("max_topic_length must be at least 10 characters"));
        }

        if self.allowed_patterns.is_empty() {
            return Err(anyhow!("allowed_patterns must contain at least one entry"));
        }

        for pattern in &self.allowed_patterns {
            Regex::new(pattern)
                .with_context(|| format!("invalid topic pattern regex: {pattern}"))?;
        }

        Ok(())
    }

    /// Check if a topic matches the configured allow-list of regex patterns.
    pub fn is_topic_allowed(&self, topic: &str) -> bool {
        if topic.len() > self.max_topic_length {
            return false;
        }

        self.allowed_patterns.iter().any(|pattern| {
            Regex::new(pattern)
                .map(|regex| regex.is_match(topic))
                .unwrap_or(false)
        })
    }
}

impl PerformanceConfig {
    /// Validate batching and connection pool limits for adapter throughput.
    pub fn validate(&self) -> Result<()> {
        if self.max_messages_per_second == 0 {
            return Err(anyhow!("max_messages_per_second must be greater than zero"));
        }
        if self.connection_pool_size == 0 {
            return Err(anyhow!("connection_pool_size must be greater than zero"));
        }
        if self.batch_size == 0 {
            return Err(anyhow!("batch_size must be greater than zero"));
        }
        if self.flush_interval.is_zero() {
            return Err(anyhow!("flush_interval must be greater than zero"));
        }

        self.reconnect
            .validate()
            .context("reconnect configuration invalid")?;

        Ok(())
    }
}

impl ReconnectConfig {
    /// Ensure reconnect jitter/backoff parameters are internally consistent.
    pub fn validate(&self) -> Result<()> {
        if self.backoff_multiplier < 1.0 {
            return Err(anyhow!("backoff_multiplier must be at least 1.0"));
        }
        if self.max_delay < self.initial_delay {
            return Err(anyhow!(
                "max_delay must be greater than or equal to initial_delay"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let config = AdapterConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn invalid_topic_prefix_fails() {
        let mut config = AdapterConfig::default();
        config.topics.prefix = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn requires_credentials_when_auth_enabled() {
        let mut config = AdapterConfig::default();
        config.security.require_authentication = true;
        config.security.auth_token = None;
        assert!(config.validate().is_err());

        config.security.auth_token = Some("token".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn queue_sizes_must_be_positive() {
        let mut config = AdapterConfig::default();
        config.queues.command_queue_size = 0;
        assert!(config.validate().is_err());
    }
}
