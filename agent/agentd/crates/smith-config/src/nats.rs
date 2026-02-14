//! NATS and JetStream configuration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// NATS connection and JetStream configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    /// NATS server URL (nats://, tls://, or ws://)
    pub url: String,

    /// Additional NATS server URLs for clustering
    pub cluster_urls: Vec<String>,

    /// JetStream domain
    pub jetstream_domain: String,

    /// Connection timeout
    #[serde(with = "duration_serde")]
    pub connection_timeout: Duration,

    /// Request timeout for pub/sub operations
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,

    /// TLS configuration
    pub tls: Option<TlsConfig>,

    /// Authentication configuration
    pub auth: Option<AuthConfig>,

    /// Performance tuning
    pub performance: NatsPerformanceConfig,

    /// Stream and consumer configuration templates
    pub streams: HashMap<String, StreamConfig>,
}

/// TLS configuration for NATS connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Client certificate file path
    pub cert_file: Option<PathBuf>,

    /// Client private key file path
    pub key_file: Option<PathBuf>,

    /// CA certificate file path
    pub ca_file: Option<PathBuf>,

    /// Skip certificate verification (dangerous, only for development)
    pub insecure: bool,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Username for basic auth
    pub username: Option<String>,

    /// Password for basic auth
    pub password: Option<String>,

    /// JWT token for JWT auth
    pub jwt: Option<String>,

    /// Seed file path for NKey auth
    pub nkey_seed: Option<PathBuf>,

    /// Credentials file path
    pub credentials_file: Option<PathBuf>,
}

/// NATS performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsPerformanceConfig {
    /// Maximum messages per second rate limit
    pub max_messages_per_second: u64,

    /// Target round-trip latency in milliseconds
    pub target_latency_ms: u64,

    /// Maximum message size in bytes
    pub max_message_size: usize,

    /// Connection pool size
    pub connection_pool_size: usize,

    /// Enable message compression
    pub enable_compression: bool,

    /// Batch size for bulk operations
    pub batch_size: usize,

    /// Flush interval for batched messages
    #[serde(with = "duration_serde")]
    pub flush_interval: Duration,

    /// Reconnection configuration
    pub reconnect: ReconnectConfig,
}

/// Reconnection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectConfig {
    /// Maximum reconnection attempts (0 = unlimited)
    pub max_attempts: u32,

    /// Initial reconnection delay
    #[serde(with = "duration_serde")]
    pub initial_delay: Duration,

    /// Maximum reconnection delay
    #[serde(with = "duration_serde")]
    pub max_delay: Duration,

    /// Backoff multiplier (exponential backoff)
    pub backoff_multiplier: f64,
}

/// JetStream stream configuration template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Stream name
    pub name: String,

    /// Stream subjects pattern
    pub subjects: Vec<String>,

    /// Maximum age for messages
    pub max_age: String,

    /// Maximum bytes for stream
    pub max_bytes: String,

    /// Maximum messages in stream
    pub max_messages: Option<i64>,

    /// Storage type (file or memory)
    pub storage: String,

    /// Retention policy
    pub retention: String,

    /// Number of replicas
    pub replicas: u32,

    /// Consumer configuration
    pub consumers: HashMap<String, ConsumerConfig>,
}

/// JetStream consumer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerConfig {
    /// Consumer name
    pub name: String,

    /// Delivery subject (for push consumers)
    pub deliver_subject: Option<String>,

    /// Delivery policy (all, last, new, by_start_sequence, by_start_time)
    pub deliver_policy: String,

    /// Ack policy (none, all, explicit)
    pub ack_policy: String,

    /// Ack wait timeout
    pub ack_wait: String,

    /// Maximum delivery attempts
    pub max_deliver: u32,

    /// Filter subject for consuming subset of stream
    pub filter_subject: Option<String>,

    /// Replay policy (instant, original)
    pub replay_policy: String,
}

impl Default for NatsConfig {
    fn default() -> Self {
        let mut streams = HashMap::new();

        // Default intent stream configuration
        streams.insert(
            "intents".to_string(),
            StreamConfig {
                name: "INTENTS".to_string(),
                subjects: vec!["smith.intents.>".to_string()],
                max_age: "10m".to_string(),
                max_bytes: "1GB".to_string(),
                max_messages: None,
                storage: "file".to_string(),
                retention: "limits".to_string(),
                replicas: 1,
                consumers: {
                    let mut consumers = HashMap::new();
                    consumers.insert(
                        "executor".to_string(),
                        ConsumerConfig {
                            name: "executor".to_string(),
                            deliver_subject: None, // Pull consumer
                            deliver_policy: "new".to_string(),
                            ack_policy: "explicit".to_string(),
                            ack_wait: "30s".to_string(),
                            max_deliver: 3,
                            filter_subject: None,
                            replay_policy: "instant".to_string(),
                        },
                    );
                    consumers
                },
            },
        );

        // Default results stream configuration
        streams.insert(
            "results".to_string(),
            StreamConfig {
                name: "RESULTS".to_string(),
                subjects: vec!["smith.results.>".to_string()],
                max_age: "5m".to_string(),
                max_bytes: "512MB".to_string(),
                max_messages: None,
                storage: "file".to_string(),
                retention: "limits".to_string(),
                replicas: 1,
                consumers: {
                    let mut consumers = HashMap::new();
                    consumers.insert(
                        "http".to_string(),
                        ConsumerConfig {
                            name: "http".to_string(),
                            deliver_subject: None,
                            deliver_policy: "new".to_string(),
                            ack_policy: "explicit".to_string(),
                            ack_wait: "10s".to_string(),
                            max_deliver: 2,
                            filter_subject: None,
                            replay_policy: "instant".to_string(),
                        },
                    );
                    consumers
                },
            },
        );

        Self {
            url: "nats://127.0.0.1:4222".to_string(),
            cluster_urls: vec![],
            jetstream_domain: "JS".to_string(),
            connection_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_millis(100),
            tls: None,
            auth: None,
            performance: NatsPerformanceConfig::default(),
            streams,
        }
    }
}

impl Default for NatsPerformanceConfig {
    fn default() -> Self {
        Self {
            max_messages_per_second: 1000,
            target_latency_ms: 20,
            max_message_size: 1024 * 1024, // 1MB
            connection_pool_size: 4,
            enable_compression: false, // Latency over bandwidth
            batch_size: 10,
            flush_interval: Duration::from_millis(10),
            reconnect: ReconnectConfig::default(),
        }
    }
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
        }
    }
}

impl NatsConfig {
    /// Validate the top-level NATS connection, TLS, and stream settings.
    pub fn validate(&self) -> Result<()> {
        // Validate URL
        if self.url.is_empty() {
            return Err(anyhow::anyhow!("NATS URL cannot be empty"));
        }

        url::Url::parse(&self.url)
            .map_err(|e| anyhow::anyhow!("Invalid NATS URL '{}': {}", self.url, e))?;

        // Validate cluster URLs
        for url in &self.cluster_urls {
            url::Url::parse(url)
                .map_err(|e| anyhow::anyhow!("Invalid cluster URL '{}': {}", url, e))?;
        }

        // Validate JetStream domain
        if self.jetstream_domain.is_empty() {
            return Err(anyhow::anyhow!("JetStream domain cannot be empty"));
        }

        // Validate timeouts
        if self.connection_timeout.as_millis() == 0 {
            return Err(anyhow::anyhow!("Connection timeout must be > 0"));
        }

        if self.request_timeout.as_millis() == 0 {
            return Err(anyhow::anyhow!("Request timeout must be > 0"));
        }

        // Validate TLS config if present
        if let Some(ref tls) = self.tls {
            tls.validate()?;
        }

        // Validate auth config if present
        if let Some(ref auth) = self.auth {
            auth.validate()?;
        }

        // Validate performance config
        self.performance.validate()?;

        // Validate stream configurations
        for (name, stream) in &self.streams {
            stream
                .validate()
                .map_err(|e| anyhow::anyhow!("Stream '{}' validation failed: {}", name, e))?;
        }

        Ok(())
    }

    /// Development profile optimized for localhost experimentation.
    pub fn development() -> Self {
        Self {
            url: "nats://127.0.0.1:4222".to_string(),
            performance: NatsPerformanceConfig {
                target_latency_ms: 50, // Relaxed for development
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Production profile with clustering and higher throughput defaults.
    pub fn production() -> Self {
        Self {
            url: "nats://nats-cluster:4222".to_string(),
            cluster_urls: vec![
                "nats://nats-1:4222".to_string(),
                "nats://nats-2:4222".to_string(),
                "nats://nats-3:4222".to_string(),
            ],
            connection_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_millis(50),
            performance: NatsPerformanceConfig {
                max_messages_per_second: 2000,
                target_latency_ms: 10,
                connection_pool_size: 8,
                ..Default::default()
            },
            streams: {
                let mut streams = HashMap::new();

                // Production intent stream with replication
                streams.insert(
                    "intents".to_string(),
                    StreamConfig {
                        name: "INTENTS".to_string(),
                        subjects: vec!["smith.intents.>".to_string()],
                        max_age: "10m".to_string(),
                        max_bytes: "5GB".to_string(),
                        max_messages: None,
                        storage: "file".to_string(),
                        retention: "limits".to_string(),
                        replicas: 3,
                        consumers: HashMap::new(),
                    },
                );

                streams.insert(
                    "results".to_string(),
                    StreamConfig {
                        name: "RESULTS".to_string(),
                        subjects: vec!["smith.results.>".to_string()],
                        max_age: "5m".to_string(),
                        max_bytes: "2GB".to_string(),
                        max_messages: None,
                        storage: "file".to_string(),
                        retention: "limits".to_string(),
                        replicas: 3,
                        consumers: HashMap::new(),
                    },
                );

                streams
            },
            ..Default::default()
        }
    }

    /// Lightweight profile used in CI where infrastructure is mocked.
    pub fn testing() -> Self {
        Self {
            url: "nats://127.0.0.1:4222".to_string(),
            request_timeout: Duration::from_millis(500), // Generous for CI
            performance: NatsPerformanceConfig {
                max_messages_per_second: 100, // Limited for tests
                batch_size: 5,                // Smaller batches
                ..Default::default()
            },
            streams: HashMap::new(), // No default streams for tests
            ..Default::default()
        }
    }
}

impl TlsConfig {
    /// Ensure referenced TLS artifacts exist on disk.
    pub fn validate(&self) -> Result<()> {
        if let Some(ref cert_file) = self.cert_file {
            if !cert_file.exists() {
                return Err(anyhow::anyhow!(
                    "TLS cert file does not exist: {}",
                    cert_file.display()
                ));
            }
        }

        if let Some(ref key_file) = self.key_file {
            if !key_file.exists() {
                return Err(anyhow::anyhow!(
                    "TLS key file does not exist: {}",
                    key_file.display()
                ));
            }
        }

        if let Some(ref ca_file) = self.ca_file {
            if !ca_file.exists() {
                return Err(anyhow::anyhow!(
                    "TLS CA file does not exist: {}",
                    ca_file.display()
                ));
            }
        }

        Ok(())
    }
}

impl AuthConfig {
    /// Ensure exactly one authentication mechanism is configured correctly.
    pub fn validate(&self) -> Result<()> {
        // At most one auth method should be configured
        let auth_methods = [
            self.username.is_some() && self.password.is_some(),
            self.jwt.is_some(),
            self.nkey_seed.is_some(),
            self.credentials_file.is_some(),
        ];

        let auth_count = auth_methods.iter().filter(|&&x| x).count();
        if auth_count > 1 {
            return Err(anyhow::anyhow!(
                "Multiple authentication methods configured. Use only one."
            ));
        }

        if let Some(ref nkey_file) = self.nkey_seed {
            if !nkey_file.exists() {
                return Err(anyhow::anyhow!(
                    "NKey seed file does not exist: {}",
                    nkey_file.display()
                ));
            }
        }

        if let Some(ref creds_file) = self.credentials_file {
            if !creds_file.exists() {
                return Err(anyhow::anyhow!(
                    "Credentials file does not exist: {}",
                    creds_file.display()
                ));
            }
        }

        Ok(())
    }
}

impl NatsPerformanceConfig {
    /// Validate batching, pool sizing, and reconnect tuning before use.
    pub fn validate(&self) -> Result<()> {
        if self.max_messages_per_second == 0 {
            return Err(anyhow::anyhow!("Max messages per second must be > 0"));
        }

        if self.target_latency_ms > 1000 {
            tracing::warn!("Target latency > 1000ms may impact system performance");
        }

        if self.max_message_size < 1024 {
            return Err(anyhow::anyhow!("Max message size must be >= 1KB"));
        }

        if self.connection_pool_size == 0 {
            return Err(anyhow::anyhow!("Connection pool size must be > 0"));
        }

        if self.batch_size == 0 {
            return Err(anyhow::anyhow!("Batch size must be > 0"));
        }

        self.reconnect.validate()?;

        Ok(())
    }
}

impl ReconnectConfig {
    /// Ensure reconnect backoff parameters are positive and ordered correctly.
    pub fn validate(&self) -> Result<()> {
        if self.initial_delay.as_millis() == 0 {
            return Err(anyhow::anyhow!("Initial delay must be > 0"));
        }

        if self.max_delay < self.initial_delay {
            return Err(anyhow::anyhow!("Max delay must be >= initial delay"));
        }

        if self.backoff_multiplier <= 1.0 {
            return Err(anyhow::anyhow!("Backoff multiplier must be > 1.0"));
        }

        Ok(())
    }
}

impl StreamConfig {
    /// Validate stream metadata, retention, and nested consumer templates.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(anyhow::anyhow!("Stream name cannot be empty"));
        }

        if self.subjects.is_empty() {
            return Err(anyhow::anyhow!("Stream must have at least one subject"));
        }

        // Validate storage type
        if !["file", "memory"].contains(&self.storage.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid storage type: {}. Must be 'file' or 'memory'",
                self.storage
            ));
        }

        // Validate retention policy
        if !["limits", "interest", "workqueue"].contains(&self.retention.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid retention policy: {}. Must be 'limits', 'interest', or 'workqueue'",
                self.retention
            ));
        }

        if self.replicas == 0 {
            return Err(anyhow::anyhow!("Stream replicas must be > 0"));
        }

        // Validate consumers
        for (name, consumer) in &self.consumers {
            consumer
                .validate()
                .map_err(|e| anyhow::anyhow!("Consumer '{}' validation failed: {}", name, e))?;
        }

        Ok(())
    }
}

impl ConsumerConfig {
    /// Validate deliver/ack policies and replay configuration for a consumer.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(anyhow::anyhow!("Consumer name cannot be empty"));
        }

        // Validate deliver policy
        let valid_policies = ["all", "last", "new", "by_start_sequence", "by_start_time"];
        if !valid_policies.contains(&self.deliver_policy.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid deliver policy: {}. Must be one of: {}",
                self.deliver_policy,
                valid_policies.join(", ")
            ));
        }

        // Validate ack policy
        if !["none", "all", "explicit"].contains(&self.ack_policy.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid ack policy: {}. Must be 'none', 'all', or 'explicit'",
                self.ack_policy
            ));
        }

        // Validate replay policy
        if !["instant", "original"].contains(&self.replay_policy.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid replay policy: {}. Must be 'instant' or 'original'",
                self.replay_policy
            ));
        }

        if self.max_deliver == 0 {
            return Err(anyhow::anyhow!("Max deliver must be > 0"));
        }

        Ok(())
    }
}

/// Helper module for serializing durations as millisecond integers.
pub(crate) mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    /// Serialize a `Duration` using millisecond precision for config files.
    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    /// Deserialize a millisecond count into a `Duration`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
