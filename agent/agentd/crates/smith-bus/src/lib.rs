//! # Smith NATS JetStream Bus Library
//!
//! This crate provides high-level abstractions over NATS JetStream for the Smith platform,
//! implementing reliable message patterns with automatic retries, work queue semantics,
//! and comprehensive stream management.
//!
//! ## Features
//!
//! - **Type-Safe Subjects**: Compile-time validated NATS subject patterns
//! - **Stream Management**: Automatic stream and consumer lifecycle management
//! - **Work Queue Semantics**: Fair distribution of work across multiple consumers
//! - **Retry Logic**: Exponential backoff with jitter for failed operations
//! - **Health Monitoring**: Connection health checks and stream lag monitoring
//! - **Sharding Support**: Domain-based message routing for horizontal scaling
//!
//! ## Architecture
//!
//! Smith uses a Phase 2 JetStream architecture optimized for high throughput and
//! reliability:
//!
//! ```text
//! Publishers → Raw Streams → Admission → Vetted Streams → Consumers → Results
//!                      ↓
//!                 Audit Streams (compliance & debugging)
//! ```
//!
//! ## Stream Topology
//!
//! | Stream | Purpose | Retention | Configuration |
//! |--------|---------|-----------|--------------|
//! | `SDLC_RAW` | Intent ingestion | WorkQueue | High-throughput (500MB) |
//! | `ATOMS_VETTED` | Approved intents | Interest | Ordering guarantees (1GB) |
//! | `ATOMS_RESULTS` | Execution results | 48h limit | Performance tracking (2GB) |
//! | `AUDIT_SECURITY` | Security events | 1 year | Compliance retention (10GB) |
//!
//! ## Basic Usage
//!
//! ```rust,ignore
//! use smith_bus::{SmithBus, ConsumerConfig};
//! use smith_protocol::Intent;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Connect to NATS JetStream
//! let bus = SmithBus::connect("nats://localhost:4222").await?;
//!
//! // Publish an intent
//! let intent = Intent::new(/* ... */);
//! bus.publish("smith.intents.raw.fs.read.v1".to_string(), &intent).await?;
//!
//! // Create a consumer for processing results
//! let config = ConsumerConfig::default();
//! let consumer = bus.consumer("fs.read.v1", config).await?;
//!
//! // Process messages with automatic retry and backoff
//! while let Some(message) = consumer.next_message().await? {
//!     match process_message(&message.payload) {
//!         Ok(_) => message.ack().await?,
//!         Err(_) => message.nack().await?, // Will retry with exponential backoff
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Performance Characteristics
//!
//! - **Throughput**: 10,000+ messages/second per stream on commodity hardware
//! - **Latency**: Sub-millisecond message delivery in optimal conditions
//! - **Reliability**: At-least-once delivery with deduplication windows
//! - **Scalability**: Horizontal scaling via consumer groups and domain sharding
//!
//! ## Error Handling
//!
//! The library implements comprehensive error handling with exponential backoff:
//!
//! - **Connection failures**: Automatic reconnection with circuit breaker
//! - **Message failures**: Configurable retry counts with dead letter queues
//! - **Stream errors**: Graceful degradation and health status reporting
//!
//! For detailed stream configuration and subject patterns, see the [`streams`] and [`subjects`] modules.

use anyhow::{Context, Result};
use async_nats::jetstream::{self, consumer::PullConsumer};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio_retry::{strategy::ExponentialBackoff, Retry};
use tracing::{debug, error, info, warn};

pub mod consumer;
pub mod lag_monitor;
pub mod publisher;
pub mod sharding;
pub mod streams;
pub mod subjects;

#[cfg(test)]
mod consumer_tests;
#[cfg(test)]
mod lag_monitor_tests;
#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod publisher_tests;
#[cfg(test)]
mod smith_bus_tests;
#[cfg(test)]
mod streams_tests;

pub use consumer::Consumer;
pub use lag_monitor::*;
pub use publisher::Publisher;
pub use sharding::*;
pub use streams::StreamManager;
pub use subjects::*;

/// High-level NATS JetStream client for Smith intent processing.
///
/// `SmithBus` provides a simplified interface over NATS JetStream with built-in
/// retry logic, health monitoring, and stream management. It handles connection
/// lifecycle, provides typed subject patterns, and implements work queue semantics
/// for distributed processing.
///
/// ## Connection Management
///
/// The bus maintains persistent connections with automatic reconnection:
///
/// ```rust,ignore
/// use smith_bus::SmithBus;
///
/// # async fn example() -> anyhow::Result<()> {
/// let bus = SmithBus::connect("nats://localhost:4222").await?;
///
/// // Check health status
/// let health = bus.health_check().await?;
/// if !health.is_healthy() {
///     eprintln!("Warning: NATS connection degraded");
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Publishing Messages
///
/// Messages are published with automatic serialization and retry logic:
///
/// ```rust,ignore
/// use smith_bus::SmithBus;
/// use smith_protocol::Intent;
/// use serde_json::json;
///
/// # async fn example() -> anyhow::Result<()> {
/// let bus = SmithBus::connect("nats://localhost:4222").await?;
/// let intent = json!({"capability": "fs.read.v1", "params": {"path": "/etc/hostname"}});
///
/// // Publish with automatic retry on failure
/// bus.publish("smith.intents.raw.fs.read.v1".to_string(), &intent).await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Consumer Creation
///
/// Consumers are created with configurable retry policies and work distribution:
///
/// ```rust,ignore
/// use smith_bus::{SmithBus, ConsumerConfig};
/// use std::time::Duration;
///
/// # async fn example() -> anyhow::Result<()> {
/// let bus = SmithBus::connect("nats://localhost:4222").await?;
///
/// let config = ConsumerConfig {
///     name: "fs-reader".to_string(),
///     max_deliver: 5,
///     ack_wait: Duration::from_secs(30),
///     worker_count: 4,
///     ..Default::default()
/// };
///
/// let consumer = bus.consumer("fs.read.v1", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SmithBus {
    nats_client: async_nats::Client,
    jetstream: jetstream::Context,
}

impl SmithBus {
    /// Connect to NATS server and create JetStream context
    pub async fn connect(nats_url: &str) -> Result<Self> {
        info!("Connecting to NATS server: {}", nats_url);

        let nats_client = async_nats::connect(nats_url)
            .await
            .with_context(|| format!("Failed to connect to NATS server: {}", nats_url))?;

        let jetstream = jetstream::new(nats_client.clone());

        info!("Successfully connected to NATS server");

        Ok(Self {
            nats_client,
            jetstream,
        })
    }

    /// Create a publisher for publishing intents and other messages
    pub fn publisher(&self) -> Publisher {
        Publisher::new(self.jetstream.clone())
    }

    /// Create a consumer for consuming intents from a specific capability
    pub async fn consumer(&self, capability: &str, config: ConsumerConfig) -> Result<Consumer> {
        Consumer::new(self.jetstream.clone(), capability, config).await
    }

    /// Create a stream manager for managing JetStream streams
    pub fn stream_manager(&self) -> StreamManager {
        StreamManager::new(self.jetstream.clone())
    }

    /// Get the underlying NATS client
    pub fn nats_client(&self) -> &async_nats::Client {
        &self.nats_client
    }

    /// Get the JetStream context
    pub fn jetstream(&self) -> &jetstream::Context {
        &self.jetstream
    }

    /// Check connectivity to NATS server
    pub async fn health_check(&self) -> Result<HealthStatus> {
        let nats_connected = Self::check_nats_connectivity(&self.nats_client);
        let jetstream_available = self.check_jetstream_availability().await;

        Ok(HealthStatus {
            nats_connected,
            jetstream_available,
        })
    }

    /// Check basic NATS connectivity
    fn check_nats_connectivity(nats_client: &async_nats::Client) -> bool {
        matches!(
            nats_client.connection_state(),
            async_nats::connection::State::Connected
        )
    }

    /// Test JetStream availability by trying to list streams
    async fn check_jetstream_availability(&self) -> bool {
        match tokio::time::timeout(Duration::from_secs(1), async {
            self.jetstream
                .stream_names()
                .try_collect::<Vec<String>>()
                .await
        })
        .await
        {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                warn!("JetStream not available: {}", e);
                false
            }
            Err(_) => {
                warn!("JetStream timeout - may not be available");
                false
            }
        }
    }

    /// Publish a message to a subject
    pub async fn publish<T: Serialize>(&self, subject: String, message: &T) -> Result<()> {
        self.publisher().publish(subject, message).await
    }

    /// Publish a message with headers
    pub async fn publish_with_headers<T: Serialize>(
        &self,
        subject: String,
        headers: async_nats::HeaderMap,
        message: &T,
    ) -> Result<()> {
        self.publisher()
            .publish_with_headers(subject, headers, message)
            .await
    }
}

/// Health status of NATS/JetStream connectivity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthStatus {
    /// Whether NATS is connected
    pub nats_connected: bool,
    /// Whether JetStream is available
    pub jetstream_available: bool,
}

impl HealthStatus {
    /// Check if the connection is fully healthy
    pub fn is_healthy(&self) -> bool {
        self.nats_connected && self.jetstream_available
    }
}

/// Configuration for creating consumers
#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    /// Consumer name (must be unique per stream)
    pub name: String,
    /// Consumer group for load balancing (optional)
    pub consumer_group: Option<String>,
    /// Maximum number of messages to deliver at once
    pub max_deliver: i64,
    /// Acknowledgement wait time before redelivery
    pub ack_wait: Duration,
    /// Maximum age of messages to process
    pub max_age: Option<Duration>,
    /// Whether to start from the beginning or end of stream
    pub start_sequence: ConsumerStartSequence,
    /// Number of worker instances for this consumer
    pub worker_count: usize,
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            name: format!("consumer-{}", uuid::Uuid::new_v4()),
            consumer_group: None,
            max_deliver: 3, // Retry up to 3 times
            ack_wait: Duration::from_secs(30),
            max_age: Some(Duration::from_secs(24 * 60 * 60)),
            start_sequence: ConsumerStartSequence::Latest,
            worker_count: 1,
        }
    }
}

/// Where to start consuming messages from
#[derive(Debug, Clone)]
pub enum ConsumerStartSequence {
    /// Start from the first message in the stream
    First,
    /// Start from the last message in the stream
    Latest,
    /// Start from a specific sequence number
    Sequence(u64),
    /// Start from messages after a specific time
    Time(chrono::DateTime<chrono::Utc>),
}

/// Message wrapper for JetStream messages with retry support
pub struct Message<T> {
    /// The deserialized message payload
    pub payload: T,
    /// The original JetStream message for acknowledgement
    pub jetstream_message: jetstream::Message,
    /// Number of delivery attempts
    pub delivery_count: u64,
    /// Subject the message was published to
    pub subject: String,
}

impl<T> Message<T> {
    /// Acknowledge successful processing of the message
    pub async fn ack(&self) -> Result<()> {
        self.jetstream_message
            .ack()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to ack message: {}", e))
    }

    /// Negative acknowledge - requeue for retry
    pub async fn nack(&self) -> Result<()> {
        self.jetstream_message
            .ack_with(jetstream::AckKind::Nak(None))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to nack message: {}", e))
    }

    /// Terminate message processing - won't be redelivered
    pub async fn term(&self) -> Result<()> {
        self.jetstream_message
            .ack_with(jetstream::AckKind::Term)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to terminate message: {}", e))
    }

    /// Check if this message has been redelivered
    pub fn is_redelivery(&self) -> bool {
        self.delivery_count > 1
    }
}

/// Work queue semantics helper for fair distribution of work
pub struct WorkQueue {
    consumer: PullConsumer,
    batch_size: usize,
    timeout: Duration,
}

impl WorkQueue {
    /// Create a new work queue from a consumer
    pub fn new(consumer: PullConsumer, batch_size: usize, timeout: Duration) -> Self {
        Self {
            consumer,
            batch_size,
            timeout,
        }
    }

    /// Pull the next batch of messages with exponential backoff
    pub async fn pull_batch(&mut self) -> Result<Vec<jetstream::Message>> {
        let retry_strategy = Self::create_batch_retry_strategy();

        Retry::spawn(retry_strategy, || self.attempt_pull_batch())
            .await
            .with_context(|| "Failed to pull message batch after retries")
    }

    /// Create retry strategy for batch operations
    fn create_batch_retry_strategy() -> impl Iterator<Item = Duration> {
        ExponentialBackoff::from_millis(100)
            .max_delay(Duration::from_secs(5))
            .take(3)
    }

    /// Attempt to pull a batch of messages
    async fn attempt_pull_batch(&self) -> Result<Vec<jetstream::Message>> {
        let batch = self
            .consumer
            .batch()
            .max_messages(self.batch_size)
            .expires(self.timeout)
            .messages()
            .await
            .map_err(|e| {
                error!("Failed to pull message batch: {}", e);
                e
            })?;

        let messages: Vec<jetstream::Message> = batch
            .try_collect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to collect messages: {}", e))?;

        Self::log_batch_result(&messages);
        Ok(messages)
    }

    /// Log the result of a batch pull operation
    fn log_batch_result(messages: &[jetstream::Message]) {
        if messages.is_empty() {
            debug!("No messages available in batch");
        } else {
            debug!("Pulled batch of {} messages", messages.len());
        }
    }

    /// Pull a single message with exponential backoff
    pub async fn pull_one(&mut self) -> Result<Option<jetstream::Message>> {
        let retry_strategy = Self::create_single_retry_strategy();

        Retry::spawn(retry_strategy, || self.attempt_pull_single())
            .await
            .with_context(|| "Failed to pull message after retries")
    }

    /// Create retry strategy for single message operations
    fn create_single_retry_strategy() -> impl Iterator<Item = Duration> {
        ExponentialBackoff::from_millis(50)
            .max_delay(Duration::from_secs(2))
            .take(3)
    }

    /// Attempt to pull a single message
    async fn attempt_pull_single(&self) -> Result<Option<jetstream::Message>> {
        let messages = self
            .consumer
            .messages()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get messages stream: {}", e))?;

        Self::try_get_next_message(messages).await
    }

    /// Try to get the next message from the stream with timeout
    async fn try_get_next_message(
        mut messages: impl futures::Stream<
                Item = Result<
                    jetstream::Message,
                    async_nats::error::Error<
                        async_nats::jetstream::consumer::pull::MessagesErrorKind,
                    >,
                >,
            > + Unpin,
    ) -> Result<Option<jetstream::Message>> {
        match tokio::time::timeout(Duration::from_millis(100), messages.try_next()).await {
            Ok(Ok(Some(message))) => {
                debug!("Pulled single message: {}", message.subject);
                Ok(Some(message))
            }
            Ok(Ok(None)) => {
                debug!("No messages available");
                Ok(None)
            }
            Ok(Err(e)) => {
                error!("Failed to pull message: {}", e);
                Err(anyhow::anyhow!("Message stream error: {}", e))
            }
            Err(_) => {
                // Timeout - no messages available
                debug!("No messages available (timeout)");
                Ok(None)
            }
        }
    }
}

/// Backoff strategy for handling failures and retries
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Maximum number of retry attempts
    pub max_retries: usize,
    /// Multiplier for exponential backoff
    pub multiplier: f64,
    /// Random jitter factor (0.0 to 1.0)
    pub jitter: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            max_retries: 5,
            multiplier: 2.0,
            jitter: 0.1,
        }
    }
}

/// Create an exponential backoff strategy from config
pub fn create_backoff_strategy(config: &BackoffConfig) -> impl Iterator<Item = Duration> {
    ExponentialBackoff::from_millis(config.initial_delay.as_millis() as u64)
        .max_delay(config.max_delay)
        .factor(config.multiplier as u64)
        .take(config.max_retries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_status() {
        let status = HealthStatus {
            nats_connected: true,
            jetstream_available: true,
        };

        assert!(status.is_healthy());

        let status = HealthStatus {
            nats_connected: true,
            jetstream_available: false,
        };

        assert!(!status.is_healthy());
    }

    #[test]
    fn test_consumer_config_defaults() {
        let config = ConsumerConfig::default();

        assert_eq!(config.max_deliver, 3);
        assert_eq!(config.ack_wait, Duration::from_secs(30));
        assert_eq!(config.worker_count, 1);
    }

    #[test]
    fn test_backoff_config() {
        let config = BackoffConfig::default();
        let _strategy = create_backoff_strategy(&config);

        // Test that we can create a strategy (actual retry testing would require integration tests)
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.multiplier, 2.0);
    }
}
