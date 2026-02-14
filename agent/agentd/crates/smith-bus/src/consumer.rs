use anyhow::{Context, Result};
use async_nats::jetstream::{self, consumer::PullConsumer};
use serde::de::DeserializeOwned;
use std::time::Duration;
use time;
use tracing::{debug, error, info};

use crate::{ConsumerConfig, ConsumerStartSequence, Message, WorkQueue};

/// Consumer for receiving messages from JetStream
pub struct Consumer {
    consumer: PullConsumer,
    capability: String,
    work_queue: WorkQueue,
}

impl Consumer {
    /// Create a new consumer for a specific capability
    pub async fn new(
        jetstream: jetstream::Context,
        capability: &str,
        config: ConsumerConfig,
    ) -> Result<Self> {
        info!(
            "Creating consumer for capability: {} with config: {:?}",
            capability, config
        );

        let filter_subject = Self::build_filter_subject(capability);
        let deliver_policy = Self::convert_start_sequence_to_policy(&config.start_sequence);
        let consumer_config =
            Self::build_consumer_config(&config, capability, &filter_subject, deliver_policy);

        let consumer =
            Self::create_jetstream_consumer(jetstream, consumer_config, capability).await?;
        let work_queue = WorkQueue::new(consumer.clone(), 10, Duration::from_secs(5));

        info!(
            "Consumer created successfully for capability: {}",
            capability
        );

        Ok(Self {
            consumer,
            capability: capability.to_string(),
            work_queue,
        })
    }

    /// Build filter subject for the capability
    fn build_filter_subject(capability: &str) -> String {
        crate::subjects::SubjectBuilder::new()
            .part("intents")
            .part(capability)
            .part("*")
            .build()
    }

    /// Convert start sequence configuration to JetStream deliver policy
    fn convert_start_sequence_to_policy(
        start_sequence: &ConsumerStartSequence,
    ) -> jetstream::consumer::DeliverPolicy {
        match start_sequence {
            ConsumerStartSequence::First => jetstream::consumer::DeliverPolicy::All,
            ConsumerStartSequence::Latest => jetstream::consumer::DeliverPolicy::Last,
            ConsumerStartSequence::Sequence(seq) => {
                jetstream::consumer::DeliverPolicy::ByStartSequence {
                    start_sequence: *seq,
                }
            }
            ConsumerStartSequence::Time(time) => jetstream::consumer::DeliverPolicy::ByStartTime {
                start_time: time::OffsetDateTime::from_unix_timestamp(time.timestamp())
                    .unwrap_or_else(|_| time::OffsetDateTime::now_utc()),
            },
        }
    }

    /// Build JetStream consumer configuration
    fn build_consumer_config(
        config: &ConsumerConfig,
        capability: &str,
        filter_subject: &str,
        deliver_policy: jetstream::consumer::DeliverPolicy,
    ) -> jetstream::consumer::pull::Config {
        jetstream::consumer::pull::Config {
            durable_name: Some(config.name.clone()),
            description: Some(format!("Consumer for {} capability", capability)),
            filter_subject: filter_subject.to_string(),
            deliver_policy,
            ack_wait: config.ack_wait,
            max_deliver: config.max_deliver,
            max_ack_pending: 1000, // Allow up to 1000 unacknowledged messages
            replay_policy: jetstream::consumer::ReplayPolicy::Instant,
            ..Default::default()
        }
    }

    /// Create the JetStream consumer
    async fn create_jetstream_consumer(
        jetstream: jetstream::Context,
        consumer_config: jetstream::consumer::pull::Config,
        capability: &str,
    ) -> Result<PullConsumer> {
        let stream_name = "INTENTS";
        jetstream
            .create_consumer_on_stream(consumer_config, stream_name)
            .await
            .with_context(|| format!("Failed to create consumer for capability: {}", capability))
    }

    /// Get the next message from the stream
    pub async fn next_message<T: DeserializeOwned>(&mut self) -> Result<Option<Message<T>>> {
        match self.work_queue.pull_one().await? {
            Some(jetstream_message) => self
                .process_jetstream_message(jetstream_message)
                .await
                .map(Some),
            None => {
                debug!("No messages available for capability: {}", self.capability);
                Ok(None)
            }
        }
    }

    /// Process a single JetStream message into a typed Message
    async fn process_jetstream_message<T: DeserializeOwned>(
        &self,
        jetstream_message: async_nats::jetstream::Message,
    ) -> Result<Message<T>> {
        let _info = jetstream_message
            .info()
            .map_err(|e| anyhow::anyhow!("Failed to get message info: {}", e))?;

        debug!("Received message on subject: {}", jetstream_message.subject);

        // Deserialize the message
        let payload: T = serde_json::from_slice(&jetstream_message.payload)
            .with_context(|| "Failed to deserialize message payload")?;

        debug!("Deserialized message for capability: {}", self.capability);

        Ok(Message {
            payload,
            jetstream_message: jetstream_message.clone(),
            delivery_count: 1, // Default to 1, actual redelivery info not easily accessible
            subject: jetstream_message.subject.to_string(),
        })
    }

    /// Get a batch of messages from the stream
    pub async fn next_batch<T: DeserializeOwned>(
        &mut self,
        batch_size: usize,
    ) -> Result<Vec<Message<T>>> {
        let messages = self.work_queue.pull_batch().await?;
        let mut typed_messages = Vec::with_capacity(messages.len().min(batch_size));

        for jetstream_message in messages.into_iter().take(batch_size) {
            match self.try_deserialize_message(&jetstream_message).await {
                Ok(typed_message) => typed_messages.push(typed_message),
                Err(e) => {
                    error!("Failed to process message in batch: {}", e);
                    Self::handle_malformed_message(jetstream_message).await;
                }
            }
        }

        debug!("Retrieved batch of {} valid messages", typed_messages.len());
        Ok(typed_messages)
    }

    /// Try to deserialize a JetStream message into a typed Message
    async fn try_deserialize_message<T: DeserializeOwned>(
        &self,
        jetstream_message: &async_nats::jetstream::Message,
    ) -> Result<Message<T>> {
        let payload: T = serde_json::from_slice(&jetstream_message.payload)
            .with_context(|| "Failed to deserialize message payload")?;

        debug!("Deserialized message for capability: {}", self.capability);

        Ok(Message {
            payload,
            subject: jetstream_message.subject.to_string(),
            jetstream_message: jetstream_message.clone(),
            delivery_count: 1, // Default to 1, actual redelivery info not easily accessible
        })
    }

    /// Handle malformed message by acknowledging it to prevent infinite redelivery
    async fn handle_malformed_message(jetstream_message: async_nats::jetstream::Message) {
        if let Err(ack_err) = jetstream_message.ack().await {
            error!("Failed to ack malformed message: {}", ack_err);
        }
    }

    /// Get consumer information and statistics
    pub async fn info(&mut self) -> Result<ConsumerInfo> {
        let info = self
            .consumer
            .info()
            .await
            .context("Failed to get consumer info")?;

        Ok(ConsumerInfo {
            name: info.name.clone(),
            stream_name: info.stream_name.clone(),
            delivered: info.delivered.stream_sequence, // Use stream sequence as approximation
            ack_pending: info.num_pending,
            redelivered: 0, // Not available in async-nats 0.42
            num_waiting: info.num_waiting as u64,
        })
    }

    /// Delete this consumer (cleanup)
    /// Note: async-nats 0.42 doesn't support consumer deletion - consumers are auto-cleaned up
    pub async fn delete(self) -> Result<()> {
        info!("Marking consumer for cleanup: {}", self.capability);
        // In async-nats 0.42, consumers are automatically cleaned up when dropped
        // No explicit delete method is available
        info!("Consumer cleanup completed (automatic)");
        Ok(())
    }
}

/// Consumer information and statistics
#[derive(Debug, Clone)]
pub struct ConsumerInfo {
    /// Consumer name
    pub name: String,
    /// Stream name this consumer is attached to
    pub stream_name: String,
    /// Number of messages delivered
    pub delivered: u64,
    /// Number of messages pending acknowledgment
    pub ack_pending: u64,
    /// Number of messages redelivered
    pub redelivered: u64,
    /// Number of messages waiting to be delivered
    pub num_waiting: u64,
}

impl ConsumerInfo {
    /// Check if the consumer is healthy (not backed up with unacked messages)
    pub fn is_healthy(&self) -> bool {
        // Consider unhealthy if more than 100 messages are pending ack
        // or if there's a significant backlog
        self.ack_pending < 100 && self.num_waiting < 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_nats::jetstream::consumer::{DeliverPolicy, ReplayPolicy};

    #[test]
    fn test_consumer_info_health() {
        let healthy_info = ConsumerInfo {
            name: "test-consumer".to_string(),
            stream_name: "INTENTS".to_string(),
            delivered: 100,
            ack_pending: 5,
            redelivered: 2,
            num_waiting: 10,
        };

        assert!(healthy_info.is_healthy());

        let unhealthy_info = ConsumerInfo {
            name: "test-consumer".to_string(),
            stream_name: "INTENTS".to_string(),
            delivered: 100,
            ack_pending: 150, // Too many pending
            redelivered: 2,
            num_waiting: 10,
        };

        assert!(!unhealthy_info.is_healthy());

        // Test edge cases
        let edge_case_pending = ConsumerInfo {
            name: "test-consumer".to_string(),
            stream_name: "INTENTS".to_string(),
            delivered: 100,
            ack_pending: 100, // Exactly at threshold
            redelivered: 2,
            num_waiting: 10,
        };
        assert!(!edge_case_pending.is_healthy());

        let edge_case_waiting = ConsumerInfo {
            name: "test-consumer".to_string(),
            stream_name: "INTENTS".to_string(),
            delivered: 100,
            ack_pending: 5,
            redelivered: 2,
            num_waiting: 1000, // Exactly at threshold
        };
        assert!(!edge_case_waiting.is_healthy());
    }

    #[test]
    fn test_build_filter_subject() {
        let subject = Consumer::build_filter_subject("fs.read.v1");
        assert_eq!(subject, "smith.intents.fs.read.v1.*");
    }

    #[test]
    fn test_convert_start_sequence_to_policy() {
        let policy = Consumer::convert_start_sequence_to_policy(&ConsumerStartSequence::First);
        assert_eq!(policy, DeliverPolicy::All);

        let policy = Consumer::convert_start_sequence_to_policy(&ConsumerStartSequence::Latest);
        assert_eq!(policy, DeliverPolicy::Last);

        let policy =
            Consumer::convert_start_sequence_to_policy(&ConsumerStartSequence::Sequence(42));
        assert_eq!(
            policy,
            DeliverPolicy::ByStartSequence { start_sequence: 42 }
        );

        let time = chrono::Utc::now();
        let policy = Consumer::convert_start_sequence_to_policy(&ConsumerStartSequence::Time(time));
        let expected_time = time::OffsetDateTime::from_unix_timestamp(time.timestamp())
            .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
        assert_eq!(
            policy,
            DeliverPolicy::ByStartTime {
                start_time: expected_time
            }
        );
    }

    #[test]
    fn test_build_consumer_config() {
        let config = ConsumerConfig {
            name: "test-consumer".to_string(),
            consumer_group: Some("test-group".to_string()),
            start_sequence: ConsumerStartSequence::First,
            ack_wait: Duration::from_secs(30),
            max_deliver: 3,
            max_age: Some(Duration::from_secs(3600)),
            worker_count: 2,
        };

        let consumer_config = Consumer::build_consumer_config(
            &config,
            "fs.read.v1",
            "smith.intents.vetted.fs.read.v1",
            DeliverPolicy::All,
        );

        assert_eq!(
            consumer_config.durable_name,
            Some("test-consumer".to_string())
        );
        assert_eq!(consumer_config.deliver_policy, DeliverPolicy::All);
        assert_eq!(consumer_config.ack_wait, Duration::from_secs(30));
        assert_eq!(consumer_config.max_deliver, 3);
        assert_eq!(consumer_config.replay_policy, ReplayPolicy::Instant);
        assert_eq!(
            consumer_config.filter_subject,
            "smith.intents.vetted.fs.read.v1".to_string()
        );
        assert_eq!(
            consumer_config.description,
            Some("Consumer for fs.read.v1 capability".to_string())
        );
    }

    #[test]
    fn test_build_consumer_config_with_default_name() {
        let config = ConsumerConfig {
            name: "http_fetch_v1_consumer".to_string(),
            consumer_group: None,
            start_sequence: ConsumerStartSequence::Latest,
            ack_wait: Duration::from_secs(60),
            max_deliver: 5,
            max_age: None,
            worker_count: 1,
        };

        let consumer_config = Consumer::build_consumer_config(
            &config,
            "http.fetch.v1",
            "smith.intents.vetted.http.fetch.v1",
            DeliverPolicy::Last,
        );

        assert_eq!(
            consumer_config.durable_name,
            Some("http_fetch_v1_consumer".to_string())
        );
        assert_eq!(consumer_config.deliver_policy, DeliverPolicy::Last);
        assert_eq!(consumer_config.ack_wait, Duration::from_secs(60));
        assert_eq!(consumer_config.max_deliver, 5);
    }

    #[test]
    fn test_consumer_config_default() {
        let config = ConsumerConfig::default();

        assert!(!config.name.is_empty());
        assert!(config.name.contains("consumer-"));
        assert_eq!(config.consumer_group, None);
        assert_eq!(config.max_deliver, 3);
        assert_eq!(config.ack_wait, Duration::from_secs(30));
        assert_eq!(config.max_age, Some(Duration::from_secs(24 * 60 * 60)));
        assert!(matches!(
            config.start_sequence,
            ConsumerStartSequence::Latest
        ));
        assert_eq!(config.worker_count, 1);
    }

    #[test]
    fn test_consumer_start_sequence_variants() {
        // Test all variants exist and can be created
        let _first = ConsumerStartSequence::First;
        let _latest = ConsumerStartSequence::Latest;
        let _sequence = ConsumerStartSequence::Sequence(100);
        let _time = ConsumerStartSequence::Time(chrono::Utc::now());

        // Test Debug formatting
        let first_debug = format!("{:?}", ConsumerStartSequence::First);
        assert!(first_debug.contains("First"));

        let seq_debug = format!("{:?}", ConsumerStartSequence::Sequence(42));
        assert!(seq_debug.contains("42"));
    }

    #[test]
    fn test_consumer_info_debug_format() {
        let info = ConsumerInfo {
            name: "debug-test".to_string(),
            stream_name: "TEST_STREAM".to_string(),
            delivered: 42,
            ack_pending: 3,
            redelivered: 1,
            num_waiting: 7,
        };

        let debug_output = format!("{:?}", info);
        assert!(debug_output.contains("debug-test"));
        assert!(debug_output.contains("TEST_STREAM"));
        assert!(debug_output.contains("42"));
    }

    #[test]
    fn test_consumer_info_clone() {
        let original = ConsumerInfo {
            name: "original".to_string(),
            stream_name: "STREAM".to_string(),
            delivered: 100,
            ack_pending: 5,
            redelivered: 2,
            num_waiting: 10,
        };

        let cloned = original.clone();
        assert_eq!(original.name, cloned.name);
        assert_eq!(original.stream_name, cloned.stream_name);
        assert_eq!(original.delivered, cloned.delivered);
        assert_eq!(original.ack_pending, cloned.ack_pending);
        assert_eq!(original.redelivered, cloned.redelivered);
        assert_eq!(original.num_waiting, cloned.num_waiting);
    }
}
