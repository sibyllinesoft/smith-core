use anyhow::{anyhow, Context, Result};
use async_nats::jetstream::consumer::PullConsumer;
use async_nats::jetstream::stream::Stream;
use async_nats::Subscriber;
use async_trait::async_trait;
use futures::StreamExt;
use once_cell::sync::Lazy;
use smith_bus::builders::ResultSubject;
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::config::NatsConfig;

/// Trait for NATS publishing operations
///
/// This trait abstracts the publishing functionality of NatsClient
/// to enable mocking in tests and dependency injection.
#[async_trait]
pub trait NatsPublisher: Send + Sync {
    /// Publish a message to a subject
    async fn publish(&self, subject: &str, payload: &[u8]) -> Result<()>;

    /// Publish with reply-to header
    async fn publish_with_reply(&self, subject: &str, reply: &str, payload: &[u8]) -> Result<()>;

    /// Request-reply pattern
    async fn request(&self, subject: &str, payload: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for publishing intent results
///
/// This trait abstracts the result publishing functionality to enable
/// mocking in tests. It handles serialization of IntentResult internally.
#[async_trait]
pub trait IntentResultPublisher: Send + Sync {
    /// Publish an intent result
    async fn publish_result(
        &self,
        intent_id: &str,
        result: &smith_protocol::IntentResult,
    ) -> Result<()>;
}

/// NATS client with JetStream support for pulling intents
#[derive(Clone)]
pub struct NatsClient {
    client: async_nats::Client,
    jetstream: async_nats::jetstream::Context,
    config: NatsConfig,
}

impl NatsClient {
    /// Create new NATS client and connect to server
    pub async fn new(config: &NatsConfig) -> Result<Self> {
        info!("Connecting to NATS servers: {:?}", config.servers);

        let mut connect_opts = async_nats::ConnectOptions::new();

        // Set connection name
        connect_opts = connect_opts.name("smith-executor");

        // Configure TLS if certificates are provided
        if let (Some(cert_path), Some(key_path), Some(ca_path)) =
            (&config.tls_cert, &config.tls_key, &config.tls_ca)
        {
            info!("Configuring TLS connection");

            // Use the public API to configure TLS
            connect_opts = connect_opts
                .require_tls(true)
                .add_client_certificate(cert_path.clone(), key_path.clone())
                .add_root_certificates(ca_path.clone());
        }

        // Set reconnection and timeout options
        connect_opts = connect_opts
            .max_reconnects(None) // Unlimited reconnects
            .read_buffer_capacity(65535) // Max read buffer
            .connection_timeout(Duration::from_secs(10))
            .request_timeout(Some(Duration::from_secs(30)));

        // Connect to NATS server(s)
        let client = if config.servers.len() == 1 {
            async_nats::connect_with_options(&config.servers[0], connect_opts).await
        } else {
            async_nats::connect_with_options(&config.servers, connect_opts).await
        }
        .context("Failed to connect to NATS server")?;

        info!("Connected to NATS server");

        // Get JetStream context
        let jetstream = async_nats::jetstream::new(client.clone());

        Ok(Self {
            client,
            jetstream,
            config: config.clone(),
        })
    }

    /// Create or get existing JetStream stream for a capability
    pub async fn ensure_stream(
        &self,
        capability: &str,
        stream_config: &crate::config::IntentStreamConfig,
    ) -> Result<Stream> {
        let stream_name = format!("JS_INTENTS_{}", capability.replace(".", "_").to_uppercase());

        debug!("Ensuring stream exists: {}", stream_name);

        // Try to get existing stream first
        match self.jetstream.get_stream(&stream_name).await {
            Ok(stream) => {
                debug!("Using existing stream: {}", stream_name);
                return Ok(stream);
            }
            Err(_) => {
                debug!("Stream {} does not exist, creating it", stream_name);
            }
        }

        // Parse configuration values
        let max_age = parse_duration(&stream_config.max_age)?;
        let max_bytes = crate::config::parse_byte_size(&stream_config.max_bytes)? as i64;
        let stream_subject = stream_config.subject.clone();

        // Create stream configuration
        let js_stream_config = async_nats::jetstream::stream::Config {
            name: stream_name.clone(),
            subjects: vec![stream_subject.clone()],
            retention: async_nats::jetstream::stream::RetentionPolicy::WorkQueue,
            max_age,
            max_bytes,
            storage: async_nats::jetstream::stream::StorageType::File,
            num_replicas: 1,
            discard: async_nats::jetstream::stream::DiscardPolicy::Old,
            ..Default::default()
        };

        // Create the stream
        match self.jetstream.create_stream(js_stream_config).await {
            Ok(stream) => {
                info!("Created JetStream stream: {}", stream_name);
                Ok(stream)
            }
            Err(err) => {
                warn!(
                    stream = %stream_name,
                    error = %err,
                    "Failed to create stream; assuming it already exists via bootstrap"
                );

                if stream_subject.starts_with("smith.intents.") {
                    match self.jetstream.get_stream("INTENTS").await {
                        Ok(stream) => {
                            info!(
                                stream = %stream_name,
                                fallback_stream = "INTENTS",
                                "Using INTENTS stream provided by bootstrap for capability"
                            );
                            return Ok(stream);
                        }
                        Err(fallback_err) => {
                            warn!(
                                stream = %stream_name,
                                fallback_stream = "INTENTS",
                                error = %fallback_err,
                                "Failed to fetch fallback INTENTS stream after creation conflict"
                            );
                        }
                    }
                }

                self.jetstream
                    .get_stream(&stream_name)
                    .await
                    .with_context(|| {
                        format!(
                            "Stream creation failed and fetching existing stream {} also failed",
                            stream_name
                        )
                    })
            }
        }
    }

    /// Create pull consumer for a capability  
    pub async fn create_consumer(
        &self,
        capability: &str,
        stream_config: &crate::config::IntentStreamConfig,
    ) -> Result<IntentConsumer> {
        // Ensure stream exists
        let stream = self.ensure_stream(capability, stream_config).await?;

        let consumer_name = format!("executor-{}-workqueue", capability.replace(".", "-"));

        // Create pull consumer configuration
        let consumer_config = async_nats::jetstream::consumer::pull::Config {
            durable_name: Some(consumer_name.clone()),
            description: Some(format!(
                "executor worker consumer for capability {capability}"
            )),
            filter_subject: stream_config.subject.clone(),
            ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_secs(30),
            max_ack_pending: (stream_config.workers * 2) as i64, // 2x worker concurrency
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
            replay_policy: async_nats::jetstream::consumer::ReplayPolicy::Instant,
            inactive_threshold: Duration::from_secs(600),
            ..Default::default()
        };

        // Create or re-use the consumer
        let mut consumer = stream
            .get_or_create_consumer(&consumer_name, consumer_config)
            .await
            .with_context(|| format!("Failed to create consumer: {}", consumer_name))?;

        let info = consumer
            .info()
            .await
            .with_context(|| format!("Failed to fetch consumer info: {}", consumer_name))?;
        info!(
            consumer = %consumer_name,
            capability = capability,
            created_at = %info.created,
            "JetStream consumer ready for capability"
        );

        Ok(IntentConsumer {
            consumer,
            capability: capability.to_string(),
        })
    }

    /// Publish result to results subject
    pub async fn publish_result(
        &self,
        intent_id: &str,
        result: &smith_protocol::IntentResult,
    ) -> Result<()> {
        let subject = ResultSubject::for_intent(intent_id);
        let payload = serde_json::to_vec(result).context("Failed to serialize intent result")?;

        let payload_len = payload.len();
        let subject_len = subject.len();
        let subject_hex: String = subject
            .as_bytes()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        debug!(
            subject = %subject,
            subject_len,
            subject_hex = %subject_hex,
            payload_len = payload_len,
            "Publishing executor result to core NATS"
        );

        self.client
            .publish(subject.clone(), payload.into())
            .await
            .context("Failed to publish result to NATS")?;

        let flush_disabled = std::env::var("SMITH_EXECUTOR_DISABLE_RESULT_FLUSH")
            .map(|val| val == "1")
            .unwrap_or(false);

        if !flush_disabled {
            debug!(subject = %subject, subject_len, "Awaiting executor result flush");
            let flush_client = self.client.clone();
            let flush_subject = subject.clone();
            tokio::spawn(async move {
                let subject_len = flush_subject.len();
                debug!(subject = %flush_subject, subject_len, "Executor flush task started");
                match timeout(Duration::from_secs(2), flush_client.flush()).await {
                    Ok(Ok(())) => {
                        info!(subject = %flush_subject, subject_len, "Flushed executor result publish");
                    }
                    Ok(Err(err)) => {
                        warn!(
                            subject = %flush_subject,
                            subject_len,
                            error = %err,
                            "Failed to flush executor result publish"
                        );
                    }
                    Err(_) => {
                        warn!(
                            subject = %flush_subject,
                            subject_len,
                            "Executor result flush timed out; continuing without confirmation"
                        );
                    }
                }
            });
        } else {
            debug!(subject = %subject, subject_len, "Skipping executor result flush (disabled)");
        }

        info!(
            subject = %subject,
            subject_len,
            subject_hex = %subject_hex,
            intent_id = intent_id,
            payload_len = payload_len,
            "Executor result publish completed"
        );

        Ok(())
    }

    pub async fn maybe_spawn_debug_result_tap(&self) -> Result<()> {
        let debug_enabled = std::env::var("SMITH_EXECUTOR_DEBUG_TAP")
            .map(|val| val == "1")
            .unwrap_or(false);

        if !debug_enabled {
            return Ok(());
        }

        let mut subscriber = self
            .client
            .subscribe(ResultSubject::all())
            .await
            .context("Failed to subscribe to smith.results.* for debug tap")?;

        tokio::spawn(async move {
            while let Some(message) = subscriber.next().await {
                let subject = message.subject.clone();
                let payload_len = message.payload.len();
                let preview: String = String::from_utf8_lossy(&message.payload)
                    .chars()
                    .take(256)
                    .collect();
                info!(
                    subject = %subject,
                    payload_len,
                    payload_preview = %preview,
                    "Executor debug tap observed smith.results message"
                );
            }
        });

        Ok(())
    }

    pub async fn subscribe(&self, subject: &str, queue: Option<&str>) -> Result<Subscriber> {
        if let Some(queue) = queue {
            self.client
                .queue_subscribe(subject.to_string(), queue.to_string())
                .await
                .context("Failed to create queued subscription")
        } else {
            self.client
                .subscribe(subject.to_string())
                .await
                .context("Failed to create subscription")
        }
    }

    /// Get stream configuration for capability
    fn get_stream_config(&self, _capability: &str) -> Result<&crate::config::IntentStreamConfig> {
        // This would need access to the full config - for now return error
        Err(anyhow::anyhow!(
            "Stream config not available in this context"
        ))
    }

    /// Get NATS server info
    pub async fn server_info(&self) -> Result<async_nats::ServerInfo> {
        Ok(self.client.server_info())
    }

    /// Check connection status
    pub fn connection_status(&self) -> async_nats::connection::State {
        self.client.connection_state()
    }
}

#[async_trait]
impl NatsPublisher for NatsClient {
    async fn publish(&self, subject: &str, payload: &[u8]) -> Result<()> {
        self.client
            .publish(subject.to_string(), payload.to_vec().into())
            .await
            .context("Failed to publish message to NATS")?;
        Ok(())
    }

    async fn publish_with_reply(&self, subject: &str, reply: &str, payload: &[u8]) -> Result<()> {
        self.client
            .publish_with_reply(
                subject.to_string(),
                reply.to_string(),
                payload.to_vec().into(),
            )
            .await
            .context("Failed to publish message with reply to NATS")?;
        Ok(())
    }

    async fn request(&self, subject: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .client
            .request(subject.to_string(), payload.to_vec().into())
            .await
            .context("Failed to make NATS request")?;
        Ok(response.payload.to_vec())
    }
}

#[async_trait]
impl IntentResultPublisher for NatsClient {
    async fn publish_result(
        &self,
        intent_id: &str,
        result: &smith_protocol::IntentResult,
    ) -> Result<()> {
        // Delegate to the existing publish_result method
        NatsClient::publish_result(self, intent_id, result).await
    }
}

/// Consumer wrapper for pulling intents from JetStream
pub struct IntentConsumer {
    consumer: PullConsumer,
    capability: String,
}

impl IntentConsumer {
    fn debug_pull_enabled(&self) -> bool {
        static DEBUG_PULL_CAPS: Lazy<HashSet<String>> = Lazy::new(|| {
            std::env::var("SMITH_EXECUTOR_DEBUG_PULL")
                .ok()
                .map(|raw| {
                    raw.split(',')
                        .map(|cap| cap.trim().to_string())
                        .filter(|cap| !cap.is_empty())
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default()
        });

        if DEBUG_PULL_CAPS.is_empty() {
            return false;
        }

        DEBUG_PULL_CAPS.contains("*") || DEBUG_PULL_CAPS.contains(&self.capability)
    }

    /// Pull next message from the stream
    pub async fn next(&mut self) -> Result<Option<IntentMessage>> {
        let mut batch = match self
            .consumer
            .stream()
            .max_messages_per_batch(1)
            .expires(Duration::from_secs(30))
            .messages()
            .await
        {
            Ok(batch) => batch,
            Err(err) => {
                error!(
                    capability = %self.capability,
                    error = %err,
                    "Failed to create JetStream pull stream"
                );
                return Err(anyhow::anyhow!(
                    "Failed to create JetStream pull stream: {}",
                    err
                ));
            }
        };

        debug!(
            capability = %self.capability,
            "Awaiting next message from JetStream stream"
        );

        match batch.next().await {
            Some(Ok(message)) => {
                if self.debug_pull_enabled() {
                    info!(
                        capability = %self.capability,
                        subject = %message.subject,
                        "IntentConsumer received message"
                    );
                } else {
                    debug!("Received message for capability: {}", self.capability);
                }
                Ok(Some(IntentMessage { message }))
            }
            Some(Err(err)) => {
                error!(
                    capability = %self.capability,
                    error = %err,
                    "Error receiving message from JetStream stream"
                );
                Err(anyhow::anyhow!("Error receiving message: {}", err))
            }
            None => {
                debug!(
                    capability = %self.capability,
                    "JetStream stream returned no messages"
                );
                if self.debug_pull_enabled() {
                    match self.consumer.info().await {
                        Ok(info) => {
                            info!(
                                capability = %self.capability,
                                num_pending = info.num_pending,
                                num_waiting = info.num_waiting,
                                num_ack_pending = info.num_ack_pending,
                                "IntentConsumer stream yielded no data"
                            );
                        }
                        Err(err) => {
                            warn!(
                                capability = %self.capability,
                                error = %err,
                                "IntentConsumer failed to fetch consumer info after empty batch"
                            );
                        }
                    }
                }
                Ok(None)
            }
        }
    }

    /// Pull multiple messages in batch
    pub async fn batch(&mut self, max_messages: usize) -> Result<Vec<IntentMessage>> {
        let mut messages = self
            .consumer
            .fetch()
            .max_messages(max_messages)
            .messages()
            .await?;

        let mut batch = Vec::new();

        while let Some(message_result) = messages.next().await {
            match message_result {
                Ok(message) => {
                    batch.push(IntentMessage { message });
                }
                Err(e) => {
                    error!("Error in batch message: {}", e);
                    return Err(anyhow::anyhow!("Error in batch message: {}", e));
                }
            }
        }

        Ok(batch)
    }

    /// Get consumer info
    pub async fn info(&mut self) -> Result<async_nats::jetstream::consumer::Info> {
        Ok(self.consumer.info().await?.clone())
    }
}

/// Wrapper around JetStream message for intent processing
pub struct IntentMessage {
    pub message: async_nats::jetstream::Message,
}

impl IntentMessage {
    /// Get message payload as bytes
    pub fn payload(&self) -> &[u8] {
        &self.message.payload
    }

    /// Get message subject
    pub fn subject(&self) -> &str {
        &self.message.subject
    }

    /// Get message metadata
    pub fn context(&self) -> &async_nats::jetstream::context::Context {
        &self.message.context
    }

    /// Acknowledge message processing
    pub async fn ack(&self) -> Result<()> {
        self.message
            .ack()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to acknowledge message: {}", e))
    }

    /// Negative acknowledge (requeue for retry)
    pub async fn nak(&self) -> Result<()> {
        self.message
            .ack_with(async_nats::jetstream::AckKind::Nak(None))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to negative acknowledge message: {}", e))
    }

    /// Negative acknowledge with delay
    pub async fn nak_with_delay(&self, delay: Duration) -> Result<()> {
        self.message
            .ack_with(async_nats::jetstream::AckKind::Nak(Some(delay)))
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to negative acknowledge message with delay: {}", e)
            })
    }

    /// Terminate message (don't redeliver)
    pub async fn term(&self) -> Result<()> {
        self.message
            .ack_with(async_nats::jetstream::AckKind::Term)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to terminate message: {}", e))
    }
}

/// Parse duration string to Duration (e.g., "10m", "1h", "30s")
fn parse_duration(duration_str: &str) -> Result<Duration> {
    let seconds = crate::config::parse_duration_seconds(duration_str)?;
    Ok(Duration::from_secs(seconds))
}

/// Mock implementation of IntentResultPublisher for testing
#[cfg(any(test, feature = "test-support"))]
pub mod mock {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A mock result publisher that tracks calls for testing
    #[derive(Default)]
    pub struct MockResultPublisher {
        pub publish_calls: std::sync::Mutex<Vec<(String, smith_protocol::IntentResult)>>,
        pub should_fail: std::sync::atomic::AtomicBool,
        pub fail_count: AtomicUsize,
    }

    impl MockResultPublisher {
        pub fn new() -> Self {
            Self::default()
        }

        /// Configure the mock to fail on the next N calls
        pub fn fail_next(&self, count: usize) {
            self.fail_count.store(count, Ordering::SeqCst);
            self.should_fail.store(true, Ordering::SeqCst);
        }

        /// Get all published results
        pub fn published_results(&self) -> Vec<(String, smith_protocol::IntentResult)> {
            self.publish_calls.lock().unwrap().clone()
        }

        /// Get the count of publish calls
        pub fn call_count(&self) -> usize {
            self.publish_calls.lock().unwrap().len()
        }

        /// Clear recorded calls
        pub fn clear(&self) {
            self.publish_calls.lock().unwrap().clear();
        }
    }

    #[async_trait]
    impl IntentResultPublisher for MockResultPublisher {
        async fn publish_result(
            &self,
            intent_id: &str,
            result: &smith_protocol::IntentResult,
        ) -> Result<()> {
            if self.should_fail.load(Ordering::SeqCst) {
                let remaining = self.fail_count.fetch_sub(1, Ordering::SeqCst);
                if remaining > 0 {
                    if remaining == 1 {
                        self.should_fail.store(false, Ordering::SeqCst);
                    }
                    return Err(anyhow!("Mock publish failure"));
                }
            }
            self.publish_calls
                .lock()
                .unwrap()
                .push((intent_id.to_string(), result.clone()));
            Ok(())
        }
    }

    #[async_trait]
    impl NatsPublisher for MockResultPublisher {
        async fn publish(&self, _subject: &str, _payload: &[u8]) -> Result<()> {
            Ok(())
        }

        async fn publish_with_reply(
            &self,
            _subject: &str,
            _reply: &str,
            _payload: &[u8],
        ) -> Result<()> {
            Ok(())
        }

        async fn request(&self, _subject: &str, _payload: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));

        assert!(parse_duration("invalid").is_err());
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604800));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("60m").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn test_truncate_payload_short() {
        let payload = b"Hello, World!";
        let truncated = truncate_payload(payload, 100);
        assert_eq!(truncated, "Hello, World!");
    }

    #[test]
    fn test_truncate_payload_long() {
        let payload = b"This is a very long payload that should be truncated";
        let truncated = truncate_payload(payload, 10);
        assert_eq!(truncated, "This is a ");
    }

    #[test]
    fn test_truncate_payload_empty() {
        let payload: &[u8] = b"";
        let truncated = truncate_payload(payload, 100);
        assert_eq!(truncated, "");
    }

    #[test]
    fn test_truncate_payload_exact_length() {
        let payload = b"12345";
        let truncated = truncate_payload(payload, 5);
        assert_eq!(truncated, "12345");
    }

    #[test]
    fn test_extract_intent_id_valid() {
        let payload = br#"{"intent_id": "test-123", "data": "hello"}"#;
        let id = extract_intent_id(payload);
        assert_eq!(id, Some("test-123".to_string()));
    }

    #[test]
    fn test_extract_intent_id_missing() {
        let payload = br#"{"data": "hello"}"#;
        let id = extract_intent_id(payload);
        assert_eq!(id, None);
    }

    #[test]
    fn test_extract_intent_id_invalid_json() {
        let payload = b"not valid json";
        let id = extract_intent_id(payload);
        assert_eq!(id, None);
    }

    #[test]
    fn test_extract_intent_id_non_string() {
        let payload = br#"{"intent_id": 12345}"#;
        let id = extract_intent_id(payload);
        assert_eq!(id, None);
    }

    #[test]
    fn test_extract_intent_id_null() {
        let payload = br#"{"intent_id": null}"#;
        let id = extract_intent_id(payload);
        assert_eq!(id, None);
    }

    #[test]
    fn test_extract_intent_id_empty_string() {
        let payload = br#"{"intent_id": ""}"#;
        let id = extract_intent_id(payload);
        assert_eq!(id, Some("".to_string()));
    }

    #[test]
    fn test_extract_intent_id_uuid_format() {
        let payload = br#"{"intent_id": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let id = extract_intent_id(payload);
        assert_eq!(id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
    }

    #[tokio::test]
    async fn test_nats_client_creation() {
        // This test requires a running NATS server, so it's disabled by default
        // Enable by setting TEST_NATS=1 environment variable

        if std::env::var("TEST_NATS").is_ok() {
            let config = NatsConfig {
                servers: vec!["nats://127.0.0.1:4222".to_string()],
                jetstream_domain: "JS".to_string(),
                tls_cert: None,
                tls_key: None,
                tls_ca: None,
            };

            let client = NatsClient::new(&config).await;
            assert!(client.is_ok(), "Should connect to NATS server");
        }
    }

    #[test]
    fn test_nats_config_clone() {
        let config = NatsConfig {
            servers: vec!["nats://localhost:4222".to_string()],
            jetstream_domain: "JS".to_string(),
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
        };

        let cloned = config.clone();
        assert_eq!(cloned.servers, config.servers);
        assert_eq!(cloned.jetstream_domain, config.jetstream_domain);
    }

    #[test]
    fn test_nats_config_with_tls() {
        use std::path::PathBuf;

        let config = NatsConfig {
            servers: vec!["nats://localhost:4222".to_string()],
            jetstream_domain: "JS".to_string(),
            tls_cert: Some(PathBuf::from("/path/to/cert.pem")),
            tls_key: Some(PathBuf::from("/path/to/key.pem")),
            tls_ca: Some(PathBuf::from("/path/to/ca.pem")),
        };

        assert!(config.tls_cert.is_some());
        assert!(config.tls_key.is_some());
        assert!(config.tls_ca.is_some());
    }

    #[test]
    fn test_nats_config_multiple_servers() {
        let config = NatsConfig {
            servers: vec![
                "nats://server1:4222".to_string(),
                "nats://server2:4222".to_string(),
                "nats://server3:4222".to_string(),
            ],
            jetstream_domain: "JS".to_string(),
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
        };

        assert_eq!(config.servers.len(), 3);
    }

    // ==================== Mock Publisher Tests ====================

    mod mock_tests {
        use super::super::mock::*;
        use super::*;
        use smith_protocol::{AuditRef, ExecutionStatus, IntentResult, RunnerMetadata};

        fn create_test_result(intent_id: &str) -> IntentResult {
            IntentResult {
                intent_id: intent_id.to_string(),
                status: ExecutionStatus::Ok,
                output: Some(serde_json::json!({"test": "output"})),
                error: None,
                started_at_ns: 1000,
                finished_at_ns: 2000,
                runner_meta: RunnerMetadata::empty(),
                audit_ref: AuditRef {
                    id: "test-audit".to_string(),
                    timestamp: 1000,
                    hash: "abc".to_string(),
                },
            }
        }

        #[tokio::test]
        async fn test_mock_publisher_records_calls() {
            let mock = MockResultPublisher::new();
            let result = create_test_result("intent-1");

            mock.publish_result("intent-1", &result).await.unwrap();

            assert_eq!(mock.call_count(), 1);
            let published = mock.published_results();
            assert_eq!(published[0].0, "intent-1");
            assert_eq!(published[0].1.status, ExecutionStatus::Ok);
        }

        #[tokio::test]
        async fn test_mock_publisher_multiple_calls() {
            let mock = MockResultPublisher::new();
            let result1 = create_test_result("intent-1");
            let result2 = create_test_result("intent-2");

            mock.publish_result("intent-1", &result1).await.unwrap();
            mock.publish_result("intent-2", &result2).await.unwrap();

            assert_eq!(mock.call_count(), 2);
        }

        #[tokio::test]
        async fn test_mock_publisher_fail_next() {
            let mock = MockResultPublisher::new();
            let result = create_test_result("intent-1");

            mock.fail_next(1);
            let publish_result = mock.publish_result("intent-1", &result).await;
            assert!(publish_result.is_err());

            // Next call should succeed
            let publish_result = mock.publish_result("intent-1", &result).await;
            assert!(publish_result.is_ok());
        }

        #[tokio::test]
        async fn test_mock_publisher_fail_multiple() {
            let mock = MockResultPublisher::new();
            let result = create_test_result("intent-1");

            mock.fail_next(3);
            assert!(mock.publish_result("intent-1", &result).await.is_err());
            assert!(mock.publish_result("intent-1", &result).await.is_err());
            assert!(mock.publish_result("intent-1", &result).await.is_err());
            assert!(mock.publish_result("intent-1", &result).await.is_ok());
        }

        #[tokio::test]
        async fn test_mock_publisher_clear() {
            let mock = MockResultPublisher::new();
            let result = create_test_result("intent-1");

            mock.publish_result("intent-1", &result).await.unwrap();
            assert_eq!(mock.call_count(), 1);

            mock.clear();
            assert_eq!(mock.call_count(), 0);
        }

        #[tokio::test]
        async fn test_mock_nats_publisher_methods() {
            let mock = MockResultPublisher::new();

            // Test basic publish
            assert!(mock.publish("test.subject", b"payload").await.is_ok());

            // Test publish with reply
            assert!(mock
                .publish_with_reply("test.subject", "reply.to", b"payload")
                .await
                .is_ok());

            // Test request
            let response = mock.request("test.subject", b"request").await.unwrap();
            assert!(response.is_empty());
        }

        #[test]
        fn test_mock_publisher_default() {
            let mock = MockResultPublisher::default();
            assert_eq!(mock.call_count(), 0);
        }
    }
}

fn truncate_payload(payload: &[u8], max_len: usize) -> String {
    let preview = String::from_utf8_lossy(payload);
    preview.chars().take(max_len).collect()
}

fn extract_intent_id(payload: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|value| {
            value
                .get("intent_id")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
        })
}
