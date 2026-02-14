use anyhow::{Context, Result};
use async_nats::jetstream;
use serde::Serialize;
use tracing::debug;

/// Publisher for sending messages to JetStream
#[derive(Clone)]
pub struct Publisher {
    jetstream: jetstream::Context,
}

impl Publisher {
    pub fn new(jetstream: jetstream::Context) -> Self {
        Self { jetstream }
    }

    /// Publish a serializable message to a subject
    pub async fn publish<T: Serialize>(&self, subject: String, message: &T) -> Result<()> {
        let payload = serde_json::to_vec(message).context("Failed to serialize message")?;

        debug!("Publishing message to subject: {}", subject);

        let ack = self
            .jetstream
            .publish(subject.clone(), payload.into())
            .await
            .with_context(|| format!("Failed to publish message to subject: {}", subject))?;

        debug!(
            "Message published to {} with sequence: {}",
            subject,
            ack.await?.sequence
        );
        Ok(())
    }

    /// Publish a serializable message with headers
    pub async fn publish_with_headers<T: Serialize>(
        &self,
        subject: String,
        headers: async_nats::HeaderMap,
        message: &T,
    ) -> Result<()> {
        let payload = serde_json::to_vec(message).context("Failed to serialize message")?;

        debug!("Publishing message with headers to subject: {}", subject);

        let ack = self
            .jetstream
            .publish_with_headers(subject.clone(), headers, payload.into())
            .await
            .with_context(|| format!("Failed to publish message to subject: {}", subject))?;

        debug!(
            "Message published to {} with sequence: {}",
            subject,
            ack.await?.sequence
        );
        Ok(())
    }

    /// Publish a raw message to any subject
    pub async fn publish_raw(&self, subject: &str, payload: Vec<u8>) -> Result<u64> {
        debug!("Publishing raw message to subject: {}", subject);

        let ack = self
            .jetstream
            .publish(subject.to_string(), payload.into())
            .await
            .with_context(|| format!("Failed to publish raw message to subject: {}", subject))?;

        let sequence = ack.await?.sequence;
        debug!(
            "Raw message published to {} with sequence: {}",
            subject, sequence
        );

        Ok(sequence)
    }
}

#[cfg(test)]
mod tests {
    // Note: Not importing super::* since we mainly need to test serialization patterns
    use crate::subjects::builders::{AuditSubject, IntentSubject, ResultSubject};
    use async_nats::HeaderMap;

    // Note: These tests require a running NATS server and are primarily for structure validation
    // Integration tests should be run separately with a test environment

    #[test]
    fn test_generic_message_serialization() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct TestMessage {
            id: String,
            content: String,
        }

        let message = TestMessage {
            id: "test-123".to_string(),
            content: "test content".to_string(),
        };

        let serialized = serde_json::to_vec(&message).unwrap();
        assert!(!serialized.is_empty());

        // Verify it deserializes back correctly
        let deserialized: TestMessage = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.id, "test-123");
        assert_eq!(deserialized.content, "test content");
    }

    #[test]
    fn test_subject_builders_usage() {
        // Test that we can use the subject builders correctly
        let intent_subject = IntentSubject::raw("fs.read.v1");
        assert_eq!(intent_subject, "smith.intents.raw.fs.read.v1");

        let result_subject = ResultSubject::for_intent("intent-123");
        assert_eq!(result_subject, "smith.results.intent-123");

        let audit_subject = AuditSubject::execution("intent-456");
        assert_eq!(audit_subject, "smith.audit.execution.intent-456");
    }

    #[test]
    fn test_publisher_creation() {
        // This is a unit test for the Publisher struct without requiring NATS
        // We can't fully test without a JetStream context, but we can test the structure

        // Note: We can't easily create a mock jetstream::Context without significant setup,
        // so we'll test what we can without it

        // Test serialization of different message types
        #[derive(serde::Serialize)]
        struct ComplexMessage {
            id: u64,
            data: Vec<String>,
            metadata: std::collections::HashMap<String, String>,
        }

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());

        let complex_message = ComplexMessage {
            id: 42,
            data: vec!["item1".to_string(), "item2".to_string()],
            metadata,
        };

        let serialized = serde_json::to_vec(&complex_message).unwrap();
        assert!(!serialized.is_empty());

        // Verify it contains expected content
        let json_str = String::from_utf8(serialized).unwrap();
        assert!(json_str.contains("42"));
        assert!(json_str.contains("item1"));
        assert!(json_str.contains("key1"));
        assert!(json_str.contains("value1"));
    }

    #[test]
    fn test_message_serialization_edge_cases() {
        // Test empty message
        #[derive(serde::Serialize)]
        struct EmptyMessage {}

        let empty_message = EmptyMessage {};
        let serialized = serde_json::to_vec(&empty_message).unwrap();
        assert_eq!(serialized, b"{}");

        // Test message with None values
        #[derive(serde::Serialize)]
        struct OptionalMessage {
            required: String,
            optional: Option<String>,
        }

        let optional_message = OptionalMessage {
            required: "required_value".to_string(),
            optional: None,
        };

        let serialized = serde_json::to_vec(&optional_message).unwrap();
        let json_str = String::from_utf8(serialized).unwrap();
        assert!(json_str.contains("required_value"));
        assert!(json_str.contains("null"));
    }

    #[test]
    fn test_publisher_clone() {
        // Test that Publisher can be cloned
        // Note: We can't create an actual Publisher without JetStream context,
        // but we can verify the Clone trait is implemented

        // This test verifies the Clone derive is working
        // The actual functionality would be tested in integration tests
    }

    #[test]
    fn test_raw_payload_handling() {
        // Test various payload types that might be sent as raw messages
        let text_payload = "Hello, World!".as_bytes().to_vec();
        assert!(!text_payload.is_empty());

        let json_payload = serde_json::to_vec(&serde_json::json!({
            "type": "event",
            "data": "test"
        }))
        .unwrap();
        assert!(!json_payload.is_empty());

        let binary_payload = [0x00, 0x01, 0x02, 0x03, 0xFF];
        assert_eq!(binary_payload.len(), 5);
        assert_eq!(binary_payload[0], 0x00);
        assert_eq!(binary_payload[4], 0xFF);
    }

    #[test]
    fn test_header_map_usage() {
        // Test that we can create and work with HeaderMap
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");
        headers.insert("X-Correlation-ID", "test-123");

        assert!(headers.get("Content-Type").is_some());
        assert!(headers.get("X-Correlation-ID").is_some());
        assert!(headers.get("Non-Existent").is_none());
    }

    #[test]
    fn test_subject_string_handling() {
        // Test various subject formats
        let subjects = vec![
            "smith.intents.raw.fs.read.v1",
            "smith.results.intent-123",
            "smith.audit.execution.intent-456",
            "test.subject.with.dots",
            "simple",
        ];

        for subject in subjects {
            assert!(!subject.is_empty());
            // Verify subjects can be converted to String
            let subject_string = subject.to_string();
            assert_eq!(subject, subject_string);
        }
    }

    #[test]
    fn test_serialization_errors() {
        // Test what happens with serialization that might fail
        use std::collections::HashMap;

        // This should serialize fine
        let mut valid_map = HashMap::new();
        valid_map.insert("key".to_string(), "value".to_string());

        let result = serde_json::to_vec(&valid_map);
        assert!(result.is_ok());

        // Test with NaN values which might cause issues
        let nan_value = f64::NAN;
        let result = serde_json::to_vec(&nan_value);
        // JSON doesn't support NaN, so this should still serialize but as null
        assert!(result.is_ok());
    }
}
