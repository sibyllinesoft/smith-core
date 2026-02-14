//! Testing infrastructure for NATS-dependent code
//!
//! This module provides mock implementations of NATS client functionality
//! to enable unit testing of code that depends on NATS without requiring
//! a running NATS server.

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

// Re-export traits from the main nats module
pub use crate::nats::{IntentResultPublisher, NatsPublisher};

/// Mock NATS publisher for testing
///
/// Records all published messages for verification in tests.
#[derive(Default)]
pub struct MockNatsPublisher {
    /// Recorded published messages: (subject, payload)
    published_messages: Arc<Mutex<Vec<(String, Vec<u8>)>>>,

    /// Recorded request-reply messages: (subject, payload)
    request_messages: Arc<Mutex<Vec<(String, Vec<u8>)>>>,

    /// Pre-configured responses for request-reply
    responses: Arc<Mutex<HashMap<String, VecDeque<Vec<u8>>>>>,

    /// Whether to simulate failures
    fail_on_publish: Arc<Mutex<bool>>,

    /// Specific subjects to fail on
    fail_subjects: Arc<Mutex<Vec<String>>>,
}

impl MockNatsPublisher {
    /// Create a new mock publisher
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a response for a specific subject
    pub fn set_response(&self, subject: &str, response: Vec<u8>) {
        let mut responses = self.responses.lock();
        responses
            .entry(subject.to_string())
            .or_insert_with(VecDeque::new)
            .push_back(response);
    }

    /// Configure multiple responses for a subject (FIFO)
    pub fn set_responses(&self, subject: &str, responses_list: Vec<Vec<u8>>) {
        let mut responses = self.responses.lock();
        let queue = responses
            .entry(subject.to_string())
            .or_insert_with(VecDeque::new);
        for response in responses_list {
            queue.push_back(response);
        }
    }

    /// Enable publish failures
    pub fn set_fail_on_publish(&self, fail: bool) {
        *self.fail_on_publish.lock() = fail;
    }

    /// Set specific subjects that should fail
    pub fn set_fail_subjects(&self, subjects: Vec<String>) {
        *self.fail_subjects.lock() = subjects;
    }

    /// Get all published messages
    pub fn get_published(&self) -> Vec<(String, Vec<u8>)> {
        self.published_messages.lock().clone()
    }

    /// Get all request messages
    pub fn get_requests(&self) -> Vec<(String, Vec<u8>)> {
        self.request_messages.lock().clone()
    }

    /// Get published messages for a specific subject
    pub fn get_published_to(&self, subject: &str) -> Vec<Vec<u8>> {
        self.published_messages
            .lock()
            .iter()
            .filter(|(s, _)| s == subject)
            .map(|(_, p)| p.clone())
            .collect()
    }

    /// Check if a message was published to a subject
    pub fn was_published_to(&self, subject: &str) -> bool {
        self.published_messages
            .lock()
            .iter()
            .any(|(s, _)| s == subject)
    }

    /// Get the count of messages published
    pub fn published_count(&self) -> usize {
        self.published_messages.lock().len()
    }

    /// Clear all recorded messages
    pub fn clear(&self) {
        self.published_messages.lock().clear();
        self.request_messages.lock().clear();
    }

    fn should_fail(&self, subject: &str) -> bool {
        if *self.fail_on_publish.lock() {
            return true;
        }
        self.fail_subjects.lock().contains(&subject.to_string())
    }
}

#[async_trait]
impl NatsPublisher for MockNatsPublisher {
    async fn publish(&self, subject: &str, payload: &[u8]) -> Result<()> {
        if self.should_fail(subject) {
            return Err(anyhow::anyhow!(
                "Mock NATS publish failure for subject: {}",
                subject
            ));
        }

        self.published_messages
            .lock()
            .push((subject.to_string(), payload.to_vec()));
        Ok(())
    }

    async fn publish_with_reply(&self, subject: &str, _reply: &str, payload: &[u8]) -> Result<()> {
        if self.should_fail(subject) {
            return Err(anyhow::anyhow!(
                "Mock NATS publish failure for subject: {}",
                subject
            ));
        }

        self.published_messages
            .lock()
            .push((subject.to_string(), payload.to_vec()));
        Ok(())
    }

    async fn request(&self, subject: &str, payload: &[u8]) -> Result<Vec<u8>> {
        if self.should_fail(subject) {
            return Err(anyhow::anyhow!(
                "Mock NATS request failure for subject: {}",
                subject
            ));
        }

        self.request_messages
            .lock()
            .push((subject.to_string(), payload.to_vec()));

        // Get pre-configured response if available
        let response = {
            let mut responses = self.responses.lock();
            responses
                .get_mut(subject)
                .and_then(|queue| queue.pop_front())
        };

        match response {
            Some(r) => Ok(r),
            None => Err(anyhow::anyhow!(
                "No mock response configured for subject: {}",
                subject
            )),
        }
    }
}

/// Trait for NATS result publishing
///
/// This trait abstracts the result publishing functionality
/// used by the admission pipeline.
#[async_trait]
pub trait ResultPublisher: Send + Sync {
    /// Publish an intent result
    async fn publish_result(&self, intent_id: &str, result: &[u8]) -> Result<()>;
}

/// Mock result publisher for testing
#[derive(Default)]
pub struct MockResultPublisher {
    /// Recorded results: (intent_id, result)
    results: Arc<Mutex<Vec<(String, Vec<u8>)>>>,

    /// Whether to fail on publish
    fail_on_publish: Arc<Mutex<bool>>,
}

impl MockResultPublisher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_fail_on_publish(&self, fail: bool) {
        *self.fail_on_publish.lock() = fail;
    }

    pub fn get_results(&self) -> Vec<(String, Vec<u8>)> {
        self.results.lock().clone()
    }

    pub fn get_result_for(&self, intent_id: &str) -> Option<Vec<u8>> {
        self.results
            .lock()
            .iter()
            .find(|(id, _)| id == intent_id)
            .map(|(_, r)| r.clone())
    }

    pub fn was_result_published(&self, intent_id: &str) -> bool {
        self.results.lock().iter().any(|(id, _)| id == intent_id)
    }

    pub fn result_count(&self) -> usize {
        self.results.lock().len()
    }

    pub fn clear(&self) {
        self.results.lock().clear();
    }
}

#[async_trait]
impl ResultPublisher for MockResultPublisher {
    async fn publish_result(&self, intent_id: &str, result: &[u8]) -> Result<()> {
        if *self.fail_on_publish.lock() {
            return Err(anyhow::anyhow!(
                "Mock result publish failure for intent: {}",
                intent_id
            ));
        }

        self.results
            .lock()
            .push((intent_id.to_string(), result.to_vec()));
        Ok(())
    }
}

/// Mock intent result publisher for testing admission pipeline
///
/// Records all published IntentResults for verification in tests.
/// This is the preferred mock for testing code that uses IntentResultPublisher.
#[derive(Default)]
pub struct MockIntentResultPublisher {
    /// Recorded results: (intent_id, serialized result)
    results: Arc<Mutex<Vec<(String, smith_protocol::IntentResult)>>>,

    /// Whether to fail on publish
    fail_on_publish: Arc<Mutex<bool>>,

    /// Specific intent IDs to fail on
    fail_intent_ids: Arc<Mutex<Vec<String>>>,
}

impl MockIntentResultPublisher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_fail_on_publish(&self, fail: bool) {
        *self.fail_on_publish.lock() = fail;
    }

    pub fn set_fail_intent_ids(&self, intent_ids: Vec<String>) {
        *self.fail_intent_ids.lock() = intent_ids;
    }

    pub fn get_results(&self) -> Vec<(String, smith_protocol::IntentResult)> {
        self.results.lock().clone()
    }

    pub fn get_result_for(&self, intent_id: &str) -> Option<smith_protocol::IntentResult> {
        self.results
            .lock()
            .iter()
            .find(|(id, _)| id == intent_id)
            .map(|(_, r)| r.clone())
    }

    pub fn was_result_published(&self, intent_id: &str) -> bool {
        self.results.lock().iter().any(|(id, _)| id == intent_id)
    }

    pub fn result_count(&self) -> usize {
        self.results.lock().len()
    }

    pub fn clear(&self) {
        self.results.lock().clear();
    }

    fn should_fail(&self, intent_id: &str) -> bool {
        if *self.fail_on_publish.lock() {
            return true;
        }
        self.fail_intent_ids.lock().contains(&intent_id.to_string())
    }
}

#[async_trait]
impl IntentResultPublisher for MockIntentResultPublisher {
    async fn publish_result(
        &self,
        intent_id: &str,
        result: &smith_protocol::IntentResult,
    ) -> Result<()> {
        if self.should_fail(intent_id) {
            return Err(anyhow::anyhow!(
                "Mock intent result publish failure for intent: {}",
                intent_id
            ));
        }

        self.results
            .lock()
            .push((intent_id.to_string(), result.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== MockNatsPublisher Tests ====================

    #[tokio::test]
    async fn test_mock_publisher_creation() {
        let publisher = MockNatsPublisher::new();
        assert_eq!(publisher.published_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_publisher_publish() {
        let publisher = MockNatsPublisher::new();

        publisher.publish("test.subject", b"hello").await.unwrap();

        assert_eq!(publisher.published_count(), 1);
        assert!(publisher.was_published_to("test.subject"));

        let messages = publisher.get_published_to("test.subject");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], b"hello");
    }

    #[tokio::test]
    async fn test_mock_publisher_multiple_publishes() {
        let publisher = MockNatsPublisher::new();

        publisher.publish("subject1", b"msg1").await.unwrap();
        publisher.publish("subject2", b"msg2").await.unwrap();
        publisher.publish("subject1", b"msg3").await.unwrap();

        assert_eq!(publisher.published_count(), 3);
        assert_eq!(publisher.get_published_to("subject1").len(), 2);
        assert_eq!(publisher.get_published_to("subject2").len(), 1);
    }

    #[tokio::test]
    async fn test_mock_publisher_fail_on_publish() {
        let publisher = MockNatsPublisher::new();
        publisher.set_fail_on_publish(true);

        let result = publisher.publish("test.subject", b"hello").await;

        assert!(result.is_err());
        assert_eq!(publisher.published_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_publisher_fail_subjects() {
        let publisher = MockNatsPublisher::new();
        publisher.set_fail_subjects(vec!["fail.subject".to_string()]);

        // Should succeed on non-failing subject
        publisher.publish("good.subject", b"hello").await.unwrap();
        assert_eq!(publisher.published_count(), 1);

        // Should fail on failing subject
        let result = publisher.publish("fail.subject", b"hello").await;
        assert!(result.is_err());
        assert_eq!(publisher.published_count(), 1); // Still 1, not 2
    }

    #[tokio::test]
    async fn test_mock_publisher_request_with_response() {
        let publisher = MockNatsPublisher::new();
        publisher.set_response("test.request", b"response".to_vec());

        let response = publisher.request("test.request", b"request").await.unwrap();

        assert_eq!(response, b"response");
        assert_eq!(publisher.get_requests().len(), 1);
    }

    #[tokio::test]
    async fn test_mock_publisher_request_multiple_responses() {
        let publisher = MockNatsPublisher::new();
        publisher.set_responses(
            "test.request",
            vec![
                b"response1".to_vec(),
                b"response2".to_vec(),
                b"response3".to_vec(),
            ],
        );

        let r1 = publisher.request("test.request", b"req1").await.unwrap();
        let r2 = publisher.request("test.request", b"req2").await.unwrap();
        let r3 = publisher.request("test.request", b"req3").await.unwrap();

        assert_eq!(r1, b"response1");
        assert_eq!(r2, b"response2");
        assert_eq!(r3, b"response3");
    }

    #[tokio::test]
    async fn test_mock_publisher_request_no_response() {
        let publisher = MockNatsPublisher::new();

        let result = publisher.request("no.response", b"request").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_publisher_clear() {
        let publisher = MockNatsPublisher::new();

        publisher.publish("subject", b"msg").await.unwrap();
        publisher.set_response("request", b"response".to_vec());
        let _ = publisher.request("request", b"req").await;

        assert_eq!(publisher.published_count(), 1);
        assert_eq!(publisher.get_requests().len(), 1);

        publisher.clear();

        assert_eq!(publisher.published_count(), 0);
        assert_eq!(publisher.get_requests().len(), 0);
    }

    #[tokio::test]
    async fn test_mock_publisher_publish_with_reply() {
        let publisher = MockNatsPublisher::new();

        publisher
            .publish_with_reply("subject", "reply.to", b"msg")
            .await
            .unwrap();

        assert_eq!(publisher.published_count(), 1);
        assert!(publisher.was_published_to("subject"));
    }

    // ==================== MockResultPublisher Tests ====================

    #[tokio::test]
    async fn test_mock_result_publisher_creation() {
        let publisher = MockResultPublisher::new();
        assert_eq!(publisher.result_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_result_publisher_publish() {
        let publisher = MockResultPublisher::new();

        publisher
            .publish_result("intent-123", b"result data")
            .await
            .unwrap();

        assert_eq!(publisher.result_count(), 1);
        assert!(publisher.was_result_published("intent-123"));

        let result = publisher.get_result_for("intent-123").unwrap();
        assert_eq!(result, b"result data");
    }

    #[tokio::test]
    async fn test_mock_result_publisher_multiple_results() {
        let publisher = MockResultPublisher::new();

        publisher
            .publish_result("intent-1", b"result1")
            .await
            .unwrap();
        publisher
            .publish_result("intent-2", b"result2")
            .await
            .unwrap();

        assert_eq!(publisher.result_count(), 2);
        assert!(publisher.was_result_published("intent-1"));
        assert!(publisher.was_result_published("intent-2"));
    }

    #[tokio::test]
    async fn test_mock_result_publisher_fail() {
        let publisher = MockResultPublisher::new();
        publisher.set_fail_on_publish(true);

        let result = publisher.publish_result("intent-123", b"result").await;

        assert!(result.is_err());
        assert_eq!(publisher.result_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_result_publisher_clear() {
        let publisher = MockResultPublisher::new();

        publisher
            .publish_result("intent-123", b"result")
            .await
            .unwrap();
        assert_eq!(publisher.result_count(), 1);

        publisher.clear();
        assert_eq!(publisher.result_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_result_publisher_get_nonexistent() {
        let publisher = MockResultPublisher::new();

        assert!(publisher.get_result_for("nonexistent").is_none());
        assert!(!publisher.was_result_published("nonexistent"));
    }

    // ==================== Thread Safety Tests ====================

    #[tokio::test]
    async fn test_mock_publisher_concurrent_access() {
        let publisher = Arc::new(MockNatsPublisher::new());

        let mut handles = vec![];
        for i in 0..10 {
            let p = publisher.clone();
            let handle = tokio::spawn(async move {
                p.publish(&format!("subject.{}", i), format!("msg{}", i).as_bytes())
                    .await
                    .unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(publisher.published_count(), 10);
    }

    #[tokio::test]
    async fn test_mock_result_publisher_concurrent_access() {
        let publisher = Arc::new(MockResultPublisher::new());

        let mut handles = vec![];
        for i in 0..10 {
            let p = publisher.clone();
            let handle = tokio::spawn(async move {
                p.publish_result(&format!("intent-{}", i), format!("result{}", i).as_bytes())
                    .await
                    .unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(publisher.result_count(), 10);
    }

    // ==================== MockIntentResultPublisher Tests ====================

    fn create_test_intent_result(
        status: smith_protocol::ExecutionStatus,
    ) -> smith_protocol::IntentResult {
        smith_protocol::IntentResult {
            intent_id: "test-intent".to_string(),
            status,
            output: Some(serde_json::json!({"result": "output"})),
            error: None,
            started_at_ns: 0,
            finished_at_ns: 100_000_000,
            runner_meta: smith_protocol::RunnerMetadata::empty(),
            audit_ref: smith_protocol::AuditRef {
                id: "audit-test".to_string(),
                timestamp: 0,
                hash: "test-hash".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_creation() {
        let publisher = MockIntentResultPublisher::new();
        assert_eq!(publisher.result_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_publish() {
        let publisher = MockIntentResultPublisher::new();
        let result = create_test_intent_result(smith_protocol::ExecutionStatus::Ok);

        publisher
            .publish_result("intent-123", &result)
            .await
            .unwrap();

        assert_eq!(publisher.result_count(), 1);
        assert!(publisher.was_result_published("intent-123"));

        let stored = publisher.get_result_for("intent-123").unwrap();
        assert_eq!(stored.status, smith_protocol::ExecutionStatus::Ok);
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_multiple_results() {
        let publisher = MockIntentResultPublisher::new();

        let result1 = create_test_intent_result(smith_protocol::ExecutionStatus::Ok);
        let result2 = create_test_intent_result(smith_protocol::ExecutionStatus::Error);

        publisher
            .publish_result("intent-1", &result1)
            .await
            .unwrap();
        publisher
            .publish_result("intent-2", &result2)
            .await
            .unwrap();

        assert_eq!(publisher.result_count(), 2);
        assert!(publisher.was_result_published("intent-1"));
        assert!(publisher.was_result_published("intent-2"));
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_fail_on_publish() {
        let publisher = MockIntentResultPublisher::new();
        publisher.set_fail_on_publish(true);

        let result = create_test_intent_result(smith_protocol::ExecutionStatus::Ok);
        let publish_result = publisher.publish_result("intent-123", &result).await;

        assert!(publish_result.is_err());
        assert_eq!(publisher.result_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_fail_specific_intents() {
        let publisher = MockIntentResultPublisher::new();
        publisher.set_fail_intent_ids(vec!["fail-intent".to_string()]);

        let result = create_test_intent_result(smith_protocol::ExecutionStatus::Ok);

        // Should succeed on non-failing intent
        publisher
            .publish_result("good-intent", &result)
            .await
            .unwrap();
        assert_eq!(publisher.result_count(), 1);

        // Should fail on failing intent
        let fail_result = publisher.publish_result("fail-intent", &result).await;
        assert!(fail_result.is_err());
        assert_eq!(publisher.result_count(), 1);
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_clear() {
        let publisher = MockIntentResultPublisher::new();
        let result = create_test_intent_result(smith_protocol::ExecutionStatus::Ok);

        publisher.publish_result("intent-1", &result).await.unwrap();
        assert_eq!(publisher.result_count(), 1);

        publisher.clear();
        assert_eq!(publisher.result_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_get_nonexistent() {
        let publisher = MockIntentResultPublisher::new();

        assert!(publisher.get_result_for("nonexistent").is_none());
        assert!(!publisher.was_result_published("nonexistent"));
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_concurrent_access() {
        let publisher = Arc::new(MockIntentResultPublisher::new());

        let mut handles = vec![];
        for i in 0..10 {
            let p = publisher.clone();
            let handle = tokio::spawn(async move {
                let result = smith_protocol::IntentResult {
                    intent_id: format!("intent-{}", i),
                    status: smith_protocol::ExecutionStatus::Ok,
                    output: Some(serde_json::json!({"output": format!("output-{}", i)})),
                    error: None,
                    started_at_ns: 0,
                    finished_at_ns: 100_000_000,
                    runner_meta: smith_protocol::RunnerMetadata::empty(),
                    audit_ref: smith_protocol::AuditRef {
                        id: format!("audit-{}", i),
                        timestamp: 0,
                        hash: "test-hash".to_string(),
                    },
                };
                p.publish_result(&format!("intent-{}", i), &result)
                    .await
                    .unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(publisher.result_count(), 10);
    }

    #[tokio::test]
    async fn test_mock_intent_result_publisher_get_all_results() {
        let publisher = MockIntentResultPublisher::new();

        let result1 = create_test_intent_result(smith_protocol::ExecutionStatus::Ok);
        let result2 = create_test_intent_result(smith_protocol::ExecutionStatus::Error);

        publisher
            .publish_result("intent-1", &result1)
            .await
            .unwrap();
        publisher
            .publish_result("intent-2", &result2)
            .await
            .unwrap();

        let all_results = publisher.get_results();
        assert_eq!(all_results.len(), 2);
        assert_eq!(all_results[0].0, "intent-1");
        assert_eq!(all_results[1].0, "intent-2");
    }
}
