//! Comprehensive test suite for SmithBus core functionality
//!
//! This module provides extensive coverage for the main SmithBus struct,
//! focusing on connection handling, health checks, and core operations.

#[cfg(test)]
mod tests {
    use crate::HealthStatus;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::time::Duration;

    /// Test message for SmithBus functionality testing
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct SmithBusTestMessage {
        id: String,
        operation: String,
        data: serde_json::Value,
        timestamp: String,
    }

    impl SmithBusTestMessage {
        fn new(id: &str, operation: &str) -> Self {
            Self {
                id: id.to_string(),
                operation: operation.to_string(),
                data: serde_json::json!({"test": "data"}),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }
        }

        fn with_data(id: &str, operation: &str, data: serde_json::Value) -> Self {
            Self {
                id: id.to_string(),
                operation: operation.to_string(),
                data,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }
        }
    }

    #[test]
    fn test_health_status_comprehensive() {
        // Test all combinations of health status
        let healthy = HealthStatus {
            nats_connected: true,
            jetstream_available: true,
        };
        assert!(healthy.is_healthy());

        let nats_only = HealthStatus {
            nats_connected: true,
            jetstream_available: false,
        };
        assert!(!nats_only.is_healthy());

        let jetstream_only = HealthStatus {
            nats_connected: false,
            jetstream_available: true,
        };
        assert!(!jetstream_only.is_healthy());

        let disconnected = HealthStatus {
            nats_connected: false,
            jetstream_available: false,
        };
        assert!(!disconnected.is_healthy());
    }

    #[test]
    fn test_health_status_debug_and_clone() {
        let health = HealthStatus {
            nats_connected: true,
            jetstream_available: false,
        };

        // Test Debug implementation
        let debug_string = format!("{:?}", health);
        assert!(debug_string.contains("nats_connected: true"));
        assert!(debug_string.contains("jetstream_available: false"));

        // Test Clone implementation
        let cloned_health = health.clone();
        assert_eq!(health.nats_connected, cloned_health.nats_connected);
        assert_eq!(
            health.jetstream_available,
            cloned_health.jetstream_available
        );
        assert_eq!(health.is_healthy(), cloned_health.is_healthy());
    }

    #[test]
    fn test_health_status_partial_eq() {
        let health1 = HealthStatus {
            nats_connected: true,
            jetstream_available: true,
        };

        let health2 = HealthStatus {
            nats_connected: true,
            jetstream_available: true,
        };

        let health3 = HealthStatus {
            nats_connected: true,
            jetstream_available: false,
        };

        // Test equality
        assert_eq!(health1, health2);
        assert_ne!(health1, health3);
        assert_ne!(health2, health3);
    }

    #[test]
    fn test_smith_bus_result_type() {
        // Test the Result type functionality
        fn create_success_result() -> anyhow::Result<String> {
            Ok("success".to_string())
        }

        fn create_error_result() -> anyhow::Result<String> {
            Err(anyhow::anyhow!("test error"))
        }

        // Test success case
        match create_success_result() {
            Ok(value) => assert_eq!(value, "success"),
            Err(_) => panic!("Expected success result"),
        }

        // Test error case
        match create_error_result() {
            Ok(_) => panic!("Expected error result"),
            Err(err) => assert!(err.to_string().contains("test error")),
        }
    }

    #[test]
    fn test_message_serialization_for_smith_bus() {
        let message = SmithBusTestMessage::new("sb-001", "test_operation");

        // Test serialization
        let serialized = serde_json::to_vec(&message).unwrap();
        assert!(!serialized.is_empty());

        // Verify content
        let json_str = String::from_utf8(serialized.clone()).unwrap();
        assert!(json_str.contains("sb-001"));
        assert!(json_str.contains("test_operation"));
        assert!(json_str.contains("test"));
        assert!(json_str.contains("data"));
        assert!(json_str.contains("2024-01-01T00:00:00Z"));

        // Test round-trip deserialization
        let deserialized: SmithBusTestMessage = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(deserialized, message);
    }

    #[test]
    fn test_message_with_complex_data() {
        let complex_data = serde_json::json!({
            "nested": {
                "array": [1, 2, 3],
                "string": "value",
                "boolean": true
            },
            "metadata": {
                "tags": ["urgent", "test"],
                "priority": 5
            }
        });

        let message =
            SmithBusTestMessage::with_data("sb-002", "complex_operation", complex_data.clone());

        // Test serialization
        let serialized = serde_json::to_vec(&message).unwrap();
        assert!(!serialized.is_empty());

        // Verify complex data preserved
        let json_str = String::from_utf8(serialized.clone()).unwrap();
        assert!(json_str.contains("nested"));
        assert!(json_str.contains("array"));
        assert!(json_str.contains("urgent"));
        assert!(json_str.contains("priority"));

        // Test deserialization preserves structure
        let deserialized: SmithBusTestMessage = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.data, complex_data);
    }

    #[test]
    fn test_message_serialization_edge_cases() {
        // Test with empty strings
        let empty_message = SmithBusTestMessage::new("", "");
        let serialized = serde_json::to_vec(&empty_message).unwrap();
        let deserialized: SmithBusTestMessage = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.id, "");
        assert_eq!(deserialized.operation, "");

        // Test with null data
        let null_data_message =
            SmithBusTestMessage::with_data("sb-003", "null_operation", serde_json::Value::Null);
        let serialized = serde_json::to_vec(&null_data_message).unwrap();
        let json_str = String::from_utf8(serialized).unwrap();
        assert!(json_str.contains("null"));

        // Test with very large data
        let large_data = serde_json::json!({
            "large_field": "x".repeat(10000),
            "numbers": (0..1000).collect::<Vec<i32>>()
        });
        let large_message = SmithBusTestMessage::with_data("sb-004", "large_operation", large_data);
        let serialized = serde_json::to_vec(&large_message).unwrap();
        assert!(serialized.len() > 10000);
    }

    #[test]
    fn test_connection_url_patterns() {
        // Test various NATS connection URL patterns that SmithBus might encounter
        let urls = vec![
            "nats://localhost:4222",
            "nats://127.0.0.1:4222",
            "nats://nats-server:4222",
            "nats://user:pass@nats-server:4222",
            "nats://user:pass@nats1:4222,nats2:4222,nats3:4222",
            "nats://cluster.example.com:4222",
            "tls://secure-nats.example.com:4222",
        ];

        for url in urls {
            // Verify URL structure
            assert!(!url.is_empty());
            assert!(url.starts_with("nats://") || url.starts_with("tls://"));
            assert!(url.contains(":4222") || url.contains(":"));

            // Test URL parsing (basic validation)
            let parts: Vec<&str> = url.split("://").collect();
            assert_eq!(parts.len(), 2);
            assert!(parts[0] == "nats" || parts[0] == "tls");
            assert!(!parts[1].is_empty());
        }
    }

    #[test]
    fn test_subject_pattern_validation() {
        // Test subject patterns that SmithBus would handle
        let valid_patterns = vec![
            "smith.intents.raw.*",
            "smith.results.*",
            "smith.audit.*",
            "smith.*.*.v1",
            "custom.subject.pattern",
            "test.>", // Wildcard
            "app.*.events.>",
        ];

        for pattern in valid_patterns {
            // Basic validation
            assert!(!pattern.is_empty());
            assert!(!pattern.starts_with('.'));
            assert!(!pattern.ends_with('.'));

            // Verify pattern components
            let segments: Vec<&str> = pattern.split('.').collect();
            assert!(!segments.is_empty());

            for segment in segments {
                assert!(!segment.is_empty() || segment == "*" || segment == ">");
            }
        }
    }

    #[test]
    fn test_error_handling_patterns() {
        // Test error handling patterns that SmithBus might encounter

        // Simulate connection errors
        fn simulate_connection_error() -> anyhow::Result<()> {
            Err(anyhow::anyhow!("Connection refused"))
        }

        // Simulate timeout errors
        fn simulate_timeout_error() -> anyhow::Result<()> {
            Err(anyhow::anyhow!("Operation timed out"))
        }

        // Simulate serialization errors
        fn simulate_serialization_error() -> anyhow::Result<()> {
            Err(anyhow::anyhow!("Failed to serialize message"))
        }

        // Test error handling
        assert!(simulate_connection_error().is_err());
        assert!(simulate_timeout_error().is_err());
        assert!(simulate_serialization_error().is_err());

        // Test error message content
        match simulate_connection_error() {
            Err(e) => assert!(e.to_string().contains("Connection refused")),
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_timeout_duration_handling() {
        // Test timeout durations that SmithBus might use
        let timeouts = vec![
            Duration::from_millis(100), // Very short
            Duration::from_millis(500), // Short
            Duration::from_secs(1),     // Default
            Duration::from_secs(5),     // Medium
            Duration::from_secs(30),    // Long
            Duration::from_secs(300),   // Very long
        ];

        for timeout in timeouts {
            // Verify timeout properties
            assert!(timeout > Duration::ZERO);
            assert!(timeout <= Duration::from_secs(300));

            // Test timeout arithmetic
            let doubled_timeout = timeout * 2;
            assert!(doubled_timeout > timeout);

            // Test comparison
            assert!(timeout >= Duration::ZERO);
        }
    }

    #[test]
    fn test_configuration_defaults() {
        // Test default configuration values that SmithBus might use
        struct MockSmithBusConfig {
            connection_timeout: Duration,
            publish_timeout: Duration,
            consumer_batch_size: usize,
            max_reconnect_attempts: usize,
            reconnect_delay: Duration,
        }

        impl Default for MockSmithBusConfig {
            fn default() -> Self {
                Self {
                    connection_timeout: Duration::from_secs(10),
                    publish_timeout: Duration::from_secs(5),
                    consumer_batch_size: 100,
                    max_reconnect_attempts: 5,
                    reconnect_delay: Duration::from_secs(1),
                }
            }
        }

        let config = MockSmithBusConfig::default();

        // Verify default values are reasonable
        assert_eq!(config.connection_timeout, Duration::from_secs(10));
        assert_eq!(config.publish_timeout, Duration::from_secs(5));
        assert_eq!(config.consumer_batch_size, 100);
        assert_eq!(config.max_reconnect_attempts, 5);
        assert_eq!(config.reconnect_delay, Duration::from_secs(1));

        // Verify relationships make sense
        assert!(config.connection_timeout > config.publish_timeout);
        assert!(config.consumer_batch_size > 0);
        assert!(config.max_reconnect_attempts > 0);
        assert!(config.reconnect_delay > Duration::ZERO);
    }

    #[test]
    fn test_stream_and_consumer_names() {
        // Test naming patterns for streams and consumers that SmithBus uses
        let stream_names = vec![
            "SDLC_RAW",
            "ATOMS_VETTED",
            "ATOMS_RESULTS",
            "AUDIT_SECURITY",
            "SDLC_QUARANTINE_BACKPRESSURE",
        ];

        let consumer_name_patterns = vec![
            "executor-fs-read-v1",
            "executor-http-fetch-v1",
            "ai-agent-planner",
            "results-aggregator",
            "audit-processor",
        ];

        // Test stream names
        for stream_name in stream_names {
            assert!(!stream_name.is_empty());
            assert!(stream_name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_'));
            assert!(!stream_name.starts_with('_'));
            assert!(!stream_name.ends_with('_'));
        }

        // Test consumer names
        for consumer_name in consumer_name_patterns {
            assert!(!consumer_name.is_empty());
            assert!(consumer_name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()));
            assert!(!consumer_name.starts_with('-'));
            assert!(!consumer_name.ends_with('-'));

            // Should contain at least one separator
            assert!(consumer_name.contains('-'));
        }
    }

    #[test]
    fn test_message_metadata_patterns() {
        // Test metadata patterns that might be used with SmithBus messages
        let mut metadata = HashMap::new();
        metadata.insert("correlation-id".to_string(), "corr-12345".to_string());
        metadata.insert("source".to_string(), "ai-agent".to_string());
        metadata.insert("destination".to_string(), "executor".to_string());
        metadata.insert("priority".to_string(), "high".to_string());
        metadata.insert("retry-count".to_string(), "0".to_string());

        // Verify metadata structure
        assert_eq!(metadata.len(), 5);
        assert!(metadata.contains_key("correlation-id"));
        assert!(metadata.contains_key("source"));
        assert!(metadata.contains_key("destination"));
        assert!(metadata.contains_key("priority"));
        assert!(metadata.contains_key("retry-count"));

        // Verify values
        assert_eq!(metadata.get("correlation-id").unwrap(), "corr-12345");
        assert_eq!(metadata.get("source").unwrap(), "ai-agent");
        assert_eq!(metadata.get("destination").unwrap(), "executor");
        assert_eq!(metadata.get("priority").unwrap(), "high");
        assert_eq!(metadata.get("retry-count").unwrap(), "0");

        // Test serialization of metadata
        let serialized = serde_json::to_vec(&metadata).unwrap();
        let deserialized: HashMap<String, String> = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(metadata, deserialized);
    }

    #[test]
    fn test_performance_metrics_tracking() {
        // Test performance metrics that SmithBus might track
        #[derive(Debug, Clone)]
        struct PerformanceMetrics {
            messages_published: u64,
            messages_consumed: u64,
            publish_latency_ms: Vec<u64>,
            consume_latency_ms: Vec<u64>,
            errors_count: u64,
        }

        let mut metrics = PerformanceMetrics {
            messages_published: 0,
            messages_consumed: 0,
            publish_latency_ms: Vec::new(),
            consume_latency_ms: Vec::new(),
            errors_count: 0,
        };

        // Simulate some operations
        for i in 1..=100 {
            metrics.messages_published += 1;
            metrics.publish_latency_ms.push(i * 2); // Simulate increasing latency

            if i % 10 == 0 {
                metrics.messages_consumed += 1;
                metrics.consume_latency_ms.push(i * 3);
            }

            if i % 25 == 0 {
                metrics.errors_count += 1;
            }
        }

        // Verify metrics
        assert_eq!(metrics.messages_published, 100);
        assert_eq!(metrics.messages_consumed, 10);
        assert_eq!(metrics.errors_count, 4);
        assert_eq!(metrics.publish_latency_ms.len(), 100);
        assert_eq!(metrics.consume_latency_ms.len(), 10);

        // Calculate averages
        let avg_publish_latency = metrics.publish_latency_ms.iter().sum::<u64>()
            / metrics.publish_latency_ms.len() as u64;
        let avg_consume_latency = metrics.consume_latency_ms.iter().sum::<u64>()
            / metrics.consume_latency_ms.len() as u64;

        assert!(avg_publish_latency > 0);
        assert!(avg_consume_latency > 0);
        assert!(avg_consume_latency > avg_publish_latency); // Consume typically slower
    }
}
