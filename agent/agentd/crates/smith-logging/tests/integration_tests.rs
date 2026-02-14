//! Integration tests for Smith logging infrastructure

use smith_config::{Config, NatsLoggingConfig};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

#[tokio::test]
async fn test_console_logging_initialization() {
    // Test basic console logging without NATS
    let result = smith_logging::init_console_logging("debug");
    assert!(result.is_ok());

    // Test logging at different levels
    info!("Test info message");
    warn!("Test warning message");
    error!("Test error message");
}

#[tokio::test]
async fn test_logging_config_loading() {
    // Test that we can load logging config
    let config = Config::development();

    // Verify NATS logging config is present
    assert!(config.logging.nats.enabled);
    assert_eq!(config.logging.nats.buffer_size, 500);
    assert!(!config.logging.nats.target_filters.is_empty());

    let config = Config::production();
    assert!(config.logging.nats.enabled);
    assert_eq!(config.logging.nats.buffer_size, 2000);
    assert!(config.logging.nats.batch_enabled);

    let config = Config::testing();
    assert!(!config.logging.nats.enabled); // Disabled in testing
}

#[tokio::test]
async fn test_nats_logging_config_environments() {
    // Test development config
    let dev_config = NatsLoggingConfig::development();
    assert!(dev_config.enabled);
    assert!(!dev_config.batch_enabled); // Immediate logging for dev
    assert!(dev_config.include_traces); // Traces enabled for dev
    assert_eq!(dev_config.rate_limit, 0); // No rate limiting

    // Test production config
    let prod_config = NatsLoggingConfig::production();
    assert!(prod_config.enabled);
    assert!(prod_config.batch_enabled); // Batching for performance
    assert!(!prod_config.include_traces); // No traces for performance
    assert!(prod_config.rate_limit > 0); // Rate limiting enabled

    // Test testing config
    let test_config = NatsLoggingConfig::testing();
    assert!(!test_config.enabled); // Disabled during tests
}

#[tokio::test]
async fn test_structured_logging_with_fields() {
    // Initialize console logging for testing
    let _ = smith_logging::init_console_logging("info");

    // Test structured logging with fields
    info!(
        user_id = "user123",
        action = "login",
        ip_address = "192.168.1.1",
        session_duration_ms = 1500,
        success = true,
        "User logged in successfully"
    );

    warn!(
        error_count = 3,
        service = "database",
        latency_ms = 2500,
        "High latency detected"
    );

    error!(
        error_code = 500,
        error_type = "connection_timeout",
        retry_attempts = 3,
        "Database connection failed"
    );
}

#[tokio::test]
async fn test_performance_logging() {
    let _ = smith_logging::init_console_logging("debug");

    // Simulate performance logging
    let start = std::time::Instant::now();

    // Simulate some work
    sleep(Duration::from_millis(10)).await;

    let duration = start.elapsed();

    info!(
        performance_category = "api_request",
        duration_ms = duration.as_millis() as u64,
        endpoint = "/api/users",
        status_code = 200,
        "API request completed"
    );
}

#[tokio::test]
async fn test_error_handling_logging() {
    let _ = smith_logging::init_console_logging("error");

    // Test error handling patterns
    let result: Result<(), &str> = Err("Simulated error");

    if let Err(e) = result {
        error!(
            error_message = e,
            error_source = "test_function",
            context = "integration_test",
            "Test error occurred"
        );
    }
}

// Note: Integration tests with actual NATS server would require
// a running NATS server. These tests focus on configuration
// and basic functionality that can be tested without external dependencies.
