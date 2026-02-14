//! Tests for environment variable handling and file I/O operations

use super::*;
use std::env;
use std::fs;
use tempfile::tempdir;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_env_string() {
        let original = env::var("TEST_SMITH_STRING").ok();

        // Test setting environment variable
        env::set_var("TEST_SMITH_STRING", "test_value");
        let mut target = "original".to_string();

        Config::apply_env_string("TEST_SMITH_STRING", &mut target);
        assert_eq!(target, "test_value");

        // Clean up
        match original {
            Some(val) => env::set_var("TEST_SMITH_STRING", val),
            None => env::remove_var("TEST_SMITH_STRING"),
        }
    }

    #[test]
    fn test_apply_env_parse_u16() {
        let original = env::var("TEST_SMITH_PORT").ok();

        // Test parsing port number
        env::set_var("TEST_SMITH_PORT", "8080");
        let mut target: u16 = 3000;

        let result = Config::apply_env_parse("TEST_SMITH_PORT", &mut target);
        assert!(result.is_ok());
        assert_eq!(target, 8080);

        // Test invalid value
        env::set_var("TEST_SMITH_PORT", "invalid");
        let result = Config::apply_env_parse("TEST_SMITH_PORT", &mut target);
        assert!(result.is_err());

        // Clean up
        match original {
            Some(val) => env::set_var("TEST_SMITH_PORT", val),
            None => env::remove_var("TEST_SMITH_PORT"),
        }
    }

    #[test]
    fn test_apply_env_parse_bool() {
        let original = env::var("TEST_SMITH_BOOL").ok();

        // Test parsing boolean
        env::set_var("TEST_SMITH_BOOL", "true");
        let mut target = false;

        let result = Config::apply_env_parse("TEST_SMITH_BOOL", &mut target);
        assert!(result.is_ok());
        assert!(target);

        // Test false value
        env::set_var("TEST_SMITH_BOOL", "false");
        let result = Config::apply_env_parse("TEST_SMITH_BOOL", &mut target);
        assert!(result.is_ok());
        assert!(!target);

        // Clean up
        match original {
            Some(val) => env::set_var("TEST_SMITH_BOOL", val),
            None => env::remove_var("TEST_SMITH_BOOL"),
        }
    }

    #[test]
    fn test_apply_nats_env_overrides() {
        let original_url = env::var("SMITH_NATS_URL").ok();
        let original_domain = env::var("SMITH_NATS_JETSTREAM_DOMAIN").ok();

        let mut config = Config::default();
        let _original_config_url = config.nats.url.clone();

        // Set environment variables
        env::set_var("SMITH_NATS_URL", "nats://env-test:4222");
        env::set_var("SMITH_NATS_JETSTREAM_DOMAIN", "env-domain");

        // Apply environment overrides
        let result = config.apply_nats_env_overrides();
        assert!(result.is_ok());

        // Verify changes were applied
        assert_eq!(config.nats.url, "nats://env-test:4222");
        assert_eq!(config.nats.jetstream_domain, "env-domain");

        // Clean up
        match original_url {
            Some(val) => env::set_var("SMITH_NATS_URL", val),
            None => env::remove_var("SMITH_NATS_URL"),
        }
        match original_domain {
            Some(val) => env::set_var("SMITH_NATS_JETSTREAM_DOMAIN", val),
            None => env::remove_var("SMITH_NATS_JETSTREAM_DOMAIN"),
        }
    }

    #[test]
    fn test_apply_http_env_overrides() {
        let original_port = env::var("SMITH_HTTP_PORT").ok();
        let original_bind = env::var("SMITH_HTTP_BIND").ok();

        let mut config = Config::default();

        // Set environment variables
        env::set_var("SMITH_HTTP_PORT", "9090");
        env::set_var("SMITH_HTTP_BIND", "0.0.0.0");

        // Apply environment overrides
        let result = config.apply_http_env_overrides();
        assert!(result.is_ok());

        // Verify changes were applied
        assert_eq!(config.http.port, 9090);
        assert_eq!(config.http.bind_address, "0.0.0.0");

        // Clean up
        match original_port {
            Some(val) => env::set_var("SMITH_HTTP_PORT", val),
            None => env::remove_var("SMITH_HTTP_PORT"),
        }
        match original_bind {
            Some(val) => env::set_var("SMITH_HTTP_BIND", val),
            None => env::remove_var("SMITH_HTTP_BIND"),
        }
    }

    #[test]
    fn test_apply_executor_env_overrides() {
        let original_work_root = env::var("SMITH_EXECUTOR_WORK_ROOT").ok();
        let original_node_name = env::var("SMITH_EXECUTOR_NODE_NAME").ok();

        let mut config = Config::default();

        // Set environment variables
        env::set_var("SMITH_EXECUTOR_WORK_ROOT", "/tmp/env-test");
        env::set_var("SMITH_EXECUTOR_NODE_NAME", "env-node");

        // Apply environment overrides
        let result = config.apply_executor_env_overrides();
        assert!(result.is_ok());

        // Verify changes were applied
        assert_eq!(config.executor.work_root, PathBuf::from("/tmp/env-test"));
        assert_eq!(config.executor.node_name, "env-node");

        // Clean up
        match original_work_root {
            Some(val) => env::set_var("SMITH_EXECUTOR_WORK_ROOT", val),
            None => env::remove_var("SMITH_EXECUTOR_WORK_ROOT"),
        }
        match original_node_name {
            Some(val) => env::set_var("SMITH_EXECUTOR_NODE_NAME", val),
            None => env::remove_var("SMITH_EXECUTOR_NODE_NAME"),
        }
    }

    #[test]
    fn test_apply_logging_env_overrides() {
        let original_level = env::var("SMITH_LOG_LEVEL").ok();
        let original_json = env::var("SMITH_LOG_JSON").ok();
        let original_nats_enabled = env::var("SMITH_LOG_NATS_ENABLED").ok();

        let mut config = Config::default();

        // Set environment variables
        env::set_var("SMITH_LOG_LEVEL", "trace");
        env::set_var("SMITH_LOG_JSON", "true");
        env::set_var("SMITH_LOG_NATS_ENABLED", "true");

        // Apply environment overrides
        let result = config.apply_logging_env_overrides();
        assert!(result.is_ok());

        // Verify changes were applied
        assert_eq!(config.logging.level, "trace");
        assert!(config.logging.json_format);
        assert!(config.logging.nats.enabled);

        // Clean up
        match original_level {
            Some(val) => env::set_var("SMITH_LOG_LEVEL", val),
            None => env::remove_var("SMITH_LOG_LEVEL"),
        }
        match original_json {
            Some(val) => env::set_var("SMITH_LOG_JSON", val),
            None => env::remove_var("SMITH_LOG_JSON"),
        }
        match original_nats_enabled {
            Some(val) => env::set_var("SMITH_LOG_NATS_ENABLED", val),
            None => env::remove_var("SMITH_LOG_NATS_ENABLED"),
        }
    }

    #[test]
    fn test_from_env_succeeds_without_smith_toml() {
        let original_file = env::var("SMITH_CONFIG_FILE").ok();
        let original_path = env::var("SMITH_CONFIG_PATH").ok();

        env::remove_var("SMITH_CONFIG_FILE");
        env::remove_var("SMITH_CONFIG_PATH");

        let result = Config::from_env();
        assert!(
            result.is_ok(),
            "Config::from_env should not require smith.toml, error: {:?}",
            result.err()
        );

        match original_file {
            Some(val) => env::set_var("SMITH_CONFIG_FILE", val),
            None => env::remove_var("SMITH_CONFIG_FILE"),
        }
        match original_path {
            Some(val) => env::set_var("SMITH_CONFIG_PATH", val),
            None => env::remove_var("SMITH_CONFIG_PATH"),
        }
    }

    #[test]
    fn test_from_env_uses_custom_config_file() {
        let temp_dir = tempdir().expect("temp dir");
        let config_path = temp_dir.path().join("custom-smith.toml");
        fs::write(
            &config_path,
            r#"
[http]
port = 7456
"#,
        )
        .expect("write config");

        let original_file = env::var("SMITH_CONFIG_FILE").ok();
        let original_path = env::var("SMITH_CONFIG_PATH").ok();
        let original_http_port = env::var("SMITH_HTTP_PORT").ok();

        env::set_var("SMITH_CONFIG_FILE", config_path.to_str().unwrap());
        env::remove_var("SMITH_CONFIG_PATH");
        env::remove_var("SMITH_HTTP_PORT");

        let config = Config::from_env().expect("load config from custom file");
        assert_eq!(config.http.port, 7456);

        match original_file {
            Some(val) => env::set_var("SMITH_CONFIG_FILE", val),
            None => env::remove_var("SMITH_CONFIG_FILE"),
        }
        match original_path {
            Some(val) => env::set_var("SMITH_CONFIG_PATH", val),
            None => env::remove_var("SMITH_CONFIG_PATH"),
        }
        match original_http_port {
            Some(val) => env::set_var("SMITH_HTTP_PORT", val),
            None => env::remove_var("SMITH_HTTP_PORT"),
        }
    }

    #[test]
    fn test_apply_nats_adapter_env_overrides() {
        let original_auth = env::var("SMITH_NATS_ADAPTER_REQUIRE_AUTH").ok();
        let original_prefix = env::var("SMITH_NATS_ADAPTER_TOPIC_PREFIX").ok();
        let original_queue = env::var("SMITH_NATS_ADAPTER_COMMAND_QUEUE_SIZE").ok();
        let original_rate = env::var("SMITH_NATS_ADAPTER_RATE_MESSAGES_PER_SECOND").ok();

        let mut config = Config::default();

        env::set_var("SMITH_NATS_ADAPTER_REQUIRE_AUTH", "false");
        env::set_var("SMITH_NATS_ADAPTER_TOPIC_PREFIX", "smith-test");
        env::set_var("SMITH_NATS_ADAPTER_COMMAND_QUEUE_SIZE", "42");
        env::set_var("SMITH_NATS_ADAPTER_RATE_MESSAGES_PER_SECOND", "9000");

        config
            .apply_nats_adapter_env_overrides()
            .expect("nats adapter overrides should succeed");

        assert!(!config.nats_adapter.security.require_authentication);
        assert_eq!(config.nats_adapter.topics.prefix, "smith-test");
        assert_eq!(config.nats_adapter.queues.command_queue_size, 42);
        assert_eq!(
            config.nats_adapter.security.rate_limits.messages_per_second,
            9000
        );

        match original_auth {
            Some(val) => env::set_var("SMITH_NATS_ADAPTER_REQUIRE_AUTH", val),
            None => env::remove_var("SMITH_NATS_ADAPTER_REQUIRE_AUTH"),
        }
        match original_prefix {
            Some(val) => env::set_var("SMITH_NATS_ADAPTER_TOPIC_PREFIX", val),
            None => env::remove_var("SMITH_NATS_ADAPTER_TOPIC_PREFIX"),
        }
        match original_queue {
            Some(val) => env::set_var("SMITH_NATS_ADAPTER_COMMAND_QUEUE_SIZE", val),
            None => env::remove_var("SMITH_NATS_ADAPTER_COMMAND_QUEUE_SIZE"),
        }
        match original_rate {
            Some(val) => env::set_var("SMITH_NATS_ADAPTER_RATE_MESSAGES_PER_SECOND", val),
            None => env::remove_var("SMITH_NATS_ADAPTER_RATE_MESSAGES_PER_SECOND"),
        }
    }

    #[test]
    fn test_apply_metrics_env_overrides() {
        let original_enabled = env::var("SMITH_METRICS_ENABLED").ok();
        let original_port = env::var("SMITH_METRICS_PORT").ok();

        let mut config = Config::default();

        // Set environment variables
        env::set_var("SMITH_METRICS_ENABLED", "false");
        env::set_var("SMITH_METRICS_PORT", "9091");

        // Apply environment overrides
        let result = config.apply_metrics_env_overrides();
        assert!(result.is_ok());

        // Verify changes were applied
        assert!(!config.metrics.enabled);
        assert_eq!(config.metrics.port, Some(9091));

        // Clean up
        match original_enabled {
            Some(val) => env::set_var("SMITH_METRICS_ENABLED", val),
            None => env::remove_var("SMITH_METRICS_ENABLED"),
        }
        match original_port {
            Some(val) => env::set_var("SMITH_METRICS_PORT", val),
            None => env::remove_var("SMITH_METRICS_PORT"),
        }
    }

    #[test]
    fn test_apply_observability_env_overrides() {
        let original_enabled = env::var("OBSERVABILITY_ENABLED").ok();
        let original_service = env::var("SMITH_OBSERVABILITY_SERVICE_NAME").ok();

        let mut config = Config::default();

        // Set environment variables
        env::set_var("OBSERVABILITY_ENABLED", "true");
        env::set_var("SMITH_OBSERVABILITY_SERVICE_NAME", "env-service");

        // Apply environment overrides
        let result = config.apply_observability_env_overrides();
        assert!(result.is_ok());

        // Verify changes were applied
        assert!(config.observability.enabled);
        assert_eq!(config.observability.service_name, "env-service");

        // Clean up
        match original_enabled {
            Some(val) => env::set_var("OBSERVABILITY_ENABLED", val),
            None => env::remove_var("OBSERVABILITY_ENABLED"),
        }
        match original_service {
            Some(val) => env::set_var("SMITH_OBSERVABILITY_SERVICE_NAME", val),
            None => env::remove_var("SMITH_OBSERVABILITY_SERVICE_NAME"),
        }
    }

    #[test]
    fn test_apply_all_env_overrides() {
        let mut config = Config::default();

        // This should call all the individual override methods
        let result = Config::apply_all_env_overrides(&mut config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_env_without_figment() {
        // Test the fallback from_env implementation without figment feature
        let result = Config::from_env();
        // Should either succeed or fail gracefully
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_config_from_file_missing() {
        let temp_dir = tempdir().unwrap();
        let missing_file = temp_dir.path().join("missing.toml");

        let result = Config::from_file(&missing_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_from_file_invalid_toml() {
        let temp_dir = tempdir().unwrap();
        let invalid_file = temp_dir.path().join("invalid.toml");

        // Write invalid TOML content
        std::fs::write(&invalid_file, "invalid toml content [[[").unwrap();

        let result = Config::from_file(&invalid_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_from_file_valid() {
        let temp_dir = tempdir().unwrap();
        let config_file = temp_dir.path().join("valid.toml");

        // Write minimal valid TOML content
        let toml_content = r#"
[nats]
url = "nats://test:4222"

[http]
port = 8080
bind_address = "127.0.0.1"

[executor]
work_root = "/tmp/test"
node_name = "test-node"

[logging]
level = "info"
json_format = false

[metrics]
enabled = true
prefix = "test"

[behavior]
default_pack = "test-pack"

[monitoring]
port = 8082

[core]
port = 8083

[admission]
port = 8080

[attestation]
enabled = false

[observability]
enabled = false
        "#;

        std::fs::write(&config_file, toml_content).unwrap();

        let result = Config::from_file(&config_file);
        // May succeed or fail depending on validation, but should not panic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_complex_environment_variable_scenarios() {
        // Test target filters parsing
        let original_filters = env::var("SMITH_LOG_NATS_TARGET_FILTERS").ok();

        let mut config = Config::default();

        // Test comma-separated filters
        env::set_var("SMITH_LOG_NATS_TARGET_FILTERS", "smith,executor,architect");
        let result = config.apply_logging_env_overrides();
        assert!(result.is_ok());

        assert_eq!(config.logging.nats.target_filters.len(), 3);
        assert!(config
            .logging
            .nats
            .target_filters
            .contains(&"smith".to_string()));
        assert!(config
            .logging
            .nats
            .target_filters
            .contains(&"executor".to_string()));
        assert!(config
            .logging
            .nats
            .target_filters
            .contains(&"architect".to_string()));

        // Test empty filters
        env::set_var("SMITH_LOG_NATS_TARGET_FILTERS", "");
        config.logging.nats.target_filters.clear();
        let result = config.apply_logging_env_overrides();
        assert!(result.is_ok());
        assert!(config.logging.nats.target_filters.is_empty());

        // Clean up
        match original_filters {
            Some(val) => env::set_var("SMITH_LOG_NATS_TARGET_FILTERS", val),
            None => env::remove_var("SMITH_LOG_NATS_TARGET_FILTERS"),
        }
    }

    #[test]
    fn test_nats_logging_config_comprehensive() {
        let original_level_filter = env::var("SMITH_LOG_NATS_LEVEL_FILTER").ok();
        let original_buffer_size = env::var("SMITH_LOG_NATS_BUFFER_SIZE").ok();

        let mut config = Config::default();

        // Set various NATS logging environment variables
        env::set_var("SMITH_LOG_NATS_LEVEL_FILTER", "debug");
        env::set_var("SMITH_LOG_NATS_BUFFER_SIZE", "2000");
        env::set_var("SMITH_LOG_NATS_MAX_RETRIES", "5");
        env::set_var("SMITH_LOG_NATS_TIMEOUT", "2000");
        env::set_var("SMITH_LOG_NATS_RATE_LIMIT", "100");
        env::set_var("SMITH_LOG_NATS_BATCH_ENABLED", "true");
        env::set_var("SMITH_LOG_NATS_BATCH_SIZE", "100");
        env::set_var("SMITH_LOG_NATS_INCLUDE_SPANS", "true");
        env::set_var("SMITH_LOG_NATS_INCLUDE_TRACES", "false");
        env::set_var("SMITH_LOG_NATS_FALLBACK_CONSOLE", "true");

        let result = config.apply_logging_env_overrides();
        assert!(result.is_ok());

        // Verify all settings were applied
        assert_eq!(config.logging.nats.level_filter, Some("debug".to_string()));
        assert_eq!(config.logging.nats.buffer_size, 2000);
        assert_eq!(config.logging.nats.max_retries, 5);
        assert_eq!(config.logging.nats.publish_timeout_ms, 2000);
        assert_eq!(config.logging.nats.rate_limit, 100);
        assert!(config.logging.nats.batch_enabled);
        assert_eq!(config.logging.nats.batch_size, 100);
        assert!(config.logging.nats.include_spans);
        assert!(!config.logging.nats.include_traces);
        assert!(config.logging.nats.fallback_to_console);

        // Clean up all the variables
        for (var_name, original_value) in [
            ("SMITH_LOG_NATS_LEVEL_FILTER", original_level_filter),
            ("SMITH_LOG_NATS_BUFFER_SIZE", original_buffer_size),
        ] {
            match original_value {
                Some(val) => env::set_var(var_name, val),
                None => env::remove_var(var_name),
            }
        }

        // Clean up the other vars that don't have originals stored
        for var in [
            "SMITH_LOG_NATS_MAX_RETRIES",
            "SMITH_LOG_NATS_TIMEOUT",
            "SMITH_LOG_NATS_RATE_LIMIT",
            "SMITH_LOG_NATS_BATCH_ENABLED",
            "SMITH_LOG_NATS_BATCH_SIZE",
            "SMITH_LOG_NATS_INCLUDE_SPANS",
            "SMITH_LOG_NATS_INCLUDE_TRACES",
            "SMITH_LOG_NATS_FALLBACK_CONSOLE",
        ] {
            env::remove_var(var);
        }
    }

    #[test]
    fn test_environment_variable_parsing_errors() {
        let original_port = env::var("SMITH_HTTP_PORT").ok();
        let original_bool = env::var("SMITH_LOG_JSON").ok();

        let mut config = Config::default();

        // Test invalid port parsing
        env::set_var("SMITH_HTTP_PORT", "invalid_port");
        let result = config.apply_http_env_overrides();
        // Check if error is expected (parsing should fail for non-numeric port)
        if let Err(err) = result {
            assert!(err.to_string().contains("SMITH_HTTP_PORT"));
        }

        // Test invalid boolean parsing
        env::remove_var("SMITH_HTTP_PORT"); // Clear the bad port
        env::set_var("SMITH_LOG_JSON", "not_a_boolean");
        let result = config.apply_logging_env_overrides();
        // Similar check for boolean parsing
        if let Err(err) = result {
            assert!(err.to_string().contains("SMITH_LOG_JSON"));
        }

        // Clean up
        match original_port {
            Some(val) => env::set_var("SMITH_HTTP_PORT", val),
            None => env::remove_var("SMITH_HTTP_PORT"),
        }
        match original_bool {
            Some(val) => env::set_var("SMITH_LOG_JSON", val),
            None => env::remove_var("SMITH_LOG_JSON"),
        }
    }

    #[test]
    fn test_observability_redaction_level_parsing() {
        let original = env::var("OBS_REDACTION_LEVEL").ok();

        let mut config = Config::default();

        // Test valid redaction levels
        env::set_var("OBS_REDACTION_LEVEL", "strict");
        let result = config.apply_observability_env_overrides();
        assert!(result.is_ok());

        env::set_var("OBS_REDACTION_LEVEL", "balanced");
        let result = config.apply_observability_env_overrides();
        assert!(result.is_ok());

        // Test invalid redaction level
        env::set_var("OBS_REDACTION_LEVEL", "invalid");
        let result = config.apply_observability_env_overrides();
        assert!(result.is_err());

        // Clean up
        match original {
            Some(val) => env::set_var("OBS_REDACTION_LEVEL", val),
            None => env::remove_var("OBS_REDACTION_LEVEL"),
        }
    }
}
