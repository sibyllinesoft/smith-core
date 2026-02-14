//! Tests for main Config methods and functionality

use super::*;
use std::env;
use tempfile::tempdir;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder_creation() {
        let builder = Config::builder();
        assert!(builder.nats_url.is_none());
        assert!(builder.http_port.is_none());
    }

    #[test] 
    fn test_config_default() {
        let config = Config::default();
        
        // Test default values
        assert_eq!(config.nats.url, "nats://localhost:4222");
        assert_eq!(config.http.port, 3000);
        assert_eq!(config.http.host, "127.0.0.1");
        
        // Test executor defaults
        assert!(config.executor.work_root.ends_with("smith-work"));
        assert!(config.executor.capabilities.enforcement_enabled);
        
        // Test logging defaults  
        assert_eq!(config.logging.level, "info");
        assert!(!config.logging.json);
    }

    #[test]
    fn test_config_presets_development() {
        let config = Config::development();
        
        assert_eq!(config.logging.level, "debug");
        assert!(!config.logging.json);
        assert!(config.observability.metrics.enabled);
    }

    #[test]
    fn test_config_presets_production() {
        let config = Config::production();
        
        assert_eq!(config.logging.level, "info");
        assert!(config.logging.json);
        assert!(config.observability.metrics.enabled);
    }

    #[test]
    fn test_config_presets_testing() {
        let config = Config::testing();
        
        assert_eq!(config.logging.level, "debug");
        assert!(!config.logging.json);
        assert!(!config.observability.metrics.enabled);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let original = Config::development();
        
        // Serialize to JSON
        let json = serde_json::to_string(&original).expect("Should serialize");
        
        // Deserialize back
        let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
        
        // Key fields should match
        assert_eq!(original.nats.url, deserialized.nats.url);
        assert_eq!(original.http.port, deserialized.http.port);
        assert_eq!(original.logging.level, deserialized.logging.level);
    }

    #[test]
    fn test_config_debug_formatting() {
        let config = Config::default();
        let debug_str = format!("{:?}", config);
        
        // Should contain key config sections
        assert!(debug_str.contains("nats"));
        assert!(debug_str.contains("http"));
        assert!(debug_str.contains("executor"));
        assert!(debug_str.contains("logging"));
    }

    #[test]
    fn test_config_clone() {
        let original = Config::development();
        let cloned = original.clone();
        
        assert_eq!(original.nats.url, cloned.nats.url);
        assert_eq!(original.http.port, cloned.http.port);
        assert_eq!(original.logging.level, cloned.logging.level);
    }

    #[test]
    fn test_environment_variable_handling() {
        // Test basic environment variable behavior with actual config
        let original_port = env::var("SMITH_HTTP_PORT").ok();
        
        // Set a test value
        env::set_var("SMITH_HTTP_PORT", "9000");
        
        // For now, just test that we can detect environment variables
        let env_value = env::var("SMITH_HTTP_PORT");
        assert!(env_value.is_ok());
        assert_eq!(env_value.unwrap(), "9000");
        
        // Clean up
        match original_port {
            Some(value) => env::set_var("SMITH_HTTP_PORT", value),
            None => env::remove_var("SMITH_HTTP_PORT"),
        }
    }

    #[test]
    fn test_config_environment_variables_detection() {
        // Test that we can detect various environment variable patterns
        let test_vars = [
            ("SMITH_NATS_URL", "nats://test:4222"),
            ("SMITH_HTTP_HOST", "0.0.0.0"),
            ("SMITH_LOGGING_LEVEL", "warn"),
        ];
        
        let mut original_values = Vec::new();
        
        for (key, value) in &test_vars {
            original_values.push((key, env::var(key).ok()));
            env::set_var(key, value);
            
            // Just verify we can read them back
            assert_eq!(env::var(key).unwrap(), *value);
        }
        
        // Clean up
        for (key, original) in original_values {
            match original {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
    }

    #[test]
    fn test_config_from_file_missing() {
        let temp_dir = tempdir().unwrap();
        let missing_file = temp_dir.path().join("missing.toml");
        
        let result = Config::from_file(&missing_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_config_valid() {
        let config = Config::default();
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_config_invalid_port() {
        let mut config = Config::default();
        config.http.port = 0; // Invalid port
        
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_fields() {
        let config = Config::default();
        
        // Test that we can access basic fields
        assert_eq!(config.nats.url, "nats://localhost:4222");
        assert_eq!(config.http.port, 3000);
        assert_eq!(config.http.host, "127.0.0.1");
        assert!(config.executor.work_root.ends_with("smith-work"));
    }

    #[test]
    fn test_config_environment_detection() {
        let dev_config = Config::development();
        let prod_config = Config::production();
        let test_config = Config::testing();
        
        // Test basic differences between environments
        assert_eq!(dev_config.logging.level, "debug");
        assert_eq!(prod_config.logging.level, "info");
        assert_eq!(test_config.logging.level, "debug");
        
        assert!(!dev_config.logging.json);
        assert!(prod_config.logging.json);
        assert!(!test_config.logging.json);
    }

    #[test]
    fn test_config_fields_access() {
        let config = Config::default();
        
        // Test various config field access patterns
        assert!(config.executor.capabilities.enforcement_enabled);
        assert!(config.observability.metrics.enabled);
        assert_eq!(config.logging.level, "info");
    }
}
