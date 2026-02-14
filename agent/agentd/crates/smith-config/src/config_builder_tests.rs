//! Tests for ConfigBuilder functionality

use super::*;
use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder_creation() {
        let builder = ConfigBuilder::new();
        assert!(builder.nats_url.is_none());
        assert!(builder.http_port.is_none());
        assert!(builder.executor_work_root.is_none());
        assert!(builder.log_level.is_none());
        assert!(builder.environment.is_none());
    }

    #[test]
    fn test_config_builder_default() {
        let builder = ConfigBuilder::default();
        assert!(builder.nats_url.is_none());
        assert!(builder.http_port.is_none());
        assert!(builder.executor_work_root.is_none());
        assert!(builder.log_level.is_none());
        assert!(builder.environment.is_none());
    }

    #[test]
    fn test_config_builder_nats_url() {
        let url = "nats://test.example.com:4222";
        let builder = ConfigBuilder::new().with_nats_url(url);
        assert_eq!(builder.nats_url, Some(url.to_string()));
    }

    #[test]
    fn test_config_builder_http_port() {
        let port = 8080;
        let builder = ConfigBuilder::new().with_http_port(port);
        assert_eq!(builder.http_port, Some(port));
    }

    #[test]
    fn test_config_builder_executor_work_root() {
        let path = PathBuf::from("/tmp/smith-work");
        let builder = ConfigBuilder::new().with_executor_work_root(path.clone());
        assert_eq!(builder.executor_work_root, Some(path));
    }

    #[test]
    fn test_config_builder_log_level() {
        let level = "debug";
        let builder = ConfigBuilder::new().with_log_level(level);
        assert_eq!(builder.log_level, Some(level.to_string()));
    }

    #[test]
    fn test_config_builder_environment_development() {
        let builder = ConfigBuilder::new().for_environment(ConfigEnvironment::Development);
        matches!(builder.environment, Some(ConfigEnvironment::Development));
    }

    #[test]
    fn test_config_builder_environment_production() {
        let builder = ConfigBuilder::new().for_environment(ConfigEnvironment::Production);
        matches!(builder.environment, Some(ConfigEnvironment::Production));
    }

    #[test]
    fn test_config_builder_environment_testing() {
        let builder = ConfigBuilder::new().for_environment(ConfigEnvironment::Testing);
        matches!(builder.environment, Some(ConfigEnvironment::Testing));
    }

    #[test]
    fn test_config_builder_method_chaining() {
        let builder = ConfigBuilder::new()
            .with_nats_url("nats://localhost:4222")
            .with_http_port(3000)
            .with_executor_work_root(PathBuf::from("/tmp/work"))
            .with_log_level("info")
            .for_environment(ConfigEnvironment::Development);

        assert_eq!(builder.nats_url, Some("nats://localhost:4222".to_string()));
        assert_eq!(builder.http_port, Some(3000));
        assert_eq!(builder.executor_work_root, Some(PathBuf::from("/tmp/work")));
        assert_eq!(builder.log_level, Some("info".to_string()));
        matches!(builder.environment, Some(ConfigEnvironment::Development));
    }

    #[test]
    fn test_config_builder_build() {
        let config = ConfigBuilder::new()
            .nats_url("nats://test:4222")
            .http_port(8080)
            .build();

        assert_eq!(config.nats.url, "nats://test:4222");
        assert_eq!(config.http.port, 8080);
    }

    #[test]
    fn test_config_builder_build_with_defaults() {
        let config = ConfigBuilder::new().build();
        
        // Should use default values
        assert_eq!(config.nats.url, "nats://localhost:4222");
        assert_eq!(config.http.port, 3000);
        assert_eq!(config.http.host, "127.0.0.1");
    }

    #[test]
    fn test_config_builder_partial_overrides() {
        let config = ConfigBuilder::new()
            .http_port(9090)
            .log_level("warn")
            .build();

        // Overridden values
        assert_eq!(config.http.port, 9090);
        
        // Default values should still be present
        assert_eq!(config.nats.url, "nats://localhost:4222");
        assert_eq!(config.http.host, "127.0.0.1");
    }

    #[test]
    fn test_config_environment_variants_debug() {
        let dev = ConfigEnvironment::Development;
        let prod = ConfigEnvironment::Production;
        let test = ConfigEnvironment::Testing;

        // Test that debug formatting works
        assert!(format!("{:?}", dev).contains("Development"));
        assert!(format!("{:?}", prod).contains("Production"));
        assert!(format!("{:?}", test).contains("Testing"));
    }

    #[test]
    fn test_config_environment_clone() {
        let original = ConfigEnvironment::Development;
        let cloned = original;
        
        // Both should be equivalent
        matches!(original, ConfigEnvironment::Development);
        matches!(cloned, ConfigEnvironment::Development);
    }

    #[test]
    fn test_config_environment_copy() {
        let env = ConfigEnvironment::Production;
        let copied = env;
        
        // Should be able to use both after copy
        matches!(env, ConfigEnvironment::Production);
        matches!(copied, ConfigEnvironment::Production);
    }
}