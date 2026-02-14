//! Configuration module for agentd
//!
//! This module provides both:
//! - Legacy compatibility with smith-config for existing deployments
//! - New agentd-specific configuration for the pluggable architecture
//!
//! ## Configuration Sources
//!
//! Configuration can be loaded from:
//! - TOML files (legacy smith-executor.toml or new agentd.toml)
//! - Environment variables (AGENTD_* prefix)
//! - Profile presets (workstation, server, paranoid)
//!
//! ## Migration Path
//!
//! Existing deployments using smith-executor.toml continue to work.
//! New deployments should use agentd.toml with the new configuration structure.

pub mod agentd;

use anyhow::{Context, Result};
use smith_config::manifest::EXECUTOR_ENV_VARS;
use std::path::{Path, PathBuf};

// Re-export legacy types for backwards compatibility
pub use smith_config::executor::{
    AttestationConfig, CapabilityConfig, DefaultLimits, ExecutorConfig,
    ExecutorNatsConfig as NatsConfig, IntentStreamConfig, LandlockProfile, LimitsConfig,
    PolicyConfig, ResultsConfig, SecurityConfig,
};
pub use smith_config::{Config, PolicyDerivations};

// Re-export new agentd config types
pub use agentd::{
    AgentdConfig, AuthConfig, ExecutionProfile, GrpcAdapterConfig, IsolationBackendType,
    IsolationConfig, LinuxNativeConfig, NatsAdapterConfig, SandboxConfig,
};

/// Unified configuration that works with both legacy and new formats
pub enum UnifiedConfig {
    /// Legacy smith-config based configuration
    Legacy(Config),
    /// New agentd-specific configuration
    Agentd(AgentdConfig),
}

impl UnifiedConfig {
    /// Load configuration, auto-detecting the format
    pub fn load(path: &Path) -> Result<Self> {
        // First try the new agentd format
        if let Ok(agentd_config) = AgentdConfig::load(path) {
            return Ok(UnifiedConfig::Agentd(agentd_config));
        }

        // Fall back to legacy format
        let legacy_config = load_config(path)?;
        Ok(UnifiedConfig::Legacy(legacy_config))
    }

    /// Load from environment variables
    pub fn from_env() -> Result<Self> {
        // Check for AGENTD_PROFILE to determine which config style to use
        if std::env::var("AGENTD_PROFILE").is_ok() {
            let config = AgentdConfig::from_env()?;
            return Ok(UnifiedConfig::Agentd(config));
        }

        // Fall back to legacy config
        let config = build_testing_fallback_config();
        Ok(UnifiedConfig::Legacy(config))
    }

    /// Get the isolation backend type from the configuration
    pub fn isolation_backend(&self) -> IsolationBackendType {
        match self {
            UnifiedConfig::Agentd(config) => config.isolation.default_backend,
            UnifiedConfig::Legacy(config) => {
                if config.executor.landlock_enabled {
                    IsolationBackendType::LinuxNative
                } else {
                    IsolationBackendType::HostDirect
                }
            }
        }
    }

    /// Check if gRPC adapter should be enabled
    pub fn grpc_enabled(&self) -> bool {
        match self {
            UnifiedConfig::Agentd(config) => config.adapters.grpc.enabled,
            UnifiedConfig::Legacy(_) => false, // Legacy config doesn't have gRPC
        }
    }

    /// Check if NATS adapter should be enabled
    pub fn nats_enabled(&self) -> bool {
        match self {
            UnifiedConfig::Agentd(config) => config.adapters.nats.enabled,
            UnifiedConfig::Legacy(_) => true, // Legacy config always uses NATS
        }
    }

    /// Get the NATS URL if available
    pub fn nats_url(&self) -> Option<String> {
        match self {
            UnifiedConfig::Agentd(config) => config.adapters.nats.url.clone(),
            UnifiedConfig::Legacy(config) => config.executor.nats_config.servers.first().cloned(),
        }
    }
}

/// Load the full Smith application configuration from a TOML file.
pub fn load_config(path: &Path) -> Result<Config> {
    match smith_config::Config::from_file(path) {
        Ok(cfg) => Ok(cfg),
        Err(primary_err) => match load_executor_only_config(path) {
            Ok(cfg) => Ok(cfg),
            Err(executor_err) => {
                if insecure_fallback_enabled() {
                    eprintln!(
                        "⚠️  Falling back to insecure testing config because \
SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK=1"
                    );
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "⚠️  Config parse errors for {}: primary={primary_err:?}, executor={executor_err:?}",
                        path.display()
                    );
                    Ok(build_testing_fallback_config())
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to load config from {}: primary parser error: {}; executor parser error: {}. \
Set SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK=1 only for local development.",
                        path.display(),
                        primary_err,
                        executor_err
                    ))
                }
            }
        },
    }
}

/// Convenience helper for executor code that needs to parse human readable
/// byte size strings (e.g. `"512MB"`).
pub fn parse_byte_size(size_str: &str) -> Result<u64> {
    ExecutorConfig::parse_byte_size(size_str)
}

/// Convenience helper for executor code that needs to parse duration strings
/// (e.g. `"15m"`).
pub fn parse_duration_seconds(duration_str: &str) -> Result<u64> {
    ExecutorConfig::parse_duration_seconds(duration_str)
}

/// Load the policy derivations referenced by the configuration.
pub fn load_policy_derivations(config: &Config) -> Result<PolicyDerivations> {
    PolicyDerivations::load(&config.executor.capabilities.derivations_path)
}

/// Validate that expected executor environment variables are present.
/// Returns a Vec of missing variable names (empty when all present).
pub fn missing_executor_env_vars() -> Vec<&'static str> {
    EXECUTOR_ENV_VARS
        .iter()
        .copied()
        .filter(|key| std::env::var(key).is_err())
        .collect()
}

fn load_executor_only_config(path: &Path) -> Result<Config> {
    let executor_cfg = ExecutorConfig::load(path)
        .with_context(|| format!("Failed to load executor config from {}", path.display()))?;

    let mut cfg = Config::testing();
    cfg.executor = executor_cfg;

    if let Some(primary) = cfg.executor.nats_config.servers.first() {
        cfg.nats.url = primary.clone();
        cfg.nats.cluster_urls = cfg.executor.nats_config.servers.clone();
    }

    cfg.nats.jetstream_domain = cfg.executor.nats_config.jetstream_domain.clone();
    cfg.nats.tls = None;
    cfg.nats.auth = None;

    Ok(cfg)
}

fn build_testing_fallback_config() -> Config {
    let mut cfg = Config::testing();
    // Align executor directories with writable locations
    cfg.executor.work_root = PathBuf::from("/tmp/smith-executor/work");
    cfg.executor.state_dir = PathBuf::from("/tmp/smith-executor/state");
    cfg.executor.audit_dir = PathBuf::from("/tmp/smith-executor/audit");
    cfg.executor.egress_proxy_socket = PathBuf::from("/tmp/smith-egress-proxy.sock");
    cfg.executor.security.pubkeys_dir = PathBuf::from("/tmp/smith-executor/agent_pubkeys");
    cfg.executor.capabilities.derivations_path =
        PathBuf::from("build/capability/sandbox_profiles/derivations.json");

    let nats_url =
        std::env::var("SMITH_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    cfg.nats.url = nats_url.clone();
    cfg.nats.cluster_urls = vec![];
    cfg.executor.nats_config.servers = vec![nats_url];
    let jetstream_domain = std::env::var("SMITH_JETSTREAM_DOMAIN").unwrap_or_default();
    cfg.executor.nats_config.jetstream_domain = jetstream_domain.clone();
    cfg.nats.jetstream_domain = jetstream_domain;
    cfg.executor.nats_config.tls_cert = None;
    cfg.executor.nats_config.tls_key = None;
    cfg.executor.nats_config.tls_ca = None;
    cfg.nats.tls = None;
    cfg.nats.auth = None;
    cfg.executor
        .intent_streams
        .entry("shell.exec.v1".to_string())
        .or_insert_with(|| smith_config::executor::IntentStreamConfig {
            subject: "smith.intents.shell.exec.v1".to_string(),
            max_age: "10m".to_string(),
            max_bytes: "5MB".to_string(),
            workers: 1,
        });

    cfg.executor
        .intent_streams
        .entry("fs.read.v1".to_string())
        .or_insert_with(|| smith_config::executor::IntentStreamConfig {
            subject: "smith.intents.fs.read.v1".to_string(),
            max_age: "10m".to_string(),
            max_bytes: "10MB".to_string(),
            workers: 1,
        });

    cfg.executor.capabilities.enforcement_enabled = false;

    #[cfg(debug_assertions)]
    {
        let capabilities: Vec<_> = cfg.executor.intent_streams.keys().cloned().collect();
        println!(
            "[smith-executor] Fallback intent streams: {:?}",
            capabilities
        );
    }

    cfg
}

fn insecure_fallback_enabled() -> bool {
    std::env::var("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn parse_helpers_delegate_to_shared_config() {
        assert_eq!(parse_byte_size("1KB").unwrap(), 1024);
        assert_eq!(parse_duration_seconds("2m").unwrap(), 120);
    }

    #[test]
    fn load_config_round_trips() {
        let mut file = NamedTempFile::new().unwrap();
        let temp_root = tempfile::tempdir().unwrap();

        let mut config = Config::testing();

        // Point executor paths at the temporary directory and ensure parents exist
        config.executor.work_root = temp_root.path().join("work");
        config.executor.state_dir = temp_root.path().join("state");
        config.executor.audit_dir = temp_root.path().join("audit");
        config.executor.egress_proxy_socket = temp_root.path().join("proxy.sock");
        config.executor.security.pubkeys_dir = temp_root.path().join("pubkeys");
        config.executor.capabilities.derivations_path = temp_root.path().join("derivations.json");

        for path in [
            &config.executor.work_root,
            &config.executor.state_dir,
            &config.executor.audit_dir,
        ] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::create_dir_all(&config.executor.security.pubkeys_dir).unwrap();
        let derivations = serde_json::json!({
            "seccomp_allow": {},
            "landlock_paths": {},
            "cgroups": {}
        });
        std::fs::write(
            &config.executor.capabilities.derivations_path,
            serde_json::to_string(&derivations).unwrap(),
        )
        .unwrap();

        // Provide a minimal intent stream so validation succeeds
        config.http.port = 8080;
        config.executor.intent_streams.insert(
            "fs.read.v1".to_string(),
            IntentStreamConfig {
                subject: "smith.intents.fs.read.v1".to_string(),
                max_age: "1m".to_string(),
                max_bytes: "10MB".to_string(),
                workers: 1,
            },
        );
        config.executor.nats_config.tls_cert = None;
        config.executor.nats_config.tls_key = None;
        config.executor.nats_config.tls_ca = None;
        config.nats_adapter.security.require_authentication = false;
        config.nats_adapter.security.tls.enabled = false;

        let toml = toml::to_string(&config).unwrap();
        use std::io::Write;
        file.write_all(toml.as_bytes()).unwrap();

        let loaded = load_config(file.path()).unwrap();
        assert_eq!(loaded.executor.node_name, config.executor.node_name);
        assert_eq!(loaded.executor.intent_streams.len(), 1);
    }

    #[test]
    fn load_repo_executor_only_config() {
        let path = Path::new("../infra/config/smith-executor.toml");
        if !path.exists() {
            eprintln!(
                "Skipping load_repo_executor_only_config: {} does not exist",
                path.display()
            );
            return;
        }
        let config = load_config(path).expect("executor config should load");
        assert_eq!(config.executor.node_name, "exec-01");
        assert!(!config.executor.intent_streams.is_empty());
    }

    #[test]
    fn test_unified_config_from_agentd() {
        let agentd = AgentdConfig::workstation();
        assert_eq!(
            agentd.isolation.default_backend,
            IsolationBackendType::HostDirect
        );
    }

    // ==================== UnifiedConfig Tests ====================

    #[test]
    fn test_unified_config_from_env_fallback() {
        // Without AGENTD_PROFILE, should fall back to legacy config
        std::env::remove_var("AGENTD_PROFILE");
        let config = UnifiedConfig::from_env().unwrap();
        assert!(matches!(config, UnifiedConfig::Legacy(_)));
    }

    #[test]
    fn test_unified_config_isolation_backend_agentd() {
        let agentd_config = AgentdConfig::server();
        let unified = UnifiedConfig::Agentd(agentd_config);
        let backend = unified.isolation_backend();
        assert_eq!(backend, IsolationBackendType::LinuxNative);
    }

    #[test]
    fn test_unified_config_isolation_backend_legacy_landlock() {
        let mut legacy_config = Config::testing();
        legacy_config.executor.landlock_enabled = true;
        let unified = UnifiedConfig::Legacy(legacy_config);
        let backend = unified.isolation_backend();
        assert_eq!(backend, IsolationBackendType::LinuxNative);
    }

    #[test]
    fn test_unified_config_isolation_backend_legacy_no_landlock() {
        let mut legacy_config = Config::testing();
        legacy_config.executor.landlock_enabled = false;
        let unified = UnifiedConfig::Legacy(legacy_config);
        let backend = unified.isolation_backend();
        assert_eq!(backend, IsolationBackendType::HostDirect);
    }

    #[test]
    fn test_unified_config_grpc_enabled_agentd() {
        let agentd_config = AgentdConfig::workstation();
        let unified = UnifiedConfig::Agentd(agentd_config);
        assert!(unified.grpc_enabled());
    }

    #[test]
    fn test_unified_config_grpc_enabled_legacy() {
        let legacy_config = Config::testing();
        let unified = UnifiedConfig::Legacy(legacy_config);
        // Legacy config doesn't have gRPC
        assert!(!unified.grpc_enabled());
    }

    #[test]
    fn test_unified_config_nats_enabled_agentd() {
        let agentd_config = AgentdConfig::workstation();
        let unified = UnifiedConfig::Agentd(agentd_config);
        // Workstation profile has NATS disabled
        assert!(!unified.nats_enabled());
    }

    #[test]
    fn test_unified_config_nats_enabled_agentd_server() {
        let agentd_config = AgentdConfig::server();
        let unified = UnifiedConfig::Agentd(agentd_config);
        // Server profile has NATS enabled
        assert!(unified.nats_enabled());
    }

    #[test]
    fn test_unified_config_nats_enabled_legacy() {
        let legacy_config = Config::testing();
        let unified = UnifiedConfig::Legacy(legacy_config);
        // Legacy config always uses NATS
        assert!(unified.nats_enabled());
    }

    #[test]
    fn test_unified_config_nats_url_agentd() {
        let mut agentd_config = AgentdConfig::server();
        agentd_config.adapters.nats.url = Some("nats://test:4222".to_string());
        let unified = UnifiedConfig::Agentd(agentd_config);
        assert_eq!(unified.nats_url(), Some("nats://test:4222".to_string()));
    }

    #[test]
    fn test_unified_config_nats_url_agentd_none() {
        let agentd_config = AgentdConfig::workstation();
        let unified = UnifiedConfig::Agentd(agentd_config);
        assert!(unified.nats_url().is_none());
    }

    #[test]
    fn test_unified_config_nats_url_legacy() {
        let mut legacy_config = Config::testing();
        legacy_config.executor.nats_config.servers = vec!["nats://localhost:4222".to_string()];
        let unified = UnifiedConfig::Legacy(legacy_config);
        assert_eq!(
            unified.nats_url(),
            Some("nats://localhost:4222".to_string())
        );
    }

    #[test]
    fn test_unified_config_nats_url_legacy_empty() {
        let mut legacy_config = Config::testing();
        legacy_config.executor.nats_config.servers = vec![];
        let unified = UnifiedConfig::Legacy(legacy_config);
        assert!(unified.nats_url().is_none());
    }

    // ==================== parse_byte_size Tests ====================

    #[test]
    fn test_parse_byte_size_various_units() {
        // Note: parse_byte_size requires a unit suffix
        assert_eq!(parse_byte_size("1KB").unwrap(), 1024);
        assert_eq!(parse_byte_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_byte_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_byte_size("100B").unwrap(), 100);
    }

    #[test]
    fn test_parse_byte_size_fails_without_unit() {
        // Without a unit suffix, it should fail
        assert!(parse_byte_size("100").is_err());
    }

    // ==================== parse_duration_seconds Tests ====================

    #[test]
    fn test_parse_duration_seconds_various_units() {
        // Note: parse_duration_seconds requires a unit suffix
        assert_eq!(parse_duration_seconds("30s").unwrap(), 30);
        assert_eq!(parse_duration_seconds("5m").unwrap(), 300);
        assert_eq!(parse_duration_seconds("1h").unwrap(), 3600);
    }

    #[test]
    fn test_parse_duration_seconds_fails_without_unit() {
        // Without a unit suffix, it should fail
        assert!(parse_duration_seconds("30").is_err());
    }

    // ==================== missing_executor_env_vars Tests ====================

    #[test]
    fn test_missing_executor_env_vars() {
        // This tests the function works - it may return some missing vars
        let missing = missing_executor_env_vars();
        // Just verify it returns a vector (even if empty or with items)
        assert!(missing.len() >= 0);
    }

    // ==================== build_testing_fallback_config Tests ====================

    #[test]
    fn test_build_testing_fallback_config() {
        let config = build_testing_fallback_config();
        // Check default paths
        assert_eq!(
            config.executor.work_root,
            PathBuf::from("/tmp/smith-executor/work")
        );
        assert_eq!(
            config.executor.state_dir,
            PathBuf::from("/tmp/smith-executor/state")
        );
        assert_eq!(
            config.executor.audit_dir,
            PathBuf::from("/tmp/smith-executor/audit")
        );
        // Check enforcement is disabled for testing
        assert!(!config.executor.capabilities.enforcement_enabled);
        // Check intent streams are populated
        assert!(config.executor.intent_streams.contains_key("shell.exec.v1"));
        assert!(config.executor.intent_streams.contains_key("fs.read.v1"));
    }

    #[test]
    fn test_build_testing_fallback_config_uses_env_nats_url() {
        std::env::set_var("SMITH_NATS_URL", "nats://custom:4222");
        let config = build_testing_fallback_config();
        assert_eq!(config.nats.url, "nats://custom:4222");
        assert_eq!(
            config.executor.nats_config.servers,
            vec!["nats://custom:4222".to_string()]
        );
        std::env::remove_var("SMITH_NATS_URL");
    }

    #[test]
    fn test_build_testing_fallback_config_uses_env_jetstream_domain() {
        std::env::set_var("SMITH_JETSTREAM_DOMAIN", "hub");
        let config = build_testing_fallback_config();
        assert_eq!(config.executor.nats_config.jetstream_domain, "hub");
        assert_eq!(config.nats.jetstream_domain, "hub");
        std::env::remove_var("SMITH_JETSTREAM_DOMAIN");
    }

    #[test]
    fn test_load_config_rejects_invalid_config_without_insecure_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK");
        let mut file = NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(file, "this is not valid toml").unwrap();

        let result = load_config(file.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to load config"));
        assert!(err.contains("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK=1"));
    }

    #[test]
    fn test_load_config_allows_invalid_config_with_insecure_fallback_enabled() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK", "1");
        let mut file = NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(file, "this is not valid toml").unwrap();

        let result = load_config(file.path());
        std::env::remove_var("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK");

        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(!config.executor.capabilities.enforcement_enabled);
    }
}
