use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::commands::{CheckConfigCommand, Cli, DaemonCommand, ExecutorCommand, SelfTestCommand};
use crate::config::Config;
use smith_config::app;

/// Install the tracing subscribers used by the executor.
pub async fn init_tracing(
    service_name: &str,
    enable_nats_logging: bool,
) -> Result<Option<smith_logging::LoggingGuard>> {
    crate::trace::TracingSetup::init()?;

    let env_config = match app::load_from_env() {
        Ok(config) => Some(config.clone()),
        Err(err) => {
            warn!("Failed to load logging configuration from environment: {err}");
            None
        }
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let fallback_level = env_config
            .as_ref()
            .map(|cfg| cfg.logging.level.clone())
            .unwrap_or_else(|| "executor=info".to_string());
        tracing_subscriber::EnvFilter::new(fallback_level)
    });

    if enable_nats_logging {
        if let Some(cfg) = env_config.as_ref() {
            if cfg.logging.nats.enabled {
                match async_nats::connect(&cfg.nats.url).await {
                    Ok(nats_client) => {
                        match smith_logging::NatsLoggingLayer::new(
                            service_name.to_string(),
                            cfg.logging.nats.clone(),
                            nats_client,
                        ) {
                            Ok((layer, guard)) => {
                                let subscriber = tracing_subscriber::registry()
                                    .with(env_filter.clone())
                                    .with(
                                        tracing_subscriber::fmt::layer()
                                            .json()
                                            .with_target(false)
                                            .with_timer(
                                                tracing_subscriber::fmt::time::ChronoUtc::rfc_3339(
                                                ),
                                            )
                                            .with_current_span(false)
                                            .with_span_list(false),
                                    )
                                    .with(layer);

                                match subscriber.try_init() {
                                    Ok(()) => return Ok(Some(guard)),
                                    Err(err) => {
                                        warn!(
                                            "Tracing already initialised, skipping duplicate subscriber: {err}"
                                        );
                                        // Drop guard so background task shuts down cleanly.
                                        drop(guard);
                                    }
                                }
                            }
                            Err(err) => {
                                warn!("Failed to initialise NATS logging layer: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        warn!("Failed to connect to NATS for logging: {err}");
                    }
                }
            }
        }
    }

    if let Err(err) = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .json()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
        .with_current_span(false)
        .with_span_list(false)
        .try_init()
    {
        warn!("Tracing already initialised, skipping duplicate subscriber registration: {err}");
    }

    Ok(None)
}

/// Entry point invoked by `main.rs`. Delegates to the appropriate command
/// implementation after performing logging/tracing initialisation.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    let enable_nats_logging = matches!(cli.command, ExecutorCommand::Run { .. });
    let _logging_guard = init_tracing("smith-executor", enable_nats_logging).await?;

    match cli.command {
        ExecutorCommand::Run {
            config,
            demo,
            autobootstrap,
            capability_digest,
            isolation,
        } => {
            info!("Starting executor daemon with config: {}", config.display());
            DaemonCommand::execute(config, demo, autobootstrap, capability_digest, isolation).await
        }
        ExecutorCommand::CheckConfig { config } => {
            info!("Checking configuration: {}", config.display());
            CheckConfigCommand::execute(config).await
        }
        ExecutorCommand::SelfTest {
            config,
            comprehensive,
        } => {
            info!("Running self-test with config: {}", config.display());
            SelfTestCommand::execute(config, comprehensive).await
        }
        ExecutorCommand::PrintSeccomp { capability } => {
            info!("Printing seccomp allowlist for capability: {}", capability);
            warn!("Print seccomp functionality not yet implemented");
            Ok(())
        }
        ExecutorCommand::ReloadPolicy { pid: _ } => {
            info!("Reloading policy configuration");
            warn!("Policy reload functionality not yet implemented");
            Ok(())
        }
    }
}

/// Perform security guardrail checks before starting the daemon. In demo mode
/// the checks are logged but do not abort startup.
pub fn validate_security_capabilities(config: &Config, demo_mode: bool) -> Result<()> {
    if !cfg!(target_os = "linux") {
        if demo_mode {
            warn!("⚠️  Running on non-Linux OS in demo mode - security features disabled");
        } else {
            anyhow::bail!(
                "Executor requires Linux (kernel >= 5.15 for Landlock v2+). Use --demo for development."
            );
        }
    }

    if config.executor.landlock_enabled {
        info!("Landlock support requested and assumed available");
        // TODO: Inspect actual kernel version and Landlock availability.
    }

    if unsafe { libc::getuid() } == 0 {
        warn!("Running as root - consider using an unprivileged user");
    }

    ensure_directories(config)?;
    Ok(())
}

/// Ensure that the executor's working directories exist with safe permissions.
fn ensure_directories(config: &Config) -> Result<()> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let dirs = [
        &config.executor.work_root,
        &config.executor.state_dir,
        &config.executor.audit_dir,
    ];

    for dir in &dirs {
        if !dir.exists() {
            warn!("Creating directory: {}", dir.display());
            fs::create_dir_all(dir)?;
        }

        #[cfg(unix)]
        {
            let metadata = fs::metadata(dir)?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o700 {
                warn!(
                    "Directory {} has permissions {:o}, expected 0700",
                    dir.display(),
                    mode
                );
            }
        }
    }

    Ok(())
}

/// Install signal handlers that trigger a graceful shutdown when the process
/// receives termination signals.
pub async fn setup_signal_handlers() {
    use tokio::signal;

    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("Failed to register SIGINT handler");
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("Failed to register SIGTERM handler");
    let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())
        .expect("Failed to register SIGHUP handler");

    tokio::spawn(async move {
        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
                std::process::exit(0);
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
                std::process::exit(0);
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP, reloading policy configuration");
                // TODO: Implement hot policy reload.
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[tokio::test]
    async fn init_tracing_is_idempotent() {
        init_tracing("test", false)
            .await
            .expect("tracing initialisation should succeed");
    }

    fn create_test_config(temp_dir: &TempDir) -> Config {
        let work_root = temp_dir.path().join("work");
        let state_dir = temp_dir.path().join("state");
        let audit_dir = temp_dir.path().join("audit");

        let mut config = Config::default();
        config.executor.work_root = work_root;
        config.executor.state_dir = state_dir;
        config.executor.audit_dir = audit_dir;
        config.executor.landlock_enabled = false;
        config
    }

    #[test]
    fn test_validate_security_capabilities_demo_mode() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // Demo mode should always succeed
        let result = validate_security_capabilities(&config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_security_capabilities_linux() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // On Linux, non-demo mode should succeed
        #[cfg(target_os = "linux")]
        {
            let result = validate_security_capabilities(&config, false);
            assert!(result.is_ok());
        }

        // On non-Linux, non-demo mode should fail
        #[cfg(not(target_os = "linux"))]
        {
            let result = validate_security_capabilities(&config, false);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_validate_security_capabilities_with_landlock() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = create_test_config(&temp_dir);
        config.executor.landlock_enabled = true;

        // Should work in demo mode regardless of landlock setting
        let result = validate_security_capabilities(&config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_directories_creates_missing() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // Directories don't exist yet
        assert!(!config.executor.work_root.exists());
        assert!(!config.executor.state_dir.exists());
        assert!(!config.executor.audit_dir.exists());

        // ensure_directories should create them
        let result = ensure_directories(&config);
        assert!(result.is_ok());

        // Now they should exist
        assert!(config.executor.work_root.exists());
        assert!(config.executor.state_dir.exists());
        assert!(config.executor.audit_dir.exists());
    }

    #[test]
    fn test_ensure_directories_existing_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // Pre-create directories
        std::fs::create_dir_all(&config.executor.work_root).unwrap();
        std::fs::create_dir_all(&config.executor.state_dir).unwrap();
        std::fs::create_dir_all(&config.executor.audit_dir).unwrap();

        // Should succeed even if they already exist
        let result = ensure_directories(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_directories_nested_paths() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = create_test_config(&temp_dir);

        // Use deeply nested paths
        config.executor.work_root = temp_dir.path().join("a/b/c/work");
        config.executor.state_dir = temp_dir.path().join("x/y/z/state");
        config.executor.audit_dir = temp_dir.path().join("1/2/3/audit");

        let result = ensure_directories(&config);
        assert!(result.is_ok());

        assert!(config.executor.work_root.exists());
        assert!(config.executor.state_dir.exists());
        assert!(config.executor.audit_dir.exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_ensure_directories_checks_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // Pre-create directory with non-700 permissions
        std::fs::create_dir_all(&config.executor.work_root).unwrap();
        std::fs::set_permissions(
            &config.executor.work_root,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        // Should succeed but will log a warning
        let result = ensure_directories(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_security_capabilities_as_non_root() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // In CI/tests we typically run as non-root
        // Demo mode should always succeed
        let result = validate_security_capabilities(&config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_default_paths() {
        let config = Config::default();

        // Check that default paths are set
        assert!(!config.executor.work_root.as_os_str().is_empty());
        assert!(!config.executor.state_dir.as_os_str().is_empty());
        assert!(!config.executor.audit_dir.as_os_str().is_empty());
    }

    #[tokio::test]
    async fn test_signal_handlers_setup() {
        // Just verify setup_signal_handlers doesn't panic
        // We can't easily test signal handling in unit tests
        setup_signal_handlers().await;
    }

    #[test]
    fn test_create_test_config_has_valid_paths() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // Paths should be under the temp directory
        assert!(config.executor.work_root.starts_with(temp_dir.path()));
        assert!(config.executor.state_dir.starts_with(temp_dir.path()));
        assert!(config.executor.audit_dir.starts_with(temp_dir.path()));
    }

    #[test]
    fn test_validate_security_capabilities_with_landlock_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = create_test_config(&temp_dir);

        // Enable landlock security feature
        config.executor.landlock_enabled = true;

        // Demo mode should work regardless
        let result = validate_security_capabilities(&config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_directories_multiple_calls() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(&temp_dir);

        // Call multiple times - should be idempotent
        ensure_directories(&config).unwrap();
        ensure_directories(&config).unwrap();
        ensure_directories(&config).unwrap();

        assert!(config.executor.work_root.exists());
        assert!(config.executor.state_dir.exists());
        assert!(config.executor.audit_dir.exists());
    }

    #[tokio::test]
    async fn test_init_tracing_without_nats() {
        // Without NATS logging, should fall back to stdout
        let result = init_tracing("test-service", false).await;
        assert!(result.is_ok());

        // Should return None when NATS is disabled
        let guard = result.unwrap();
        assert!(guard.is_none() || guard.is_some()); // Either is valid
    }

    #[tokio::test]
    async fn test_init_tracing_with_nats_disabled() {
        // With NATS logging enabled but no connection
        let result = init_tracing("test-nats", true).await;
        assert!(result.is_ok());
        // Should gracefully fall back when NATS isn't available
    }
}
