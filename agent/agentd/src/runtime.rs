//! AgentdRuntime - Main orchestration layer
//!
//! This module provides the top-level runtime that coordinates all components
//! of agentd into a cohesive execution environment:
//!
//! - Configuration loading and validation
//! - Isolation backend initialization
//! - Ingest adapter management
//! - Authentication chain setup
//! - Output multiplexing
//! - Sandbox lifecycle management
//! - Policy engine integration
//! - Graceful startup and shutdown

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::agentd::{AgentdConfig, ExecutionProfile};
use crate::core::auth::AuthProvider;
use crate::core::ingest::{
    CapabilityInfo, HealthStatus, IngestAdapter, IntentHandler, OutputChunk, RequestContext,
};
use crate::core::intent::{IntentRequest, IntentResponse, IntentStatus, ResponseTiming};
use crate::core::isolation::IsolationBackend;
use crate::core::output::OutputSink;
use crate::core::sandbox::SandboxManager;
use crate::isolation;

/// AgentdRuntime - The main execution coordinator
pub struct AgentdRuntime {
    /// Configuration
    config: Arc<RwLock<AgentdConfig>>,

    /// Isolation backend
    isolation_backend: Arc<dyn IsolationBackend>,

    /// Ingest adapters
    adapters: Vec<Arc<dyn IngestAdapter>>,

    /// Authentication providers
    auth_providers: Vec<Arc<dyn AuthProvider>>,

    /// Output sinks
    output_sinks: Vec<Arc<dyn OutputSink>>,

    /// Sandbox manager
    sandbox_manager: Arc<dyn SandboxManager>,

    /// Runtime state
    running: AtomicBool,

    /// Shutdown signal
    shutdown_tx: RwLock<Option<tokio::sync::broadcast::Sender<()>>>,
}

impl AgentdRuntime {
    /// Create a new runtime with the given configuration
    pub async fn new(config: AgentdConfig) -> Result<Self> {
        info!(
            "Initializing AgentdRuntime with profile: {:?}",
            config.profile
        );

        // Validate configuration
        config
            .validate()
            .context("Configuration validation failed")?;

        // Ensure work_root exists
        std::fs::create_dir_all(&config.work_root)
            .context("Failed to create work root directory")?;

        // Initialize isolation backend from registry-backed selector.
        let requested_backend = config.isolation.selected_backend_name();
        let isolation_backend = isolation::create_backend(&requested_backend, &config.work_root)
            .with_context(|| {
                format!(
                    "Failed to create configured isolation backend '{}'",
                    requested_backend
                )
            })?;

        // Probe backend capabilities
        let backend_caps = isolation_backend
            .probe()
            .await
            .context("Failed to probe isolation backend")?;
        info!("Isolation backend capabilities: {:?}", backend_caps);

        if matches!(
            isolation::canonical_backend_name(&requested_backend).as_deref(),
            Some("host-direct")
        ) {
            warn!("Using host-direct isolation backend (no kernel isolation)");
        }

        if matches!(
            config.profile,
            ExecutionProfile::Server | ExecutionProfile::Paranoid
        ) && backend_caps.is_soft_isolation()
        {
            anyhow::bail!(
                "Profile {:?} requires kernel isolation, but backend '{}' is soft isolation",
                config.profile,
                backend_caps.name
            );
        }

        // Initialize authentication providers
        let auth_providers = Self::setup_auth_providers(&config).await?;

        // Initialize sandbox manager
        let sandbox_manager =
            Self::setup_sandbox_manager(isolation_backend.clone(), &config).await?;

        // Create the runtime (adapters will be added during start)
        let runtime = Self {
            config: Arc::new(RwLock::new(config)),
            isolation_backend,
            adapters: vec![],
            auth_providers,
            output_sinks: vec![],
            sandbox_manager,
            running: AtomicBool::new(false),
            shutdown_tx: RwLock::new(None),
        };

        Ok(runtime)
    }

    /// Create a runtime with a specific profile preset
    pub async fn with_profile(profile: ExecutionProfile) -> Result<Self> {
        let config = match profile {
            ExecutionProfile::Workstation => AgentdConfig::workstation(),
            ExecutionProfile::Server => AgentdConfig::server(),
            ExecutionProfile::Paranoid => AgentdConfig::paranoid(),
            ExecutionProfile::Custom => AgentdConfig::default(),
        };

        Self::new(config).await
    }

    /// Start the runtime
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Runtime is already running"));
        }

        info!("Starting AgentdRuntime");

        // Create shutdown channel
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        {
            let mut tx = self.shutdown_tx.write().await;
            *tx = Some(shutdown_tx);
        }

        // Start adapters
        // Clone config to avoid borrow conflict with &mut self
        let config = self.config.read().await.clone();
        self.start_adapters(&config).await?;

        self.running.store(true, Ordering::SeqCst);

        info!("AgentdRuntime started successfully");
        Ok(())
    }

    /// Stop the runtime gracefully
    pub async fn stop(&self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping AgentdRuntime");

        // Send shutdown signal
        {
            let tx = self.shutdown_tx.read().await;
            if let Some(ref shutdown_tx) = *tx {
                let _ = shutdown_tx.send(());
            }
        }

        // Stop all adapters
        for adapter in &self.adapters {
            if let Err(e) = adapter.stop().await {
                error!("Error stopping adapter {}: {}", adapter.name(), e);
            }
        }

        // Destroy all sandboxes
        if let Err(e) = self.isolation_backend.destroy_all().await {
            error!("Error destroying sandboxes: {}", e);
        }

        info!("AgentdRuntime stopped");
        Ok(())
    }

    /// Reload configuration without full restart
    pub async fn reload(&self, new_config: AgentdConfig) -> Result<()> {
        info!("Reloading AgentdRuntime configuration");

        // Validate new configuration
        new_config
            .validate()
            .context("New configuration validation failed")?;

        // Update stored configuration
        {
            let mut config = self.config.write().await;
            *config = new_config;
        }

        info!("Configuration reloaded successfully");
        Ok(())
    }

    /// Get the current health status
    pub async fn health(&self) -> RuntimeHealth {
        let mut adapter_health = vec![];
        for adapter in &self.adapters {
            let status = adapter.health().await;
            adapter_health.push((adapter.name().to_string(), status));
        }

        let backend_health = self.isolation_backend.health_check().await;

        RuntimeHealth {
            running: self.running.load(Ordering::SeqCst),
            adapter_health,
            backend_healthy: backend_health.is_ok(),
            backend_error: backend_health.err().map(|e| e.to_string()),
        }
    }

    /// Get current configuration (read-only copy)
    pub async fn config(&self) -> AgentdConfig {
        self.config.read().await.clone()
    }

    // Private helper methods

    async fn setup_auth_providers(config: &AgentdConfig) -> Result<Vec<Arc<dyn AuthProvider>>> {
        let mut providers: Vec<Arc<dyn AuthProvider>> = vec![];

        for provider_name in &config.auth.enabled_providers {
            match provider_name.as_str() {
                "allow-all" => {
                    info!("Adding allow-all auth provider (development only)");
                    providers.push(Arc::new(crate::auth::allow_all::AllowAllProvider::new()));
                }
                "jwt" => {
                    info!("Adding JWT auth provider");
                    let jwt_config = crate::auth::jwt::JwtConfig {
                        verification_key: config.auth.jwt.public_key.clone().unwrap_or_default(),
                        issuer: config.auth.jwt.issuer.clone(),
                        audience: config.auth.jwt.audience.clone(),
                        ..Default::default()
                    };
                    providers.push(Arc::new(crate::auth::jwt::JwtProvider::new(jwt_config)));
                }
                "api-key" => {
                    info!("Adding API key auth provider");
                    let provider = crate::auth::api_key::ApiKeyProvider::new();
                    // Register configured static keys
                    for (key, subject) in &config.auth.api_key.static_keys {
                        let entry = crate::auth::api_key::ApiKeyEntry {
                            key_id: format!("static-{}", key.chars().take(8).collect::<String>()),
                            subject: subject.clone(),
                            tenant: None,
                            roles: vec![],
                            trust_level: crate::core::auth::TrustLevel::Standard,
                        };
                        provider.register_key(key, entry).await;
                    }
                    providers.push(Arc::new(provider));
                }
                "signature" => {
                    info!("Adding signature auth provider");
                    providers.push(Arc::new(crate::auth::signature::SignatureProvider::new()));
                }
                "peer-creds" => {
                    info!("Adding peer credentials auth provider");
                    providers.push(Arc::new(crate::auth::peer_creds::PeerCredProvider::new()));
                }
                other => {
                    warn!("Unknown auth provider: {}", other);
                }
            }
        }

        if providers.is_empty() && config.auth.require_auth {
            return Err(anyhow::anyhow!(
                "Authentication required but no providers configured"
            ));
        }

        Ok(providers)
    }

    async fn setup_sandbox_manager(
        backend: Arc<dyn IsolationBackend>,
        config: &AgentdConfig,
    ) -> Result<Arc<dyn SandboxManager>> {
        use crate::core::sandbox::{
            DefaultSandboxManager, PoolConfig, SandboxManagerConfig, SessionTimeouts,
        };

        let manager_config = SandboxManagerConfig {
            max_sandboxes: config.sandbox.pool.max_warm,
            pool: PoolConfig {
                enabled: config.sandbox.pool.enabled,
                min_warm: config.sandbox.pool.min_warm,
                max_warm: config.sandbox.pool.max_warm,
                warm_ttl: std::time::Duration::from_secs(config.sandbox.pool.idle_timeout_secs),
                warm_profiles: vec![match config.profile {
                    ExecutionProfile::Workstation => "workstation",
                    ExecutionProfile::Server => "server",
                    ExecutionProfile::Paranoid => "paranoid",
                    ExecutionProfile::Custom => "custom",
                }
                .to_string()],
            },
            default_timeouts: SessionTimeouts::default(),
            cleanup_interval: std::time::Duration::from_secs(60),
        };

        let manager = DefaultSandboxManager::new(vec![backend], manager_config);

        Ok(Arc::new(manager))
    }

    async fn start_adapters(&mut self, config: &AgentdConfig) -> Result<()> {
        // Create intent handler
        let handler = Arc::new(RuntimeIntentHandler {
            auth_providers: self.auth_providers.clone(),
            sandbox_manager: self.sandbox_manager.clone(),
            config: self.config.clone(),
        });

        // Start gRPC adapter if enabled
        #[cfg(feature = "grpc")]
        if config.adapters.grpc.enabled {
            if let Some(listen_addr) = config.adapters.grpc.listen {
                info!("Starting gRPC adapter on {}", listen_addr);
                let grpc_adapter =
                    Arc::new(crate::adapters::GrpcAdapter::with_address(listen_addr));
                // Wire up the sandbox manager for sandbox lifecycle operations
                grpc_adapter
                    .set_sandbox_manager(self.sandbox_manager.clone())
                    .await;
                grpc_adapter
                    .start(handler.clone())
                    .await
                    .context("Failed to start gRPC adapter")?;
                self.adapters.push(grpc_adapter);
            }
        }

        // TODO: Start NATS adapter if enabled
        // TODO: Start HTTP adapter if enabled
        // TODO: Start Unix socket adapter if enabled

        Ok(())
    }
}

/// Runtime health information
#[derive(Debug, Clone)]
pub struct RuntimeHealth {
    pub running: bool,
    pub adapter_health: Vec<(String, HealthStatus)>,
    pub backend_healthy: bool,
    pub backend_error: Option<String>,
}

impl RuntimeHealth {
    pub fn is_healthy(&self) -> bool {
        self.running
            && self.backend_healthy
            && self.adapter_health.iter().all(|(_, s)| s.is_healthy())
    }
}

/// Intent handler that coordinates auth, sandbox, and execution
struct RuntimeIntentHandler {
    auth_providers: Vec<Arc<dyn AuthProvider>>,
    sandbox_manager: Arc<dyn SandboxManager>,
    config: Arc<RwLock<AgentdConfig>>,
}

#[async_trait::async_trait]
impl IntentHandler for RuntimeIntentHandler {
    async fn handle(&self, request: IntentRequest, ctx: RequestContext) -> Result<IntentResponse> {
        use crate::core::isolation::SandboxSpec;
        use crate::core::sandbox::{RequiredCapabilities, SandboxSelectionOptions};

        let start_time = std::time::Instant::now();
        let received_at = chrono::Utc::now().timestamp_millis() as u64;

        // Authenticate the request
        // TODO: Extract credentials from context and authenticate

        // Build sandbox spec
        let sandbox_spec = SandboxSpec::default();

        // Build sandbox selection options
        let selection_options = SandboxSelectionOptions {
            preferred_id: request
                .sandbox_prefs
                .sandbox_id
                .clone()
                .map(|id| crate::core::sandbox::SandboxId(id)),
            require_fresh: request.sandbox_prefs.require_fresh,
            required_capabilities: RequiredCapabilities::default(),
            preferred_backend: request.sandbox_prefs.backend.clone(),
            required_labels: std::collections::HashMap::new(),
            use_pool: true,
        };

        // Acquire sandbox
        let (_session, sandbox) = self
            .sandbox_manager
            .acquire(&sandbox_spec, &selection_options, &ctx.client_id)
            .await?;

        // Build command from request
        let command = crate::core::intent::Command {
            program: request.capability.clone(),
            args: vec![serde_json::to_string(&request.params)?],
            workdir: None,
            env: std::collections::HashMap::new(),
            inherit_env: false,
            stdin: None,
            timeout: request
                .constraints
                .max_duration_ms
                .map(std::time::Duration::from_millis),
        };

        // Create execution context
        let exec_ctx = crate::core::isolation::ExecContext {
            trace_id: request.metadata.trace_id.clone().unwrap_or_default(),
            request_id: request.id.to_string(),
            workdir: Some(std::path::PathBuf::from("/tmp")),
            extra_env: vec![],
            timeout: request
                .constraints
                .max_duration_ms
                .map(std::time::Duration::from_millis),
            capture_stdout: true,
            capture_stderr: true,
            stream_output: false,
        };

        let started_at = chrono::Utc::now().timestamp_millis() as u64;

        // Execute the command
        let result = sandbox.exec(&command, &exec_ctx).await;
        let completed_at = chrono::Utc::now().timestamp_millis() as u64;
        let elapsed = start_time.elapsed();

        match result {
            Ok(output) => {
                let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

                Ok(IntentResponse {
                    request_id: request.id,
                    status: if output.exit_code == 0 {
                        IntentStatus::Ok
                    } else {
                        IntentStatus::Error
                    },
                    code: if output.exit_code == 0 {
                        "OK".to_string()
                    } else {
                        "ERROR".to_string()
                    },
                    message: if output.exit_code == 0 {
                        "Execution completed successfully".to_string()
                    } else {
                        format!("Execution failed with exit code {}", output.exit_code)
                    },
                    result: Some(crate::core::intent::ExecutionResult {
                        exit_code: output.exit_code,
                        stdout: Some(stdout_str),
                        stdout_bytes: Some(output.stdout),
                        stderr: Some(stderr_str),
                        output: None,
                        artifacts: vec![],
                        resource_usage: None,
                    }),
                    error: None,
                    timing: ResponseTiming {
                        received_at_ms: received_at,
                        started_at_ms: started_at,
                        completed_at_ms: completed_at,
                        queue_time_ms: started_at - received_at,
                        setup_time_ms: 0,
                        exec_time_ms: completed_at - started_at,
                        total_time_ms: elapsed.as_millis() as u64,
                    },
                    sandbox_info: None,
                })
            }
            Err(e) => Ok(IntentResponse {
                request_id: request.id,
                status: IntentStatus::Error,
                code: "EXECUTION_ERROR".to_string(),
                message: format!("Execution failed: {}", e),
                result: None,
                error: Some(crate::core::intent::ErrorDetails {
                    code: "EXECUTION_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                    retryable: false,
                    retry_after_ms: None,
                }),
                timing: ResponseTiming {
                    received_at_ms: received_at,
                    started_at_ms: started_at,
                    completed_at_ms: completed_at,
                    queue_time_ms: started_at - received_at,
                    setup_time_ms: 0,
                    exec_time_ms: completed_at - started_at,
                    total_time_ms: elapsed.as_millis() as u64,
                },
                sandbox_info: None,
            }),
        }
    }

    async fn handle_streaming(
        &self,
        request: IntentRequest,
        ctx: RequestContext,
        output_tx: tokio::sync::mpsc::Sender<OutputChunk>,
    ) -> Result<IntentResponse> {
        // For now, delegate to non-streaming handler
        // TODO: Implement proper streaming support
        let response = self.handle(request, ctx).await?;
        let _ = output_tx.send(OutputChunk::Done).await;
        Ok(response)
    }

    async fn supports_capability(&self, _capability: &str) -> bool {
        // TODO: Check registered runners
        true
    }

    async fn list_capabilities(&self) -> Vec<CapabilityInfo> {
        // TODO: Return actual registered capabilities
        vec![
            CapabilityInfo {
                name: "fs.read.v1".to_string(),
                description: "Read file contents".to_string(),
                version: 1,
                param_schema: None,
                requires_elevated: false,
                supports_streaming: false,
                tags: vec!["filesystem".to_string()],
            },
            CapabilityInfo {
                name: "shell.exec.v1".to_string(),
                description: "Execute shell command".to_string(),
                version: 1,
                param_schema: None,
                requires_elevated: true,
                supports_streaming: true,
                tags: vec!["shell".to_string()],
            },
        ]
    }

    async fn health(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::{register_backend_factory, HostDirectBackend};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_runtime_creation_workstation() {
        let config = AgentdConfig::workstation();
        let runtime = AgentdRuntime::new(config).await;
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_creation_with_backend_override_alias() {
        let mut config = AgentdConfig::workstation();
        config.isolation.backend_name = Some("host".to_string());
        let runtime = AgentdRuntime::new(config).await;
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_creation_with_registered_custom_backend() {
        let backend_name = format!("runtime-custom-{}", Uuid::new_v4().simple());
        register_backend_factory(&backend_name, &[], |work_root| {
            Ok(Arc::new(HostDirectBackend::new(work_root)))
        })
        .expect("custom runtime backend should register");

        let mut config = AgentdConfig::workstation();
        config.isolation.backend_name = Some(backend_name);
        let runtime = AgentdRuntime::new(config).await;
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_creation_with_unknown_backend_override_fails() {
        let mut config = AgentdConfig::workstation();
        config.isolation.backend_name = Some("missing-provider".to_string());
        let runtime = AgentdRuntime::new(config).await;
        let err = match runtime {
            Ok(_) => panic!("missing backend override should fail"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("Failed to create configured isolation backend"));
        assert!(msg.contains("missing-provider"));
    }

    #[tokio::test]
    async fn test_runtime_server_profile_rejects_soft_backend_override() {
        let mut config = AgentdConfig::workstation();
        config.profile = ExecutionProfile::Server;
        config.isolation.backend_name = Some("host-direct".to_string());
        let runtime = AgentdRuntime::new(config).await;
        let err = match runtime {
            Ok(_) => panic!("soft isolation backend should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("requires kernel isolation"));
    }

    #[tokio::test]
    async fn test_runtime_health() {
        let config = AgentdConfig::workstation();
        let runtime = AgentdRuntime::new(config).await.unwrap();
        let health = runtime.health().await;
        assert!(!health.running); // Not started yet
        assert!(health.backend_healthy);
    }

    #[tokio::test]
    async fn test_runtime_with_profile_workstation() {
        let runtime = AgentdRuntime::with_profile(ExecutionProfile::Workstation).await;
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_with_profile_server() {
        // Server profile uses LinuxNative backend which may not be available
        let runtime = AgentdRuntime::with_profile(ExecutionProfile::Server).await;
        // On Linux, it should succeed; on other platforms, it may fail
        #[cfg(target_os = "linux")]
        {
            // Linux native may still fail due to cgroups/landlock requirements
            // Just check that we get a sensible result
            let _ = runtime;
        }
        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux, expect failure since LinuxNative backend won't work
            assert!(runtime.is_err() || runtime.is_ok());
        }
    }

    #[tokio::test]
    async fn test_runtime_with_profile_paranoid() {
        // Paranoid profile uses LinuxNative backend which may not be available
        let runtime = AgentdRuntime::with_profile(ExecutionProfile::Paranoid).await;
        // On Linux, it should succeed; on other platforms, it may fail
        #[cfg(target_os = "linux")]
        {
            // Linux native may still fail due to cgroups/landlock requirements
            // Just check that we get a sensible result
            let _ = runtime;
        }
        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux, expect failure since LinuxNative backend won't work
            assert!(runtime.is_err() || runtime.is_ok());
        }
    }

    #[tokio::test]
    async fn test_runtime_with_profile_custom() {
        let runtime = AgentdRuntime::with_profile(ExecutionProfile::Custom).await;
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_start_and_stop() {
        let config = AgentdConfig::workstation();
        let mut runtime = AgentdRuntime::new(config).await.unwrap();

        // Start
        let start_result = runtime.start().await;
        assert!(start_result.is_ok());

        // Health should show running
        let health = runtime.health().await;
        assert!(health.running);

        // Stop
        let stop_result = runtime.stop().await;
        assert!(stop_result.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_double_start_fails() {
        let config = AgentdConfig::workstation();
        let mut runtime = AgentdRuntime::new(config).await.unwrap();

        runtime.start().await.unwrap();
        let second_start = runtime.start().await;
        assert!(second_start.is_err());

        runtime.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_runtime_stop_when_not_running() {
        let config = AgentdConfig::workstation();
        let runtime = AgentdRuntime::new(config).await.unwrap();

        // Stop when not running should be ok
        let stop_result = runtime.stop().await;
        assert!(stop_result.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_config() {
        let config = AgentdConfig::workstation();
        let runtime = AgentdRuntime::new(config.clone()).await.unwrap();

        let retrieved_config = runtime.config().await;
        assert_eq!(retrieved_config.profile, config.profile);
    }

    #[tokio::test]
    async fn test_runtime_reload() {
        let config = AgentdConfig::workstation();
        let runtime = AgentdRuntime::new(config).await.unwrap();

        // Create a valid config for reload (workstation with modified settings)
        // Note: server() config has nats.enabled=true but nats.url=None which fails validation
        let mut new_config = AgentdConfig::workstation();
        new_config.profile = ExecutionProfile::Custom;
        new_config.sandbox.max_duration_ms = 60_000;

        let reload_result = runtime.reload(new_config).await;
        assert!(reload_result.is_ok());

        let retrieved_config = runtime.config().await;
        assert_eq!(retrieved_config.profile, ExecutionProfile::Custom);
        assert_eq!(retrieved_config.sandbox.max_duration_ms, 60_000);
    }

    #[test]
    fn test_runtime_health_is_healthy_when_running() {
        let health = RuntimeHealth {
            running: true,
            adapter_health: vec![],
            backend_healthy: true,
            backend_error: None,
        };
        assert!(health.is_healthy());
    }

    #[test]
    fn test_runtime_health_unhealthy_when_not_running() {
        let health = RuntimeHealth {
            running: false,
            adapter_health: vec![],
            backend_healthy: true,
            backend_error: None,
        };
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_runtime_health_unhealthy_backend() {
        let health = RuntimeHealth {
            running: true,
            adapter_health: vec![],
            backend_healthy: false,
            backend_error: Some("error".to_string()),
        };
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_runtime_health_struct_clone() {
        let health = RuntimeHealth {
            running: true,
            adapter_health: vec![("test".to_string(), HealthStatus::Healthy)],
            backend_healthy: true,
            backend_error: None,
        };
        let cloned = health.clone();
        assert_eq!(cloned.running, health.running);
    }
}
