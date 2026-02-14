//! Agentd-specific configuration for the pluggable architecture
//!
//! This module provides configuration for:
//! - Profile-based presets (workstation, server, paranoid, custom)
//! - Isolation backend selection and configuration
//! - Ingest adapter configuration (gRPC, NATS, HTTP, etc.)
//! - Auth provider configuration
//! - Output sink configuration
//! - Sandbox pool configuration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Top-level agentd configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentdConfig {
    /// Execution profile preset
    #[serde(default)]
    pub profile: ExecutionProfile,

    /// Working root directory for sandboxes and temporary files
    #[serde(default = "default_work_root")]
    pub work_root: PathBuf,

    /// Isolation backend configuration
    #[serde(default)]
    pub isolation: IsolationConfig,

    /// Ingest adapters configuration
    #[serde(default)]
    pub adapters: AdaptersConfig,

    /// Authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// Output sink configuration
    #[serde(default)]
    pub output: OutputConfig,

    /// Sandbox pool configuration
    #[serde(default)]
    pub sandbox: SandboxConfig,

    /// Policy configuration
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Default for AgentdConfig {
    fn default() -> Self {
        Self {
            profile: ExecutionProfile::Workstation,
            work_root: default_work_root(),
            isolation: IsolationConfig::default(),
            adapters: AdaptersConfig::default(),
            auth: AuthConfig::default(),
            output: OutputConfig::default(),
            sandbox: SandboxConfig::default(),
            policy: PolicyConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

fn default_work_root() -> PathBuf {
    std::env::var("AGENTD_WORK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Use XDG_DATA_HOME or fallback
            if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
                PathBuf::from(xdg_data).join("agentd").join("work")
            } else if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home).join(".local/share/agentd/work")
            } else {
                PathBuf::from("/var/lib/agentd/work")
            }
        })
}

impl AgentdConfig {
    /// Load from TOML file
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: AgentdConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load from environment variables
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        // Profile from environment
        if let Ok(profile) = std::env::var("AGENTD_PROFILE") {
            config.profile = match profile.to_lowercase().as_str() {
                "workstation" => ExecutionProfile::Workstation,
                "server" => ExecutionProfile::Server,
                "paranoid" => ExecutionProfile::Paranoid,
                _ => ExecutionProfile::Custom,
            };
        }

        // gRPC listen address
        if let Ok(addr) = std::env::var("AGENTD_GRPC_LISTEN") {
            config.adapters.grpc.listen = Some(addr.parse()?);
        }

        // NATS URL
        if let Ok(url) = std::env::var("AGENTD_NATS_URL") {
            config.adapters.nats.url = Some(url);
        }

        // Isolation backend override (supports custom provider IDs)
        if let Ok(backend_name) = std::env::var("AGENTD_ISOLATION_BACKEND") {
            config.isolation.backend_name = Some(backend_name);
        }

        config.validate()?;
        Ok(config)
    }

    /// Create workstation profile configuration
    pub fn workstation() -> Self {
        Self {
            profile: ExecutionProfile::Workstation,
            work_root: default_work_root(),
            isolation: IsolationConfig {
                default_backend: IsolationBackendType::HostDirect,
                host_direct: HostDirectConfig::default(),
                ..Default::default()
            },
            adapters: AdaptersConfig {
                enabled: vec!["grpc".to_string()],
                grpc: GrpcAdapterConfig {
                    enabled: true,
                    listen: Some("127.0.0.1:9500".parse().unwrap()),
                    ..Default::default()
                },
                nats: NatsAdapterConfig {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            },
            auth: AuthConfig {
                enabled_providers: vec!["allow-all".to_string()],
                ..Default::default()
            },
            policy: PolicyConfig {
                bundle: "permissive".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create server profile configuration
    pub fn server() -> Self {
        Self {
            profile: ExecutionProfile::Server,
            work_root: default_work_root(),
            isolation: IsolationConfig {
                default_backend: IsolationBackendType::LinuxNative,
                linux_native: LinuxNativeConfig {
                    landlock_enabled: true,
                    seccomp_enabled: true,
                    cgroups_enabled: true,
                    namespaces_enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            adapters: AdaptersConfig {
                enabled: vec!["grpc".to_string(), "nats".to_string()],
                grpc: GrpcAdapterConfig {
                    enabled: true,
                    listen: Some("0.0.0.0:9500".parse().unwrap()),
                    ..Default::default()
                },
                nats: NatsAdapterConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            auth: AuthConfig {
                enabled_providers: vec!["mtls".to_string(), "jwt".to_string()],
                require_auth: true,
                ..Default::default()
            },
            policy: PolicyConfig {
                bundle: "strict".to_string(),
                ..Default::default()
            },
            sandbox: SandboxConfig {
                auto_create: true,
                pool: SandboxPoolConfig {
                    enabled: true,
                    min_warm: 2,
                    max_warm: 10,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create paranoid (maximum security) profile configuration
    pub fn paranoid() -> Self {
        Self {
            profile: ExecutionProfile::Paranoid,
            work_root: default_work_root(),
            isolation: IsolationConfig {
                default_backend: IsolationBackendType::LinuxNative,
                linux_native: LinuxNativeConfig {
                    landlock_enabled: true,
                    seccomp_enabled: true,
                    cgroups_enabled: true,
                    namespaces_enabled: true,
                    user_namespace: true,
                    network_namespace: true,
                    mount_namespace: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            adapters: AdaptersConfig {
                enabled: vec!["grpc".to_string()],
                grpc: GrpcAdapterConfig {
                    enabled: true,
                    listen: Some("127.0.0.1:9500".parse().unwrap()),
                    require_mtls: true,
                    ..Default::default()
                },
                nats: NatsAdapterConfig {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            },
            auth: AuthConfig {
                enabled_providers: vec!["mtls".to_string()],
                require_auth: true,
                ..Default::default()
            },
            policy: PolicyConfig {
                bundle: "paranoid".to_string(),
                ..Default::default()
            },
            sandbox: SandboxConfig {
                auto_create: true,
                fresh_sandbox_per_request: true,
                max_duration_ms: 30_000, // 30 seconds max
                pool: SandboxPoolConfig {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate adapters
        if self.adapters.enabled.is_empty() {
            anyhow::bail!("At least one adapter must be enabled");
        }

        for adapter in &self.adapters.enabled {
            match adapter.as_str() {
                "grpc" => {
                    if self.adapters.grpc.enabled && self.adapters.grpc.listen.is_none() {
                        anyhow::bail!("gRPC adapter enabled but no listen address configured");
                    }
                }
                "nats" => {
                    if self.adapters.nats.enabled && self.adapters.nats.url.is_none() {
                        anyhow::bail!("NATS adapter enabled but no URL configured");
                    }
                }
                "http" => {
                    if self.adapters.http.enabled && self.adapters.http.listen.is_none() {
                        anyhow::bail!("HTTP adapter enabled but no listen address configured");
                    }
                }
                _ => {}
            }
        }

        // Validate auth
        if self.auth.require_auth && self.auth.enabled_providers.is_empty() {
            anyhow::bail!("Auth required but no providers enabled");
        }

        // Validate sandbox pool
        if self.sandbox.pool.enabled {
            if self.sandbox.pool.max_warm < self.sandbox.pool.min_warm {
                anyhow::bail!("Sandbox pool max_warm must be >= min_warm");
            }
        }

        if let Some(name) = self.isolation.backend_name.as_deref() {
            if name.trim().is_empty() {
                anyhow::bail!("isolation.backend_name cannot be empty when set");
            }
        }

        Ok(())
    }
}

/// Execution profile presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionProfile {
    /// Workstation mode: Direct host execution with policy guards
    #[default]
    Workstation,
    /// Server mode: Full sandbox isolation for untrusted workloads
    Server,
    /// Paranoid mode: Maximum security isolation
    Paranoid,
    /// Custom mode: Mix and match settings
    Custom,
}

/// Isolation backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationConfig {
    /// Default isolation backend
    #[serde(default)]
    pub default_backend: IsolationBackendType,

    /// Optional backend name override.
    ///
    /// When set, this takes precedence over `default_backend` and allows
    /// selecting custom providers registered via `isolation::register_backend_factory`.
    #[serde(default)]
    pub backend_name: Option<String>,

    /// Linux native backend configuration
    #[serde(default)]
    pub linux_native: LinuxNativeConfig,

    /// Host direct (no isolation) backend configuration
    #[serde(default)]
    pub host_direct: HostDirectConfig,

    /// Container backend configuration
    #[serde(default)]
    pub container: ContainerBackendConfig,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            default_backend: IsolationBackendType::HostDirect,
            backend_name: None,
            linux_native: LinuxNativeConfig::default(),
            host_direct: HostDirectConfig::default(),
            container: ContainerBackendConfig::default(),
        }
    }
}

impl IsolationConfig {
    /// Return the configured backend selector name.
    ///
    /// Custom backend names override profile defaults.
    pub fn selected_backend_name(&self) -> String {
        self.backend_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| self.default_backend.canonical_name().to_string())
    }
}

/// Available isolation backend types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IsolationBackendType {
    /// Linux native isolation (Landlock, seccomp, cgroups, namespaces)
    LinuxNative,
    /// Host direct execution (no isolation, policy only)
    #[default]
    HostDirect,
    /// Container-based isolation (Docker/Podman)
    Container,
    /// No isolation at all (dangerous, for debugging only)
    None,
}

impl IsolationBackendType {
    /// Canonical backend selector for this built-in backend type.
    pub const fn canonical_name(self) -> &'static str {
        match self {
            IsolationBackendType::LinuxNative => "linux-native",
            IsolationBackendType::HostDirect => "host-direct",
            IsolationBackendType::Container => "container",
            IsolationBackendType::None => "none",
        }
    }
}

/// Linux native backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxNativeConfig {
    /// Enable Landlock LSM filesystem isolation
    #[serde(default = "default_true")]
    pub landlock_enabled: bool,

    /// Enable seccomp-bpf system call filtering
    #[serde(default = "default_true")]
    pub seccomp_enabled: bool,

    /// Enable cgroups v2 resource limits
    #[serde(default = "default_true")]
    pub cgroups_enabled: bool,

    /// Enable Linux namespaces
    #[serde(default = "default_true")]
    pub namespaces_enabled: bool,

    /// Enable user namespace (for unprivileged sandboxing)
    #[serde(default)]
    pub user_namespace: bool,

    /// Enable network namespace
    #[serde(default)]
    pub network_namespace: bool,

    /// Enable mount namespace
    #[serde(default)]
    pub mount_namespace: bool,

    /// cgroups path prefix
    #[serde(default = "default_cgroups_path")]
    pub cgroups_path: PathBuf,

    /// Default memory limit in bytes
    #[serde(default = "default_memory_limit")]
    pub default_memory_bytes: u64,

    /// Default CPU quota (microseconds per second)
    #[serde(default = "default_cpu_quota")]
    pub default_cpu_quota: u64,

    /// Default max processes
    #[serde(default = "default_max_pids")]
    pub default_max_pids: u32,
}

impl Default for LinuxNativeConfig {
    fn default() -> Self {
        Self {
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
            user_namespace: false,
            network_namespace: false,
            mount_namespace: false,
            cgroups_path: default_cgroups_path(),
            default_memory_bytes: default_memory_limit(),
            default_cpu_quota: default_cpu_quota(),
            default_max_pids: default_max_pids(),
        }
    }
}

/// Host direct backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDirectConfig {
    /// Apply soft resource limits (nice, ulimit)
    #[serde(default = "default_true")]
    pub soft_limits_enabled: bool,

    /// Nice value for subprocess priority
    #[serde(default = "default_nice_value")]
    pub nice_value: i32,

    /// Allowed base directories for filesystem operations
    #[serde(default)]
    pub allowed_paths: Vec<PathBuf>,

    /// Blocked paths (overrides allowed_paths)
    #[serde(default)]
    pub blocked_paths: Vec<PathBuf>,
}

impl Default for HostDirectConfig {
    fn default() -> Self {
        Self {
            soft_limits_enabled: true,
            nice_value: 10,
            allowed_paths: vec![],
            blocked_paths: vec![
                PathBuf::from("/etc/passwd"),
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/root"),
            ],
        }
    }
}

/// Container backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerBackendConfig {
    /// Container runtime (docker, podman)
    #[serde(default = "default_container_runtime")]
    pub runtime: String,

    /// Socket path for container runtime
    #[serde(default)]
    pub socket_path: Option<PathBuf>,

    /// Default image for sandboxes
    #[serde(default)]
    pub default_image: Option<String>,

    /// Enable GPU passthrough
    #[serde(default)]
    pub gpu_enabled: bool,
}

impl Default for ContainerBackendConfig {
    fn default() -> Self {
        Self {
            runtime: "docker".to_string(),
            socket_path: None,
            default_image: Some("alpine:latest".to_string()),
            gpu_enabled: false,
        }
    }
}

/// Ingest adapters configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptersConfig {
    /// List of enabled adapter names
    #[serde(default = "default_enabled_adapters")]
    pub enabled: Vec<String>,

    /// gRPC adapter configuration
    #[serde(default)]
    pub grpc: GrpcAdapterConfig,

    /// NATS adapter configuration
    #[serde(default)]
    pub nats: NatsAdapterConfig,

    /// HTTP adapter configuration
    #[serde(default)]
    pub http: HttpAdapterConfig,

    /// Unix socket adapter configuration
    #[serde(default)]
    pub unix: UnixAdapterConfig,
}

impl Default for AdaptersConfig {
    fn default() -> Self {
        Self {
            enabled: vec!["grpc".to_string()],
            grpc: GrpcAdapterConfig::default(),
            nats: NatsAdapterConfig::default(),
            http: HttpAdapterConfig::default(),
            unix: UnixAdapterConfig::default(),
        }
    }
}

/// gRPC adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcAdapterConfig {
    /// Enable gRPC adapter
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Listen address
    #[serde(default)]
    pub listen: Option<SocketAddr>,

    /// TLS certificate path
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,

    /// TLS key path
    #[serde(default)]
    pub tls_key: Option<PathBuf>,

    /// TLS CA certificate path (for mTLS)
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,

    /// Require mutual TLS
    #[serde(default)]
    pub require_mtls: bool,

    /// Maximum concurrent streams
    #[serde(default = "default_max_streams")]
    pub max_concurrent_streams: u32,

    /// Connection keepalive interval in seconds
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
}

impl Default for GrpcAdapterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: Some("127.0.0.1:9500".parse().unwrap()),
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            require_mtls: false,
            max_concurrent_streams: 100,
            keepalive_secs: 30,
        }
    }
}

/// NATS adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsAdapterConfig {
    /// Enable NATS adapter
    #[serde(default)]
    pub enabled: bool,

    /// NATS server URL
    #[serde(default)]
    pub url: Option<String>,

    /// JetStream domain
    #[serde(default)]
    pub jetstream_domain: Option<String>,

    /// TLS certificate path
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,

    /// TLS key path
    #[serde(default)]
    pub tls_key: Option<PathBuf>,

    /// Credential file path
    #[serde(default)]
    pub credentials: Option<PathBuf>,

    /// Queue group for load balancing
    #[serde(default)]
    pub queue_group: Option<String>,

    /// Subjects to subscribe to
    #[serde(default)]
    pub subjects: Vec<String>,
}

impl Default for NatsAdapterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            jetstream_domain: None,
            tls_cert: None,
            tls_key: None,
            credentials: None,
            queue_group: None,
            subjects: vec!["smith.intents.>".to_string()],
        }
    }
}

/// HTTP adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAdapterConfig {
    /// Enable HTTP adapter
    #[serde(default)]
    pub enabled: bool,

    /// Listen address
    #[serde(default)]
    pub listen: Option<SocketAddr>,

    /// TLS configuration
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,

    /// TLS key path
    #[serde(default)]
    pub tls_key: Option<PathBuf>,

    /// CORS origins
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

impl Default for HttpAdapterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: None,
            tls_cert: None,
            tls_key: None,
            cors_origins: vec![],
        }
    }
}

/// Unix socket adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixAdapterConfig {
    /// Enable Unix socket adapter
    #[serde(default)]
    pub enabled: bool,

    /// Socket path
    #[serde(default)]
    pub path: Option<PathBuf>,

    /// Socket permissions (octal)
    #[serde(default = "default_socket_mode")]
    pub mode: u32,
}

impl Default for UnixAdapterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            mode: 0o660,
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enabled authentication providers
    #[serde(default)]
    pub enabled_providers: Vec<String>,

    /// Require authentication for all requests
    #[serde(default)]
    pub require_auth: bool,

    /// JWT authentication configuration
    #[serde(default)]
    pub jwt: JwtAuthConfig,

    /// API key authentication configuration
    #[serde(default)]
    pub api_key: ApiKeyAuthConfig,

    /// mTLS authentication configuration
    #[serde(default)]
    pub mtls: MtlsAuthConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled_providers: vec!["allow-all".to_string()],
            require_auth: false,
            jwt: JwtAuthConfig::default(),
            api_key: ApiKeyAuthConfig::default(),
            mtls: MtlsAuthConfig::default(),
        }
    }
}

/// JWT authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JwtAuthConfig {
    /// Expected issuer
    #[serde(default)]
    pub issuer: Option<String>,

    /// Expected audience
    #[serde(default)]
    pub audience: Option<String>,

    /// JWKS URL for key fetching
    #[serde(default)]
    pub jwks_url: Option<String>,

    /// Static public key (PEM encoded)
    #[serde(default)]
    pub public_key: Option<String>,

    /// Allowed algorithms
    #[serde(default)]
    pub algorithms: Vec<String>,
}

/// API key authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyAuthConfig {
    /// Header name for API key
    #[serde(default = "default_api_key_header")]
    pub header_name: String,

    /// Static API keys (key -> subject mapping)
    #[serde(default)]
    pub static_keys: HashMap<String, String>,
}

impl Default for ApiKeyAuthConfig {
    fn default() -> Self {
        Self {
            header_name: "X-API-Key".to_string(),
            static_keys: HashMap::new(),
        }
    }
}

/// mTLS authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MtlsAuthConfig {
    /// Require client certificate
    #[serde(default)]
    pub required: bool,

    /// Allowed client certificate subjects
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
}

/// Output sink configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Reply to source adapter
    #[serde(default = "default_true")]
    pub reply_to_source: bool,

    /// Output sinks
    #[serde(default)]
    pub sinks: Vec<OutputSinkConfig>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            reply_to_source: true,
            sinks: vec![],
        }
    }
}

/// Individual output sink configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSinkConfig {
    /// Sink name
    pub name: String,

    /// Sink type (nats, audit, webhook)
    pub sink_type: String,

    /// Routing rule (always, on_error, on_success, if_available)
    #[serde(default = "default_routing_rule")]
    pub rule: String,

    /// Sink-specific configuration
    #[serde(default)]
    pub config: HashMap<String, String>,
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy bundle name
    #[serde(default = "default_policy_bundle")]
    pub bundle: String,

    /// Policy bundle path
    #[serde(default)]
    pub bundle_path: Option<PathBuf>,

    /// Enable policy enforcement
    #[serde(default = "default_true")]
    pub enforcement_enabled: bool,

    /// Policy update interval in seconds
    #[serde(default = "default_policy_update_interval")]
    pub update_interval_secs: u64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            bundle: "permissive".to_string(),
            bundle_path: None,
            enforcement_enabled: true,
            update_interval_secs: 300,
        }
    }
}

/// Sandbox management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Auto-create sandboxes on request
    #[serde(default = "default_true")]
    pub auto_create: bool,

    /// Require fresh sandbox for each request
    #[serde(default)]
    pub fresh_sandbox_per_request: bool,

    /// Default execution timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub max_duration_ms: u64,

    /// Sandbox pool configuration
    #[serde(default)]
    pub pool: SandboxPoolConfig,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            auto_create: true,
            fresh_sandbox_per_request: false,
            max_duration_ms: 300_000, // 5 minutes
            pool: SandboxPoolConfig::default(),
        }
    }
}

/// Sandbox pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPoolConfig {
    /// Enable sandbox pooling
    #[serde(default)]
    pub enabled: bool,

    /// Minimum warm sandboxes
    #[serde(default)]
    pub min_warm: u32,

    /// Maximum warm sandboxes
    #[serde(default = "default_max_warm")]
    pub max_warm: u32,

    /// Idle timeout in seconds before recycling
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

impl Default for SandboxPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_warm: 0,
            max_warm: 10,
            idle_timeout_secs: 300,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (json, pretty)
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Include timestamps
    #[serde(default = "default_true")]
    pub timestamps: bool,

    /// Include span IDs
    #[serde(default)]
    pub span_ids: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            timestamps: true,
            span_ids: false,
        }
    }
}

// Default value functions
fn default_true() -> bool {
    true
}

fn default_cgroups_path() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup/agentd")
}

fn default_memory_limit() -> u64 {
    256 * 1024 * 1024 // 256MB
}

fn default_cpu_quota() -> u64 {
    50_000 // 50ms per 100ms period = 50%
}

fn default_max_pids() -> u32 {
    64
}

fn default_nice_value() -> i32 {
    10
}

fn default_container_runtime() -> String {
    "docker".to_string()
}

fn default_enabled_adapters() -> Vec<String> {
    vec!["grpc".to_string()]
}

fn default_max_streams() -> u32 {
    100
}

fn default_keepalive() -> u64 {
    30
}

fn default_socket_mode() -> u32 {
    0o660
}

fn default_api_key_header() -> String {
    "X-API-Key".to_string()
}

fn default_routing_rule() -> String {
    "always".to_string()
}

fn default_policy_bundle() -> String {
    "permissive".to_string()
}

fn default_policy_update_interval() -> u64 {
    300
}

fn default_timeout_ms() -> u64 {
    300_000 // 5 minutes
}

fn default_max_warm() -> u32 {
    10
}

fn default_idle_timeout() -> u64 {
    300
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workstation_profile() {
        let config = AgentdConfig::workstation();
        assert_eq!(config.profile, ExecutionProfile::Workstation);
        assert_eq!(
            config.isolation.default_backend,
            IsolationBackendType::HostDirect
        );
        assert!(config.adapters.grpc.enabled);
        assert!(!config.adapters.nats.enabled);
        assert!(!config.auth.require_auth);
    }

    #[test]
    fn test_server_profile() {
        let config = AgentdConfig::server();
        assert_eq!(config.profile, ExecutionProfile::Server);
        assert_eq!(
            config.isolation.default_backend,
            IsolationBackendType::LinuxNative
        );
        assert!(config.isolation.linux_native.landlock_enabled);
        assert!(config.auth.require_auth);
        assert!(config.sandbox.pool.enabled);
    }

    #[test]
    fn test_paranoid_profile() {
        let config = AgentdConfig::paranoid();
        assert_eq!(config.profile, ExecutionProfile::Paranoid);
        assert!(config.adapters.grpc.require_mtls);
        assert!(config.sandbox.fresh_sandbox_per_request);
        assert_eq!(config.sandbox.max_duration_ms, 30_000);
    }

    #[test]
    fn test_validation_fails_no_adapters() {
        let mut config = AgentdConfig::default();
        config.adapters.enabled = vec![];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_grpc_no_listen() {
        let mut config = AgentdConfig::default();
        config.adapters.enabled = vec!["grpc".to_string()];
        config.adapters.grpc.enabled = true;
        config.adapters.grpc.listen = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_empty_backend_override() {
        let mut config = AgentdConfig::default();
        config.isolation.backend_name = Some("   ".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let config = AgentdConfig::server();
        let toml = toml::to_string(&config).unwrap();
        let parsed: AgentdConfig = toml::from_str(&toml).unwrap();
        assert_eq!(config.profile, parsed.profile);
    }

    // ==================== ExecutionProfile Tests ====================

    #[test]
    fn test_execution_profile_serialization() {
        let profiles = vec![
            (ExecutionProfile::Workstation, "\"workstation\""),
            (ExecutionProfile::Server, "\"server\""),
            (ExecutionProfile::Paranoid, "\"paranoid\""),
            (ExecutionProfile::Custom, "\"custom\""),
        ];

        for (profile, expected_json) in profiles {
            let json = serde_json::to_string(&profile).unwrap();
            assert_eq!(json, expected_json);
            let parsed: ExecutionProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(profile, parsed);
        }
    }

    #[test]
    fn test_execution_profile_default() {
        let profile = ExecutionProfile::default();
        assert_eq!(profile, ExecutionProfile::Workstation);
    }

    #[test]
    fn test_execution_profile_clone() {
        let profile = ExecutionProfile::Server;
        let cloned = profile.clone();
        assert_eq!(profile, cloned);
    }

    // ==================== IsolationBackendType Tests ====================

    #[test]
    fn test_isolation_backend_type_serialization() {
        let types = vec![
            (IsolationBackendType::LinuxNative, "\"linux_native\""),
            (IsolationBackendType::HostDirect, "\"host_direct\""),
            (IsolationBackendType::Container, "\"container\""),
            (IsolationBackendType::None, "\"none\""),
        ];

        for (backend, expected_json) in types {
            let json = serde_json::to_string(&backend).unwrap();
            assert_eq!(json, expected_json);
            let parsed: IsolationBackendType = serde_json::from_str(&json).unwrap();
            assert_eq!(backend, parsed);
        }
    }

    #[test]
    fn test_isolation_backend_type_default() {
        let backend = IsolationBackendType::default();
        assert_eq!(backend, IsolationBackendType::HostDirect);
    }

    #[test]
    fn test_isolation_backend_type_canonical_name() {
        assert_eq!(
            IsolationBackendType::LinuxNative.canonical_name(),
            "linux-native"
        );
        assert_eq!(
            IsolationBackendType::HostDirect.canonical_name(),
            "host-direct"
        );
        assert_eq!(
            IsolationBackendType::Container.canonical_name(),
            "container"
        );
        assert_eq!(IsolationBackendType::None.canonical_name(), "none");
    }

    // ==================== Default Value Tests ====================

    #[test]
    fn test_default_values() {
        assert_eq!(default_memory_limit(), 256 * 1024 * 1024);
        assert_eq!(default_cpu_quota(), 50_000);
        assert_eq!(default_max_pids(), 64);
        assert_eq!(default_nice_value(), 10);
        assert_eq!(default_container_runtime(), "docker");
        assert_eq!(default_enabled_adapters(), vec!["grpc".to_string()]);
        assert_eq!(default_max_streams(), 100);
        assert_eq!(default_keepalive(), 30);
        assert_eq!(default_socket_mode(), 0o660);
        assert_eq!(default_api_key_header(), "X-API-Key");
        assert_eq!(default_routing_rule(), "always");
        assert_eq!(default_policy_bundle(), "permissive");
        assert_eq!(default_policy_update_interval(), 300);
        assert_eq!(default_timeout_ms(), 300_000);
        assert_eq!(default_max_warm(), 10);
        assert_eq!(default_idle_timeout(), 300);
        assert_eq!(default_log_level(), "info");
        assert_eq!(default_log_format(), "pretty");
        assert!(default_true());
    }

    #[test]
    fn test_default_cgroups_path() {
        let path = default_cgroups_path();
        assert_eq!(path, PathBuf::from("/sys/fs/cgroup/agentd"));
    }

    // ==================== AgentdConfig Default Tests ====================

    #[test]
    fn test_agentd_config_default() {
        let config = AgentdConfig::default();
        assert_eq!(config.profile, ExecutionProfile::Workstation);
        assert_eq!(
            config.isolation.default_backend,
            IsolationBackendType::HostDirect
        );
        assert!(config.adapters.grpc.enabled);
        assert!(!config.auth.require_auth);
        assert!(config.sandbox.auto_create);
        assert!(config.policy.enforcement_enabled);
        assert_eq!(config.logging.level, "info");
    }

    // ==================== IsolationConfig Tests ====================

    #[test]
    fn test_isolation_config_default() {
        let config = IsolationConfig::default();
        assert_eq!(config.default_backend, IsolationBackendType::HostDirect);
        assert!(config.backend_name.is_none());
        assert!(config.linux_native.landlock_enabled);
        assert!(config.linux_native.seccomp_enabled);
        assert!(config.linux_native.cgroups_enabled);
        assert!(config.linux_native.namespaces_enabled);
    }

    #[test]
    fn test_isolation_config_selected_backend_name_defaults_to_backend_type() {
        let config = IsolationConfig {
            default_backend: IsolationBackendType::LinuxNative,
            ..Default::default()
        };
        assert_eq!(config.selected_backend_name(), "linux-native");
    }

    #[test]
    fn test_isolation_config_selected_backend_name_prefers_override() {
        let config = IsolationConfig {
            default_backend: IsolationBackendType::LinuxNative,
            backend_name: Some("gondolin".to_string()),
            ..Default::default()
        };
        assert_eq!(config.selected_backend_name(), "gondolin");
    }

    #[test]
    fn test_linux_native_config_serialization() {
        let config = LinuxNativeConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: LinuxNativeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.landlock_enabled, parsed.landlock_enabled);
        assert_eq!(config.seccomp_enabled, parsed.seccomp_enabled);
        assert_eq!(config.default_memory_bytes, parsed.default_memory_bytes);
    }

    #[test]
    fn test_linux_native_config_default() {
        let config = LinuxNativeConfig::default();
        assert!(config.landlock_enabled);
        assert!(config.seccomp_enabled);
        assert!(config.cgroups_enabled);
        assert!(config.namespaces_enabled);
        assert!(!config.user_namespace);
        assert!(!config.network_namespace);
        assert!(!config.mount_namespace);
        assert_eq!(config.default_memory_bytes, 256 * 1024 * 1024);
        assert_eq!(config.default_cpu_quota, 50_000);
        assert_eq!(config.default_max_pids, 64);
    }

    // ==================== HostDirectConfig Tests ====================

    #[test]
    fn test_host_direct_config_default() {
        let config = HostDirectConfig::default();
        assert!(config.soft_limits_enabled);
        assert_eq!(config.nice_value, 10);
        assert!(config.allowed_paths.is_empty());
        assert!(!config.blocked_paths.is_empty());
        assert!(config.blocked_paths.contains(&PathBuf::from("/etc/shadow")));
    }

    #[test]
    fn test_host_direct_config_serialization() {
        let config = HostDirectConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: HostDirectConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.soft_limits_enabled, parsed.soft_limits_enabled);
        assert_eq!(config.nice_value, parsed.nice_value);
    }

    // ==================== ContainerBackendConfig Tests ====================

    #[test]
    fn test_container_backend_config_default() {
        let config = ContainerBackendConfig::default();
        assert_eq!(config.runtime, "docker");
        assert!(config.socket_path.is_none());
        assert_eq!(config.default_image, Some("alpine:latest".to_string()));
        assert!(!config.gpu_enabled);
    }

    #[test]
    fn test_container_backend_config_serialization() {
        let config = ContainerBackendConfig {
            runtime: "podman".to_string(),
            socket_path: Some(PathBuf::from("/run/podman/podman.sock")),
            default_image: Some("ubuntu:22.04".to_string()),
            gpu_enabled: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ContainerBackendConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.runtime, parsed.runtime);
        assert_eq!(config.gpu_enabled, parsed.gpu_enabled);
    }

    // ==================== AdaptersConfig Tests ====================

    #[test]
    fn test_adapters_config_default() {
        let config = AdaptersConfig::default();
        assert_eq!(config.enabled, vec!["grpc".to_string()]);
        assert!(config.grpc.enabled);
        assert!(!config.nats.enabled);
        assert!(!config.http.enabled);
        assert!(!config.unix.enabled);
    }

    // ==================== GrpcAdapterConfig Tests ====================

    #[test]
    fn test_grpc_adapter_config_default() {
        let config = GrpcAdapterConfig::default();
        assert!(config.enabled);
        assert!(config.listen.is_some());
        assert_eq!(config.listen.unwrap().to_string(), "127.0.0.1:9500");
        assert!(!config.require_mtls);
        assert_eq!(config.max_concurrent_streams, 100);
        assert_eq!(config.keepalive_secs, 30);
    }

    #[test]
    fn test_grpc_adapter_config_serialization() {
        let config = GrpcAdapterConfig {
            enabled: true,
            listen: Some("0.0.0.0:9501".parse().unwrap()),
            tls_cert: Some(PathBuf::from("/etc/certs/server.crt")),
            tls_key: Some(PathBuf::from("/etc/certs/server.key")),
            tls_ca: Some(PathBuf::from("/etc/certs/ca.crt")),
            require_mtls: true,
            max_concurrent_streams: 200,
            keepalive_secs: 60,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: GrpcAdapterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.require_mtls, parsed.require_mtls);
        assert_eq!(config.max_concurrent_streams, parsed.max_concurrent_streams);
    }

    // ==================== NatsAdapterConfig Tests ====================

    #[test]
    fn test_nats_adapter_config_default() {
        let config = NatsAdapterConfig::default();
        assert!(!config.enabled);
        assert!(config.url.is_none());
        assert!(config.jetstream_domain.is_none());
        assert_eq!(config.subjects, vec!["smith.intents.>".to_string()]);
    }

    #[test]
    fn test_nats_adapter_config_serialization() {
        let config = NatsAdapterConfig {
            enabled: true,
            url: Some("nats://localhost:4222".to_string()),
            jetstream_domain: Some("hub".to_string()),
            tls_cert: None,
            tls_key: None,
            credentials: Some(PathBuf::from("/etc/nats/creds.creds")),
            queue_group: Some("workers".to_string()),
            subjects: vec!["smith.intents.fs.>".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: NatsAdapterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.url, parsed.url);
        assert_eq!(config.queue_group, parsed.queue_group);
    }

    // ==================== HttpAdapterConfig Tests ====================

    #[test]
    fn test_http_adapter_config_default() {
        let config = HttpAdapterConfig::default();
        assert!(!config.enabled);
        assert!(config.listen.is_none());
        assert!(config.cors_origins.is_empty());
    }

    #[test]
    fn test_http_adapter_config_serialization() {
        let config = HttpAdapterConfig {
            enabled: true,
            listen: Some("0.0.0.0:8080".parse().unwrap()),
            tls_cert: Some(PathBuf::from("/certs/cert.pem")),
            tls_key: Some(PathBuf::from("/certs/key.pem")),
            cors_origins: vec!["https://example.com".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: HttpAdapterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.enabled, parsed.enabled);
        assert_eq!(config.cors_origins.len(), parsed.cors_origins.len());
    }

    // ==================== UnixAdapterConfig Tests ====================

    #[test]
    fn test_unix_adapter_config_default() {
        let config = UnixAdapterConfig::default();
        assert!(!config.enabled);
        assert!(config.path.is_none());
        assert_eq!(config.mode, 0o660);
    }

    #[test]
    fn test_unix_adapter_config_serialization() {
        let config = UnixAdapterConfig {
            enabled: true,
            path: Some(PathBuf::from("/var/run/agentd.sock")),
            mode: 0o770,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: UnixAdapterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.enabled, parsed.enabled);
        assert_eq!(config.mode, parsed.mode);
    }

    // ==================== AuthConfig Tests ====================

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();
        assert_eq!(config.enabled_providers, vec!["allow-all".to_string()]);
        assert!(!config.require_auth);
    }

    #[test]
    fn test_auth_config_serialization() {
        let config = AuthConfig {
            enabled_providers: vec!["jwt".to_string(), "mtls".to_string()],
            require_auth: true,
            jwt: JwtAuthConfig {
                issuer: Some("https://auth.example.com".to_string()),
                audience: Some("agentd".to_string()),
                jwks_url: Some("https://auth.example.com/.well-known/jwks.json".to_string()),
                public_key: None,
                algorithms: vec!["RS256".to_string()],
            },
            api_key: ApiKeyAuthConfig::default(),
            mtls: MtlsAuthConfig::default(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.require_auth, parsed.require_auth);
        assert_eq!(config.jwt.issuer, parsed.jwt.issuer);
    }

    // ==================== JwtAuthConfig Tests ====================

    #[test]
    fn test_jwt_auth_config_default() {
        let config = JwtAuthConfig::default();
        assert!(config.issuer.is_none());
        assert!(config.audience.is_none());
        assert!(config.jwks_url.is_none());
        assert!(config.algorithms.is_empty());
    }

    #[test]
    fn test_jwt_auth_config_serialization() {
        let config = JwtAuthConfig {
            issuer: Some("issuer".to_string()),
            audience: Some("audience".to_string()),
            jwks_url: Some("https://jwks.url".to_string()),
            public_key: Some("-----BEGIN PUBLIC KEY-----\n...".to_string()),
            algorithms: vec!["RS256".to_string(), "ES256".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: JwtAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.issuer, parsed.issuer);
        assert_eq!(config.algorithms, parsed.algorithms);
    }

    // ==================== ApiKeyAuthConfig Tests ====================

    #[test]
    fn test_api_key_auth_config_default() {
        let config = ApiKeyAuthConfig::default();
        assert_eq!(config.header_name, "X-API-Key");
        assert!(config.static_keys.is_empty());
    }

    #[test]
    fn test_api_key_auth_config_serialization() {
        let mut static_keys = HashMap::new();
        static_keys.insert("key1".to_string(), "user1".to_string());
        static_keys.insert("key2".to_string(), "user2".to_string());

        let config = ApiKeyAuthConfig {
            header_name: "Authorization".to_string(),
            static_keys,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ApiKeyAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.header_name, parsed.header_name);
        assert_eq!(config.static_keys.len(), parsed.static_keys.len());
    }

    // ==================== MtlsAuthConfig Tests ====================

    #[test]
    fn test_mtls_auth_config_default() {
        let config = MtlsAuthConfig::default();
        assert!(!config.required);
        assert!(config.allowed_subjects.is_empty());
    }

    #[test]
    fn test_mtls_auth_config_serialization() {
        let config = MtlsAuthConfig {
            required: true,
            allowed_subjects: vec!["CN=client1".to_string(), "CN=client2".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: MtlsAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.required, parsed.required);
        assert_eq!(config.allowed_subjects.len(), parsed.allowed_subjects.len());
    }

    // ==================== OutputConfig Tests ====================

    #[test]
    fn test_output_config_default() {
        let config = OutputConfig::default();
        assert!(config.reply_to_source);
        assert!(config.sinks.is_empty());
    }

    #[test]
    fn test_output_config_serialization() {
        let config = OutputConfig {
            reply_to_source: false,
            sinks: vec![OutputSinkConfig {
                name: "audit".to_string(),
                sink_type: "audit".to_string(),
                rule: "always".to_string(),
                config: HashMap::from([("path".to_string(), "/var/log/agentd".to_string())]),
            }],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: OutputConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.reply_to_source, parsed.reply_to_source);
        assert_eq!(config.sinks.len(), parsed.sinks.len());
    }

    // ==================== OutputSinkConfig Tests ====================

    #[test]
    fn test_output_sink_config_serialization() {
        let config = OutputSinkConfig {
            name: "webhook".to_string(),
            sink_type: "webhook".to_string(),
            rule: "on_error".to_string(),
            config: HashMap::from([
                (
                    "url".to_string(),
                    "https://hooks.example.com/alert".to_string(),
                ),
                ("secret".to_string(), "webhook_secret".to_string()),
            ]),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: OutputSinkConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.name, parsed.name);
        assert_eq!(config.rule, parsed.rule);
    }

    // ==================== PolicyConfig Tests ====================

    #[test]
    fn test_policy_config_default() {
        let config = PolicyConfig::default();
        assert_eq!(config.bundle, "permissive");
        assert!(config.bundle_path.is_none());
        assert!(config.enforcement_enabled);
        assert_eq!(config.update_interval_secs, 300);
    }

    #[test]
    fn test_policy_config_serialization() {
        let config = PolicyConfig {
            bundle: "strict".to_string(),
            bundle_path: Some(PathBuf::from("/etc/agentd/policy.bundle")),
            enforcement_enabled: true,
            update_interval_secs: 60,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.bundle, parsed.bundle);
        assert_eq!(config.update_interval_secs, parsed.update_interval_secs);
    }

    // ==================== SandboxConfig Tests ====================

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert!(config.auto_create);
        assert!(!config.fresh_sandbox_per_request);
        assert_eq!(config.max_duration_ms, 300_000);
        assert!(!config.pool.enabled);
    }

    #[test]
    fn test_sandbox_config_serialization() {
        let config = SandboxConfig {
            auto_create: true,
            fresh_sandbox_per_request: true,
            max_duration_ms: 60_000,
            pool: SandboxPoolConfig {
                enabled: true,
                min_warm: 2,
                max_warm: 20,
                idle_timeout_secs: 600,
            },
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.max_duration_ms, parsed.max_duration_ms);
        assert_eq!(config.pool.min_warm, parsed.pool.min_warm);
    }

    // ==================== SandboxPoolConfig Tests ====================

    #[test]
    fn test_sandbox_pool_config_default() {
        let config = SandboxPoolConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.min_warm, 0);
        assert_eq!(config.max_warm, 10);
        assert_eq!(config.idle_timeout_secs, 300);
    }

    #[test]
    fn test_sandbox_pool_config_serialization() {
        let config = SandboxPoolConfig {
            enabled: true,
            min_warm: 5,
            max_warm: 50,
            idle_timeout_secs: 120,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SandboxPoolConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.enabled, parsed.enabled);
        assert_eq!(config.min_warm, parsed.min_warm);
    }

    // ==================== LoggingConfig Tests ====================

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "pretty");
        assert!(config.timestamps);
        assert!(!config.span_ids);
    }

    #[test]
    fn test_logging_config_serialization() {
        let config = LoggingConfig {
            level: "debug".to_string(),
            format: "json".to_string(),
            timestamps: true,
            span_ids: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: LoggingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.level, parsed.level);
        assert_eq!(config.format, parsed.format);
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_validation_fails_nats_no_url() {
        let mut config = AgentdConfig::default();
        config.adapters.enabled = vec!["nats".to_string()];
        config.adapters.nats.enabled = true;
        config.adapters.nats.url = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_http_no_listen() {
        let mut config = AgentdConfig::default();
        config.adapters.enabled = vec!["http".to_string()];
        config.adapters.http.enabled = true;
        config.adapters.http.listen = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_auth_required_no_providers() {
        let mut config = AgentdConfig::default();
        config.auth.require_auth = true;
        config.auth.enabled_providers = vec![];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_sandbox_pool_max_less_than_min() {
        let mut config = AgentdConfig::default();
        config.sandbox.pool.enabled = true;
        config.sandbox.pool.min_warm = 10;
        config.sandbox.pool.max_warm = 5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_passes_with_valid_config() {
        let config = AgentdConfig::workstation();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_passes_server_profile() {
        let mut config = AgentdConfig::server();
        // Server profile has NATS enabled but needs URL configured
        config.adapters.nats.url = Some("nats://localhost:4222".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_passes_paranoid_profile() {
        let config = AgentdConfig::paranoid();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_unknown_adapter_passes() {
        let mut config = AgentdConfig::default();
        config.adapters.enabled = vec!["custom".to_string()];
        // Unknown adapters should pass validation (for extensibility)
        assert!(config.validate().is_ok());
    }

    // ==================== TOML Serialization Tests ====================

    #[test]
    fn test_workstation_toml_roundtrip() {
        let config = AgentdConfig::workstation();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: AgentdConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.profile, parsed.profile);
        assert_eq!(
            config.isolation.default_backend,
            parsed.isolation.default_backend
        );
    }

    #[test]
    fn test_server_toml_roundtrip() {
        let config = AgentdConfig::server();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: AgentdConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.profile, parsed.profile);
        assert!(parsed.sandbox.pool.enabled);
    }

    #[test]
    fn test_paranoid_toml_roundtrip() {
        let config = AgentdConfig::paranoid();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: AgentdConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.profile, parsed.profile);
        assert!(parsed.sandbox.fresh_sandbox_per_request);
    }

    // ==================== Clone Tests ====================

    #[test]
    fn test_agentd_config_clone() {
        let config = AgentdConfig::server();
        let cloned = config.clone();
        assert_eq!(config.profile, cloned.profile);
        assert_eq!(
            config.isolation.default_backend,
            cloned.isolation.default_backend
        );
    }

    #[test]
    fn test_isolation_config_clone() {
        let config = IsolationConfig::default();
        let cloned = config.clone();
        assert_eq!(config.default_backend, cloned.default_backend);
    }

    #[test]
    fn test_adapters_config_clone() {
        let config = AdaptersConfig::default();
        let cloned = config.clone();
        assert_eq!(config.enabled, cloned.enabled);
    }

    // ==================== Debug Tests ====================

    #[test]
    fn test_agentd_config_debug() {
        let config = AgentdConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("AgentdConfig"));
        assert!(debug_str.contains("profile"));
    }

    #[test]
    fn test_execution_profile_debug() {
        let profile = ExecutionProfile::Paranoid;
        let debug_str = format!("{:?}", profile);
        assert!(debug_str.contains("Paranoid"));
    }

    #[test]
    fn test_isolation_backend_type_debug() {
        let backend = IsolationBackendType::LinuxNative;
        let debug_str = format!("{:?}", backend);
        assert!(debug_str.contains("LinuxNative"));
    }
}
