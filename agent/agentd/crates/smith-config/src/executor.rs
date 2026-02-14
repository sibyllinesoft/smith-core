//! Executor service configuration

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

/// Executor service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorConfig {
    /// Executor node name
    pub node_name: String,

    /// Work directory root
    pub work_root: PathBuf,

    /// State directory for persistence
    pub state_dir: PathBuf,

    /// Audit directory for audit logs
    pub audit_dir: PathBuf,

    /// User UID to run intents as
    pub user_uid: u32,

    /// User GID to run intents as
    pub user_gid: u32,

    /// Enable Landlock LSM sandboxing
    pub landlock_enabled: bool,

    /// Egress proxy socket path
    pub egress_proxy_socket: PathBuf,

    /// Metrics port for Prometheus
    pub metrics_port: Option<u16>,

    /// Intent stream configurations by capability
    pub intent_streams: HashMap<String, IntentStreamConfig>,

    /// Results configuration
    pub results: ResultsConfig,

    /// Resource limits
    pub limits: LimitsConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Capability bundle configuration
    pub capabilities: CapabilityConfig,

    /// OPA policy update configuration
    pub policy: PolicyConfig,

    /// NATS configuration specific to executor
    pub nats_config: ExecutorNatsConfig,

    /// Supply chain attestation configuration
    pub attestation: AttestationConfig,

    /// Micro-VM pool configuration for persistent shell environments
    #[serde(default)]
    pub vm_pool: VmPoolConfig,
}

/// Intent stream configuration for a capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentStreamConfig {
    /// NATS subject pattern
    pub subject: String,

    /// Maximum age for messages
    pub max_age: String,

    /// Maximum bytes in stream
    pub max_bytes: String,

    /// Number of worker instances
    pub workers: u32,
}

/// Results stream configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultsConfig {
    /// Subject prefix for results
    pub subject_prefix: String,

    /// Maximum age for result messages
    pub max_age: String,
}

/// Resource limits configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LimitsConfig {
    /// Default resource limits
    pub defaults: DefaultLimits,

    /// Per-capability limit overrides
    pub overrides: HashMap<String, DefaultLimits>,
}

/// Default resource limits for intent execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultLimits {
    /// CPU time per 100ms window
    pub cpu_ms_per_100ms: u32,

    /// Memory limit in bytes
    pub mem_bytes: u64,

    /// I/O bytes limit
    pub io_bytes: u64,

    /// Maximum number of processes/threads
    pub pids_max: u32,

    /// Temporary filesystem size in MB
    pub tmpfs_mb: u32,

    /// Maximum intent payload size
    pub intent_max_bytes: u64,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Public keys directory for signature verification
    pub pubkeys_dir: PathBuf,

    /// JWT token issuers (URLs)
    pub jwt_issuers: Vec<String>,

    /// Enable strict sandbox mode
    pub strict_sandbox: bool,

    /// Enable network isolation
    pub network_isolation: bool,

    /// Allowed outbound network destinations
    pub allowed_destinations: Vec<String>,
}

/// Capability enforcement configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityConfig {
    /// Path to capability derivations file
    pub derivations_path: PathBuf,

    /// Enable capability enforcement
    pub enforcement_enabled: bool,
}

/// OPA policy update configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy update check interval in seconds
    pub update_interval_seconds: u64,

    /// NATS subject for streaming policy updates
    #[serde(default = "PolicyConfig::default_updates_subject")]
    pub updates_subject: String,

    /// Optional queue group for load-balanced policy updates
    #[serde(default)]
    pub updates_queue: Option<String>,
}

/// NATS configuration specific to executor service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorNatsConfig {
    /// NATS server URLs
    pub servers: Vec<String>,

    /// JetStream domain
    pub jetstream_domain: String,

    /// TLS certificate file path
    pub tls_cert: Option<PathBuf>,

    /// TLS key file path
    pub tls_key: Option<PathBuf>,

    /// TLS CA file path
    pub tls_ca: Option<PathBuf>,
}

/// Supply chain attestation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Enable capability bundle signing and verification
    pub enable_capability_signing: bool,

    /// Enable container image verification
    pub enable_image_verification: bool,

    /// Enable SLSA provenance generation and verification
    pub enable_slsa_provenance: bool,

    /// Fail execution if attestation verification fails
    pub fail_on_signature_error: bool,

    /// Cosign public key for verification (optional for keyless)
    pub cosign_public_key: Option<String>,

    /// SLSA provenance output directory
    pub provenance_output_dir: PathBuf,

    /// Attestation verification cache TTL in seconds
    pub verification_cache_ttl: u64,

    /// Periodic attestation verification interval in seconds
    pub periodic_verification_interval: u64,
}

/// Persistent micro-VM pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmPoolConfig {
    /// Enable the pool; when disabled the executor falls back to per-intent sandboxes
    #[serde(default)]
    pub enabled: bool,

    /// Root directory where per-session volumes are stored
    pub volume_root: PathBuf,

    /// Optional Nix profile or flake reference used to hydrate VM environments
    pub nix_profile: Option<String>,

    /// Base shell binary used to execute commands inside a VM
    pub shell: PathBuf,

    /// Additional shell arguments (e.g., ["-lc"] or nix develop flags)
    #[serde(default)]
    pub shell_args: Vec<String>,

    /// Static environment variables injected into every VM command
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Maximum number of concurrently active VMs
    pub max_vms: usize,

    /// Idle duration (seconds) before a VM is automatically shut down
    pub idle_shutdown_seconds: u64,

    /// Additional grace period after shutdown before pruning persistent volumes
    pub prune_after_seconds: u64,

    /// Optional delay before triggering a backup of the user volume once stopped
    pub backup_after_seconds: Option<u64>,

    /// Destination directory for backups (if enabled)
    pub backup_destination: Option<PathBuf>,

    /// Optional bootstrap command invoked once when the VM volume is created
    #[serde(default)]
    pub bootstrap_command: Option<Vec<String>>,
}

impl Default for VmPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            volume_root: PathBuf::from("/var/lib/smith/executor/vm-pool"),
            nix_profile: None,
            shell: PathBuf::from("/bin/bash"),
            shell_args: vec!["-lc".to_string()],
            env: HashMap::new(),
            max_vms: 32,
            idle_shutdown_seconds: 900,
            prune_after_seconds: 3_600,
            backup_after_seconds: None,
            backup_destination: None,
            bootstrap_command: None,
        }
    }
}

impl VmPoolConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.max_vms == 0 {
            return Err(anyhow::anyhow!(
                "vm_pool.max_vms must be greater than zero when the pool is enabled"
            ));
        }

        if self.idle_shutdown_seconds == 0 {
            return Err(anyhow::anyhow!(
                "vm_pool.idle_shutdown_seconds must be greater than zero"
            ));
        }

        if self.prune_after_seconds == 0 {
            return Err(anyhow::anyhow!(
                "vm_pool.prune_after_seconds must be greater than zero"
            ));
        }

        if let Some(backup_after) = self.backup_after_seconds {
            if backup_after == 0 {
                return Err(anyhow::anyhow!(
                    "vm_pool.backup_after_seconds must be greater than zero"
                ));
            }
            if self.backup_destination.is_none() {
                return Err(anyhow::anyhow!(
                    "vm_pool.backup_destination must be set when backup_after_seconds is provided"
                ));
            }
        }

        if !self.volume_root.exists() {
            std::fs::create_dir_all(&self.volume_root).with_context(|| {
                format!(
                    "Failed to create vm_pool.volume_root directory: {}",
                    self.volume_root.display()
                )
            })?;
        }

        if let Some(dest) = &self.backup_destination {
            if !dest.exists() {
                std::fs::create_dir_all(dest).with_context(|| {
                    format!(
                        "Failed to create vm_pool.backup_destination directory: {}",
                        dest.display()
                    )
                })?;
            }
        }

        Ok(())
    }
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        let mut intent_streams = HashMap::new();

        intent_streams.insert(
            "fs.read.v1".to_string(),
            IntentStreamConfig {
                subject: "smith.intents.fs.read.v1".to_string(),
                max_age: "10m".to_string(),
                max_bytes: "1GB".to_string(),
                workers: 4,
            },
        );

        intent_streams.insert(
            "http.fetch.v1".to_string(),
            IntentStreamConfig {
                subject: "smith.intents.http.fetch.v1".to_string(),
                max_age: "10m".to_string(),
                max_bytes: "1GB".to_string(),
                workers: 4,
            },
        );

        Self {
            node_name: "exec-01".to_string(),
            work_root: PathBuf::from("/var/lib/smith/executor/work"),
            state_dir: PathBuf::from("/var/lib/smith/executor/state"),
            audit_dir: PathBuf::from("/var/lib/smith/executor/audit"),
            user_uid: 65534, // nobody
            user_gid: 65534, // nobody
            landlock_enabled: true,
            egress_proxy_socket: PathBuf::from("/run/smith/egress-proxy.sock"),
            metrics_port: Some(9090),
            intent_streams,
            results: ResultsConfig::default(),
            limits: LimitsConfig::default(),
            security: SecurityConfig::default(),
            capabilities: CapabilityConfig::default(),
            policy: PolicyConfig::default(),
            nats_config: ExecutorNatsConfig::default(),
            attestation: AttestationConfig::default(),
            vm_pool: VmPoolConfig::default(),
        }
    }
}

impl Default for ResultsConfig {
    fn default() -> Self {
        Self {
            subject_prefix: "smith.results.".to_string(),
            max_age: "5m".to_string(),
        }
    }
}

impl Default for DefaultLimits {
    fn default() -> Self {
        Self {
            cpu_ms_per_100ms: 50,
            mem_bytes: 256 * 1024 * 1024, // 256MB
            io_bytes: 10 * 1024 * 1024,   // 10MB
            pids_max: 32,
            tmpfs_mb: 64,
            intent_max_bytes: 64 * 1024, // 64KB
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            pubkeys_dir: PathBuf::from("/etc/smith/executor/pubkeys"),
            jwt_issuers: vec!["https://auth.smith.example.com/".to_string()],
            strict_sandbox: false,
            network_isolation: true,
            allowed_destinations: vec![],
        }
    }
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            derivations_path: PathBuf::from("build/capability/sandbox_profiles/derivations.json"),
            enforcement_enabled: true,
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            update_interval_seconds: 300, // 5 minutes
            updates_subject: "smith.policies.updates".to_string(),
            updates_queue: None,
        }
    }
}

impl Default for ExecutorNatsConfig {
    fn default() -> Self {
        Self {
            servers: vec!["nats://127.0.0.1:4222".to_string()],
            jetstream_domain: "JS".to_string(),
            tls_cert: Some(PathBuf::from("/etc/smith/executor/nats.crt")),
            tls_key: Some(PathBuf::from("/etc/smith/executor/nats.key")),
            tls_ca: Some(PathBuf::from("/etc/smith/executor/ca.crt")),
        }
    }
}

impl ExecutorConfig {
    pub fn validate(&self) -> Result<()> {
        // Validate node name
        if self.node_name.is_empty() {
            return Err(anyhow::anyhow!("Node name cannot be empty"));
        }

        if self.node_name.len() > 63 {
            return Err(anyhow::anyhow!("Node name too long (max 63 chars)"));
        }

        // Validate directories exist or can be created
        for (name, path) in [
            ("work_root", &self.work_root),
            ("state_dir", &self.state_dir),
            ("audit_dir", &self.audit_dir),
        ] {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!(
                            "Failed to create {} parent directory: {}",
                            name,
                            parent.display()
                        )
                    })?;
                }
            }
        }

        // Validate UIDs/GIDs
        if self.user_uid == 0 {
            tracing::warn!("⚠️  Running as root (UID 0) is not recommended for security");
        }

        if self.user_gid == 0 {
            tracing::warn!("⚠️  Running as root group (GID 0) is not recommended for security");
        }

        // Validate metrics port
        if let Some(port) = self.metrics_port {
            if port < 1024 {
                return Err(anyhow::anyhow!(
                    "Invalid metrics port: {}. Must be between 1024 and 65535",
                    port
                ));
            }
        }

        // Validate intent stream configurations
        if self.intent_streams.is_empty() {
            return Err(anyhow::anyhow!("No intent streams configured"));
        }

        for (capability, stream_config) in &self.intent_streams {
            stream_config.validate().map_err(|e| {
                anyhow::anyhow!("Intent stream '{}' validation failed: {}", capability, e)
            })?;
        }

        // Validate sub-configurations
        self.results
            .validate()
            .context("Results configuration validation failed")?;

        self.limits
            .validate()
            .context("Limits configuration validation failed")?;

        self.security
            .validate()
            .context("Security configuration validation failed")?;

        self.capabilities
            .validate()
            .context("Capability configuration validation failed")?;

        self.policy
            .validate()
            .context("Policy configuration validation failed")?;

        self.nats_config
            .validate()
            .context("NATS configuration validation failed")?;

        self.vm_pool
            .validate()
            .context("VM pool configuration validation failed")?;

        Ok(())
    }

    pub fn development() -> Self {
        Self {
            work_root: PathBuf::from("/tmp/smith/executor/work"),
            state_dir: PathBuf::from("/tmp/smith/executor/state"),
            audit_dir: PathBuf::from("/tmp/smith/executor/audit"),
            landlock_enabled: false, // May not be available in all dev environments
            security: SecurityConfig {
                strict_sandbox: false,
                network_isolation: false,
                ..Default::default()
            },
            limits: LimitsConfig {
                defaults: DefaultLimits {
                    cpu_ms_per_100ms: 80,         // More generous for development
                    mem_bytes: 512 * 1024 * 1024, // 512MB
                    io_bytes: 50 * 1024 * 1024,   // 50MB
                    ..Default::default()
                },
                overrides: HashMap::new(),
            },
            nats_config: ExecutorNatsConfig::default(),
            ..Default::default()
        }
    }

    pub fn production() -> Self {
        Self {
            landlock_enabled: true,
            security: SecurityConfig {
                strict_sandbox: true,
                network_isolation: true,
                allowed_destinations: vec!["127.0.0.1".to_string(), "::1".to_string()],
                ..Default::default()
            },
            limits: LimitsConfig {
                defaults: DefaultLimits {
                    cpu_ms_per_100ms: 30,         // Strict limits for production
                    mem_bytes: 128 * 1024 * 1024, // 128MB
                    io_bytes: 5 * 1024 * 1024,    // 5MB
                    pids_max: 16,
                    tmpfs_mb: 32,
                    intent_max_bytes: 32 * 1024, // 32KB
                },
                overrides: {
                    let mut overrides = HashMap::new();

                    // HTTP fetch needs more network I/O
                    overrides.insert(
                        "http.fetch.v1".to_string(),
                        DefaultLimits {
                            io_bytes: 20 * 1024 * 1024,   // 20MB
                            intent_max_bytes: 128 * 1024, // 128KB
                            ..DefaultLimits::default()
                        },
                    );

                    overrides
                },
            },
            capabilities: CapabilityConfig {
                enforcement_enabled: true,
                ..Default::default()
            },
            policy: PolicyConfig {
                update_interval_seconds: 60, // More frequent in production
                ..Default::default()
            },
            nats_config: ExecutorNatsConfig::default(),
            ..Default::default()
        }
    }

    pub fn testing() -> Self {
        Self {
            work_root: PathBuf::from("/tmp/smith-test/work"),
            state_dir: PathBuf::from("/tmp/smith-test/state"),
            audit_dir: PathBuf::from("/tmp/smith-test/audit"),
            landlock_enabled: false,        // Disable for test simplicity
            metrics_port: None,             // Disable metrics in tests
            intent_streams: HashMap::new(), // Tests define their own
            security: SecurityConfig {
                strict_sandbox: false,
                network_isolation: false,
                jwt_issuers: vec![], // No JWT validation in tests
                ..Default::default()
            },
            limits: LimitsConfig {
                defaults: DefaultLimits {
                    cpu_ms_per_100ms: 100,         // Generous for test timing
                    mem_bytes: 1024 * 1024 * 1024, // 1GB
                    io_bytes: 100 * 1024 * 1024,   // 100MB
                    pids_max: 64,
                    tmpfs_mb: 128,
                    intent_max_bytes: 1024 * 1024, // 1MB
                },
                overrides: HashMap::new(),
            },
            capabilities: CapabilityConfig {
                enforcement_enabled: false, // Disable capability enforcement in tests
                ..Default::default()
            },
            nats_config: ExecutorNatsConfig::default(),
            ..Default::default()
        }
    }
}

impl IntentStreamConfig {
    pub fn validate(&self) -> Result<()> {
        if self.subject.is_empty() {
            return Err(anyhow::anyhow!("Subject cannot be empty"));
        }

        if self.workers == 0 {
            return Err(anyhow::anyhow!("Worker count must be > 0"));
        }

        if self.workers > 64 {
            return Err(anyhow::anyhow!("Worker count too high (max 64)"));
        }

        // Validate duration format
        self.validate_duration(&self.max_age)
            .context("Invalid max_age format")?;

        // Validate byte size format
        self.validate_byte_size(&self.max_bytes)
            .context("Invalid max_bytes format")?;

        Ok(())
    }

    fn validate_duration(&self, duration_str: &str) -> Result<()> {
        if duration_str.is_empty() {
            return Err(anyhow::anyhow!("Duration cannot be empty"));
        }

        let valid_suffixes = ["s", "m", "h", "d"];
        let has_valid_suffix = valid_suffixes
            .iter()
            .any(|&suffix| duration_str.ends_with(suffix));

        if !has_valid_suffix {
            return Err(anyhow::anyhow!(
                "Duration must end with valid time unit (s, m, h, d): {}",
                duration_str
            ));
        }

        let numeric_part = &duration_str[..duration_str.len() - 1];
        numeric_part
            .parse::<u64>()
            .with_context(|| format!("Invalid numeric part in duration: {}", duration_str))?;

        Ok(())
    }

    fn validate_byte_size(&self, size_str: &str) -> Result<()> {
        if size_str.is_empty() {
            return Err(anyhow::anyhow!("Byte size cannot be empty"));
        }

        let valid_suffixes = ["TB", "GB", "MB", "KB", "B"]; // Longest first
        let suffix = valid_suffixes
            .iter()
            .find(|&&suffix| size_str.ends_with(suffix))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Byte size must end with valid unit (B, KB, MB, GB, TB): {}",
                    size_str
                )
            })?;

        if let Some(numeric_part) = size_str.strip_suffix(suffix) {
            numeric_part
                .parse::<u64>()
                .with_context(|| format!("Invalid numeric part in byte size: {}", size_str))?;
        } else {
            return Err(anyhow::anyhow!("Failed to parse byte size: {}", size_str));
        }

        Ok(())
    }
}

impl ResultsConfig {
    pub fn validate(&self) -> Result<()> {
        if self.subject_prefix.is_empty() {
            return Err(anyhow::anyhow!("Results subject prefix cannot be empty"));
        }

        // Simple duration validation
        if !self.max_age.ends_with(['s', 'm', 'h', 'd']) {
            return Err(anyhow::anyhow!(
                "Results max_age must end with valid time unit (s, m, h, d): {}",
                self.max_age
            ));
        }

        Ok(())
    }
}

impl LimitsConfig {
    pub fn validate(&self) -> Result<()> {
        self.defaults
            .validate()
            .context("Default limits validation failed")?;

        for (capability, limits) in &self.overrides {
            limits.validate().map_err(|e| {
                anyhow::anyhow!(
                    "Limits override for '{}' validation failed: {}",
                    capability,
                    e
                )
            })?;
        }

        Ok(())
    }
}

impl DefaultLimits {
    pub fn validate(&self) -> Result<()> {
        if self.cpu_ms_per_100ms > 100 {
            return Err(anyhow::anyhow!("CPU limit cannot exceed 100ms per 100ms"));
        }

        if self.mem_bytes == 0 {
            return Err(anyhow::anyhow!("Memory limit cannot be zero"));
        }

        if self.mem_bytes > 8 * 1024 * 1024 * 1024 {
            tracing::warn!("Memory limit > 8GB may be excessive");
        }

        if self.pids_max == 0 || self.pids_max > 1024 {
            return Err(anyhow::anyhow!("PID limit must be between 1 and 1024"));
        }

        if self.tmpfs_mb > 1024 {
            tracing::warn!("tmpfs size > 1GB may consume excessive memory");
        }

        if self.intent_max_bytes > 10 * 1024 * 1024 {
            tracing::warn!("Intent max bytes > 10MB may cause memory issues");
        }

        Ok(())
    }
}

impl SecurityConfig {
    pub fn validate(&self) -> Result<()> {
        // Validate JWT issuers are valid URLs
        for issuer in &self.jwt_issuers {
            url::Url::parse(issuer)
                .with_context(|| format!("Invalid JWT issuer URL: {}", issuer))?;
        }

        // Validate allowed destinations
        for dest in &self.allowed_destinations {
            if dest.parse::<std::net::IpAddr>().is_err() && !dest.contains(':') {
                // Simple hostname validation
                if dest.is_empty() || dest.len() > 255 {
                    return Err(anyhow::anyhow!("Invalid destination: {}", dest));
                }
            }
        }

        Ok(())
    }
}

impl CapabilityConfig {
    pub fn validate(&self) -> Result<()> {
        if self.derivations_path.as_os_str().is_empty() {
            return Err(anyhow::anyhow!(
                "Capability derivations path cannot be empty"
            ));
        }

        Ok(())
    }
}

impl PolicyConfig {
    fn default_updates_subject() -> String {
        "smith.policies.updates".to_string()
    }

    pub fn validate(&self) -> Result<()> {
        if self.update_interval_seconds == 0 {
            return Err(anyhow::anyhow!("Policy update interval must be > 0"));
        }

        if self.update_interval_seconds < 60 {
            tracing::warn!("Policy update interval < 60s may cause excessive load");
        }

        if self.updates_subject.trim().is_empty() {
            return Err(anyhow::anyhow!("Policy updates subject cannot be empty"));
        }

        if let Some(queue) = &self.updates_queue {
            if queue.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "Policy updates queue group cannot be blank"
                ));
            }
        }

        Ok(())
    }
}

impl ExecutorNatsConfig {
    pub fn validate(&self) -> Result<()> {
        // Validate NATS servers format
        for server in &self.servers {
            if !server.starts_with("nats://") && !server.starts_with("tls://") {
                return Err(anyhow::anyhow!("Invalid NATS server URL: {}", server));
            }
        }

        // Validate TLS configuration consistency
        if let (Some(cert), Some(key), Some(ca)) = (&self.tls_cert, &self.tls_key, &self.tls_ca) {
            // All TLS files specified - validate they exist
            if !cert.exists() {
                return Err(anyhow::anyhow!(
                    "TLS cert file not found: {}",
                    cert.display()
                ));
            }
            if !key.exists() {
                return Err(anyhow::anyhow!("TLS key file not found: {}", key.display()));
            }
            if !ca.exists() {
                return Err(anyhow::anyhow!("TLS CA file not found: {}", ca.display()));
            }
        }

        Ok(())
    }
}

/// Policy derivations loaded from derivations.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDerivations {
    pub seccomp_allow: HashMap<String, Vec<String>>,
    pub landlock_paths: HashMap<String, LandlockProfile>,
    pub cgroups: HashMap<String, CgroupLimits>,
}

/// Landlock access profile for a capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LandlockProfile {
    /// Paths with read access
    pub read: Vec<String>,
    /// Paths with write access  
    pub write: Vec<String>,
}

/// Cgroup resource limits for a capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupLimits {
    /// CPU percentage limit
    pub cpu_pct: u32,
    /// Memory limit in MB
    pub mem_mb: u64,
}

impl ExecutorConfig {
    /// Convert byte size string to actual bytes
    pub fn parse_byte_size(size_str: &str) -> Result<u64> {
        let multipliers = [
            ("TB", 1024_u64.pow(4)),
            ("GB", 1024_u64.pow(3)),
            ("MB", 1024_u64.pow(2)),
            ("KB", 1024),
            ("B", 1),
        ];

        for (suffix, multiplier) in &multipliers {
            if let Some(numeric_part) = size_str.strip_suffix(suffix) {
                let number: u64 = numeric_part
                    .parse()
                    .with_context(|| format!("Invalid numeric part in byte size: {}", size_str))?;
                return Ok(number * multiplier);
            }
        }

        Err(anyhow::anyhow!("Invalid byte size format: {}", size_str))
    }

    /// Convert duration string to seconds
    pub fn parse_duration_seconds(duration_str: &str) -> Result<u64> {
        let multipliers = [
            ("d", 86400), // days
            ("h", 3600),  // hours
            ("m", 60),    // minutes
            ("s", 1),     // seconds
        ];

        for (suffix, multiplier) in &multipliers {
            if let Some(numeric_part) = duration_str.strip_suffix(suffix) {
                let number: u64 = numeric_part.parse().with_context(|| {
                    format!("Invalid numeric part in duration: {}", duration_str)
                })?;
                return Ok(number * multiplier);
            }
        }

        Err(anyhow::anyhow!("Invalid duration format: {}", duration_str))
    }

    /// Load configuration from TOML file
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let raw_value: toml::Value = toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML config: {}", path.display()))?;

        let mut config: ExecutorConfig = if let Some(executor_table) = raw_value.get("executor") {
            executor_table
                .clone()
                .try_into()
                .map_err(anyhow::Error::from)
                .with_context(|| {
                    format!(
                        "Failed to parse TOML config `[executor]` section: {}",
                        path.display()
                    )
                })?
        } else {
            toml::from_str(&content)
                .map_err(anyhow::Error::from)
                .with_context(|| {
                    format!(
                        "Failed to parse TOML config: {} (expected top-level executor fields \
                         or an `[executor]` table)",
                        path.display()
                    )
                })?
        };

        config.apply_env_overrides()?;
        config.validate()?;
        Ok(config)
    }

    fn apply_env_overrides(&mut self) -> Result<()> {
        if let Ok(raw_servers) = env::var("SMITH_EXECUTOR_NATS_SERVERS") {
            let servers = Self::parse_env_server_list(&raw_servers);
            if !servers.is_empty() {
                self.nats_config.servers = servers;
            }
        } else if let Ok(single) = env::var("SMITH_EXECUTOR_NATS_URL") {
            let trimmed = single.trim();
            if !trimmed.is_empty() {
                self.nats_config.servers = vec![trimmed.to_string()];
            }
        } else if let Ok(single) = env::var("SMITH_NATS_URL") {
            let trimmed = single.trim();
            if !trimmed.is_empty() {
                self.nats_config.servers = vec![trimmed.to_string()];
            }
        }

        if let Ok(domain) = env::var("SMITH_EXECUTOR_JETSTREAM_DOMAIN")
            .or_else(|_| env::var("SMITH_NATS_JETSTREAM_DOMAIN"))
            .or_else(|_| env::var("SMITH_JETSTREAM_DOMAIN"))
        {
            let trimmed = domain.trim();
            if !trimmed.is_empty() {
                self.nats_config.jetstream_domain = trimmed.to_string();
            }
        }

        Ok(())
    }

    fn parse_env_server_list(raw: &str) -> Vec<String> {
        raw.split(|c| c == ',' || c == ';')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(|part| part.to_string())
            .collect()
    }
}

impl PolicyDerivations {
    /// Load policy derivations from JSON file
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read derivations file: {}", path.display()))?;

        let derivations: PolicyDerivations = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse derivations JSON: {}", path.display()))?;

        Ok(derivations)
    }

    /// Get seccomp syscall allowlist for a capability
    pub fn get_seccomp_allowlist(&self, capability: &str) -> Option<&Vec<String>> {
        self.seccomp_allow.get(capability)
    }

    /// Get landlock paths configuration for a capability
    pub fn get_landlock_profile(&self, capability: &str) -> Option<&LandlockProfile> {
        self.landlock_paths.get(capability)
    }

    /// Get cgroup limits for a capability
    pub fn get_cgroup_limits(&self, capability: &str) -> Option<&CgroupLimits> {
        self.cgroups.get(capability)
    }
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            enable_capability_signing: true,
            enable_image_verification: true,
            enable_slsa_provenance: true,
            fail_on_signature_error: std::env::var("SMITH_FAIL_ON_SIGNATURE_ERROR")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            cosign_public_key: std::env::var("SMITH_COSIGN_PUBLIC_KEY").ok(),
            provenance_output_dir: PathBuf::from(
                std::env::var("SMITH_PROVENANCE_OUTPUT_DIR")
                    .unwrap_or_else(|_| "build/attestation".to_string()),
            ),
            verification_cache_ttl: 3600,        // 1 hour
            periodic_verification_interval: 300, // 5 minutes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_executor_config_creation() {
        let config = ExecutorConfig {
            node_name: "test-executor".to_string(),
            work_root: PathBuf::from("/tmp/work"),
            state_dir: PathBuf::from("/tmp/state"),
            audit_dir: PathBuf::from("/tmp/audit"),
            user_uid: 1000,
            user_gid: 1000,
            landlock_enabled: true,
            egress_proxy_socket: PathBuf::from("/tmp/proxy.sock"),
            metrics_port: Some(9090),
            intent_streams: HashMap::new(),
            results: ResultsConfig::default(),
            limits: LimitsConfig::default(),
            security: SecurityConfig::default(),
            capabilities: CapabilityConfig::default(),
            policy: PolicyConfig::default(),
            nats_config: ExecutorNatsConfig::default(),
            attestation: AttestationConfig::default(),
            vm_pool: VmPoolConfig::default(),
        };

        assert_eq!(config.node_name, "test-executor");
        assert_eq!(config.work_root, PathBuf::from("/tmp/work"));
        assert_eq!(config.user_uid, 1000);
        assert!(config.landlock_enabled);
        assert_eq!(config.metrics_port, Some(9090));
    }

    #[test]
    fn test_intent_stream_config() {
        let stream_config = IntentStreamConfig {
            subject: "smith.intents.test".to_string(),
            max_age: "1h".to_string(),
            max_bytes: "10MB".to_string(),
            workers: 4,
        };

        assert_eq!(stream_config.subject, "smith.intents.test");
        assert_eq!(stream_config.max_age, "1h");
        assert_eq!(stream_config.max_bytes, "10MB");
        assert_eq!(stream_config.workers, 4);
    }

    #[test]
    fn test_intent_stream_config_validation() {
        let mut config = IntentStreamConfig {
            subject: "smith.intents.test".to_string(),
            max_age: "1h".to_string(),
            max_bytes: "1GB".to_string(), // Use GB as in the default config
            workers: 4,
        };

        assert!(config.validate().is_ok());

        // Test empty subject
        config.subject = "".to_string();
        assert!(config.validate().is_err());
        config.subject = "smith.intents.test".to_string(); // Fix it

        // Test zero workers
        config.workers = 0;
        assert!(config.validate().is_err());

        // Test too many workers
        config.workers = 100;
        assert!(config.validate().is_err());

        // Test valid workers
        config.workers = 32;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_results_config_default() {
        let results_config = ResultsConfig::default();

        assert_eq!(results_config.subject_prefix, "smith.results."); // Includes trailing dot
        assert_eq!(results_config.max_age, "5m"); // Correct default max_age
    }

    #[test]
    fn test_limits_config_default() {
        let limits_config = LimitsConfig::default();

        // Just verify the structure exists and has defaults
        assert_eq!(limits_config.overrides.len(), 0); // Empty by default
                                                      // The actual defaults are in the impl
    }

    #[test]
    fn test_default_limits_validation() {
        let mut limits = DefaultLimits::default();
        assert!(limits.validate().is_ok());

        // Test CPU limit validation
        limits.cpu_ms_per_100ms = 150; // > 100
        assert!(limits.validate().is_err());
        limits.cpu_ms_per_100ms = 50; // Valid

        // Test memory limit validation
        limits.mem_bytes = 0; // Invalid
        assert!(limits.validate().is_err());
        limits.mem_bytes = 64 * 1024 * 1024; // Valid

        // Test PID limit validation
        limits.pids_max = 0; // Invalid
        assert!(limits.validate().is_err());
        limits.pids_max = 2000; // > 1024, invalid
        assert!(limits.validate().is_err());
        limits.pids_max = 64; // Valid

        assert!(limits.validate().is_ok());
    }

    #[test]
    fn test_security_config_validation() {
        let mut security_config = SecurityConfig::default();
        assert!(security_config.validate().is_ok());

        // Test invalid JWT issuer
        security_config.jwt_issuers = vec!["invalid-url".to_string()];
        assert!(security_config.validate().is_err());

        // Test valid JWT issuer
        security_config.jwt_issuers = vec!["https://auth.example.com".to_string()];
        assert!(security_config.validate().is_ok());

        // Test allowed destinations validation
        security_config.allowed_destinations =
            vec!["192.168.1.1".to_string(), "example.com".to_string()];
        assert!(security_config.validate().is_ok());

        // Test invalid destination (empty string)
        security_config.allowed_destinations = vec!["".to_string()];
        assert!(security_config.validate().is_err());

        // Test invalid destination (too long)
        security_config.allowed_destinations = vec!["a".repeat(256)];
        assert!(security_config.validate().is_err());
    }

    #[test]
    fn test_policy_config_validation() {
        let mut policy_config = PolicyConfig::default();
        assert!(policy_config.validate().is_ok());

        // Test zero update interval (invalid)
        policy_config.update_interval_seconds = 0;
        assert!(policy_config.validate().is_err());

        // Test valid update interval
        policy_config.update_interval_seconds = 300;
        assert!(policy_config.validate().is_ok());
    }

    #[test]
    fn test_executor_nats_config_validation() {
        let mut nats_config = ExecutorNatsConfig {
            servers: vec!["nats://127.0.0.1:4222".to_string()],
            jetstream_domain: "JS".to_string(),
            tls_cert: None, // No TLS files for testing
            tls_key: None,
            tls_ca: None,
        };
        assert!(nats_config.validate().is_ok());

        // Test invalid server URL
        nats_config.servers = vec!["invalid-url".to_string()];
        assert!(nats_config.validate().is_err());

        // Test valid server URLs
        nats_config.servers = vec![
            "nats://localhost:4222".to_string(),
            "tls://nats.example.com:4222".to_string(),
        ];
        assert!(nats_config.validate().is_ok());
    }

    #[test]
    fn test_executor_nats_config_tls_validation() {
        let temp_dir = tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        let ca_path = temp_dir.path().join("ca.pem");

        // Create dummy files
        std::fs::write(&cert_path, "cert").unwrap();
        std::fs::write(&key_path, "key").unwrap();
        std::fs::write(&ca_path, "ca").unwrap();

        let valid_config = ExecutorNatsConfig {
            tls_cert: Some(cert_path.clone()),
            tls_key: Some(key_path.clone()),
            tls_ca: Some(ca_path.clone()),
            ..ExecutorNatsConfig::default()
        };
        assert!(valid_config.validate().is_ok());

        let missing_cert = ExecutorNatsConfig {
            tls_cert: Some(temp_dir.path().join("missing.pem")),
            tls_key: Some(key_path.clone()),
            tls_ca: Some(ca_path.clone()),
            ..ExecutorNatsConfig::default()
        };
        assert!(missing_cert.validate().is_err());

        let missing_key = ExecutorNatsConfig {
            tls_cert: Some(cert_path),
            tls_key: Some(temp_dir.path().join("missing.pem")),
            tls_ca: Some(ca_path),
            ..ExecutorNatsConfig::default()
        };
        assert!(missing_key.validate().is_err());
    }

    #[test]
    #[ignore] // requires infra/config/smith-executor.toml from deployment repo
    fn test_repo_executor_config_loads() {
        let path = PathBuf::from("../../infra/config/smith-executor.toml");
        let result = ExecutorConfig::load(&path);
        assert!(result.is_ok(), "error: {:?}", result.unwrap_err());
    }

    #[test]
    fn test_executor_env_overrides_nats_servers() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("executor.toml");

        let mut config = ExecutorConfig::development();
        config.work_root = temp_dir.path().join("work");
        config.state_dir = temp_dir.path().join("state");
        config.audit_dir = temp_dir.path().join("audit");
        config.egress_proxy_socket = temp_dir.path().join("proxy.sock");
        config.security.pubkeys_dir = temp_dir.path().join("pubkeys");
        config.capabilities.derivations_path = temp_dir.path().join("capability.json");
        config.attestation.provenance_output_dir = temp_dir.path().join("attestation_outputs");
        config.nats_config.tls_cert = None;
        config.nats_config.tls_key = None;
        config.nats_config.tls_ca = None;

        let toml = toml::to_string(&config).unwrap();
        std::fs::write(&config_path, toml).unwrap();

        let prev_servers = env::var("SMITH_EXECUTOR_NATS_SERVERS").ok();
        let prev_exec_url = env::var("SMITH_EXECUTOR_NATS_URL").ok();
        let prev_nats_url = env::var("SMITH_NATS_URL").ok();
        let prev_domain = env::var("SMITH_NATS_JETSTREAM_DOMAIN").ok();
        let prev_exec_domain = env::var("SMITH_EXECUTOR_JETSTREAM_DOMAIN").ok();

        env::remove_var("SMITH_EXECUTOR_NATS_SERVERS");
        env::remove_var("SMITH_EXECUTOR_NATS_URL");
        env::remove_var("SMITH_NATS_URL");
        env::remove_var("SMITH_NATS_JETSTREAM_DOMAIN");
        env::remove_var("SMITH_EXECUTOR_JETSTREAM_DOMAIN");

        env::set_var(
            "SMITH_EXECUTOR_NATS_SERVERS",
            "nats://localhost:7222, nats://backup:7223",
        );
        env::set_var("SMITH_NATS_JETSTREAM_DOMAIN", "devtools");

        let loaded = ExecutorConfig::load(&config_path).unwrap();
        assert_eq!(
            loaded.nats_config.servers,
            vec![
                "nats://localhost:7222".to_string(),
                "nats://backup:7223".to_string()
            ]
        );
        assert_eq!(loaded.nats_config.jetstream_domain, "devtools");

        restore_env_var("SMITH_EXECUTOR_NATS_SERVERS", prev_servers);
        restore_env_var("SMITH_EXECUTOR_NATS_URL", prev_exec_url);
        restore_env_var("SMITH_NATS_URL", prev_nats_url);
        restore_env_var("SMITH_NATS_JETSTREAM_DOMAIN", prev_domain);
        restore_env_var("SMITH_EXECUTOR_JETSTREAM_DOMAIN", prev_exec_domain);
    }

    #[test]
    fn test_attestation_config_default() {
        let attestation_config = AttestationConfig::default();

        assert!(attestation_config.enable_capability_signing);
        assert!(attestation_config.enable_image_verification);
        assert!(attestation_config.enable_slsa_provenance);
        assert_eq!(attestation_config.verification_cache_ttl, 3600);
        assert_eq!(attestation_config.periodic_verification_interval, 300);
    }

    #[test]
    fn test_cgroup_limits() {
        let cgroup_limits = CgroupLimits {
            cpu_pct: 50,
            mem_mb: 128,
        };

        assert_eq!(cgroup_limits.cpu_pct, 50);
        assert_eq!(cgroup_limits.mem_mb, 128);
    }

    #[test]
    fn test_executor_config_presets() {
        // Test development preset
        let dev_config = ExecutorConfig::development();
        assert_eq!(dev_config.node_name, "exec-01"); // Uses default node_name
        assert!(!dev_config.landlock_enabled);
        assert!(!dev_config.security.strict_sandbox);

        // Test production preset
        let prod_config = ExecutorConfig::production();
        assert!(prod_config.landlock_enabled);
        assert!(prod_config.security.strict_sandbox);
        assert!(prod_config.security.network_isolation);
        assert!(prod_config.capabilities.enforcement_enabled);

        // Test testing preset
        let test_config = ExecutorConfig::testing();
        assert!(!test_config.landlock_enabled);
        assert!(!test_config.security.strict_sandbox);
        assert!(!test_config.capabilities.enforcement_enabled);
        assert_eq!(test_config.metrics_port, None);
    }

    #[test]
    fn test_parse_byte_size() {
        assert_eq!(ExecutorConfig::parse_byte_size("1024B").unwrap(), 1024);
        assert_eq!(ExecutorConfig::parse_byte_size("10KB").unwrap(), 10 * 1024);
        assert_eq!(
            ExecutorConfig::parse_byte_size("5MB").unwrap(),
            5 * 1024 * 1024
        );
        assert_eq!(
            ExecutorConfig::parse_byte_size("2GB").unwrap(),
            2 * 1024 * 1024 * 1024
        );

        // Test invalid formats
        assert!(ExecutorConfig::parse_byte_size("invalid").is_err());
        assert!(ExecutorConfig::parse_byte_size("10XB").is_err());
        assert!(ExecutorConfig::parse_byte_size("").is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let original = ExecutorConfig {
            node_name: "test-node".to_string(),
            work_root: PathBuf::from("/work"),
            state_dir: PathBuf::from("/state"),
            audit_dir: PathBuf::from("/audit"),
            user_uid: 1001,
            user_gid: 1001,
            landlock_enabled: false,
            egress_proxy_socket: PathBuf::from("/proxy.sock"),
            metrics_port: Some(8080),
            intent_streams: HashMap::new(),
            results: ResultsConfig::default(),
            limits: LimitsConfig::default(),
            security: SecurityConfig::default(),
            capabilities: CapabilityConfig::default(),
            policy: PolicyConfig::default(),
            nats_config: ExecutorNatsConfig::default(),
            attestation: AttestationConfig::default(),
            vm_pool: VmPoolConfig::default(),
        };

        // Test JSON serialization roundtrip
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: ExecutorConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(original.node_name, deserialized.node_name);
        assert_eq!(original.work_root, deserialized.work_root);
        assert_eq!(original.user_uid, deserialized.user_uid);
        assert_eq!(original.landlock_enabled, deserialized.landlock_enabled);
        assert_eq!(original.metrics_port, deserialized.metrics_port);
    }

    #[test]
    fn test_debug_formatting() {
        let config = ExecutorConfig {
            node_name: "debug-test".to_string(),
            work_root: PathBuf::from("/work"),
            state_dir: PathBuf::from("/state"),
            audit_dir: PathBuf::from("/audit"),
            user_uid: 1000,
            user_gid: 1000,
            landlock_enabled: true,
            egress_proxy_socket: PathBuf::from("/proxy.sock"),
            metrics_port: Some(9090),
            intent_streams: HashMap::new(),
            results: ResultsConfig::default(),
            limits: LimitsConfig::default(),
            security: SecurityConfig::default(),
            capabilities: CapabilityConfig::default(),
            policy: PolicyConfig::default(),
            nats_config: ExecutorNatsConfig::default(),
            attestation: AttestationConfig::default(),
            vm_pool: VmPoolConfig::default(),
        };

        let debug_output = format!("{:?}", config);
        assert!(debug_output.contains("debug-test"));
        assert!(debug_output.contains("/work"));
        assert!(debug_output.contains("1000"));
    }

    fn restore_env_var(name: &str, value: Option<String>) {
        if let Some(value) = value {
            env::set_var(name, value);
        } else {
            env::remove_var(name);
        }
    }
}
