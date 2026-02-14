use anyhow::Result;
use async_trait::async_trait;
use smith_protocol::{CapabilitySpec, ExecutionError, ExecutionLimits, Intent};
use std::collections::HashMap;

/// Core capability trait for intent execution
#[async_trait]
pub trait Capability: Send + Sync {
    /// Get capability name (e.g., "fs.read.v1")
    fn name(&self) -> &'static str;

    /// Validate intent parameters against capability schema and policy
    fn validate(&self, intent: &Intent) -> Result<(), ExecutionError>;

    /// Execute the intent with the given context
    async fn execute(
        &self,
        intent: Intent,
        ctx: ExecCtx,
    ) -> Result<CapabilityResult, ExecutionError>;

    /// Get capability specification for discovery and documentation
    fn describe(&self) -> CapabilitySpec;
}

/// Execution context for capabilities
#[derive(Debug, Clone)]
pub struct ExecCtx {
    /// Working directory for execution
    pub workdir: std::path::PathBuf,
    /// Resource limits
    pub limits: ExecutionLimits,
    /// Allowed resources (paths, URLs, etc.)
    pub scope: ExecutionScope,
    /// Trace ID for logging correlation
    pub trace_id: String,
    /// Sandbox configuration
    pub sandbox: SandboxConfig,
}

/// Execution scope defining allowed resources
#[derive(Debug, Clone)]
pub struct ExecutionScope {
    /// Allowed file paths
    pub paths: Vec<String>,
    /// Allowed URLs
    pub urls: Vec<String>,
    /// Allowed environment variables
    pub env_vars: Vec<String>,
    /// Additional scope parameters
    pub custom: HashMap<String, serde_json::Value>,
}

/// Sandbox configuration
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Sandbox mode
    pub mode: smith_protocol::SandboxMode,
    /// Enable Landlock LSM
    pub landlock_enabled: bool,
    /// Enable seccomp-bpf
    pub seccomp_enabled: bool,
    /// Enable cgroups v2
    pub cgroups_enabled: bool,
    /// Enable user/mount/pid/net namespaces
    pub namespaces_enabled: bool,
}

/// Result of capability execution
#[derive(Debug, Clone)]
pub struct CapabilityResult {
    /// Execution status
    pub status: smith_protocol::ExecutionStatus,
    /// Output data (JSON)
    pub output: Option<serde_json::Value>,
    /// Error details if failed
    pub error: Option<ExecutionError>,
    /// Execution metadata
    pub metadata: ExecutionMetadata,
    /// Resource usage during execution
    pub resource_usage: smith_protocol::ResourceUsage,
}

/// Execution metadata
#[derive(Debug, Clone)]
pub struct ExecutionMetadata {
    /// Process ID used for execution
    pub pid: u32,
    /// Exit code (if applicable)
    pub exit_code: Option<i32>,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Stdout bytes captured
    pub stdout_bytes: u64,
    /// Stderr bytes captured
    pub stderr_bytes: u64,
    /// Files created/modified
    pub artifacts: Vec<Artifact>,
}

/// Execution artifact
#[derive(Debug, Clone)]
pub struct Artifact {
    /// Artifact name
    pub name: String,
    /// File path
    pub path: std::path::PathBuf,
    /// File size in bytes
    pub size: u64,
    /// SHA256 hash
    pub sha256: String,
}

/// Registry for managing capabilities
pub struct CapabilityRegistry {
    capabilities: HashMap<String, Box<dyn Capability>>,
}

impl CapabilityRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {
            capabilities: HashMap::new(),
        }
    }

    /// Register a capability
    pub fn register(&mut self, capability: Box<dyn Capability>) {
        let name = capability.name().to_string();
        self.capabilities.insert(name.clone(), capability);
        tracing::info!("Registered capability: {}", name);
    }

    /// Get capability by name
    pub fn get(&self, name: &str) -> Option<&dyn Capability> {
        self.capabilities.get(name).map(|c| c.as_ref())
    }

    /// List all registered capability names
    pub fn list(&self) -> Vec<String> {
        self.capabilities.keys().cloned().collect()
    }

    /// Get capability specifications for discovery
    pub fn describe_all(&self) -> Vec<CapabilitySpec> {
        self.capabilities.values().map(|c| c.describe()).collect()
    }

    /// Validate intent against capability
    pub fn validate_intent(&self, intent: &Intent) -> Result<(), ExecutionError> {
        let capability_name = intent.capability.to_string();

        match self.get(&capability_name) {
            Some(capability) => capability.validate(intent),
            None => Err(ExecutionError {
                code: "CAPABILITY_NOT_FOUND".to_string(),
                message: format!("No capability found for: {}", capability_name),
            }),
        }
    }

    /// Execute intent with appropriate capability
    pub async fn execute_intent(
        &self,
        intent: Intent,
        ctx: ExecCtx,
    ) -> Result<CapabilityResult, ExecutionError> {
        let capability_name = intent.capability.to_string();

        match self.get(&capability_name) {
            Some(capability) => capability.execute(intent, ctx).await,
            None => Err(ExecutionError {
                code: "CAPABILITY_NOT_FOUND".to_string(),
                message: format!("No capability found for: {}", capability_name),
            }),
        }
    }
}

impl Default for ExecutionScope {
    fn default() -> Self {
        Self {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: smith_protocol::SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use smith_protocol::ResourceRequirements;

    struct TestCapability;

    #[async_trait]
    impl Capability for TestCapability {
        fn name(&self) -> &'static str {
            "test.v1"
        }

        fn validate(&self, _intent: &Intent) -> Result<(), ExecutionError> {
            Ok(())
        }

        async fn execute(
            &self,
            _intent: Intent,
            _ctx: ExecCtx,
        ) -> Result<CapabilityResult, ExecutionError> {
            Ok(CapabilityResult {
                status: smith_protocol::ExecutionStatus::Ok,
                output: Some(json!({"result": "success"})),
                error: None,
                metadata: ExecutionMetadata {
                    pid: 12345,
                    exit_code: Some(0),
                    duration_ms: 100,
                    stdout_bytes: 10,
                    stderr_bytes: 0,
                    artifacts: vec![],
                },
                resource_usage: smith_protocol::ResourceUsage {
                    peak_memory_kb: 1024,
                    cpu_time_ms: 50,
                    wall_time_ms: 100,
                    fd_count: 3,
                    disk_read_bytes: 0,
                    disk_write_bytes: 0,
                    network_tx_bytes: 0,
                    network_rx_bytes: 0,
                },
            })
        }

        fn describe(&self) -> CapabilitySpec {
            CapabilitySpec {
                name: self.name().to_string(),
                description: "Test capability for unit tests".to_string(),
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "test_param": {"type": "string"}
                    }
                }),
                example_params: json!({"test_param": "example"}),
                resource_requirements: ResourceRequirements {
                    cpu_ms_typical: 50,
                    memory_kb_max: 1024,
                    network_access: false,
                    filesystem_access: false,
                    external_commands: false,
                },
                security_notes: vec!["Safe test capability with no external access".to_string()],
            }
        }
    }

    #[test]
    fn test_capability_registry() {
        let mut registry = CapabilityRegistry::new();

        registry.register(Box::new(TestCapability));

        assert!(registry.get("test.v1").is_some());
        assert!(registry.get("nonexistent").is_none());

        let capabilities = registry.list();
        assert_eq!(capabilities.len(), 1);
        assert!(capabilities.contains(&"test.v1".to_string()));
    }

    #[test]
    fn test_execution_limits_default() {
        let limits = ExecutionLimits::default();

        assert_eq!(limits.cpu_ms_per_100ms, 50);
        assert_eq!(limits.mem_bytes, 128 * 1024 * 1024);
        assert_eq!(limits.timeout_ms, 30000);
    }

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();

        assert_eq!(config.mode, smith_protocol::SandboxMode::Full);
        assert!(config.landlock_enabled);
        assert!(config.seccomp_enabled);
        assert!(config.cgroups_enabled);
    }
}
