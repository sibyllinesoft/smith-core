//! Ingest adapter traits for pluggable message transport
//!
//! This module defines the core traits for ingest adapters that receive
//! execution requests. Implementations include:
//! - `GrpcAdapter`: Primary direct mode using tonic
//! - `NatsAdapter`: NATS JetStream for distributed queue processing
//! - `HttpAdapter`: REST API using axum
//! - `UnixAdapter`: Unix domain socket for local IPC
//! - `StdioAdapter`: stdin/stdout JSON-RPC for embedding

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::intent::{IntentRequest, IntentResponse};

/// Health status of an adapter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    /// Adapter is healthy and accepting requests
    Healthy,
    /// Adapter is degraded but still accepting some requests
    Degraded { reason: String },
    /// Adapter is unhealthy and not accepting requests
    Unhealthy { reason: String },
    /// Adapter is starting up
    Starting,
    /// Adapter is shutting down
    Stopping,
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded { .. })
    }
}

/// Statistics for an ingest adapter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdapterStats {
    /// Total requests received
    pub requests_received: u64,

    /// Requests currently being processed
    pub requests_in_flight: u64,

    /// Total requests completed successfully
    pub requests_succeeded: u64,

    /// Total requests that failed
    pub requests_failed: u64,

    /// Average request latency in milliseconds
    pub avg_latency_ms: f64,

    /// 95th percentile latency in milliseconds
    pub p95_latency_ms: f64,

    /// 99th percentile latency in milliseconds
    pub p99_latency_ms: f64,

    /// Bytes received
    pub bytes_received: u64,

    /// Bytes sent
    pub bytes_sent: u64,

    /// Number of active connections (for connection-oriented adapters)
    pub active_connections: u64,

    /// Adapter-specific metrics
    pub custom_metrics: Vec<(String, f64)>,
}

/// Context for handling intent requests
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Unique request identifier
    pub request_id: String,

    /// Source adapter name
    pub source_adapter: String,

    /// Client identifier (IP, peer credentials, etc.)
    pub client_id: String,

    /// When the request was received
    pub received_at: chrono::DateTime<chrono::Utc>,

    /// Reply channel identifier (adapter-specific)
    pub reply_to: Option<String>,

    /// Whether streaming responses are supported for this request
    pub supports_streaming: bool,

    /// Request metadata (headers, attributes, etc.)
    pub metadata: Vec<(String, String)>,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            source_adapter: String::new(),
            client_id: String::new(),
            received_at: chrono::Utc::now(),
            reply_to: None,
            supports_streaming: false,
            metadata: vec![],
        }
    }
}

/// Trait for handling intent requests
///
/// This is implemented by the core agentd runtime and passed to adapters
#[async_trait]
pub trait IntentHandler: Send + Sync {
    /// Handle an incoming intent request
    ///
    /// The handler is responsible for:
    /// - Authentication and authorization
    /// - Policy evaluation
    /// - Sandbox creation/selection
    /// - Command execution
    /// - Result formatting
    async fn handle(&self, request: IntentRequest, ctx: RequestContext) -> Result<IntentResponse>;

    /// Handle a streaming request (for long-running commands)
    ///
    /// Returns a stream of output chunks followed by a final response
    async fn handle_streaming(
        &self,
        request: IntentRequest,
        ctx: RequestContext,
        output_tx: tokio::sync::mpsc::Sender<OutputChunk>,
    ) -> Result<IntentResponse>;

    /// Check if a capability is supported
    async fn supports_capability(&self, capability: &str) -> bool;

    /// List all supported capabilities
    async fn list_capabilities(&self) -> Vec<CapabilityInfo>;

    /// Get the current health status
    async fn health(&self) -> HealthStatus;
}

/// Output chunk for streaming responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputChunk {
    /// Stdout data
    Stdout(Vec<u8>),
    /// Stderr data
    Stderr(Vec<u8>),
    /// Progress update
    Progress { percent: f32, message: String },
    /// Log message
    Log { level: String, message: String },
    /// Execution completed
    Done,
}

/// Information about a supported capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityInfo {
    /// Capability identifier (e.g., "fs.read.v1")
    pub name: String,

    /// Human-readable description
    pub description: String,

    /// Version number
    pub version: u32,

    /// JSON schema for parameters
    pub param_schema: Option<serde_json::Value>,

    /// Whether this capability requires special permissions
    pub requires_elevated: bool,

    /// Whether this capability supports streaming output
    pub supports_streaming: bool,

    /// Tags for categorization
    pub tags: Vec<String>,
}

/// Trait for ingest adapters that receive requests
#[async_trait]
pub trait IngestAdapter: Send + Sync {
    /// Get the name of this adapter
    fn name(&self) -> &str;

    /// Start the adapter with the given intent handler
    ///
    /// This should start listening for requests and dispatching them
    /// to the handler. Returns when the adapter has started successfully.
    async fn start(&self, handler: Arc<dyn IntentHandler>) -> Result<()>;

    /// Stop the adapter gracefully
    ///
    /// This should:
    /// 1. Stop accepting new requests
    /// 2. Wait for in-flight requests to complete (with timeout)
    /// 3. Release resources
    async fn stop(&self) -> Result<()>;

    /// Check the health of the adapter
    async fn health(&self) -> HealthStatus;

    /// Get current statistics
    async fn stats(&self) -> AdapterStats;

    /// Check if the adapter is currently running
    fn is_running(&self) -> bool;

    /// Get adapter-specific configuration info
    fn config_info(&self) -> AdapterConfigInfo;
}

/// Adapter configuration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfigInfo {
    /// Adapter type (e.g., "grpc", "nats", "http")
    pub adapter_type: String,

    /// Listen address (if applicable)
    pub listen_address: Option<String>,

    /// Remote server address (if applicable)
    pub remote_address: Option<String>,

    /// Whether TLS is enabled
    pub tls_enabled: bool,

    /// Authentication methods supported
    pub auth_methods: Vec<String>,

    /// Maximum concurrent requests
    pub max_concurrent: Option<u32>,

    /// Additional configuration details
    pub extra: Vec<(String, String)>,
}

/// Builder pattern for creating adapters (optional convenience)
pub struct AdapterBuilder {
    adapter_type: String,
    listen_address: Option<String>,
    tls_config: Option<TlsConfig>,
    auth_config: Option<AuthConfig>,
    max_concurrent: Option<u32>,
}

/// TLS configuration for adapters
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: String,
    /// Path to key file
    pub key_path: String,
    /// Path to CA certificate (for mTLS)
    pub ca_path: Option<String>,
    /// Whether to require client certificates
    pub require_client_cert: bool,
}

/// Authentication configuration for adapters
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Enabled authentication methods
    pub methods: Vec<String>,
    /// JWT validation settings
    pub jwt_config: Option<JwtConfig>,
    /// API key validation settings
    pub api_key_config: Option<ApiKeyConfig>,
}

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Expected issuer
    pub issuer: Option<String>,
    /// Expected audience
    pub audience: Option<String>,
    /// Public key or JWKS URL for verification
    pub verification_key: String,
}

/// API key configuration
#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    /// Header name for API key
    pub header_name: String,
    /// Prefix to strip (e.g., "Bearer ")
    pub prefix: Option<String>,
}

impl AdapterBuilder {
    pub fn new(adapter_type: &str) -> Self {
        Self {
            adapter_type: adapter_type.to_string(),
            listen_address: None,
            tls_config: None,
            auth_config: None,
            max_concurrent: None,
        }
    }

    pub fn listen(mut self, address: &str) -> Self {
        self.listen_address = Some(address.to_string());
        self
    }

    pub fn with_tls(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    pub fn with_auth(mut self, config: AuthConfig) -> Self {
        self.auth_config = Some(config);
        self
    }

    pub fn max_concurrent(mut self, max: u32) -> Self {
        self.max_concurrent = Some(max);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_is_healthy() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(HealthStatus::Degraded {
            reason: "test".to_string()
        }
        .is_healthy());
        assert!(!HealthStatus::Unhealthy {
            reason: "test".to_string()
        }
        .is_healthy());
        assert!(!HealthStatus::Starting.is_healthy());
        assert!(!HealthStatus::Stopping.is_healthy());
    }

    #[test]
    fn test_health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_eq!(HealthStatus::Starting, HealthStatus::Starting);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Starting);
    }

    #[test]
    fn test_adapter_stats_default() {
        let stats = AdapterStats::default();
        assert_eq!(stats.requests_received, 0);
        assert_eq!(stats.requests_in_flight, 0);
        assert_eq!(stats.requests_succeeded, 0);
        assert_eq!(stats.requests_failed, 0);
        assert_eq!(stats.avg_latency_ms, 0.0);
        assert_eq!(stats.p95_latency_ms, 0.0);
        assert_eq!(stats.p99_latency_ms, 0.0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.active_connections, 0);
        assert!(stats.custom_metrics.is_empty());
    }

    #[test]
    fn test_request_context_default() {
        let ctx = RequestContext::default();
        assert!(!ctx.request_id.is_empty());
        assert!(ctx.source_adapter.is_empty());
        assert!(ctx.client_id.is_empty());
        assert!(ctx.reply_to.is_none());
        assert!(!ctx.supports_streaming);
        assert!(ctx.metadata.is_empty());
    }

    #[test]
    fn test_output_chunk_variants() {
        let stdout = OutputChunk::Stdout(vec![1, 2, 3]);
        let stderr = OutputChunk::Stderr(vec![4, 5, 6]);
        let progress = OutputChunk::Progress {
            percent: 50.0,
            message: "halfway".to_string(),
        };
        let log = OutputChunk::Log {
            level: "info".to_string(),
            message: "test".to_string(),
        };
        let done = OutputChunk::Done;

        // Just verify we can create and clone them
        let _ = stdout.clone();
        let _ = stderr.clone();
        let _ = progress.clone();
        let _ = log.clone();
        let _ = done.clone();
    }

    #[test]
    fn test_capability_info_creation() {
        let info = CapabilityInfo {
            name: "fs.read.v1".to_string(),
            description: "Read files".to_string(),
            version: 1,
            param_schema: None,
            requires_elevated: false,
            supports_streaming: false,
            tags: vec!["filesystem".to_string()],
        };
        assert_eq!(info.name, "fs.read.v1");
        assert_eq!(info.version, 1);
    }

    #[test]
    fn test_adapter_config_info_creation() {
        let info = AdapterConfigInfo {
            adapter_type: "grpc".to_string(),
            listen_address: Some("0.0.0.0:9500".to_string()),
            remote_address: None,
            tls_enabled: true,
            auth_methods: vec!["jwt".to_string()],
            max_concurrent: Some(100),
            extra: vec![],
        };
        assert_eq!(info.adapter_type, "grpc");
        assert!(info.tls_enabled);
    }

    #[test]
    fn test_adapter_builder() {
        let builder = AdapterBuilder::new("grpc")
            .listen("0.0.0.0:9500")
            .max_concurrent(100);

        assert_eq!(builder.adapter_type, "grpc");
        assert_eq!(builder.listen_address, Some("0.0.0.0:9500".to_string()));
        assert_eq!(builder.max_concurrent, Some(100));
    }

    #[test]
    fn test_adapter_builder_with_tls() {
        let tls_config = TlsConfig {
            cert_path: "/path/to/cert".to_string(),
            key_path: "/path/to/key".to_string(),
            ca_path: Some("/path/to/ca".to_string()),
            require_client_cert: true,
        };

        let builder = AdapterBuilder::new("grpc").with_tls(tls_config);

        assert!(builder.tls_config.is_some());
        let tls = builder.tls_config.unwrap();
        assert_eq!(tls.cert_path, "/path/to/cert");
        assert!(tls.require_client_cert);
    }

    #[test]
    fn test_adapter_builder_with_auth() {
        let auth_config = AuthConfig {
            methods: vec!["jwt".to_string()],
            jwt_config: Some(JwtConfig {
                issuer: Some("test-issuer".to_string()),
                audience: Some("test-audience".to_string()),
                verification_key: "test-key".to_string(),
            }),
            api_key_config: None,
        };

        let builder = AdapterBuilder::new("http").with_auth(auth_config);

        assert!(builder.auth_config.is_some());
    }

    #[test]
    fn test_tls_config_creation() {
        let config = TlsConfig {
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
            ca_path: None,
            require_client_cert: false,
        };
        assert_eq!(config.cert_path, "cert.pem");
        assert!(!config.require_client_cert);
    }

    #[test]
    fn test_api_key_config_creation() {
        let config = ApiKeyConfig {
            header_name: "X-API-Key".to_string(),
            prefix: Some("Bearer ".to_string()),
        };
        assert_eq!(config.header_name, "X-API-Key");
        assert_eq!(config.prefix, Some("Bearer ".to_string()));
    }
}
