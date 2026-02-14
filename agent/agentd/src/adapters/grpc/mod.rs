//! gRPC ingest adapter using tonic
//!
//! This adapter provides direct mode communication using gRPC, supporting
//! both unary and streaming execution requests. It's the primary adapter
//! for workstation mode where clients connect directly to agentd.

use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info};
use uuid::Uuid;

use crate::core::ingest::{
    AdapterConfigInfo, AdapterStats, HealthStatus, IngestAdapter, IntentHandler, OutputChunk,
    RequestContext,
};
use crate::core::intent::Command;
use crate::core::intent::{
    IntentRequest, IntentResponse, IntentStatus, RequestConstraints, RequestMetadata,
    SandboxPreferences,
};
use crate::core::isolation::{
    ExecContext as SandboxExecContext, ResourceLimits as CoreResourceLimits, SandboxSpec,
};
use crate::core::sandbox::{SandboxId, SandboxManager, SandboxSelectionOptions};

// Include generated proto code
pub mod proto {
    tonic::include_proto!("agentd.v1");
}

use proto::agentd_server::{Agentd, AgentdServer};
use proto::{
    AttachSandboxRequest, AttachSandboxResponse, CreateSandboxRequest, CreateSandboxResponse,
    EditFileRequest, EditFileResponse, ExecuteOutput, ExecuteRequest, ExecuteResponse,
    ExecutionResult, ExecutionStatus, GetSandboxCapabilitiesRequest, HealthRequest, HealthResponse,
    ListCapabilitiesRequest, ListCapabilitiesResponse, ListSandboxesRequest, ListSandboxesResponse,
    ReadFileRequest, ReadFileResponse, SandboxCapabilities, TerminateSandboxRequest,
    TerminateSandboxResponse, WriteFileRequest, WriteFileResponse,
};

/// Configuration for the gRPC adapter
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Listen address (e.g., "0.0.0.0:9500")
    pub listen_address: SocketAddr,

    /// TLS certificate path (optional)
    pub tls_cert_path: Option<String>,

    /// TLS key path (optional)
    pub tls_key_path: Option<String>,

    /// Maximum concurrent streams
    pub max_concurrent_streams: Option<u32>,

    /// Maximum frame size
    pub max_frame_size: Option<u32>,

    /// Connection keepalive interval in seconds
    pub keepalive_interval_secs: Option<u64>,

    /// Request timeout in seconds
    pub request_timeout_secs: Option<u64>,

    /// Default read-only paths for sandboxes (used when client doesn't specify)
    pub default_allowed_paths_ro: Vec<std::path::PathBuf>,

    /// Default read-write paths for sandboxes (used when client doesn't specify)
    pub default_allowed_paths_rw: Vec<std::path::PathBuf>,

    /// Default bind mounts (source -> target path mappings)
    pub default_bind_mounts: Vec<crate::core::isolation::BindMount>,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0:9500".parse().unwrap(),
            tls_cert_path: None,
            tls_key_path: None,
            max_concurrent_streams: Some(100),
            max_frame_size: Some(16 * 1024 * 1024), // 16MB
            keepalive_interval_secs: Some(30),
            request_timeout_secs: Some(300),
            default_allowed_paths_ro: vec![],
            default_allowed_paths_rw: vec![],
            default_bind_mounts: vec![],
        }
    }
}

/// gRPC ingest adapter
pub struct GrpcAdapter {
    config: GrpcConfig,
    handler: RwLock<Option<Arc<dyn IntentHandler>>>,
    sandbox_manager: RwLock<Option<Arc<dyn SandboxManager>>>,
    running: AtomicBool,
    stats: AdapterStatsInner,
    shutdown_tx: RwLock<Option<tokio::sync::oneshot::Sender<()>>>,
}

struct AdapterStatsInner {
    requests_received: AtomicU64,
    requests_succeeded: AtomicU64,
    requests_failed: AtomicU64,
    requests_in_flight: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    active_connections: AtomicU64,
}

impl GrpcAdapter {
    pub fn new(config: GrpcConfig) -> Self {
        Self {
            config,
            handler: RwLock::new(None),
            sandbox_manager: RwLock::new(None),
            running: AtomicBool::new(false),
            stats: AdapterStatsInner {
                requests_received: AtomicU64::new(0),
                requests_succeeded: AtomicU64::new(0),
                requests_failed: AtomicU64::new(0),
                requests_in_flight: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                active_connections: AtomicU64::new(0),
            },
            shutdown_tx: RwLock::new(None),
        }
    }

    /// Create a new adapter with default configuration
    pub fn with_address(address: SocketAddr) -> Self {
        Self::new(GrpcConfig {
            listen_address: address,
            ..Default::default()
        })
    }

    /// Create a new adapter with address and default sandbox paths
    pub fn with_sandbox_defaults(
        address: SocketAddr,
        default_paths_ro: Vec<std::path::PathBuf>,
        default_paths_rw: Vec<std::path::PathBuf>,
    ) -> Self {
        Self::new(GrpcConfig {
            listen_address: address,
            default_allowed_paths_ro: default_paths_ro,
            default_allowed_paths_rw: default_paths_rw,
            ..Default::default()
        })
    }

    /// Create a new adapter with address, default sandbox paths, and bind mounts
    pub fn with_sandbox_defaults_and_mounts(
        address: SocketAddr,
        default_paths_ro: Vec<std::path::PathBuf>,
        default_paths_rw: Vec<std::path::PathBuf>,
        default_bind_mounts: Vec<crate::core::isolation::BindMount>,
    ) -> Self {
        Self::new(GrpcConfig {
            listen_address: address,
            default_allowed_paths_ro: default_paths_ro,
            default_allowed_paths_rw: default_paths_rw,
            default_bind_mounts,
            ..Default::default()
        })
    }

    /// Set the sandbox manager for this adapter
    pub async fn set_sandbox_manager(&self, manager: Arc<dyn SandboxManager>) {
        let mut sm = self.sandbox_manager.write().await;
        *sm = Some(manager);
    }
}

#[async_trait]
impl IngestAdapter for GrpcAdapter {
    fn name(&self) -> &str {
        "grpc"
    }

    async fn start(&self, handler: Arc<dyn IntentHandler>) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Adapter is already running"));
        }

        // Store the handler
        {
            let mut h = self.handler.write().await;
            *h = Some(handler.clone());
        }

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        {
            let mut tx = self.shutdown_tx.write().await;
            *tx = Some(shutdown_tx);
        }

        // Get the sandbox manager if available
        let sandbox_manager = {
            let sm = self.sandbox_manager.read().await;
            sm.clone()
        };

        // Create the gRPC service
        let service = GrpcService {
            handler: handler.clone(),
            sandbox_manager,
            stats: Arc::new(ServiceStats {
                requests_received: AtomicU64::new(0),
                requests_succeeded: AtomicU64::new(0),
                requests_failed: AtomicU64::new(0),
                requests_in_flight: AtomicU64::new(0),
            }),
            default_allowed_paths_ro: self.config.default_allowed_paths_ro.clone(),
            default_allowed_paths_rw: self.config.default_allowed_paths_rw.clone(),
            default_bind_mounts: self.config.default_bind_mounts.clone(),
        };

        let addr = self.config.listen_address;

        info!("Starting gRPC server on {}", addr);

        // Build the server
        let server = Server::builder()
            .add_service(AgentdServer::new(service))
            .serve_with_shutdown(addr, async {
                let _ = shutdown_rx.await;
                info!("gRPC server received shutdown signal");
            });

        self.running.store(true, Ordering::SeqCst);

        // Spawn the server in a background task
        tokio::spawn(async move {
            if let Err(e) = server.await {
                error!("gRPC server error: {}", e);
            }
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        info!("gRPC adapter started on {}", addr);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping gRPC adapter");

        // Send shutdown signal
        {
            let mut tx = self.shutdown_tx.write().await;
            if let Some(shutdown_tx) = tx.take() {
                let _ = shutdown_tx.send(());
            }
        }

        // Clear the handler
        {
            let mut h = self.handler.write().await;
            *h = None;
        }

        self.running.store(false, Ordering::SeqCst);

        info!("gRPC adapter stopped");
        Ok(())
    }

    async fn health(&self) -> HealthStatus {
        if !self.running.load(Ordering::SeqCst) {
            return HealthStatus::Unhealthy {
                reason: "Adapter is not running".to_string(),
            };
        }

        // Check if we have a handler
        let handler = self.handler.read().await;
        if handler.is_none() {
            return HealthStatus::Unhealthy {
                reason: "No handler configured".to_string(),
            };
        }

        HealthStatus::Healthy
    }

    async fn stats(&self) -> AdapterStats {
        AdapterStats {
            requests_received: self.stats.requests_received.load(Ordering::Relaxed),
            requests_in_flight: self.stats.requests_in_flight.load(Ordering::Relaxed),
            requests_succeeded: self.stats.requests_succeeded.load(Ordering::Relaxed),
            requests_failed: self.stats.requests_failed.load(Ordering::Relaxed),
            avg_latency_ms: 0.0, // TODO: Implement latency tracking
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            active_connections: self.stats.active_connections.load(Ordering::Relaxed),
            custom_metrics: vec![],
        }
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn config_info(&self) -> AdapterConfigInfo {
        AdapterConfigInfo {
            adapter_type: "grpc".to_string(),
            listen_address: Some(self.config.listen_address.to_string()),
            remote_address: None,
            tls_enabled: self.config.tls_cert_path.is_some(),
            auth_methods: vec!["mtls".to_string(), "jwt".to_string(), "api-key".to_string()],
            max_concurrent: self.config.max_concurrent_streams,
            extra: vec![],
        }
    }
}

/// Internal stats for the service
struct ServiceStats {
    requests_received: AtomicU64,
    requests_succeeded: AtomicU64,
    requests_failed: AtomicU64,
    requests_in_flight: AtomicU64,
}

/// gRPC service implementation
struct GrpcService {
    handler: Arc<dyn IntentHandler>,
    sandbox_manager: Option<Arc<dyn SandboxManager>>,
    stats: Arc<ServiceStats>,
    /// Default read-only paths for sandboxes
    default_allowed_paths_ro: Vec<std::path::PathBuf>,
    /// Default read-write paths for sandboxes
    default_allowed_paths_rw: Vec<std::path::PathBuf>,
    /// Default bind mounts (source -> target path mappings)
    default_bind_mounts: Vec<crate::core::isolation::BindMount>,
}

impl GrpcService {
    fn build_request_context(&self, request_id: &str) -> RequestContext {
        RequestContext {
            request_id: request_id.to_string(),
            source_adapter: "grpc".to_string(),
            client_id: String::new(), // TODO: Extract from TLS or metadata
            received_at: chrono::Utc::now(),
            reply_to: None,
            supports_streaming: true,
            metadata: vec![],
        }
    }

    /// Resolve sandbox for file operations: explicit ID > client session > default sandbox
    async fn resolve_sandbox_for_file_op(
        &self,
        explicit_sandbox_id: &str,
        client_id: &str,
    ) -> Result<Arc<dyn crate::core::isolation::Sandbox>, Status> {
        let manager = self
            .sandbox_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Sandbox manager not configured"))?;

        // 1. If explicit sandbox_id provided, use that
        if !explicit_sandbox_id.is_empty() {
            let sandbox_id = SandboxId::from_string(explicit_sandbox_id);
            return manager
                .get_sandbox(&sandbox_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get sandbox: {}", e)))?
                .ok_or_else(|| {
                    Status::not_found(format!("Sandbox {} not found", explicit_sandbox_id))
                });
        }

        // 2. Check for existing session for this client
        if !client_id.is_empty() {
            if let Ok(Some(session)) = manager.get_session_by_client(client_id).await {
                if let Ok(Some(sandbox)) = manager.get_sandbox(&session.sandbox_id).await {
                    return Ok(sandbox);
                }
            }
        }

        // 3. Check for default sandbox
        if let Some(default_id) = manager.get_default_sandbox().await {
            return manager
                .get_sandbox(&default_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get default sandbox: {}", e)))?
                .ok_or_else(|| {
                    Status::failed_precondition(
                        "Default sandbox not found - it may have been terminated",
                    )
                });
        }

        // 4. No sandbox available
        Err(Status::failed_precondition(
            "No sandbox configured. A sandbox must be created by the user before file operations can run."
        ))
    }

    fn convert_request(&self, req: &ExecuteRequest) -> IntentRequest {
        // Parse request_id as UUID, or generate new one
        let id = Uuid::parse_str(&req.request_id).unwrap_or_else(|_| Uuid::new_v4());

        IntentRequest {
            id,
            capability: req.capability.clone(),
            version: req.version,
            params: serde_json::from_str(&req.params_json).unwrap_or(serde_json::Value::Null),
            constraints: req
                .constraints
                .as_ref()
                .map(|c| RequestConstraints {
                    max_duration_ms: Some(c.max_duration_ms),
                    max_output_bytes: Some(c.max_output_bytes),
                    max_memory_bytes: Some(c.max_memory_bytes),
                    allow_network: Some(c.allow_network),
                    allow_writes: Some(c.allow_writes),
                })
                .unwrap_or_default(),
            metadata: req
                .metadata
                .as_ref()
                .map(|m| RequestMetadata {
                    trace_id: Some(m.trace_id.clone()).filter(|s| !s.is_empty()),
                    span_id: Some(m.span_id.clone()).filter(|s| !s.is_empty()),
                    timestamp_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
                    idempotency_key: Some(m.idempotency_key.clone()).filter(|s| !s.is_empty()),
                    priority: Some(m.priority as u8),
                    custom: m.custom.clone(),
                })
                .unwrap_or_default(),
            sandbox_prefs: req
                .sandbox_prefs
                .as_ref()
                .map(|p| SandboxPreferences {
                    sandbox_id: Some(p.sandbox_id.clone()).filter(|s| !s.is_empty()),
                    require_fresh: p.require_fresh,
                    profile: Some(p.profile.clone()).filter(|s| !s.is_empty()),
                    persist: p.persist,
                    backend: Some(p.backend.clone()).filter(|s| !s.is_empty()),
                    labels: std::collections::HashMap::new(),
                })
                .unwrap_or_default(),
        }
    }

    fn convert_response(&self, resp: IntentResponse) -> ExecuteResponse {
        let status = match resp.status {
            IntentStatus::Ok => ExecutionStatus::Ok as i32,
            IntentStatus::Denied => ExecutionStatus::Denied as i32,
            IntentStatus::Error => ExecutionStatus::Error as i32,
            IntentStatus::Expired => ExecutionStatus::Expired as i32,
            IntentStatus::Cancelled => ExecutionStatus::Cancelled as i32,
            IntentStatus::Pending => ExecutionStatus::Pending as i32,
        };

        let result = resp.result.map(|r| ExecutionResult {
            exit_code: r.exit_code,
            stdout: r.stdout.clone().unwrap_or_default(),
            stdout_bytes: r.stdout_bytes.clone().unwrap_or_default(),
            stderr: r.stderr.unwrap_or_default(),
            output_json: r.output.map(|v| v.to_string()).unwrap_or_default(),
            artifacts: r
                .artifacts
                .into_iter()
                .map(|a| proto::Artifact {
                    name: a.name,
                    content_type: a.content_type,
                    size: a.size,
                    sha256: a.sha256,
                    uri: a.uri.unwrap_or_default(),
                    content: a.content.unwrap_or_default(),
                })
                .collect(),
            resource_usage: r.resource_usage.map(|u| proto::ResourceUsage {
                peak_memory_bytes: u.peak_memory_bytes,
                cpu_time_ms: u.cpu_time_ms,
                wall_time_ms: u.wall_time_ms,
                disk_write_bytes: u.disk_write_bytes,
                disk_read_bytes: u.disk_read_bytes,
                network_tx_bytes: u.network_tx_bytes,
                network_rx_bytes: u.network_rx_bytes,
            }),
        });

        let error = resp.error.map(|e| proto::ErrorDetails {
            code: e.code,
            message: e.message,
            details_json: e.details.map(|v| v.to_string()).unwrap_or_default(),
            retryable: e.retryable,
            retry_after_ms: e.retry_after_ms.unwrap_or(0),
        });

        let timing = Some(proto::ResponseTiming {
            received_at_ms: resp.timing.received_at_ms,
            started_at_ms: resp.timing.started_at_ms,
            completed_at_ms: resp.timing.completed_at_ms,
            queue_time_ms: resp.timing.queue_time_ms,
            setup_time_ms: resp.timing.setup_time_ms,
            exec_time_ms: resp.timing.exec_time_ms,
            total_time_ms: resp.timing.total_time_ms,
        });

        ExecuteResponse {
            request_id: resp.request_id.to_string(),
            status,
            code: resp.code,
            message: resp.message,
            result,
            error,
            timing,
            sandbox_info: resp.sandbox_info.map(|s| proto::SandboxInfo {
                sandbox_id: s.sandbox_id,
                backend: s.backend,
                profile: s.profile,
                newly_created: s.newly_created,
                capabilities: Some(proto::SandboxCapabilities {
                    sandbox_id: String::new(),
                    backend: String::new(),
                    profile: String::new(),
                    can_write_filesystem: s.capabilities.can_write,
                    readable_paths: s.capabilities.readable_paths,
                    writable_paths: s.capabilities.writable_paths,
                    has_network: s.capabilities.has_network,
                    allowed_destinations: vec![],
                    limits: Some(proto::ResourceLimits {
                        max_memory_bytes: s.capabilities.limits.max_memory_bytes.unwrap_or(0),
                        max_cpu_time_ms: s.capabilities.limits.max_cpu_ms.unwrap_or(0),
                        max_wall_time_ms: s.capabilities.limits.max_wall_ms.unwrap_or(0),
                        max_processes: 0,
                        max_open_files: 0,
                        max_output_bytes: s.capabilities.limits.max_output_bytes.unwrap_or(0),
                        max_write_bytes: 0,
                    }),
                    syscall_filter_active: false,
                    blocked_syscall_categories: vec![],
                    is_persistent: false,
                    created_at_ms: 0,
                    time_remaining_ms: 0,
                }),
            }),
        }
    }
}

#[tonic::async_trait]
impl Agentd for GrpcService {
    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        self.stats.requests_received.fetch_add(1, Ordering::Relaxed);
        self.stats
            .requests_in_flight
            .fetch_add(1, Ordering::Relaxed);

        let req = request.into_inner();
        let ctx = self.build_request_context(&req.request_id);
        let intent_request = self.convert_request(&req);

        let result = self.handler.handle(intent_request, ctx).await;

        self.stats
            .requests_in_flight
            .fetch_sub(1, Ordering::Relaxed);

        match result {
            Ok(response) => {
                self.stats
                    .requests_succeeded
                    .fetch_add(1, Ordering::Relaxed);
                Ok(Response::new(self.convert_response(response)))
            }
            Err(e) => {
                self.stats.requests_failed.fetch_add(1, Ordering::Relaxed);
                error!("Execute error: {}", e);
                Err(Status::internal(format!("Execution failed: {}", e)))
            }
        }
    }

    type ExecuteStreamStream =
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<ExecuteOutput, Status>> + Send>>;

    async fn execute_stream(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStreamStream>, Status> {
        self.stats.requests_received.fetch_add(1, Ordering::Relaxed);
        self.stats
            .requests_in_flight
            .fetch_add(1, Ordering::Relaxed);

        let req = request.into_inner();
        let ctx = self.build_request_context(&req.request_id);
        let intent_request = self.convert_request(&req);

        // Create channel for streaming output
        let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<OutputChunk>(100);
        let (stream_tx, stream_rx) =
            tokio::sync::mpsc::channel::<Result<ExecuteOutput, Status>>(100);

        let handler = self.handler.clone();
        let stats = self.stats.clone();

        // Spawn handler
        tokio::spawn(async move {
            // Forward output chunks to stream
            let stream_tx_clone = stream_tx.clone();
            let forward_handle = tokio::spawn(async move {
                while let Some(chunk) = output_rx.recv().await {
                    let output = match chunk {
                        OutputChunk::Stdout(data) => ExecuteOutput {
                            output: Some(proto::execute_output::Output::StdoutChunk(data)),
                        },
                        OutputChunk::Stderr(data) => ExecuteOutput {
                            output: Some(proto::execute_output::Output::StderrChunk(data)),
                        },
                        OutputChunk::Progress { percent, message } => ExecuteOutput {
                            output: Some(proto::execute_output::Output::Progress(
                                proto::Progress { percent, message },
                            )),
                        },
                        OutputChunk::Log { level, message } => ExecuteOutput {
                            output: Some(proto::execute_output::Output::Log(proto::LogMessage {
                                level,
                                message,
                                timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
                            })),
                        },
                        OutputChunk::Done => break,
                    };

                    if stream_tx_clone.send(Ok(output)).await.is_err() {
                        break;
                    }
                }
            });

            // Execute the request
            let result = handler
                .handle_streaming(intent_request, ctx, output_tx)
                .await;

            // Wait for forwarding to complete
            let _ = forward_handle.await;

            stats.requests_in_flight.fetch_sub(1, Ordering::Relaxed);

            match result {
                Ok(response) => {
                    stats.requests_succeeded.fetch_add(1, Ordering::Relaxed);
                    // Send final response
                    let _ = stream_tx
                        .send(Ok(ExecuteOutput {
                            output: Some(proto::execute_output::Output::Complete(
                                convert_intent_response_to_proto(response),
                            )),
                        }))
                        .await;
                }
                Err(e) => {
                    stats.requests_failed.fetch_add(1, Ordering::Relaxed);
                    let _ = stream_tx.send(Err(Status::internal(e.to_string()))).await;
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(stream_rx);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_capabilities(
        &self,
        _request: Request<ListCapabilitiesRequest>,
    ) -> Result<Response<ListCapabilitiesResponse>, Status> {
        let capabilities = self.handler.list_capabilities().await;

        let proto_caps: Vec<proto::CapabilityInfo> = capabilities
            .into_iter()
            .map(|c| proto::CapabilityInfo {
                name: c.name,
                description: c.description,
                version: c.version,
                param_schema_json: c.param_schema.map(|v| v.to_string()).unwrap_or_default(),
                requires_elevated: c.requires_elevated,
                supports_streaming: c.supports_streaming,
                tags: c.tags,
            })
            .collect();

        Ok(Response::new(ListCapabilitiesResponse {
            capabilities: proto_caps,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let status = self.handler.health().await;

        let (healthy, status_str, details) = match status {
            HealthStatus::Healthy => (
                true,
                "healthy".to_string(),
                std::collections::HashMap::new(),
            ),
            HealthStatus::Degraded { reason } => {
                let mut d = std::collections::HashMap::new();
                d.insert("reason".to_string(), reason);
                (true, "degraded".to_string(), d)
            }
            HealthStatus::Unhealthy { reason } => {
                let mut d = std::collections::HashMap::new();
                d.insert("reason".to_string(), reason);
                (false, "unhealthy".to_string(), d)
            }
            HealthStatus::Starting => (
                false,
                "starting".to_string(),
                std::collections::HashMap::new(),
            ),
            HealthStatus::Stopping => (
                false,
                "stopping".to_string(),
                std::collections::HashMap::new(),
            ),
        };

        Ok(Response::new(HealthResponse {
            healthy,
            status: status_str,
            details,
        }))
    }

    async fn list_sandboxes(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let manager = self
            .sandbox_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Sandbox manager not configured"))?;

        let sessions = manager
            .list_sessions()
            .await
            .map_err(|e| Status::internal(format!("Failed to list sessions: {}", e)))?;

        let _state_filter = &request.get_ref().state_filter;

        let sandboxes: Vec<proto::SandboxSummary> = sessions
            .into_iter()
            .map(|session| proto::SandboxSummary {
                sandbox_id: session.sandbox_id.as_str().to_string(),
                backend: String::new(), // TODO: Get from sandbox capabilities
                profile: String::new(),
                state: format!("{:?}", session.state),
                created_at_ms: session.created_at.timestamp_millis() as u64,
                last_active_at_ms: session.last_active_at.timestamp_millis() as u64,
            })
            .collect();

        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let manager = self
            .sandbox_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Sandbox manager not configured"))?;

        let req = request.get_ref();

        // Convert proto ResourceLimits to core ResourceLimits
        let limits = req
            .limits
            .as_ref()
            .map(|l| CoreResourceLimits {
                max_memory_bytes: if l.max_memory_bytes > 0 {
                    Some(l.max_memory_bytes)
                } else {
                    None
                },
                max_cpu_time_ms: if l.max_cpu_time_ms > 0 {
                    Some(l.max_cpu_time_ms)
                } else {
                    None
                },
                max_wall_time_ms: if l.max_wall_time_ms > 0 {
                    Some(l.max_wall_time_ms)
                } else {
                    None
                },
                max_processes: if l.max_processes > 0 {
                    Some(l.max_processes)
                } else {
                    None
                },
                max_open_files: if l.max_open_files > 0 {
                    Some(l.max_open_files)
                } else {
                    None
                },
                max_output_bytes: if l.max_output_bytes > 0 {
                    Some(l.max_output_bytes)
                } else {
                    None
                },
                max_write_bytes: if l.max_write_bytes > 0 {
                    Some(l.max_write_bytes)
                } else {
                    None
                },
                cpu_weight: None,
            })
            .unwrap_or_default();

        // Use client-specified paths or fall back to server defaults
        let allowed_paths_ro = if req.allowed_paths_ro.is_empty() {
            self.default_allowed_paths_ro.clone()
        } else {
            req.allowed_paths_ro
                .iter()
                .map(std::path::PathBuf::from)
                .collect()
        };
        let allowed_paths_rw = if req.allowed_paths_rw.is_empty() {
            self.default_allowed_paths_rw.clone()
        } else {
            req.allowed_paths_rw
                .iter()
                .map(std::path::PathBuf::from)
                .collect()
        };

        let spec = SandboxSpec {
            profile: if req.profile.is_empty() {
                "default".to_string()
            } else {
                req.profile.clone()
            },
            workdir: std::path::PathBuf::from(if req.workdir.is_empty() {
                "/workspace"
            } else {
                &req.workdir
            }),
            allowed_paths_ro,
            allowed_paths_rw,
            bind_mounts: self.default_bind_mounts.clone(),
            allowed_network: vec![],
            environment: vec![],
            limits,
            network_enabled: req.network_enabled,
            seccomp_profile: None,
            creation_timeout: std::time::Duration::from_secs(30),
            labels: req
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };

        let options = SandboxSelectionOptions {
            preferred_id: None,
            require_fresh: true,
            required_capabilities: Default::default(),
            preferred_backend: None,
            required_labels: Default::default(),
            use_pool: false,
        };

        let (session, sandbox) = manager
            .acquire(&spec, &options, "grpc-client")
            .await
            .map_err(|e| Status::internal(format!("Failed to create sandbox: {}", e)))?;

        let caps = sandbox.capabilities();
        let capabilities = convert_sandbox_caps_to_proto(caps);

        Ok(Response::new(CreateSandboxResponse {
            sandbox_id: session.sandbox_id.as_str().to_string(),
            capabilities: Some(capabilities),
        }))
    }

    async fn attach_sandbox(
        &self,
        request: Request<AttachSandboxRequest>,
    ) -> Result<Response<AttachSandboxResponse>, Status> {
        let manager = self
            .sandbox_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Sandbox manager not configured"))?;

        let req = request.get_ref();
        let sandbox_id = SandboxId::from_string(&req.sandbox_id);

        // Check if sandbox exists
        if let Some(session) = manager
            .get_session_by_sandbox(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get session: {}", e)))?
        {
            // Sandbox exists, return session info
            return Ok(Response::new(AttachSandboxResponse {
                session_id: session.session_id.clone(),
                sandbox_id: session.sandbox_id.as_str().to_string(),
                newly_created: false,
                capabilities: None, // TODO: Get from sandbox
            }));
        }

        // Sandbox doesn't exist - create if requested
        if !req.create_if_missing {
            return Err(Status::not_found(format!(
                "Sandbox {} not found",
                req.sandbox_id
            )));
        }

        // Create new sandbox with provided spec
        let create_spec = req.create_spec.as_ref().ok_or_else(|| {
            Status::invalid_argument("create_spec required when create_if_missing is true")
        })?;

        let limits = create_spec
            .limits
            .as_ref()
            .map(|l| CoreResourceLimits {
                max_memory_bytes: if l.max_memory_bytes > 0 {
                    Some(l.max_memory_bytes)
                } else {
                    None
                },
                max_cpu_time_ms: if l.max_cpu_time_ms > 0 {
                    Some(l.max_cpu_time_ms)
                } else {
                    None
                },
                max_wall_time_ms: if l.max_wall_time_ms > 0 {
                    Some(l.max_wall_time_ms)
                } else {
                    None
                },
                max_processes: if l.max_processes > 0 {
                    Some(l.max_processes)
                } else {
                    None
                },
                max_open_files: if l.max_open_files > 0 {
                    Some(l.max_open_files)
                } else {
                    None
                },
                max_output_bytes: if l.max_output_bytes > 0 {
                    Some(l.max_output_bytes)
                } else {
                    None
                },
                max_write_bytes: if l.max_write_bytes > 0 {
                    Some(l.max_write_bytes)
                } else {
                    None
                },
                cpu_weight: None,
            })
            .unwrap_or_default();

        // Use client-specified paths or fall back to server defaults
        let allowed_paths_ro = if create_spec.allowed_paths_ro.is_empty() {
            self.default_allowed_paths_ro.clone()
        } else {
            create_spec
                .allowed_paths_ro
                .iter()
                .map(std::path::PathBuf::from)
                .collect()
        };
        let allowed_paths_rw = if create_spec.allowed_paths_rw.is_empty() {
            self.default_allowed_paths_rw.clone()
        } else {
            create_spec
                .allowed_paths_rw
                .iter()
                .map(std::path::PathBuf::from)
                .collect()
        };

        let spec = SandboxSpec {
            profile: if create_spec.profile.is_empty() {
                "default".to_string()
            } else {
                create_spec.profile.clone()
            },
            workdir: std::path::PathBuf::from(if create_spec.workdir.is_empty() {
                "/workspace"
            } else {
                &create_spec.workdir
            }),
            allowed_paths_ro,
            allowed_paths_rw,
            bind_mounts: self.default_bind_mounts.clone(),
            allowed_network: vec![],
            environment: vec![],
            limits,
            network_enabled: create_spec.network_enabled,
            seccomp_profile: None,
            creation_timeout: std::time::Duration::from_secs(30),
            labels: create_spec
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };

        let options = SandboxSelectionOptions {
            preferred_id: Some(sandbox_id),
            require_fresh: true,
            required_capabilities: Default::default(),
            preferred_backend: None,
            required_labels: Default::default(),
            use_pool: false,
        };

        let (session, sandbox) = manager
            .acquire(&spec, &options, "grpc-client")
            .await
            .map_err(|e| Status::internal(format!("Failed to create sandbox: {}", e)))?;

        let caps = sandbox.capabilities();
        let capabilities = convert_sandbox_caps_to_proto(caps);

        Ok(Response::new(AttachSandboxResponse {
            session_id: session.session_id.clone(),
            sandbox_id: session.sandbox_id.as_str().to_string(),
            newly_created: true,
            capabilities: Some(capabilities),
        }))
    }

    async fn terminate_sandbox(
        &self,
        request: Request<TerminateSandboxRequest>,
    ) -> Result<Response<TerminateSandboxResponse>, Status> {
        let manager = self
            .sandbox_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Sandbox manager not configured"))?;

        let req = request.get_ref();
        let sandbox_id = SandboxId::from_string(&req.sandbox_id);

        // Find session for this sandbox
        let session = manager
            .get_session_by_sandbox(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get session: {}", e)))?
            .ok_or_else(|| Status::not_found(format!("Sandbox {} not found", req.sandbox_id)))?;

        // Terminate the session
        manager
            .terminate(&session)
            .await
            .map_err(|e| Status::internal(format!("Failed to terminate sandbox: {}", e)))?;

        Ok(Response::new(TerminateSandboxResponse {
            success: true,
            message: format!("Sandbox {} terminated", req.sandbox_id),
        }))
    }

    async fn get_sandbox_capabilities(
        &self,
        request: Request<GetSandboxCapabilitiesRequest>,
    ) -> Result<Response<SandboxCapabilities>, Status> {
        let manager = self
            .sandbox_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Sandbox manager not configured"))?;

        let req = request.get_ref();
        let sandbox_id = SandboxId::from_string(&req.sandbox_id);

        // Find session for this sandbox
        let session = manager
            .get_session_by_sandbox(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get session: {}", e)))?
            .ok_or_else(|| Status::not_found(format!("Sandbox {} not found", req.sandbox_id)))?;

        // Get the sandbox and its capabilities
        // For now, return basic info from the session
        // TODO: Get actual sandbox capabilities from the isolation backend
        let capabilities = SandboxCapabilities {
            sandbox_id: session.sandbox_id.as_str().to_string(),
            backend: String::new(),
            profile: String::new(),
            can_write_filesystem: true,
            readable_paths: vec![],
            writable_paths: vec![],
            has_network: false,
            allowed_destinations: vec![],
            limits: None,
            syscall_filter_active: false,
            blocked_syscall_categories: vec![],
            is_persistent: false,
            created_at_ms: session.created_at.timestamp_millis() as u64,
            time_remaining_ms: 0,
        };

        Ok(Response::new(capabilities))
    }

    // =========================================================================
    // File Operations (sandboxed via shell commands)
    //
    // These operations execute within the sandbox context using shell commands,
    // ensuring Landlock/seccomp policies are enforced.
    // =========================================================================

    async fn read_file(
        &self,
        request: Request<ReadFileRequest>,
    ) -> Result<Response<ReadFileResponse>, Status> {
        let req = request.get_ref();

        // Resolve sandbox: explicit ID > client session > default
        // TODO: Extract client_id from gRPC metadata
        let client_id = "grpc-client";
        let sandbox = self
            .resolve_sandbox_for_file_op(&req.sandbox_id, client_id)
            .await?;

        // Build cat command with optional offset/limit using head/tail
        let path_escaped = shell_escape::escape(std::borrow::Cow::Borrowed(&req.path));
        let shell_cmd = if req.offset > 0 && req.limit > 0 {
            format!(
                "tail -c +{} {} | head -c {}",
                req.offset + 1,
                path_escaped,
                req.limit
            )
        } else if req.offset > 0 {
            format!("tail -c +{} {}", req.offset + 1, path_escaped)
        } else if req.limit > 0 {
            format!("head -c {} {}", req.limit, path_escaped)
        } else {
            format!("cat {}", path_escaped)
        };

        let cmd = Command {
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), shell_cmd],
            workdir: None,
            env: std::collections::HashMap::new(),
            inherit_env: true,
            stdin: None,
            timeout: Some(std::time::Duration::from_secs(30)),
        };

        let exec_ctx = SandboxExecContext {
            trace_id: format!("read-{}", Uuid::new_v4()),
            request_id: format!("read-{}", Uuid::new_v4()),
            workdir: None,
            extra_env: vec![],
            timeout: Some(std::time::Duration::from_secs(30)),
            capture_stdout: true,
            capture_stderr: true,
            stream_output: false,
        };

        match sandbox.exec(&cmd, &exec_ctx).await {
            Ok(result) => {
                if result.exit_code == 0 {
                    Ok(Response::new(ReadFileResponse {
                        success: true,
                        content: String::from_utf8_lossy(&result.stdout).to_string(),
                        error: String::new(),
                        size_bytes: String::from_utf8_lossy(&result.stdout).to_string().len()
                            as u64,
                        truncated: req.limit > 0,
                    }))
                } else {
                    Ok(Response::new(ReadFileResponse {
                        success: false,
                        content: String::new(),
                        error: if result.stderr.is_empty() {
                            format!("Command failed with exit code {}", result.exit_code)
                        } else {
                            String::from_utf8_lossy(&result.stderr).to_string()
                        },
                        size_bytes: 0,
                        truncated: false,
                    }))
                }
            }
            Err(e) => Ok(Response::new(ReadFileResponse {
                success: false,
                content: String::new(),
                error: format!("Execution failed: {}", e),
                size_bytes: 0,
                truncated: false,
            })),
        }
    }

    async fn write_file(
        &self,
        request: Request<WriteFileRequest>,
    ) -> Result<Response<WriteFileResponse>, Status> {
        use base64::Engine;

        let req = request.get_ref();

        // Resolve sandbox: explicit ID > client session > default
        // TODO: Extract client_id from gRPC metadata
        let client_id = "grpc-client";
        let sandbox = self
            .resolve_sandbox_for_file_op(&req.sandbox_id, client_id)
            .await?;

        let path_escaped = shell_escape::escape(std::borrow::Cow::Borrowed(&req.path));

        // Build command: create dirs if needed, then write content
        let mut commands = Vec::new();

        if req.create_dirs {
            let dir = std::path::Path::new(&req.path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            if !dir.is_empty() {
                let dir_escaped = shell_escape::escape(std::borrow::Cow::Borrowed(&dir));
                commands.push(format!("mkdir -p {}", dir_escaped));
            }
        }

        // Use base64 to safely pass content through shell
        let redirect = if req.append { ">>" } else { ">" };
        let content_b64 = base64::engine::general_purpose::STANDARD.encode(&req.content);
        commands.push(format!(
            "echo '{}' | base64 -d {} {}",
            content_b64, redirect, path_escaped
        ));

        let shell_cmd = commands.join(" && ");

        let cmd = Command {
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), shell_cmd],
            workdir: None,
            env: std::collections::HashMap::new(),
            inherit_env: true,
            stdin: None,
            timeout: Some(std::time::Duration::from_secs(30)),
        };

        let exec_ctx = SandboxExecContext {
            trace_id: format!("write-{}", Uuid::new_v4()),
            request_id: format!("write-{}", Uuid::new_v4()),
            workdir: None,
            extra_env: vec![],
            timeout: Some(std::time::Duration::from_secs(30)),
            capture_stdout: true,
            capture_stderr: true,
            stream_output: false,
        };

        match sandbox.exec(&cmd, &exec_ctx).await {
            Ok(result) => {
                if result.exit_code == 0 {
                    Ok(Response::new(WriteFileResponse {
                        success: true,
                        error: String::new(),
                        bytes_written: req.content.len() as u64,
                    }))
                } else {
                    Ok(Response::new(WriteFileResponse {
                        success: false,
                        error: if result.stderr.is_empty() {
                            format!("Command failed with exit code {}", result.exit_code)
                        } else {
                            String::from_utf8_lossy(&result.stderr).to_string()
                        },
                        bytes_written: 0,
                    }))
                }
            }
            Err(e) => Ok(Response::new(WriteFileResponse {
                success: false,
                error: format!("Execution failed: {}", e),
                bytes_written: 0,
            })),
        }
    }

    async fn edit_file(
        &self,
        request: Request<EditFileRequest>,
    ) -> Result<Response<EditFileResponse>, Status> {
        let req = request.get_ref();

        // Resolve sandbox: explicit ID > client session > default
        // TODO: Extract client_id from gRPC metadata
        let client_id = "grpc-client";
        let sandbox = self
            .resolve_sandbox_for_file_op(&req.sandbox_id, client_id)
            .await?;

        let path_escaped = shell_escape::escape(std::borrow::Cow::Borrowed(&req.path));

        // Use sed for replacement - escape special sed characters
        let old_escaped = req
            .old_string
            .replace('\\', "\\\\")
            .replace('/', "\\/")
            .replace('&', "\\&")
            .replace('\n', "\\n");
        let new_escaped = req
            .new_string
            .replace('\\', "\\\\")
            .replace('/', "\\/")
            .replace('&', "\\&")
            .replace('\n', "\\n");

        let sed_flags = if req.replace_all { "g" } else { "" };
        let shell_cmd = format!(
            "sed -i 's/{}/{}/{}' {} && echo 'OK'",
            old_escaped, new_escaped, sed_flags, path_escaped
        );

        let cmd = Command {
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), shell_cmd],
            workdir: None,
            env: std::collections::HashMap::new(),
            inherit_env: true,
            stdin: None,
            timeout: Some(std::time::Duration::from_secs(30)),
        };

        let exec_ctx = SandboxExecContext {
            trace_id: format!("edit-{}", Uuid::new_v4()),
            request_id: format!("edit-{}", Uuid::new_v4()),
            workdir: None,
            extra_env: vec![],
            timeout: Some(std::time::Duration::from_secs(30)),
            capture_stdout: true,
            capture_stderr: true,
            stream_output: false,
        };

        match sandbox.exec(&cmd, &exec_ctx).await {
            Ok(result) => {
                if result.exit_code == 0 {
                    Ok(Response::new(EditFileResponse {
                        success: true,
                        error: String::new(),
                        replacements_made: 1, // sed doesn't report count easily
                    }))
                } else {
                    Ok(Response::new(EditFileResponse {
                        success: false,
                        error: if result.stderr.is_empty() {
                            format!("Command failed with exit code {}", result.exit_code)
                        } else {
                            String::from_utf8_lossy(&result.stderr).to_string()
                        },
                        replacements_made: 0,
                    }))
                }
            }
            Err(e) => Ok(Response::new(EditFileResponse {
                success: false,
                error: format!("Execution failed: {}", e),
                replacements_made: 0,
            })),
        }
    }
}

/// Convert core SandboxCapabilities to proto SandboxCapabilities
fn convert_sandbox_caps_to_proto(
    caps: &crate::core::isolation::SandboxCapabilities,
) -> SandboxCapabilities {
    SandboxCapabilities {
        sandbox_id: caps.sandbox_id.clone(),
        backend: caps.backend.clone(),
        profile: caps.profile.clone(),
        can_write_filesystem: caps.can_write_filesystem,
        readable_paths: caps
            .readable_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        writable_paths: caps
            .writable_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        has_network: caps.has_network,
        allowed_destinations: caps.allowed_destinations.clone(),
        limits: Some(proto::ResourceLimits {
            max_memory_bytes: caps.limits.max_memory_bytes.unwrap_or(0),
            max_cpu_time_ms: caps.limits.max_cpu_time_ms.unwrap_or(0),
            max_wall_time_ms: caps.limits.max_wall_time_ms.unwrap_or(0),
            max_processes: caps.limits.max_processes.unwrap_or(0),
            max_open_files: caps.limits.max_open_files.unwrap_or(0),
            max_output_bytes: caps.limits.max_output_bytes.unwrap_or(0),
            max_write_bytes: caps.limits.max_write_bytes.unwrap_or(0),
        }),
        syscall_filter_active: caps.syscall_filter_active,
        blocked_syscall_categories: caps.blocked_syscall_categories.clone(),
        is_persistent: caps.is_persistent,
        created_at_ms: caps.created_at.timestamp_millis() as u64,
        time_remaining_ms: caps.time_remaining_ms.unwrap_or(0),
    }
}

/// Helper function to convert IntentResponse to proto ExecuteResponse
fn convert_intent_response_to_proto(resp: IntentResponse) -> ExecuteResponse {
    let status = match resp.status {
        IntentStatus::Ok => ExecutionStatus::Ok as i32,
        IntentStatus::Denied => ExecutionStatus::Denied as i32,
        IntentStatus::Error => ExecutionStatus::Error as i32,
        IntentStatus::Expired => ExecutionStatus::Expired as i32,
        IntentStatus::Cancelled => ExecutionStatus::Cancelled as i32,
        IntentStatus::Pending => ExecutionStatus::Pending as i32,
    };

    let result = resp.result.map(|r| ExecutionResult {
        exit_code: r.exit_code,
        stdout: r.stdout.clone().unwrap_or_default(),
        stdout_bytes: r.stdout_bytes.clone().unwrap_or_default(),
        stderr: r.stderr.unwrap_or_default(),
        output_json: r.output.map(|v| v.to_string()).unwrap_or_default(),
        artifacts: r
            .artifacts
            .into_iter()
            .map(|a| proto::Artifact {
                name: a.name,
                content_type: a.content_type,
                size: a.size,
                sha256: a.sha256,
                uri: a.uri.unwrap_or_default(),
                content: a.content.unwrap_or_default(),
            })
            .collect(),
        resource_usage: r.resource_usage.map(|u| proto::ResourceUsage {
            peak_memory_bytes: u.peak_memory_bytes,
            cpu_time_ms: u.cpu_time_ms,
            wall_time_ms: u.wall_time_ms,
            disk_write_bytes: u.disk_write_bytes,
            disk_read_bytes: u.disk_read_bytes,
            network_tx_bytes: u.network_tx_bytes,
            network_rx_bytes: u.network_rx_bytes,
        }),
    });

    let error = resp.error.map(|e| proto::ErrorDetails {
        code: e.code,
        message: e.message,
        details_json: e.details.map(|v| v.to_string()).unwrap_or_default(),
        retryable: e.retryable,
        retry_after_ms: e.retry_after_ms.unwrap_or(0),
    });

    let timing = Some(proto::ResponseTiming {
        received_at_ms: resp.timing.received_at_ms,
        started_at_ms: resp.timing.started_at_ms,
        completed_at_ms: resp.timing.completed_at_ms,
        queue_time_ms: resp.timing.queue_time_ms,
        setup_time_ms: resp.timing.setup_time_ms,
        exec_time_ms: resp.timing.exec_time_ms,
        total_time_ms: resp.timing.total_time_ms,
    });

    ExecuteResponse {
        request_id: resp.request_id.to_string(),
        status,
        code: resp.code,
        message: resp.message,
        result,
        error,
        timing,
        sandbox_info: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_config_default() {
        let config = GrpcConfig::default();
        assert_eq!(config.listen_address.port(), 9500);
        assert!(config.tls_cert_path.is_none());
    }

    #[test]
    fn test_adapter_creation() {
        let addr: SocketAddr = "127.0.0.1:9500".parse().unwrap();
        let adapter = GrpcAdapter::with_address(addr);
        assert_eq!(adapter.name(), "grpc");
        assert!(!adapter.is_running());
    }
}
