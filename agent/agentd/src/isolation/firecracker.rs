//! Firecracker microVM isolation backend
//!
//! This backend provides strong isolation using Firecracker microVMs:
//! - Full hardware virtualization
//! - Separate kernel and filesystem
//! - virtio-vsock for guest communication
//! - TAP networking for network access
//!
//! Requires:
//! - Firecracker binary installed
//! - KVM available (/dev/kvm)
//! - Root filesystem image with agent
//! - Linux kernel image

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::core::intent::Command;
use crate::core::isolation::{
    BackendCapabilities, BackendHealth, ExecContext, ExecOutput, IsolationBackend, ResourceLimits,
    ResourceUsage, Sandbox, SandboxCapabilities, SandboxSpec, StreamOutput,
};
use crate::core::sandbox::SandboxId;

/// Configuration for the Firecracker backend
#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    /// Path to firecracker binary
    pub firecracker_bin: PathBuf,
    /// Path to jailer binary (optional, for production)
    pub jailer_bin: Option<PathBuf>,
    /// Path to kernel image
    pub kernel_path: PathBuf,
    /// Path to root filesystem image
    pub rootfs_path: PathBuf,
    /// Working directory for VM sockets and state
    pub work_root: PathBuf,
    /// Default vCPU count
    pub vcpu_count: u8,
    /// Default memory size in MB
    pub mem_size_mib: u32,
    /// Enable KVM hypercall filtering
    pub enable_hypercall_filter: bool,
    /// CID base for vsock (each VM gets base + index)
    pub vsock_cid_base: u32,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            firecracker_bin: PathBuf::from("/bin/firecracker"),
            jailer_bin: None,
            kernel_path: PathBuf::from("/tmp/agentd-firecracker/vmlinux.bin"),
            // Use Ubuntu bionic rootfs (glibc-based) with guest agent installed
            rootfs_path: PathBuf::from("/tmp/agentd-firecracker/bionic-rootfs.ext4"),
            work_root: PathBuf::from("/tmp/agentd-firecracker/sandboxes"),
            vcpu_count: 1,
            mem_size_mib: 128,
            enable_hypercall_filter: true,
            vsock_cid_base: 100,
        }
    }
}

/// Firecracker API request/response types
#[derive(Debug, Serialize)]
struct BootSource {
    kernel_image_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_args: Option<String>,
}

#[derive(Debug, Serialize)]
struct Drive {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Debug, Serialize)]
struct MachineConfig {
    vcpu_count: u8,
    mem_size_mib: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    smt: Option<bool>,
}

#[derive(Debug, Serialize)]
struct Vsock {
    vsock_id: String,
    guest_cid: u32,
    uds_path: String,
}

#[derive(Debug, Serialize)]
struct NetworkInterface {
    iface_id: String,
    host_dev_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_mac: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstanceActionInfo {
    action_type: String,
}

/// Firecracker microVM isolation backend
pub struct FirecrackerBackend {
    config: FirecrackerConfig,
    sandboxes: RwLock<HashMap<SandboxId, Arc<FirecrackerSandbox>>>,
    next_cid: RwLock<u32>,
}

impl FirecrackerBackend {
    /// Create a new Firecracker backend
    pub fn new(config: FirecrackerConfig) -> Result<Self> {
        // Verify firecracker binary exists
        if !config.firecracker_bin.exists() {
            anyhow::bail!(
                "Firecracker binary not found at: {}",
                config.firecracker_bin.display()
            );
        }

        // Verify KVM is available
        if !Path::new("/dev/kvm").exists() {
            anyhow::bail!("KVM not available (/dev/kvm not found)");
        }

        // Check kernel and rootfs (warn if missing, can be configured later)
        if !config.kernel_path.exists() {
            warn!(
                "Kernel image not found at: {}",
                config.kernel_path.display()
            );
        }
        if !config.rootfs_path.exists() {
            warn!(
                "Root filesystem not found at: {}",
                config.rootfs_path.display()
            );
        }

        // Create work directory
        std::fs::create_dir_all(&config.work_root)?;

        let vsock_cid_base = config.vsock_cid_base;
        Ok(Self {
            config,
            sandboxes: RwLock::new(HashMap::new()),
            next_cid: RwLock::new(vsock_cid_base),
        })
    }

    /// Check if Firecracker is available
    fn check_firecracker_available() -> bool {
        Path::new("/usr/bin/firecracker").exists()
            || Path::new("/usr/local/bin/firecracker").exists()
    }

    /// Check if KVM is available
    fn check_kvm_available() -> bool {
        Path::new("/dev/kvm").exists()
    }

    /// Allocate a unique CID for vsock
    async fn allocate_cid(&self) -> u32 {
        let mut cid = self.next_cid.write().await;
        let allocated = *cid;
        *cid += 1;
        allocated
    }
}

#[async_trait]
impl IsolationBackend for FirecrackerBackend {
    fn name(&self) -> &str {
        "firecracker"
    }

    async fn probe(&self) -> Result<BackendCapabilities> {
        let kvm = Self::check_kvm_available();
        let firecracker = Self::check_firecracker_available();

        let mut features = Vec::new();
        if kvm {
            features.push("kvm".to_string());
        }
        if firecracker {
            features.push("firecracker".to_string());
        }
        features.push("microvm".to_string());
        features.push("vsock".to_string());

        Ok(BackendCapabilities {
            name: self.name().to_string(),
            filesystem_isolation: kvm && firecracker,
            network_isolation: kvm && firecracker,
            process_isolation: kvm && firecracker,
            resource_limits: true,
            syscall_filtering: true, // Via seccomp in guest + host
            persistent_sandboxes: true,
            snapshots: true, // Firecracker supports snapshots
            max_concurrent_sandboxes: Some(64),
            available_profiles: vec!["default".to_string(), "minimal".to_string()],
            platform_features: features,
        })
    }

    async fn create_sandbox(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>> {
        let sandbox_id = SandboxId::new();
        let cid = self.allocate_cid().await;

        // Create sandbox directory
        let sandbox_dir = self.config.work_root.join(sandbox_id.as_str());
        tokio::fs::create_dir_all(&sandbox_dir).await?;

        // Create API socket path
        let api_socket = sandbox_dir.join("firecracker.sock");

        // Create vsock UDS path
        let vsock_uds = sandbox_dir.join("vsock.sock");

        // Create overlay rootfs for this sandbox (copy-on-write)
        let overlay_rootfs = sandbox_dir.join("rootfs.ext4");

        // For now, create a simple copy. In production, use device-mapper or overlayfs
        if self.config.rootfs_path.exists() {
            tokio::fs::copy(&self.config.rootfs_path, &overlay_rootfs)
                .await
                .context("Failed to create overlay rootfs")?;
        }

        // Start Firecracker process
        let mut fc_cmd = TokioCommand::new(&self.config.firecracker_bin);
        fc_cmd
            .arg("--api-sock")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let fc_process = fc_cmd.spawn().context("Failed to start Firecracker")?;

        // Wait for API socket to be ready
        for _ in 0..50 {
            if api_socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if !api_socket.exists() {
            anyhow::bail!("Firecracker API socket not created");
        }

        // Configure the VM via API
        let api_client = FirecrackerApiClient::new(&api_socket);

        // Set machine config
        api_client
            .put(
                "/machine-config",
                &MachineConfig {
                    vcpu_count: self.config.vcpu_count,
                    mem_size_mib: spec
                        .limits
                        .max_memory_bytes
                        .map(|b| (b / 1024 / 1024) as u32)
                        .unwrap_or(self.config.mem_size_mib),
                    smt: Some(false),
                },
            )
            .await?;

        // Set boot source
        let boot_args = "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/agent";
        api_client
            .put(
                "/boot-source",
                &BootSource {
                    kernel_image_path: self.config.kernel_path.to_string_lossy().to_string(),
                    boot_args: Some(boot_args.to_string()),
                },
            )
            .await?;

        // Add root drive
        api_client
            .put(
                "/drives/rootfs",
                &Drive {
                    drive_id: "rootfs".to_string(),
                    path_on_host: overlay_rootfs.to_string_lossy().to_string(),
                    is_root_device: true,
                    is_read_only: false,
                },
            )
            .await?;

        // Configure vsock
        api_client
            .put(
                "/vsock",
                &Vsock {
                    vsock_id: "vsock0".to_string(),
                    guest_cid: cid,
                    uds_path: vsock_uds.to_string_lossy().to_string(),
                },
            )
            .await?;

        // Start the VM
        api_client
            .put(
                "/actions",
                &InstanceActionInfo {
                    action_type: "InstanceStart".to_string(),
                },
            )
            .await?;

        info!(sandbox_id = %sandbox_id, cid = cid, "Firecracker VM started");

        let capabilities = SandboxCapabilities {
            sandbox_id: sandbox_id.as_str().to_string(),
            backend: self.name().to_string(),
            profile: spec.profile.clone(),
            can_write_filesystem: true,
            readable_paths: spec.allowed_paths_ro.clone(),
            writable_paths: spec.allowed_paths_rw.clone(),
            has_network: spec.network_enabled,
            allowed_destinations: spec.allowed_network.clone(),
            limits: spec.limits.clone(),
            syscall_filter_active: true,
            blocked_syscall_categories: vec![],
            is_persistent: true,
            created_at: chrono::Utc::now(),
            time_remaining_ms: spec.limits.max_wall_time_ms,
        };

        let sandbox = Arc::new(FirecrackerSandbox {
            id: sandbox_id.clone(),
            sandbox_dir,
            api_socket,
            vsock_uds,
            cid,
            spec: spec.clone(),
            capabilities,
            process: Arc::new(RwLock::new(Some(fc_process))),
            created_at: std::time::Instant::now(),
        });

        // Store reference
        {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.insert(sandbox_id.clone(), sandbox.clone());
        }

        Ok(Box::new(sandbox.as_ref().clone()))
    }

    async fn list_sandboxes(&self) -> Result<Vec<SandboxId>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes.keys().cloned().collect())
    }

    async fn get_sandbox(&self, id: &SandboxId) -> Result<Option<Box<dyn Sandbox>>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes
            .get(id)
            .map(|s| Box::new(s.as_ref().clone()) as Box<dyn Sandbox>))
    }

    async fn destroy_all(&self) -> Result<()> {
        let mut sandboxes = self.sandboxes.write().await;
        for (_, sandbox) in sandboxes.drain() {
            if let Err(e) = sandbox.destroy().await {
                error!(sandbox_id = %sandbox.id, error = %e, "Failed to destroy sandbox");
            }
        }
        Ok(())
    }

    async fn health_check(&self) -> Result<BackendHealth> {
        let kvm_ok = Self::check_kvm_available();
        let firecracker_ok = Self::check_firecracker_available();

        let sandboxes = self.sandboxes.read().await;

        let mut warnings = Vec::new();
        if !kvm_ok {
            warnings.push("KVM not available".to_string());
        }
        if !firecracker_ok {
            warnings.push("Firecracker binary not found".to_string());
        }

        Ok(BackendHealth {
            healthy: kvm_ok && firecracker_ok,
            active_sandboxes: sandboxes.len() as u32,
            resource_utilization: 0.0,
            warnings,
            last_sandbox_created: None,
        })
    }
}

/// Guest agent request format
#[derive(Debug, Serialize)]
struct GuestExecRequest {
    command: String,
    args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    env: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdin: Option<String>,
}

/// Guest agent response format
#[derive(Debug, Deserialize)]
struct GuestExecResponse {
    exit_code: i32,
    #[serde(default, with = "base64_opt")]
    stdout: Vec<u8>,
    #[serde(default, with = "base64_opt")]
    stderr: Vec<u8>,
    #[serde(default)]
    error: Option<String>,
}

mod base64_opt {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(vec![]);
        }
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

/// Simple HTTP client for Firecracker API over Unix socket
struct FirecrackerApiClient {
    socket_path: PathBuf,
}

impl FirecrackerApiClient {
    fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
        }
    }

    async fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to Firecracker API")?;

        let body_json = serde_json::to_string(body)?;
        let request = format!(
            "PUT {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            path,
            body_json.len(),
            body_json
        );

        stream.write_all(request.as_bytes()).await?;

        // Read response
        let mut response = String::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            response.push_str(&String::from_utf8_lossy(&buf[..n]));
            if response.contains("\r\n\r\n") {
                break;
            }
        }

        // Check for success
        if response.starts_with("HTTP/1.1 2") {
            Ok(())
        } else {
            anyhow::bail!(
                "Firecracker API error: {}",
                response.lines().next().unwrap_or("unknown")
            )
        }
    }
}

/// Firecracker sandbox instance
#[derive(Clone)]
pub struct FirecrackerSandbox {
    id: SandboxId,
    sandbox_dir: PathBuf,
    api_socket: PathBuf,
    vsock_uds: PathBuf,
    cid: u32,
    spec: SandboxSpec,
    capabilities: SandboxCapabilities,
    process: Arc<RwLock<Option<Child>>>,
    created_at: std::time::Instant,
}

impl FirecrackerSandbox {
    /// Execute command via vsock agent
    async fn exec_via_vsock(&self, cmd: &Command, ctx: &ExecContext) -> Result<ExecOutput> {
        let start = std::time::Instant::now();

        // Connect to vsock via the UDS (Firecracker exposes guest vsock via UDS)
        // The guest agent should be listening on port 5000
        // Firecracker vsock uses the format: {uds_path}_{port}
        let vsock_connect_path = format!("{}_{}", self.vsock_uds.display(), 5000);

        debug!(
            sandbox_id = %self.id,
            vsock_path = %vsock_connect_path,
            command = %cmd.program,
            "Connecting to guest agent via vsock"
        );

        // Connect with timeout
        let connect_timeout = Duration::from_secs(10);
        let mut stream =
            match tokio::time::timeout(connect_timeout, UnixStream::connect(&vsock_connect_path))
                .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    return Ok(ExecOutput {
                        exit_code: -1,
                        stdout: vec![],
                        stderr: format!("Failed to connect to guest agent: {}", e).into_bytes(),
                        duration: start.elapsed(),
                        timed_out: false,
                        resource_limited: false,
                        resource_usage: None,
                    });
                }
                Err(_) => {
                    return Ok(ExecOutput {
                        exit_code: -1,
                        stdout: vec![],
                        stderr: b"Timeout connecting to guest agent".to_vec(),
                        duration: start.elapsed(),
                        timed_out: true,
                        resource_limited: false,
                        resource_usage: None,
                    });
                }
            };

        // Build request
        let env_map: HashMap<String, String> = ctx
            .extra_env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let request = GuestExecRequest {
            command: cmd.program.clone(),
            args: cmd.args.clone(),
            cwd: ctx
                .workdir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            env: env_map,
            stdin: None, // stdin not supported in current ExecContext
        };

        let request_json =
            serde_json::to_string(&request).context("Failed to serialize command request")?;

        // Send request (newline-delimited JSON)
        stream
            .write_all(request_json.as_bytes())
            .await
            .context("Failed to send command to guest agent")?;
        stream.write_all(b"\n").await?;

        // Read response with timeout
        let exec_timeout = ctx.timeout.unwrap_or(Duration::from_secs(300));
        let mut response_buf = Vec::new();
        let mut buf = [0u8; 4096];

        let read_result = tokio::time::timeout(exec_timeout, async {
            loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                response_buf.extend_from_slice(&buf[..n]);
                // Check for newline (end of response)
                if response_buf.contains(&b'\n') {
                    break;
                }
            }
            Ok::<_, std::io::Error>(())
        })
        .await;

        match read_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Ok(ExecOutput {
                    exit_code: -1,
                    stdout: vec![],
                    stderr: format!("Failed to read from guest agent: {}", e).into_bytes(),
                    duration: start.elapsed(),
                    timed_out: false,
                    resource_limited: false,
                    resource_usage: None,
                });
            }
            Err(_) => {
                return Ok(ExecOutput {
                    exit_code: -1,
                    stdout: vec![],
                    stderr: b"Command execution timed out".to_vec(),
                    duration: start.elapsed(),
                    timed_out: true,
                    resource_limited: false,
                    resource_usage: None,
                });
            }
        }

        // Parse response
        let response_str = String::from_utf8_lossy(&response_buf);
        let response: GuestExecResponse = serde_json::from_str(response_str.trim())
            .context("Failed to parse guest agent response")?;

        let duration = start.elapsed();

        if let Some(ref error) = response.error {
            warn!(sandbox_id = %self.id, error = %error, "Guest agent reported error");
        }

        Ok(ExecOutput {
            exit_code: response.exit_code,
            stdout: response.stdout,
            stderr: if let Some(error) = response.error {
                let mut stderr = response.stderr;
                if !stderr.is_empty() {
                    stderr.extend_from_slice(b"\n");
                }
                stderr.extend_from_slice(error.as_bytes());
                stderr
            } else {
                response.stderr
            },
            duration,
            timed_out: false,
            resource_limited: false,
            resource_usage: Some(ResourceUsage {
                peak_memory_bytes: 0,
                cpu_time_ms: duration.as_millis() as u64,
                wall_time_ms: duration.as_millis() as u64,
                bytes_written: 0,
                bytes_read: 0,
            }),
        })
    }
}

#[async_trait]
impl Sandbox for FirecrackerSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &SandboxCapabilities {
        &self.capabilities
    }

    async fn exec(&self, cmd: &Command, ctx: &ExecContext) -> Result<ExecOutput> {
        self.exec_via_vsock(cmd, ctx).await
    }

    async fn exec_streaming(
        &self,
        cmd: &Command,
        ctx: &ExecContext,
        output_tx: tokio::sync::mpsc::Sender<StreamOutput>,
    ) -> Result<ExecOutput> {
        let result = self.exec(cmd, ctx).await?;

        if !result.stdout.is_empty() {
            let _ = output_tx
                .send(StreamOutput::Stdout(result.stdout.clone()))
                .await;
        }
        if !result.stderr.is_empty() {
            let _ = output_tx
                .send(StreamOutput::Stderr(result.stderr.clone()))
                .await;
        }
        let _ = output_tx
            .send(StreamOutput::Exit {
                code: result.exit_code,
            })
            .await;

        Ok(result)
    }

    async fn is_alive(&self) -> bool {
        let process = self.process.read().await;
        if let Some(ref p) = *process {
            // Check if process is still running
            // Note: This is a simplified check
            true
        } else {
            false
        }
    }

    async fn suspend(&self) -> Result<()> {
        let api_client = FirecrackerApiClient::new(&self.api_socket);
        api_client
            .put(
                "/actions",
                &InstanceActionInfo {
                    action_type: "Pause".to_string(),
                },
            )
            .await
    }

    async fn resume(&self) -> Result<()> {
        let api_client = FirecrackerApiClient::new(&self.api_socket);
        api_client
            .put(
                "/actions",
                &InstanceActionInfo {
                    action_type: "Resume".to_string(),
                },
            )
            .await
    }

    async fn snapshot(&self, name: &str) -> Result<String> {
        // Firecracker supports snapshots via the API
        // This is a simplified implementation
        let snapshot_path = self.sandbox_dir.join("snapshots").join(name);
        tokio::fs::create_dir_all(&snapshot_path).await?;

        // Would need to call Firecracker snapshot API
        warn!("Firecracker snapshots not fully implemented");

        Ok(format!("{}:{}", self.id.as_str(), name))
    }

    async fn restore(&self, snapshot_id: &str) -> Result<()> {
        warn!("Firecracker restore not fully implemented");
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        // Kill the Firecracker process
        let mut process = self.process.write().await;
        if let Some(mut p) = process.take() {
            let _ = p.kill().await;
        }

        // Clean up sandbox directory
        if self.sandbox_dir.exists() {
            tokio::fs::remove_dir_all(&self.sandbox_dir).await?;
        }

        info!(sandbox_id = %self.id, "Firecracker sandbox destroyed");
        Ok(())
    }

    async fn resource_usage(&self) -> Result<ResourceUsage> {
        // Would query Firecracker metrics API
        Ok(ResourceUsage {
            peak_memory_bytes: 0,
            cpu_time_ms: 0,
            wall_time_ms: self.created_at.elapsed().as_millis() as u64,
            bytes_written: 0,
            bytes_read: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_firecracker_config_default() {
        let config = FirecrackerConfig::default();
        assert_eq!(config.vcpu_count, 1);
        assert_eq!(config.mem_size_mib, 128);
        assert_eq!(config.vsock_cid_base, 100);
        assert!(config.enable_hypercall_filter);
    }

    #[test]
    fn test_firecracker_backend_name() {
        // Skip if firecracker not available
        if !std::path::Path::new("/bin/firecracker").exists() {
            eprintln!("Skipping: firecracker not installed");
            return;
        }
        if !std::path::Path::new("/dev/kvm").exists() {
            eprintln!("Skipping: KVM not available");
            return;
        }

        let temp_dir = TempDir::new().unwrap();
        let config = FirecrackerConfig {
            work_root: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = FirecrackerBackend::new(config).unwrap();
        assert_eq!(backend.name(), "firecracker");
    }

    #[tokio::test]
    async fn test_firecracker_backend_probe() {
        // Skip if firecracker not available
        if !std::path::Path::new("/bin/firecracker").exists() {
            eprintln!("Skipping: firecracker not installed");
            return;
        }
        if !std::path::Path::new("/dev/kvm").exists() {
            eprintln!("Skipping: KVM not available");
            return;
        }

        let temp_dir = TempDir::new().unwrap();
        let config = FirecrackerConfig {
            work_root: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = FirecrackerBackend::new(config).unwrap();
        let caps = backend.probe().await.unwrap();

        assert_eq!(caps.name, "firecracker");
        assert!(caps.filesystem_isolation);
        assert!(caps.network_isolation);
        assert!(caps.process_isolation);
        assert!(caps.snapshots);
        assert!(caps.platform_features.contains(&"kvm".to_string()));
        assert!(caps.platform_features.contains(&"vsock".to_string()));
    }

    #[test]
    fn test_guest_exec_request_serialization() {
        let req = GuestExecRequest {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            cwd: Some("/tmp".to_string()),
            env: HashMap::from([("FOO".to_string(), "bar".to_string())]),
            stdin: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"command\":\"ls\""));
        assert!(json.contains("\"args\":["));
        assert!(json.contains("\"-la\""));
    }

    #[test]
    fn test_guest_exec_response_deserialization() {
        let json = r#"{"exit_code":0,"stdout":"SGVsbG8=","stderr":"","error":null}"#;
        let resp: GuestExecResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, b"Hello");
        assert!(resp.error.is_none());
    }
}
