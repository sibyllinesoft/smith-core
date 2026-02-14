use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

// ── JSON-RPC 2.0 types ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: Option<Value>,
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

// ── MCP types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
struct InitializeResult {
    #[serde(rename = "serverInfo")]
    server_info: ServerInfo,
}

#[derive(Debug, Deserialize)]
struct ToolsListResult {
    tools: Vec<McpTool>,
}

#[derive(Debug, Deserialize)]
struct ResourcesListResult {
    resources: Vec<McpResource>,
}

// ── Spawn Config ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SpawnConfig {
    pub program: String,
    pub args: Vec<String>,
    pub init_timeout: Duration,
}

// ── MCP Client ──────────────────────────────────────────────────────────

pub struct McpClient {
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    next_id: AtomicU64,
    child: Mutex<Child>,
    pub server_info: ServerInfo,
    pub tools: Vec<McpTool>,
}

impl McpClient {
    /// Spawn the MCP server process, perform the initialize handshake,
    /// and discover available tools.
    pub async fn spawn(
        program: &str,
        args: &[String],
        init_timeout: Duration,
    ) -> Result<Arc<Self>> {
        let config = SpawnConfig {
            program: program.to_string(),
            args: args.to_vec(),
            init_timeout,
        };
        Self::spawn_from_config(&config).await
    }

    /// Spawn from a reusable config (used by reload).
    pub async fn spawn_from_config(config: &SpawnConfig) -> Result<Arc<Self>> {
        tracing::info!(program = %config.program, args = ?config.args, "spawning MCP server");

        let mut child = Command::new(&config.program)
            .args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn: {}", config.program))?;

        let stdin = child.stdin.take().context("no stdin")?;
        let stdout = child.stdout.take().context("no stdout")?;

        let mut client = Self {
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: AtomicU64::new(1),
            child: Mutex::new(child),
            server_info: ServerInfo {
                name: String::new(),
                version: String::new(),
            },
            tools: Vec::new(),
        };

        // Initialize handshake with timeout
        let server_info = tokio::time::timeout(config.init_timeout, client.initialize())
            .await
            .context("MCP initialize timed out")??;
        client.server_info = server_info;

        tracing::info!(
            name = %client.server_info.name,
            version = %client.server_info.version,
            "MCP server initialized"
        );

        // Send initialized notification (no id, no response expected)
        client.send_notification("notifications/initialized", None).await?;

        // Discover tools
        let tools = client.list_tools().await.unwrap_or_else(|e| {
            tracing::warn!("tools/list failed (server may not support tools): {e}");
            Vec::new()
        });
        tracing::info!(count = tools.len(), "discovered MCP tools");
        client.tools = tools;

        Ok(Arc::new(client))
    }

    /// Gracefully shut down the child process (SIGTERM, then SIGKILL after timeout).
    pub async fn shutdown(&self) {
        let mut child = self.child.lock().await;
        // Try graceful kill first
        if let Err(e) = child.kill().await {
            tracing::warn!("failed to kill MCP child process: {e}");
        }
        // Wait for process to exit
        match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) => tracing::info!(%status, "MCP child process exited"),
            Ok(Err(e)) => tracing::warn!("error waiting for MCP child: {e}"),
            Err(_) => tracing::warn!("timed out waiting for MCP child to exit"),
        }
    }

    /// Send a JSON-RPC request and read the response.
    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

        let mut line = serde_json::to_string(&req)?;
        line.push('\n');

        tracing::debug!(method, id, "-> MCP request");

        {
            let mut stdin = self.stdin.lock().await;
            stdin.write_all(line.as_bytes()).await?;
            stdin.flush().await?;
        }

        // Read lines until we get a JSON-RPC response (skip notifications)
        loop {
            let mut buf = String::new();
            {
                let mut stdout = self.stdout.lock().await;
                let n = stdout.read_line(&mut buf).await?;
                if n == 0 {
                    bail!("MCP server closed stdout");
                }
            }

            let buf = buf.trim();
            if buf.is_empty() {
                continue;
            }

            // Try to parse as a response
            let parsed: Value = serde_json::from_str(buf)
                .with_context(|| format!("invalid JSON from MCP server: {buf}"))?;

            // Skip notifications (no id field)
            if parsed.get("id").is_none() || parsed.get("id") == Some(&Value::Null) {
                tracing::debug!("skipping MCP notification");
                continue;
            }

            let resp: JsonRpcResponse = serde_json::from_value(parsed)?;

            if let Some(err) = resp.error {
                bail!(err);
            }

            return Ok(resp.result.unwrap_or(Value::Null));
        }
    }

    /// Send a JSON-RPC notification (no id, no response expected).
    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<()> {
        #[derive(Serialize)]
        struct Notification {
            jsonrpc: &'static str,
            method: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            params: Option<Value>,
        }

        let notif = Notification {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
        };

        let mut line = serde_json::to_string(&notif)?;
        line.push('\n');

        let mut stdin = self.stdin.lock().await;
        stdin.write_all(line.as_bytes()).await?;
        stdin.flush().await?;

        Ok(())
    }

    /// MCP initialize handshake.
    async fn initialize(&self) -> Result<ServerInfo> {
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-shim",
                "version": env!("CARGO_PKG_VERSION")
            }
        });

        let result = self.request("initialize", Some(params)).await?;
        let init: InitializeResult = serde_json::from_value(result)?;
        Ok(init.server_info)
    }

    /// Discover available tools.
    async fn list_tools(&self) -> Result<Vec<McpTool>> {
        let result = self.request("tools/list", None).await?;
        let list: ToolsListResult = serde_json::from_value(result)?;
        Ok(list.tools)
    }

    /// Invoke a tool by name with the given arguments.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        let params = serde_json::json!({
            "name": name,
            "arguments": arguments,
        });

        self.request("tools/call", Some(params)).await
    }

    /// List available resources.
    pub async fn list_resources(&self) -> Result<Vec<McpResource>> {
        let result = self.request("resources/list", None).await?;
        let list: ResourcesListResult = serde_json::from_value(result)?;
        Ok(list.resources)
    }

    /// Read a resource by URI.
    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request("resources/read", Some(params)).await
    }
}
