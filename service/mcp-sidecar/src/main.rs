mod http;
mod mcp_client;
mod middleware;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use mcp_client::SpawnConfig;
use middleware::MiddlewareConfig;

#[derive(Parser)]
#[command(
    name = "mcp-sidecar",
    about = "Bridge any MCP server (stdio) to an HTTP API",
    after_help = "Pass the MCP server command after --:\n  mcp-sidecar -- npx @modelcontextprotocol/server-filesystem /data"
)]
struct Cli {
    /// HTTP listen port
    #[arg(long, default_value = "9100", env = "MCP_SIDECAR_PORT")]
    port: u16,

    /// Service name for logging
    #[arg(long, env = "MCP_SIDECAR_NAME")]
    name: Option<String>,

    /// Max seconds to wait for MCP initialize response
    #[arg(long, default_value = "10", env = "MCP_SIDECAR_INIT_TIMEOUT")]
    init_timeout: u64,

    /// Path to middleware TOML config (input/output transforms, filters)
    #[arg(long, env = "MCP_SIDECAR_MIDDLEWARE")]
    middleware: Option<PathBuf>,

    /// The MCP server command and arguments (everything after --)
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

pub struct AppState {
    pub client: RwLock<Arc<mcp_client::McpClient>>,
    pub config: SpawnConfig,
    pub middleware: RwLock<Option<Arc<MiddlewareConfig>>>,
    pub middleware_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("mcp_sidecar=info")
        }))
        .init();

    let cli = Cli::parse();

    if cli.command.is_empty() {
        bail!("no MCP server command provided — pass it after --");
    }

    let program = &cli.command[0];
    let args: Vec<String> = cli.command[1..].to_vec();
    let service_name = cli.name.as_deref().unwrap_or(program);

    tracing::info!(
        service_name,
        port = cli.port,
        "starting mcp-sidecar"
    );

    // Load middleware config if provided
    let mw = match &cli.middleware {
        Some(path) => {
            let config = MiddlewareConfig::load(path)
                .context("failed to load middleware config")?;
            Some(Arc::new(config))
        }
        None => None,
    };

    let spawn_config = SpawnConfig {
        program: program.clone(),
        args,
        init_timeout: Duration::from_secs(cli.init_timeout),
    };

    // Spawn the MCP server and perform handshake
    let client = mcp_client::McpClient::spawn_from_config(&spawn_config)
        .await
        .context("failed to start MCP server")?;

    let state = Arc::new(AppState {
        client: RwLock::new(client),
        config: spawn_config,
        middleware: RwLock::new(mw),
        middleware_path: cli.middleware,
    });

    // Build HTTP router
    let app = http::router(state);

    // Start serving
    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    tracing::info!(%addr, service_name, "HTTP server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
