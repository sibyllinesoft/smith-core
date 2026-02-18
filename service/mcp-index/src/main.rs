mod http;
mod oauth;
mod poller;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use oauth::OAuthState;
use poller::{parse_upstreams, spawn_poller, IndexState};

#[derive(Parser)]
#[command(
    name = "mcp-index",
    about = "MCP server registry — polls shims, serves unified tool index"
)]
struct Cli {
    /// HTTP listen port
    #[arg(long, default_value = "9200", env = "MCP_INDEX_PORT")]
    port: u16,

    /// Upstream MCP shim instances: name=url,name=url
    #[arg(long, env = "MCP_INDEX_UPSTREAMS")]
    upstreams: String,

    /// Poll interval in seconds
    #[arg(long, default_value = "30", env = "MCP_INDEX_POLL_INTERVAL")]
    poll_interval: u64,

    /// Directory for OAuth credential files (shared with MCP servers)
    #[arg(
        long,
        default_value = "/credentials",
        env = "MCP_INDEX_CREDENTIALS_DIR"
    )]
    credentials_dir: PathBuf,

    /// Base URL for OAuth redirect URIs
    #[arg(
        long,
        default_value = "http://localhost:9200",
        env = "MCP_INDEX_BASE_URL"
    )]
    base_url: String,

    /// Optional API token for protecting index APIs (Authorization: Bearer <token>)
    #[arg(long, env = "MCP_INDEX_API_TOKEN")]
    api_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("mcp_index=info")),
        )
        .init();

    let cli = Cli::parse();

    let upstreams = parse_upstreams(&cli.upstreams);
    if upstreams.is_empty() {
        bail!("no upstreams provided — set --upstreams or MCP_INDEX_UPSTREAMS");
    }

    // Build OAuth providers from environment
    let mut providers = HashMap::new();
    if let Some(google) = oauth::google_provider_from_env(&cli.credentials_dir) {
        tracing::info!("Google OAuth provider configured");
        // google-analytics shares the same OAuth credentials as google
        providers.insert("google-analytics".to_string(), google.clone());
        providers.insert("google".to_string(), google);
    }

    let oauth_state = Arc::new(OAuthState::new(providers));

    tracing::info!(
        port = cli.port,
        upstreams = upstreams.len(),
        poll_interval = cli.poll_interval,
        oauth_providers = oauth_state.providers.len(),
        api_token_enabled = cli
            .api_token
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "starting mcp-index"
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    let state = Arc::new(IndexState {
        servers: RwLock::new(Vec::new()),
        upstreams,
        client,
        oauth: oauth_state,
        base_url: cli.base_url.trim_end_matches('/').to_string(),
        api_token: cli.api_token.filter(|v| !v.trim().is_empty()),
    });

    spawn_poller(Arc::clone(&state), Duration::from_secs(cli.poll_interval));

    let app = http::router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    tracing::info!(%addr, "HTTP server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
