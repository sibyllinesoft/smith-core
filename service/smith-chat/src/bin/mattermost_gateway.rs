//! Mattermost Gateway that connects to the Mattermost WebSocket API, receives
//! real-time message events, and publishes them to NATS as BridgeMessageEnvelope
//! payloads.

use anyhow::{Context, Result};
use chat_bridge::gateway_common::{build_envelope, connect_nats, SenderInfo};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tracing::{debug, error, info};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(author, version, about = "Mattermost Gateway → NATS bridge for Smith")]
struct Cli {
    /// Mattermost server URL (e.g. https://mattermost.example.com)
    #[arg(long, env = "MATTERMOST_URL")]
    server_url: String,

    /// Mattermost personal access token or bot token
    #[arg(long, env = "MATTERMOST_ACCESS_TOKEN")]
    access_token: String,

    /// Team ID to filter events (optional, monitors all teams if empty)
    #[arg(long, env = "MATTERMOST_TEAM_ID")]
    team_id: Option<String>,

    /// NATS server URL
    #[arg(long, env = "SMITH_NATS_URL", default_value = "nats://127.0.0.1:7222")]
    nats_url: String,

    /// NATS subject to publish bridge envelopes to
    #[arg(long, env = "CHAT_BRIDGE_INGEST_SUBJECT", default_value = "smith.chatbridge.ingest")]
    ingest_subject: String,

    /// Optional shared secret included in envelopes
    #[arg(long, env = "CHAT_BRIDGE_EVENT_SECRET")]
    event_secret: Option<String>,

    /// Comma-separated list of allowed Mattermost user IDs (empty = allow all)
    #[arg(long, env = "MATTERMOST_ALLOWED_USER_IDS", value_delimiter = ',')]
    allowed_user_ids: Vec<String>,

    /// Skip TLS verification for self-signed certs
    #[arg(long, env = "MATTERMOST_SKIP_TLS_VERIFY", default_value_t = false)]
    skip_tls_verify: bool,
}

#[derive(Debug, Deserialize)]
struct WsEvent {
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    broadcast: Option<WsBroadcast>,
}

#[derive(Debug, Deserialize)]
struct WsBroadcast {
    #[serde(default)]
    channel_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
}

/// Bot user info fetched on startup to filter self-messages.
struct BotInfo {
    user_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();

    let cli = Cli::parse();
    let nats = connect_nats(&cli.nats_url).await?;
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(cli.skip_tls_verify)
        .build()?;

    // Fetch bot's own user ID so we can filter self-messages
    let bot_info = fetch_bot_info(&cli, &http).await?;
    info!(bot_user_id = %bot_info.user_id, "Identified bot user");

    loop {
        match run_websocket(&cli, &nats, &http, &bot_info).await {
            Ok(()) => {
                info!("Mattermost WebSocket disconnected, reconnecting in 5s...");
            }
            Err(err) => {
                error!(error = ?err, "Mattermost WebSocket error, reconnecting in 5s...");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn fetch_bot_info(cli: &Cli, http: &reqwest::Client) -> Result<BotInfo> {
    let url = format!("{}/api/v4/users/me", cli.server_url.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .bearer_auth(&cli.access_token)
        .send()
        .await
        .context("failed to fetch bot user info")?;

    let user: Value = resp.json().await?;
    let user_id = user
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("could not determine bot user ID"))?
        .to_string();

    Ok(BotInfo { user_id })
}

async fn run_websocket(
    cli: &Cli,
    nats: &async_nats::Client,
    _http: &reqwest::Client,
    bot_info: &BotInfo,
) -> Result<()> {
    let base = cli.server_url.trim_end_matches('/');
    let ws_url = if base.starts_with("https") {
        format!("{}/api/v4/websocket", base.replacen("https", "wss", 1))
    } else {
        format!("{}/api/v4/websocket", base.replacen("http", "ws", 1))
    };

    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("failed to connect to Mattermost WebSocket")?;

    // Authenticate via the WebSocket
    let auth = json!({
        "seq": 1,
        "action": "authentication_challenge",
        "data": {
            "token": cli.access_token,
        }
    });
    ws.send(WsMessage::Text(auth.to_string())).await?;
    info!(url = %ws_url, "Connected to Mattermost WebSocket");

    while let Some(frame) = ws.next().await {
        match frame {
            Ok(WsMessage::Text(text)) => {
                let event: WsEvent = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                if event.event.as_deref() == Some("posted") {
                    if let Err(err) = handle_posted(cli, nats, bot_info, &event).await {
                        error!(error = ?err, "Failed to handle posted event");
                    }
                }
            }
            Ok(WsMessage::Close(frame)) => {
                info!(?frame, "WebSocket closed by Mattermost");
                return Ok(());
            }
            Ok(WsMessage::Ping(data)) => {
                ws.send(WsMessage::Pong(data)).await?;
            }
            Ok(_) => {}
            Err(err) => {
                return Err(anyhow::anyhow!("WebSocket error: {err}"));
            }
        }
    }

    Ok(())
}

async fn handle_posted(
    cli: &Cli,
    nats: &async_nats::Client,
    bot_info: &BotInfo,
    event: &WsEvent,
) -> Result<()> {
    let data = match &event.data {
        Some(d) => d,
        None => return Ok(()),
    };

    // The "post" field is a JSON string within the data object
    let post_str = data
        .get("post")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if post_str.is_empty() {
        return Ok(());
    }

    let post: Value = serde_json::from_str(post_str)?;

    let user_id = post
        .get("user_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Skip own messages
    if user_id == bot_info.user_id {
        debug!("Skipping own message");
        return Ok(());
    }

    // Filter by allowed user IDs if configured
    if !cli.allowed_user_ids.is_empty() && !cli.allowed_user_ids.iter().any(|id| id == user_id) {
        debug!(user_id, "Ignoring message from non-allowed user");
        return Ok(());
    }

    let message = post
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if message.is_empty() {
        return Ok(());
    }

    // Skip messages that originated from the bridge to prevent loops
    if post
        .get("props")
        .and_then(|p| p.get("smith_bridge_origin"))
        .is_some()
    {
        debug!("Skipping bridge-originated message");
        return Ok(());
    }

    let channel_id = event
        .broadcast
        .as_ref()
        .and_then(|b| b.channel_id.as_deref())
        .or_else(|| post.get("channel_id").and_then(|v| v.as_str()))
        .unwrap_or("");

    let team_id = event
        .broadcast
        .as_ref()
        .and_then(|b| b.team_id.as_deref())
        .unwrap_or("");

    // Filter by team if configured
    if let Some(ref filter_team) = cli.team_id {
        if !team_id.is_empty() && team_id != filter_team {
            debug!(team_id, "Ignoring message from other team");
            return Ok(());
        }
    }

    let post_id = post.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let root_id = post
        .get("root_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(post_id);

    let sender_name = data
        .get("sender_name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('@').to_string());

    let sender = SenderInfo {
        id: user_id.to_string(),
        username: sender_name.clone(),
        display_name: sender_name,
        is_bot: false,
    };

    let envelope = build_envelope(
        "mattermost",
        team_id,
        channel_id,
        post_id,
        root_id,
        message,
        &sender,
        cli.event_secret.as_deref(),
        Vec::new(),
        Vec::new(),
    );

    let payload = serde_json::to_vec(&envelope)?;

    info!(
        post_id,
        channel_id,
        user_id,
        content_len = message.len(),
        "Publishing Mattermost message to NATS"
    );

    nats.publish(cli.ingest_subject.clone(), payload.into())
        .await
        .context("failed to publish to NATS")?;
    nats.flush().await.context("failed to flush NATS")?;

    Ok(())
}
