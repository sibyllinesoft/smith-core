//! Slack Gateway using the Socket Mode WebSocket API. Receives real-time events
//! without requiring a public URL and publishes them to NATS as
//! BridgeMessageEnvelope payloads.

use anyhow::{Context, Result};
use chat_bridge::gateway_common::{build_envelope, connect_nats, SenderInfo};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Slack Socket Mode Gateway → NATS bridge for Smith"
)]
struct Cli {
    /// Slack app-level token (xapp-...) for Socket Mode
    #[arg(long, env = "SLACK_APP_TOKEN")]
    app_token: String,

    /// Slack bot user OAuth token (xoxb-...) for API calls
    #[arg(long, env = "SLACK_BOT_TOKEN")]
    bot_token: String,

    /// NATS server URL
    #[arg(long, env = "SMITH_NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// NATS subject to publish bridge envelopes to
    #[arg(
        long,
        env = "CHAT_BRIDGE_INGEST_SUBJECT",
        default_value = "smith.chatbridge.ingest"
    )]
    ingest_subject: String,

    /// Optional shared secret included in envelopes
    #[arg(long, env = "CHAT_BRIDGE_EVENT_SECRET")]
    event_secret: Option<String>,

    /// Comma-separated list of allowed Slack user IDs (empty = allow all)
    #[arg(long, env = "SLACK_ALLOWED_USER_IDS", value_delimiter = ',')]
    allowed_user_ids: Vec<String>,

    /// Max messages to fetch for thread context (0 = disabled)
    #[arg(long, env = "SLACK_THREAD_HISTORY_LIMIT", default_value_t = 20)]
    thread_history_limit: u32,
}

#[derive(Debug, Deserialize)]
struct SocketModeConnection {
    ok: bool,
    url: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SocketModeEvent {
    #[serde(default, rename = "type")]
    event_type: Option<String>,
    #[serde(default)]
    envelope_id: Option<String>,
    #[serde(default)]
    payload: Option<Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();

    let cli = Cli::parse();
    let nats = connect_nats(&cli.nats_url).await?;
    let http = reqwest::Client::new();

    loop {
        match run_socket_mode(&cli, &nats, &http).await {
            Ok(()) => {
                info!("Socket Mode disconnected cleanly, reconnecting in 5s...");
            }
            Err(err) => {
                error!(error = ?err, "Socket Mode error, reconnecting in 5s...");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_socket_mode(
    cli: &Cli,
    nats: &async_nats::Client,
    http: &reqwest::Client,
) -> Result<()> {
    // Request a WebSocket URL via apps.connections.open
    let conn_resp: SocketModeConnection = http
        .post("https://slack.com/api/apps.connections.open")
        .bearer_auth(&cli.app_token)
        .send()
        .await
        .context("failed to call apps.connections.open")?
        .json()
        .await?;

    if !conn_resp.ok {
        let err = conn_resp.error.unwrap_or_else(|| "unknown".into());
        anyhow::bail!("apps.connections.open failed: {err}");
    }

    let ws_url = conn_resp
        .url
        .ok_or_else(|| anyhow::anyhow!("no WebSocket URL returned"))?;

    let (mut ws, _) = connect_async(&ws_url)
        .await
        .context("failed to connect to Slack Socket Mode WebSocket")?;
    info!("Connected to Slack Socket Mode");

    while let Some(frame) = ws.next().await {
        match frame {
            Ok(WsMessage::Text(text)) => {
                let event: SocketModeEvent = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(err) => {
                        warn!(error = ?err, "Failed to parse Socket Mode event");
                        continue;
                    }
                };

                // Acknowledge the envelope immediately
                if let Some(ref envelope_id) = event.envelope_id {
                    let ack = json!({ "envelope_id": envelope_id });
                    if let Err(err) = ws.send(WsMessage::Text(ack.to_string())).await {
                        warn!(error = ?err, "Failed to send acknowledgement");
                    }
                }

                match event.event_type.as_deref() {
                    Some("events_api") => {
                        if let Some(payload) = &event.payload {
                            if let Err(err) = handle_events_api(cli, nats, http, payload).await {
                                error!(error = ?err, "Failed to handle events_api payload");
                            }
                        }
                    }
                    Some("hello") => {
                        info!("Received Socket Mode hello");
                    }
                    Some("disconnect") => {
                        info!("Slack requested disconnect, will reconnect");
                        return Ok(());
                    }
                    other => {
                        debug!(event_type = ?other, "Unhandled Socket Mode event type");
                    }
                }
            }
            Ok(WsMessage::Close(frame)) => {
                info!(?frame, "WebSocket closed by Slack");
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

async fn handle_events_api(
    cli: &Cli,
    nats: &async_nats::Client,
    http: &reqwest::Client,
    payload: &Value,
) -> Result<()> {
    let event = match payload.get("event") {
        Some(e) => e,
        None => return Ok(()),
    };

    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");

    if event_type != "message" {
        debug!(event_type, "Ignoring non-message event");
        return Ok(());
    }

    // Skip subtypes (bot messages, edits, etc.) unless it's a thread broadcast
    if let Some(subtype) = event.get("subtype").and_then(|v| v.as_str()) {
        if subtype != "thread_broadcast" {
            debug!(subtype, "Skipping message subtype");
            return Ok(());
        }
    }

    let user = event.get("user").and_then(|v| v.as_str()).unwrap_or("");
    if user.is_empty() {
        return Ok(());
    }

    // Filter by allowed user IDs if configured
    if !cli.allowed_user_ids.is_empty() && !cli.allowed_user_ids.iter().any(|id| id == user) {
        debug!(user, "Ignoring message from non-allowed user");
        return Ok(());
    }

    let text = event.get("text").and_then(|v| v.as_str()).unwrap_or("");
    if text.is_empty() {
        return Ok(());
    }

    let channel = event.get("channel").and_then(|v| v.as_str()).unwrap_or("");
    let ts = event.get("ts").and_then(|v| v.as_str()).unwrap_or("");
    let thread_ts = event
        .get("thread_ts")
        .and_then(|v| v.as_str())
        .unwrap_or(ts);
    let team = event.get("team").and_then(|v| v.as_str()).unwrap_or("");

    // Fetch thread history if this is a threaded message
    let thread_history = if cli.thread_history_limit > 0 && thread_ts != ts {
        fetch_thread_history(
            http,
            &cli.bot_token,
            channel,
            thread_ts,
            ts,
            cli.thread_history_limit,
        )
        .await
    } else {
        Vec::new()
    };

    let sender = SenderInfo {
        id: user.to_string(),
        username: Some(user.to_string()),
        display_name: None,
        is_bot: false,
    };

    let history_len = thread_history.len();
    let envelope = build_envelope(
        "slack",
        team,
        channel,
        ts,
        thread_ts,
        text,
        &sender,
        cli.event_secret.as_deref(),
        Vec::new(),
        thread_history,
    );

    let payload = serde_json::to_vec(&envelope)?;

    info!(
        ts,
        channel,
        user,
        content_len = text.len(),
        history_len,
        "Publishing Slack message to NATS"
    );

    nats.publish(cli.ingest_subject.clone(), payload.into())
        .await
        .context("failed to publish to NATS")?;
    nats.flush().await.context("failed to flush NATS")?;

    Ok(())
}

async fn fetch_thread_history(
    http: &reqwest::Client,
    bot_token: &str,
    channel: &str,
    thread_ts: &str,
    before_ts: &str,
    limit: u32,
) -> Vec<Value> {
    let resp = match http
        .get("https://slack.com/api/conversations.replies")
        .bearer_auth(bot_token)
        .query(&[
            ("channel", channel),
            ("ts", thread_ts),
            ("limit", &limit.to_string()),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            warn!(error = ?err, channel, "Failed to fetch Slack thread history");
            return Vec::new();
        }
    };

    let payload: Value = match resp.json().await {
        Ok(v) => v,
        Err(err) => {
            warn!(error = ?err, "Failed to parse Slack thread history");
            return Vec::new();
        }
    };

    if !payload.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Vec::new();
    }

    let messages = match payload.get("messages").and_then(|v| v.as_array()) {
        Some(msgs) => msgs,
        None => return Vec::new(),
    };

    messages
        .iter()
        .filter(|msg| {
            // Exclude the current message
            msg.get("ts").and_then(|v| v.as_str()).unwrap_or("") != before_ts
        })
        .filter_map(|msg| {
            let text = msg.get("text")?.as_str()?;
            if text.is_empty() {
                return None;
            }
            let user = msg
                .get("user")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let bot_id = msg.get("bot_id").and_then(|v| v.as_str());
            let ts = msg.get("ts").and_then(|v| v.as_str()).unwrap_or("");

            let role = if bot_id.is_some() {
                "assistant"
            } else {
                "user"
            };

            Some(json!({
                "role": role,
                "content": text,
                "username": user,
                "timestamp": ts,
            }))
        })
        .collect()
}
