//! Discord Gateway bot that connects to Discord's WebSocket, receives message
//! events, translates them to BridgeMessageEnvelope, and publishes to NATS.
//!
//! This is the recommended way to ingest Discord messages into Smith -- no
//! public URL or webhook setup required.

use std::sync::Arc;

use anyhow::{Context, Result};
use chat_bridge::gateway_common::{build_envelope, connect_nats, SenderInfo};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(author, version, about = "Discord Gateway → NATS bridge for Smith")]
struct Cli {
    /// Discord bot token
    #[arg(long, env = "DISCORD_BOT_TOKEN")]
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

    /// Discord Gateway intents bitmask
    /// Default: GUILDS(1) | GUILD_MESSAGES(512) | DIRECT_MESSAGES(4096) | MESSAGE_CONTENT(32768) = 37377
    #[arg(long, env = "DISCORD_INTENTS", default_value_t = 37377)]
    intents: u64,

    /// Comma-separated list of allowed Discord user IDs (empty = allow all)
    #[arg(long, env = "DISCORD_ALLOWED_USER_IDS", value_delimiter = ',')]
    allowed_user_ids: Vec<String>,

    /// Max messages to fetch for thread context (0 = disabled)
    #[arg(long, env = "DISCORD_THREAD_HISTORY_LIMIT", default_value_t = 20)]
    thread_history_limit: u32,
}

const DISCORD_GATEWAY_URL: &str = "wss://gateway.discord.gg/?v=10&encoding=json";

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();

    let cli = Cli::parse();

    let nats = connect_nats(&cli.nats_url).await?;

    let http = reqwest::Client::new();
    let bot_user_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    loop {
        match run_gateway(&cli, &nats, &http, Arc::clone(&bot_user_id)).await {
            Ok(()) => {
                info!("Gateway disconnected cleanly, reconnecting in 5s...");
            }
            Err(err) => {
                error!(error = ?err, "Gateway error, reconnecting in 5s...");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_gateway(
    cli: &Cli,
    nats: &async_nats::Client,
    http: &reqwest::Client,
    bot_user_id: Arc<Mutex<Option<String>>>,
) -> Result<()> {
    let (mut ws, _) = connect_async(DISCORD_GATEWAY_URL)
        .await
        .context("failed to connect to Discord Gateway")?;
    info!("Connected to Discord Gateway");

    // Wait for Hello (opcode 10) to get heartbeat interval
    let hello = read_next_text(&mut ws).await?;
    let hello_payload: GatewayEvent =
        serde_json::from_str(&hello).context("failed to parse Hello")?;

    let heartbeat_interval_ms = hello_payload
        .d
        .as_ref()
        .and_then(|d| d.get("heartbeat_interval"))
        .and_then(|v| v.as_u64())
        .unwrap_or(41250);

    info!(heartbeat_interval_ms, "Received Hello");

    // Send Identify (opcode 2)
    let identify = json!({
        "op": 2,
        "d": {
            "token": cli.bot_token,
            "intents": cli.intents,
            "properties": {
                "os": "linux",
                "browser": "smith",
                "device": "smith"
            }
        }
    });
    ws.send(WsMessage::Text(identify.to_string())).await?;
    info!("Sent Identify");

    let mut sequence: Option<u64> = None;
    let mut heartbeat_ticker = interval(Duration::from_millis(heartbeat_interval_ms));
    // Skip the first immediate tick
    heartbeat_ticker.tick().await;

    loop {
        tokio::select! {
            _ = heartbeat_ticker.tick() => {
                let hb = json!({ "op": 1, "d": sequence });
                ws.send(WsMessage::Text(hb.to_string())).await?;
                debug!("Sent heartbeat");
            }
            frame = ws.next() => {
                match frame {
                    Some(Ok(WsMessage::Text(text))) => {
                        let event: GatewayEvent = match serde_json::from_str(&text) {
                            Ok(e) => e,
                            Err(err) => {
                                warn!(error = ?err, "Failed to parse gateway event");
                                continue;
                            }
                        };

                        if let Some(s) = event.s {
                            sequence = Some(s);
                        }

                        match event.op {
                            0 => {
                                // Dispatch event
                                if let Some(ref t) = event.t {
                                    handle_dispatch(cli, nats, http, &bot_user_id, t, &event.d).await;
                                }
                            }
                            1 => {
                                // Heartbeat request
                                let hb = json!({ "op": 1, "d": sequence });
                                ws.send(WsMessage::Text(hb.to_string())).await?;
                                debug!("Sent heartbeat (requested)");
                            }
                            7 => {
                                // Reconnect
                                info!("Discord requested reconnect");
                                return Ok(());
                            }
                            9 => {
                                // Invalid session
                                warn!("Invalid session, will reconnect");
                                return Ok(());
                            }
                            11 => {
                                // Heartbeat ACK
                                debug!("Heartbeat ACK");
                            }
                            _ => {
                                debug!(op = event.op, "Unhandled opcode");
                            }
                        }
                    }
                    Some(Ok(WsMessage::Close(frame))) => {
                        info!(?frame, "WebSocket closed by server");
                        return Ok(());
                    }
                    Some(Ok(WsMessage::Ping(data))) => {
                        ws.send(WsMessage::Pong(data)).await?;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        return Err(anyhow::anyhow!("WebSocket error: {err}"));
                    }
                    None => {
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn handle_dispatch(
    cli: &Cli,
    nats: &async_nats::Client,
    http: &reqwest::Client,
    bot_user_id: &Mutex<Option<String>>,
    event_type: &str,
    data: &Option<Value>,
) {
    match event_type {
        "READY" => {
            if let Some(d) = data {
                let user = d
                    .get("user")
                    .and_then(|u| u.get("username"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("unknown");
                let guilds = d
                    .get("guilds")
                    .and_then(|g| g.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);

                if let Some(id) = d
                    .get("user")
                    .and_then(|u| u.get("id"))
                    .and_then(|v| v.as_str())
                {
                    *bot_user_id.lock().await = Some(id.to_string());
                    info!(
                        bot_user = user,
                        bot_id = id,
                        guild_count = guilds,
                        "Discord bot is READY"
                    );
                } else {
                    info!(
                        bot_user = user,
                        guild_count = guilds,
                        "Discord bot is READY (no user ID)"
                    );
                }
            }
        }
        "MESSAGE_CREATE" => {
            if let Some(d) = data {
                if let Err(err) = handle_message_create(cli, nats, http, bot_user_id, d).await {
                    error!(error = ?err, "Failed to handle MESSAGE_CREATE");
                }
            }
        }
        _ => {
            debug!(event_type, "Received dispatch event");
        }
    }
}

async fn handle_message_create(
    cli: &Cli,
    nats: &async_nats::Client,
    http: &reqwest::Client,
    bot_user_id: &Mutex<Option<String>>,
    data: &Value,
) -> Result<()> {
    let author = data.get("author");

    // Ignore bot messages to prevent loops
    if author
        .and_then(|a| a.get("bot"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false)
    {
        return Ok(());
    }

    let sender_id = author
        .and_then(|a| a.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Filter by allowed user IDs if configured
    if !cli.allowed_user_ids.is_empty() && !cli.allowed_user_ids.iter().any(|id| id == sender_id) {
        debug!(sender_id, "Ignoring message from non-allowed user");
        return Ok(());
    }

    let message_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let content = data.get("content").and_then(|v| v.as_str()).unwrap_or("");
    let channel_id = data
        .get("channel_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let guild_id = data.get("guild_id").and_then(|v| v.as_str()).unwrap_or("");
    let timestamp = data.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");

    let sender_username = author
        .and_then(|a| a.get("username"))
        .and_then(|v| v.as_str());
    let sender_display = author
        .and_then(|a| a.get("global_name"))
        .and_then(|v| v.as_str())
        .or_else(|| sender_username);

    // Parse timestamp to unix epoch
    let unix_ts = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.timestamp())
        .unwrap_or_else(|_| chrono::Utc::now().timestamp());

    // Use message_id as thread_root for new conversations,
    // or referenced_message.id if this is a reply
    let thread_root = data
        .get("message_reference")
        .and_then(|r| r.get("message_id"))
        .and_then(|v| v.as_str())
        .unwrap_or(message_id);

    // Fetch thread history if enabled
    let thread_history = if cli.thread_history_limit > 0 {
        let bot_id = bot_user_id.lock().await.clone().unwrap_or_default();
        fetch_thread_history(
            http,
            &cli.bot_token,
            channel_id,
            message_id,
            cli.thread_history_limit,
            &bot_id,
        )
        .await
    } else {
        Vec::new()
    };

    // Build attachments
    let attachments: Vec<Value> = data
        .get("attachments")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .map(|att| {
                    json!({
                        "id": att.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                        "name": att.get("filename").and_then(|v| v.as_str()).unwrap_or(""),
                        "mime_type": att.get("content_type").and_then(|v| v.as_str()),
                        "size_bytes": att.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let sender_info = SenderInfo {
        id: sender_id.to_string(),
        username: sender_username.map(|s| s.to_string()),
        display_name: sender_display.map(|s| s.to_string()),
        is_bot: false,
    };

    let history_len = thread_history.len();
    let envelope = build_envelope(
        "discord",
        guild_id,
        channel_id,
        message_id,
        thread_root,
        content,
        &sender_info,
        cli.event_secret.as_deref(),
        attachments,
        thread_history,
    );

    let payload = serde_json::to_vec(&envelope)?;

    info!(
        message_id,
        channel_id,
        guild_id,
        sender = sender_username.unwrap_or("unknown"),
        content_len = content.len(),
        history_len,
        "Publishing Discord message to NATS"
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
    channel_id: &str,
    before_message_id: &str,
    limit: u32,
    bot_user_id: &str,
) -> Vec<Value> {
    let url = format!(
        "https://discord.com/api/v10/channels/{}/messages?limit={}&before={}",
        channel_id, limit, before_message_id
    );

    let resp = match http
        .get(&url)
        .header("Authorization", format!("Bot {}", bot_token))
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            warn!(error = ?err, channel_id, "Failed to fetch thread history");
            return Vec::new();
        }
    };

    if !resp.status().is_success() {
        warn!(status = %resp.status(), channel_id, "Discord API returned error for history fetch");
        return Vec::new();
    }

    let messages: Vec<Value> = match resp.json().await {
        Ok(m) => m,
        Err(err) => {
            warn!(error = ?err, channel_id, "Failed to parse thread history response");
            return Vec::new();
        }
    };

    // Discord returns newest-first; reverse to chronological order
    let history: Vec<Value> = messages
        .into_iter()
        .rev()
        .filter_map(|msg| {
            let content = msg.get("content")?.as_str()?;
            if content.is_empty() {
                return None;
            }
            let author = msg.get("author")?;
            let author_id = author.get("id")?.as_str()?;
            let is_bot = author.get("bot").and_then(|b| b.as_bool()).unwrap_or(false);
            let username = author
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let timestamp = msg.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");

            let role = if author_id == bot_user_id && is_bot {
                "assistant"
            } else {
                "user"
            };

            Some(json!({
                "role": role,
                "content": content,
                "username": username,
                "timestamp": timestamp
            }))
        })
        .collect();

    info!(
        count = history.len(),
        channel_id, "Fetched thread history messages"
    );

    history
}

async fn read_next_text(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<String> {
    while let Some(frame) = ws.next().await {
        match frame? {
            WsMessage::Text(text) => return Ok(text),
            WsMessage::Close(frame) => {
                return Err(anyhow::anyhow!("WebSocket closed: {frame:?}"));
            }
            _ => continue,
        }
    }
    Err(anyhow::anyhow!("WebSocket stream ended"))
}

#[derive(Debug, Deserialize)]
struct GatewayEvent {
    op: u8,
    #[serde(default)]
    d: Option<Value>,
    #[serde(default)]
    s: Option<u64>,
    #[serde(default)]
    t: Option<String>,
}
