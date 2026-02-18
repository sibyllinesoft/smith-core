//! Matrix Gateway that uses the Client-Server `/sync` long-poll loop to receive
//! room messages and publishes them to NATS as BridgeMessageEnvelope payloads.

use anyhow::{Context, Result};
use chat_bridge::gateway_common::{build_envelope, connect_nats, GatewayContext, SenderInfo};
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(author, version, about = "Matrix Gateway → NATS bridge for Smith")]
struct Cli {
    /// Matrix homeserver URL (e.g. https://matrix.org)
    #[arg(long, env = "MATRIX_HOMESERVER_URL")]
    homeserver_url: String,

    /// Matrix access token for the bot user
    #[arg(long, env = "MATRIX_ACCESS_TOKEN")]
    access_token: String,

    /// Matrix user ID of the bot (e.g. @smithbot:matrix.org)
    #[arg(long, env = "MATRIX_USER_ID")]
    user_id: String,

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

    /// Sync timeout in seconds (Matrix long-poll duration)
    #[arg(long, env = "MATRIX_SYNC_TIMEOUT_SECS", default_value_t = 30)]
    sync_timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
struct SyncResponse {
    #[serde(default)]
    next_batch: Option<String>,
    #[serde(default)]
    rooms: Option<SyncRooms>,
}

#[derive(Debug, Deserialize)]
struct SyncRooms {
    #[serde(default)]
    join: Option<std::collections::HashMap<String, JoinedRoom>>,
}

#[derive(Debug, Deserialize)]
struct JoinedRoom {
    #[serde(default)]
    timeline: Option<Timeline>,
}

#[derive(Debug, Deserialize)]
struct Timeline {
    #[serde(default)]
    events: Vec<TimelineEvent>,
}

#[derive(Debug, Deserialize)]
struct TimelineEvent {
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    sender: Option<String>,
    #[serde(default, rename = "type")]
    event_type: Option<String>,
    #[serde(default)]
    content: Option<Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();

    let cli = Cli::parse();
    let nats = connect_nats(&cli.nats_url).await?;
    let http = reqwest::Client::new();

    let gw = GatewayContext {
        nats,
        ingest_subject: cli.ingest_subject.clone(),
        event_secret: cli.event_secret.clone(),
        platform: "matrix",
    };

    info!(
        homeserver = %cli.homeserver_url,
        user_id = %cli.user_id,
        "Starting Matrix sync loop"
    );

    let mut since: Option<String> = None;
    let mut consecutive_errors: u32 = 0;

    loop {
        match sync_once(&cli, &http, &gw, since.as_deref()).await {
            Ok(next_batch) => {
                since = next_batch;
                consecutive_errors = 0;
            }
            Err(err) => {
                consecutive_errors += 1;
                let backoff = Duration::from_secs((2u64).pow(consecutive_errors.min(6)));
                error!(
                    error = ?err,
                    consecutive_errors,
                    backoff_secs = backoff.as_secs(),
                    "Matrix sync failed"
                );
                sleep(backoff).await;
            }
        }
    }
}

async fn sync_once(
    cli: &Cli,
    http: &reqwest::Client,
    gw: &GatewayContext,
    since: Option<&str>,
) -> Result<Option<String>> {
    let base = cli.homeserver_url.trim_end_matches('/');
    let timeout_ms = cli.sync_timeout_secs * 1000;

    let url = if let Some(since) = since {
        format!(
            "{base}/_matrix/client/v3/sync?since={since}&timeout={timeout_ms}&filter={{\"room\":{{\"timeline\":{{\"limit\":50}}}}}}"
        )
    } else {
        // Initial sync: only get a small amount of history
        format!(
            "{base}/_matrix/client/v3/sync?filter={{\"room\":{{\"timeline\":{{\"limit\":1}}}}}}"
        )
    };

    let resp = http
        .get(&url)
        .bearer_auth(&cli.access_token)
        .timeout(Duration::from_secs(cli.sync_timeout_secs + 30))
        .send()
        .await
        .context("Matrix sync request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Matrix sync returned {status}: {body}");
    }

    let sync: SyncResponse = resp.json().await?;
    let next_batch = sync.next_batch.clone();

    // On initial sync (no since token), skip processing events — we only want
    // the next_batch token to start receiving live events from this point.
    if since.is_none() {
        if let Some(ref token) = next_batch {
            info!(next_batch = %token, "Initial sync complete, will process live events from here");
        }
        return Ok(next_batch);
    }

    // Process room events
    if let Some(rooms) = sync.rooms {
        if let Some(joined) = rooms.join {
            for (room_id, room) in joined {
                if let Some(timeline) = room.timeline {
                    for event in timeline.events {
                        if let Err(err) = handle_timeline_event(cli, gw, &room_id, &event).await {
                            warn!(
                                error = ?err,
                                room_id,
                                event_id = ?event.event_id,
                                "Failed to handle timeline event"
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(next_batch)
}

async fn handle_timeline_event(
    cli: &Cli,
    gw: &GatewayContext,
    room_id: &str,
    event: &TimelineEvent,
) -> Result<()> {
    // Only process m.room.message events
    if event.event_type.as_deref() != Some("m.room.message") {
        return Ok(());
    }

    let sender = event.sender.as_deref().unwrap_or("unknown");

    // Skip own messages
    if sender == cli.user_id {
        debug!("Skipping own message");
        return Ok(());
    }

    let content = match &event.content {
        Some(c) => c,
        None => return Ok(()),
    };

    let text = content.get("body").and_then(|v| v.as_str()).unwrap_or("");
    if text.is_empty() {
        return Ok(());
    }

    let event_id = event.event_id.as_deref().unwrap_or("unknown");

    // Extract reply-to if present
    let thread_root = content
        .get("m.relates_to")
        .and_then(|r| r.get("m.in_reply_to"))
        .and_then(|r| r.get("event_id"))
        .and_then(|v| v.as_str())
        .unwrap_or(event_id);

    // Extract display name from MXID: @user:server → user
    let display_name = sender
        .strip_prefix('@')
        .and_then(|s| s.split(':').next())
        .map(|s| s.to_string());

    let sender_info = SenderInfo {
        id: sender.to_string(),
        username: Some(sender.to_string()),
        display_name,
        is_bot: false,
    };

    let envelope = build_envelope(
        "matrix",
        "",
        room_id,
        event_id,
        thread_root,
        text,
        &sender_info,
        gw.event_secret.as_deref(),
        Vec::new(),
        Vec::new(),
    );

    info!(
        event_id,
        room_id,
        sender,
        content_len = text.len(),
        "Publishing Matrix message to NATS"
    );

    gw.publish_envelope(envelope).await?;
    Ok(())
}
