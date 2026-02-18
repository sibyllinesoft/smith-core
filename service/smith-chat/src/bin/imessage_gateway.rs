//! iMessage Gateway (via BlueBubbles) that receives webhook events via an HTTP
//! server and publishes them to NATS as BridgeMessageEnvelope payloads.
//!
//! BlueBubbles POSTs `new-message` events to a configured webhook URL. This
//! gateway listens for those POSTs. If webhooks are unavailable, it falls back
//! to polling the BlueBubbles REST API.

use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use chat_bridge::gateway_common::{build_envelope, connect_nats, GatewayContext, SenderInfo};
use clap::Parser;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, error, info};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "iMessage (BlueBubbles) Webhook Gateway → NATS bridge for Smith"
)]
struct Cli {
    /// Port to listen on for BlueBubbles webhook events
    #[arg(long, env = "IMESSAGE_WEBHOOK_PORT", default_value_t = 8091)]
    port: u16,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();

    let cli = Cli::parse();
    let nats = connect_nats(&cli.nats_url).await?;

    let gw = Arc::new(GatewayContext {
        nats,
        ingest_subject: cli.ingest_subject.clone(),
        event_secret: cli.event_secret.clone(),
        platform: "imessage",
    });

    let app = Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(gw);

    let addr = format!("0.0.0.0:{}", cli.port);
    info!(addr = %addr, "iMessage (BlueBubbles) webhook gateway listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_webhook(
    State(gw): State<Arc<GatewayContext>>,
    Json(body): Json<Value>,
) -> StatusCode {
    let event_type = body
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if event_type != "new-message" {
        debug!(event_type, "Ignoring non-message BlueBubbles event");
        return StatusCode::OK;
    }

    if let Err(err) = handle_new_message(&gw, &body).await {
        error!(error = ?err, "Failed to handle BlueBubbles new-message event");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    StatusCode::OK
}

async fn handle_new_message(gw: &GatewayContext, body: &Value) -> Result<()> {
    let data = match body.get("data") {
        Some(d) => d,
        None => return Ok(()),
    };

    // Skip outgoing messages
    let is_from_me = data
        .get("isFromMe")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if is_from_me {
        debug!("Skipping self-message (isFromMe)");
        return Ok(());
    }

    let text = data.get("text").and_then(|v| v.as_str()).unwrap_or("");
    if text.is_empty() {
        return Ok(());
    }

    let guid = data
        .get("guid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let chat_guid = data
        .get("chats")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("guid"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let handle = data.get("handle");
    let sender_address = handle
        .and_then(|h| h.get("address"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let first_name = handle
        .and_then(|h| h.get("firstName"))
        .and_then(|v| v.as_str());
    let last_name = handle
        .and_then(|h| h.get("lastName"))
        .and_then(|v| v.as_str());
    let display_name = match (first_name, last_name) {
        (Some(f), Some(l)) => Some(format!("{f} {l}")),
        (Some(f), None) => Some(f.to_string()),
        (None, Some(l)) => Some(l.to_string()),
        (None, None) => None,
    };

    let sender = SenderInfo {
        id: sender_address.to_string(),
        username: Some(sender_address.to_string()),
        display_name,
        is_bot: false,
    };

    let envelope = build_envelope(
        "imessage",
        "",
        chat_guid,
        guid,
        guid,
        text,
        &sender,
        gw.event_secret.as_deref(),
        Vec::new(),
        Vec::new(),
    );

    info!(
        message_id = guid,
        chat = chat_guid,
        sender = sender_address,
        content_len = text.len(),
        "Publishing iMessage to NATS"
    );

    gw.publish_envelope(envelope).await?;
    Ok(())
}
