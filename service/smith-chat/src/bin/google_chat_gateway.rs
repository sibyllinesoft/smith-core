//! Google Chat Gateway that receives webhook events via an HTTP server and
//! publishes them to NATS as BridgeMessageEnvelope payloads.
//!
//! Google Chat pushes events (MESSAGE, ADDED_TO_SPACE, etc.) to a configured
//! webhook URL. This gateway listens for those POSTs.

use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use chat_bridge::gateway_common::{build_envelope, connect_nats, GatewayContext, SenderInfo};
use clap::Parser;
use serde_json::Value;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Google Chat Webhook Gateway → NATS bridge for Smith"
)]
struct Cli {
    /// Port to listen on for Google Chat webhook events
    #[arg(long, env = "GOOGLE_CHAT_WEBHOOK_PORT", default_value_t = 8090)]
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

    /// Google Cloud project number for basic request verification
    #[arg(long, env = "GOOGLE_CHAT_PROJECT_NUMBER")]
    project_number: Option<String>,
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
        platform: "google_chat",
    });

    let app = Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(gw);

    let addr = format!("0.0.0.0:{}", cli.port);
    info!(addr = %addr, "Google Chat webhook gateway listening");

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
        .unwrap_or("UNKNOWN");

    match event_type {
        "MESSAGE" => {
            if let Err(err) = handle_message(&gw, &body).await {
                error!(error = ?err, "Failed to handle Google Chat MESSAGE event");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        "ADDED_TO_SPACE" => {
            info!("Bot added to space");
        }
        "REMOVED_FROM_SPACE" => {
            info!("Bot removed from space");
        }
        other => {
            warn!(event_type = other, "Unhandled Google Chat event type");
        }
    }

    StatusCode::OK
}

async fn handle_message(gw: &GatewayContext, body: &Value) -> Result<()> {
    let message = body.get("message");

    let text = message
        .and_then(|m| m.get("text"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if text.is_empty() {
        return Ok(());
    }

    let msg_name = message
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let message_id = msg_name.rsplit('/').next().unwrap_or(msg_name);

    let space_name = body
        .get("space")
        .and_then(|s| s.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let thread_name = message
        .and_then(|m| m.get("thread"))
        .and_then(|t| t.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(message_id);
    let thread_root = thread_name.rsplit('/').next().unwrap_or(thread_name);

    let sender_obj = message.and_then(|m| m.get("sender"));
    let sender_name = sender_obj
        .and_then(|s| s.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let sender_id = sender_name.rsplit('/').next().unwrap_or(sender_name);
    let sender_display = sender_obj
        .and_then(|s| s.get("displayName"))
        .and_then(|v| v.as_str());
    let sender_type = sender_obj
        .and_then(|s| s.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("HUMAN");

    // Skip bot messages
    if sender_type == "BOT" {
        return Ok(());
    }

    let sender = SenderInfo {
        id: sender_id.to_string(),
        username: None,
        display_name: sender_display.map(|s| s.to_string()),
        is_bot: false,
    };

    let envelope = build_envelope(
        "google_chat",
        space_name,
        space_name,
        message_id,
        thread_root,
        text,
        &sender,
        gw.event_secret.as_deref(),
        Vec::new(),
        Vec::new(),
    );

    info!(
        message_id,
        space = space_name,
        sender = sender_id,
        content_len = text.len(),
        "Publishing Google Chat message to NATS"
    );

    gw.publish_envelope(envelope).await?;
    Ok(())
}
