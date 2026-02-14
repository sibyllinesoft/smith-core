//! WhatsApp Gateway that receives Cloud API webhook events via an HTTP server
//! and publishes them to NATS as BridgeMessageEnvelope payloads.
//!
//! WhatsApp uses the Meta Cloud API which sends events to a configured webhook URL.
//! This gateway listens for those POSTs and verifies them with the webhook secret.

use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chat_bridge::gateway_common::{build_envelope, connect_nats, GatewayContext, SenderInfo};
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(author, version, about = "WhatsApp Cloud API Gateway → NATS bridge for Smith")]
struct Cli {
    /// Port to listen on for WhatsApp webhook events
    #[arg(long, env = "WHATSAPP_WEBHOOK_PORT", default_value_t = 8091)]
    port: u16,

    /// WhatsApp webhook verify token (for GET verification handshake)
    #[arg(long, env = "WHATSAPP_VERIFY_TOKEN")]
    verify_token: String,

    /// NATS server URL
    #[arg(long, env = "SMITH_NATS_URL", default_value = "nats://127.0.0.1:7222")]
    nats_url: String,

    /// NATS subject to publish bridge envelopes to
    #[arg(long, env = "CHAT_BRIDGE_INGEST_SUBJECT", default_value = "smith.chatbridge.ingest")]
    ingest_subject: String,

    /// Optional shared secret included in envelopes
    #[arg(long, env = "CHAT_BRIDGE_EVENT_SECRET")]
    event_secret: Option<String>,
}

struct WhatsAppState {
    gw: GatewayContext,
    verify_token: String,
}

#[derive(Debug, Deserialize)]
struct VerifyQuery {
    #[serde(rename = "hub.mode")]
    mode: Option<String>,
    #[serde(rename = "hub.verify_token")]
    verify_token: Option<String>,
    #[serde(rename = "hub.challenge")]
    challenge: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();

    let cli = Cli::parse();
    let nats = connect_nats(&cli.nats_url).await?;

    let state = Arc::new(WhatsAppState {
        gw: GatewayContext {
            nats,
            ingest_subject: cli.ingest_subject.clone(),
            event_secret: cli.event_secret.clone(),
            platform: "whatsapp",
        },
        verify_token: cli.verify_token.clone(),
    });

    let app = Router::new()
        .route("/webhook", get(verify_webhook))
        .route("/webhook", post(handle_webhook))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cli.port);
    info!(addr = %addr, "WhatsApp webhook gateway listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// GET /webhook — Meta verification handshake
async fn verify_webhook(
    State(state): State<Arc<WhatsAppState>>,
    Query(q): Query<VerifyQuery>,
) -> Result<String, StatusCode> {
    if q.mode.as_deref() != Some("subscribe") {
        return Err(StatusCode::FORBIDDEN);
    }

    match q.verify_token {
        Some(token) if token == state.verify_token => {
            info!("WhatsApp webhook verification successful");
            Ok(q.challenge.unwrap_or_default())
        }
        _ => {
            warn!("WhatsApp webhook verification failed: invalid token");
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// POST /webhook — Incoming WhatsApp message events
async fn handle_webhook(
    State(state): State<Arc<WhatsAppState>>,
    Json(body): Json<Value>,
) -> StatusCode {
    let entries = match body.get("entry").and_then(|v| v.as_array()) {
        Some(e) => e,
        None => return StatusCode::OK,
    };

    for entry in entries {
        let changes = match entry.get("changes").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => continue,
        };

        for change in changes {
            let value = match change.get("value") {
                Some(v) => v,
                None => continue,
            };

            // Extract contacts for display name lookup
            let contacts = value
                .get("contacts")
                .and_then(|v| v.as_array());

            let messages = match value.get("messages").and_then(|v| v.as_array()) {
                Some(m) => m,
                None => continue,
            };

            for msg in messages {
                if let Err(err) = handle_message(&state.gw, msg, contacts).await {
                    error!(error = ?err, "Failed to handle WhatsApp message");
                }
            }
        }
    }

    StatusCode::OK
}

async fn handle_message(
    gw: &GatewayContext,
    msg: &Value,
    contacts: Option<&Vec<Value>>,
) -> Result<()> {
    let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");

    // Only handle text messages for now
    if msg_type != "text" {
        debug!(msg_type, "Skipping non-text WhatsApp message");
        return Ok(());
    }

    let text = msg
        .get("text")
        .and_then(|t| t.get("body"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if text.is_empty() {
        return Ok(());
    }

    let from = msg.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let message_id = msg.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let timestamp = msg.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");

    // Look up display name from contacts
    let display_name = contacts
        .and_then(|cs| {
            cs.iter().find(|c| {
                c.get("wa_id").and_then(|v| v.as_str()) == Some(from)
            })
        })
        .and_then(|c| c.get("profile"))
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Check for reply context
    let thread_root = msg
        .get("context")
        .and_then(|c| c.get("message_id"))
        .and_then(|v| v.as_str())
        .unwrap_or(message_id);

    let sender = SenderInfo {
        id: from.to_string(),
        username: Some(from.to_string()),
        display_name,
        is_bot: false,
    };

    let envelope = build_envelope(
        "whatsapp",
        "",
        from, // WhatsApp uses phone number as channel
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
        from,
        timestamp,
        content_len = text.len(),
        "Publishing WhatsApp message to NATS"
    );

    gw.publish_envelope(envelope).await?;
    Ok(())
}
