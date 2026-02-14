use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Shared state for webhook handlers.
pub struct WebhookState {
    pub nats: async_nats::Client,
    /// Optional verify token for WhatsApp webhook verification.
    pub whatsapp_verify_token: Option<String>,
}

/// Build the webhook Axum router.
pub fn router(state: Arc<WebhookState>) -> Router {
    Router::new()
        .route("/webhook/telegram", post(telegram_webhook))
        .route("/webhook/discord", post(discord_webhook))
        .route("/webhook/whatsapp", post(whatsapp_webhook))
        .route("/webhook/whatsapp", get(whatsapp_verify))
        .with_state(state)
}

async fn telegram_webhook(
    State(state): State<Arc<WebhookState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    info!("Received Telegram webhook");

    let subject = "smith.chatbridge.ingest.telegram";
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(err) = state.nats.publish(subject.to_string(), bytes.into()).await {
                error!(error = ?err, "Failed to publish Telegram webhook to NATS");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        Err(err) => {
            error!(error = ?err, "Failed to serialize Telegram payload");
            return StatusCode::BAD_REQUEST;
        }
    }

    StatusCode::OK
}

async fn discord_webhook(
    State(state): State<Arc<WebhookState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    // Discord interaction verification: respond to PING (type=1) with PONG
    if let Some(1) = payload.get("type").and_then(|t| t.as_u64()) {
        info!("Responding to Discord PING interaction");
        return (StatusCode::OK, Json(json!({"type": 1}))).into_response();
    }

    info!("Received Discord webhook");

    let subject = "smith.chatbridge.ingest.discord";
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(err) = state.nats.publish(subject.to_string(), bytes.into()).await {
                error!(error = ?err, "Failed to publish Discord webhook to NATS");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        Err(err) => {
            error!(error = ?err, "Failed to serialize Discord payload");
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    StatusCode::OK.into_response()
}

async fn whatsapp_webhook(
    State(state): State<Arc<WebhookState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    info!("Received WhatsApp webhook");

    let subject = "smith.chatbridge.ingest.whatsapp";
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(err) = state.nats.publish(subject.to_string(), bytes.into()).await {
                error!(error = ?err, "Failed to publish WhatsApp webhook to NATS");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        Err(err) => {
            error!(error = ?err, "Failed to serialize WhatsApp payload");
            return StatusCode::BAD_REQUEST;
        }
    }

    StatusCode::OK
}

/// WhatsApp webhook verification (GET endpoint).
async fn whatsapp_verify(
    State(state): State<Arc<WebhookState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let mode = params.get("hub.mode").cloned().unwrap_or_default();
    let token = params.get("hub.verify_token").cloned().unwrap_or_default();
    let challenge = params.get("hub.challenge").cloned().unwrap_or_default();

    if mode == "subscribe" {
        if let Some(expected) = &state.whatsapp_verify_token {
            if token == *expected {
                info!("WhatsApp webhook verified");
                return (StatusCode::OK, challenge).into_response();
            }
        }
        warn!("WhatsApp webhook verification failed");
        return (StatusCode::FORBIDDEN, "verification failed").into_response();
    }

    (StatusCode::BAD_REQUEST, "invalid mode").into_response()
}
