use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::pairing_store::PairingStore;

/// Shared state for webhook handlers.
pub struct WebhookState {
    pub nats: async_nats::Client,
    /// When true, webhook endpoints reject unsigned/unauthenticated requests.
    pub require_signed_webhooks: bool,
    /// Optional Telegram webhook secret token expected in X-Telegram-Bot-Api-Secret-Token.
    pub telegram_webhook_secret: Option<String>,
    /// Optional Discord interactions public key (hex) for Ed25519 verification.
    pub discord_public_key: Option<String>,
    /// Optional verify token for WhatsApp webhook verification.
    pub whatsapp_verify_token: Option<String>,
    /// Optional WhatsApp app secret used to validate X-Hub-Signature-256.
    pub whatsapp_app_secret: Option<String>,
    /// Optional GitHub webhook secret used to validate X-Hub-Signature-256.
    pub github_webhook_secret: Option<String>,
    /// Subject to publish normalized GitHub orchestration events to.
    pub github_ingest_subject: String,
    /// Pairing store for generating pairing codes via admin API.
    pub pairing_store: Arc<PairingStore>,
    /// Bearer token for admin API endpoints. When `None`, admin endpoints
    /// are accessible without authentication.
    pub admin_token: Option<String>,
}

/// Build the webhook Axum router.
pub fn router(state: Arc<WebhookState>) -> Router {
    Router::new()
        .route("/webhook/telegram", post(telegram_webhook))
        .route("/webhook/discord", post(discord_webhook))
        .route("/webhook/whatsapp", post(whatsapp_webhook))
        .route("/webhook/whatsapp", get(whatsapp_verify))
        .route("/webhook/github", post(github_webhook))
        .route("/admin/pairing-codes", post(create_pairing_code))
        .with_state(state)
}

async fn telegram_webhook(
    State(state): State<Arc<WebhookState>>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    if let Some(response) = require_telegram_auth(&state, &headers) {
        return response;
    }

    info!("Received Telegram webhook");

    let subject = "smith.chatbridge.ingest.telegram";
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(err) = state.nats.publish(subject.to_string(), bytes.into()).await {
                error!(error = ?err, "Failed to publish Telegram webhook to NATS");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        Err(err) => {
            error!(error = ?err, "Failed to serialize Telegram payload");
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    StatusCode::OK.into_response()
}

async fn discord_webhook(
    State(state): State<Arc<WebhookState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(response) = require_discord_auth(&state, &headers, &body) {
        return response;
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => {
            warn!(error = ?err, "Rejected Discord webhook with invalid JSON payload");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid JSON payload"})),
            )
                .into_response();
        }
    };

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
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(response) = require_whatsapp_auth(&state, &headers, &body) {
        return response;
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => {
            warn!(error = ?err, "Rejected WhatsApp webhook with invalid JSON payload");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid JSON payload"})),
            )
                .into_response();
        }
    };

    info!("Received WhatsApp webhook");

    let subject = "smith.chatbridge.ingest.whatsapp";
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(err) = state.nats.publish(subject.to_string(), bytes.into()).await {
                error!(error = ?err, "Failed to publish WhatsApp webhook to NATS");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        Err(err) => {
            error!(error = ?err, "Failed to serialize WhatsApp payload");
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    StatusCode::OK.into_response()
}

async fn github_webhook(
    State(state): State<Arc<WebhookState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if state.require_signed_webhooks && state.github_webhook_secret.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "github webhook secret is not configured"})),
        )
            .into_response();
    }

    let event = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if event.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "missing x-github-event header"})),
        )
            .into_response();
    }

    let delivery_id = headers
        .get("x-github-delivery")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();

    if let Some(secret) = state.github_webhook_secret.as_deref() {
        let Some(signature) = headers
            .get("x-hub-signature-256")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            warn!(
                event = event,
                delivery_id = delivery_id,
                "Rejected GitHub webhook without X-Hub-Signature-256"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing signature"})),
            )
                .into_response();
        };
        if !verify_github_signature(secret, &body, signature) {
            warn!(
                event = event,
                delivery_id = delivery_id,
                "Rejected GitHub webhook with invalid signature"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid signature"})),
            )
                .into_response();
        }
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => {
            warn!(error = ?err, "Rejected GitHub webhook with invalid JSON payload");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid JSON payload"})),
            )
                .into_response();
        }
    };

    let normalized = json!({
        "source": "github",
        "kind": "webhook",
        "event": event,
        "delivery_id": delivery_id,
        "received_at": Utc::now().to_rfc3339(),
        "action": payload.get("action").cloned().unwrap_or(Value::Null),
        "repository": payload.get("repository").cloned().unwrap_or(Value::Null),
        "sender": payload.get("sender").cloned().unwrap_or(Value::Null),
        "installation_id": payload
            .get("installation")
            .and_then(|installation| installation.get("id"))
            .cloned()
            .unwrap_or(Value::Null),
        "signature_validated": state.github_webhook_secret.is_some(),
        "payload": payload,
    });

    let subject = state.github_ingest_subject.clone();
    match serde_json::to_vec(&normalized) {
        Ok(bytes) => {
            if let Err(err) = state.nats.publish(subject.clone(), bytes.into()).await {
                error!(
                    error = ?err,
                    subject = subject,
                    "Failed to publish GitHub webhook to NATS"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        Err(err) => {
            error!(error = ?err, "Failed to serialize normalized GitHub webhook payload");
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    StatusCode::ACCEPTED.into_response()
}

/// WhatsApp webhook verification (GET endpoint).
async fn whatsapp_verify(
    State(state): State<Arc<WebhookState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if state.require_signed_webhooks && state.whatsapp_verify_token.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "whatsapp verify token not configured",
        )
            .into_response();
    }

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

#[derive(Deserialize)]
struct CreatePairingCodeRequest {
    agent_id: String,
}

async fn create_pairing_code(
    State(state): State<Arc<WebhookState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreatePairingCodeRequest>,
) -> impl IntoResponse {
    if state.require_signed_webhooks && state.admin_token.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "admin token not configured"})),
        )
            .into_response();
    }

    // Verify bearer token when configured.
    if let Some(expected) = &state.admin_token {
        if bearer_from_headers(&headers).as_deref() != Some(expected.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    }

    match state.pairing_store.create_code(&body.agent_id).await {
        Ok(code) => {
            info!(agent_id = %body.agent_id, "Pairing code created via admin API");
            (
                StatusCode::CREATED,
                Json(json!({
                    "code": code,
                    "agent_id": body.agent_id,
                    "expires_in": state.pairing_store.code_ttl_secs,
                })),
            )
                .into_response()
        }
        Err(err) => {
            error!(error = ?err, "Failed to create pairing code");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "failed to create pairing code"})),
            )
                .into_response()
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn require_telegram_auth(
    state: &WebhookState,
    headers: &HeaderMap,
) -> Option<axum::response::Response> {
    if state.require_signed_webhooks && state.telegram_webhook_secret.is_none() {
        return Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "telegram webhook secret is not configured"})),
            )
                .into_response(),
        );
    }
    let Some(expected) = state.telegram_webhook_secret.as_deref() else {
        return None;
    };
    let provided = headers
        .get("x-telegram-bot-api-secret-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    if provided != expected {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid telegram webhook secret"})),
            )
                .into_response(),
        );
    }
    None
}

fn require_discord_auth(
    state: &WebhookState,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<axum::response::Response> {
    if state.require_signed_webhooks && state.discord_public_key.is_none() {
        return Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "discord public key is not configured"})),
            )
                .into_response(),
        );
    }

    let Some(public_key_hex) = state.discord_public_key.as_deref() else {
        return None;
    };
    let Some(signature_hex) = headers
        .get("x-signature-ed25519")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    else {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing discord signature"})),
            )
                .into_response(),
        );
    };
    let Some(timestamp) = headers
        .get("x-signature-timestamp")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    else {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing discord signature timestamp"})),
            )
                .into_response(),
        );
    };

    if !verify_discord_signature(public_key_hex, timestamp, body, signature_hex) {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid discord signature"})),
            )
                .into_response(),
        );
    }
    None
}

fn require_whatsapp_auth(
    state: &WebhookState,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<axum::response::Response> {
    if state.require_signed_webhooks && state.whatsapp_app_secret.is_none() {
        return Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "whatsapp app secret is not configured"})),
            )
                .into_response(),
        );
    }

    let Some(secret) = state.whatsapp_app_secret.as_deref() else {
        return None;
    };
    let Some(signature) = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    else {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing whatsapp signature"})),
            )
                .into_response(),
        );
    };
    if !verify_github_signature(secret, body, signature) {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid whatsapp signature"})),
            )
                .into_response(),
        );
    }
    None
}

fn verify_github_signature(secret: &str, body: &[u8], signature_header: &str) -> bool {
    let Some(signature_bytes) = parse_github_signature(signature_header) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&signature_bytes).is_ok()
}

fn parse_github_signature(signature_header: &str) -> Option<[u8; 32]> {
    let signature_hex = signature_header.strip_prefix("sha256=")?;
    parse_fixed_hex::<32>(signature_hex)
}

fn verify_discord_signature(
    public_key_hex: &str,
    timestamp: &str,
    body: &[u8],
    signature_hex: &str,
) -> bool {
    let Some(public_key_bytes) = parse_fixed_hex::<32>(public_key_hex) else {
        return false;
    };
    let Some(signature_bytes) = parse_fixed_hex::<64>(signature_hex) else {
        return false;
    };
    let Ok(public_key) = VerifyingKey::from_bytes(&public_key_bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);

    let mut msg = Vec::with_capacity(timestamp.len() + body.len());
    msg.extend_from_slice(timestamp.as_bytes());
    msg.extend_from_slice(body);

    public_key.verify(&msg, &signature).is_ok()
}

fn parse_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let bytes = value.as_bytes();
    for idx in 0..N {
        let hi = hex_nibble(bytes[idx * 2])?;
        let lo = hex_nibble(bytes[idx * 2 + 1])?;
        out[idx] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_github_signature_accepts_valid_sha256_header() {
        let header = "sha256=2ad6fdf5f8b57be45174d66ab892a68f48616f58f8d85f7f4d50d08f8f3f6c32";
        let parsed = parse_github_signature(header);
        assert!(parsed.is_some());
        assert_eq!(
            parsed.expect("signature"),
            [
                0x2a, 0xd6, 0xfd, 0xf5, 0xf8, 0xb5, 0x7b, 0xe4, 0x51, 0x74, 0xd6, 0x6a, 0xb8, 0x92,
                0xa6, 0x8f, 0x48, 0x61, 0x6f, 0x58, 0xf8, 0xd8, 0x5f, 0x7f, 0x4d, 0x50, 0xd0, 0x8f,
                0x8f, 0x3f, 0x6c, 0x32
            ]
        );
    }

    #[test]
    fn parse_github_signature_rejects_invalid_headers() {
        assert!(parse_github_signature("sha1=deadbeef").is_none());
        assert!(parse_github_signature("sha256=deadbeef").is_none());
        assert!(parse_github_signature(
            "sha256=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_none());
    }

    #[test]
    fn verify_github_signature_matches_expected_hmac() {
        let secret = "test-secret";
        let body = br#"{"action":"opened","repository":{"full_name":"org/repo"}}"#;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("mac");
        mac.update(body);
        let digest = mac.finalize().into_bytes();
        let signature = format!("sha256={}", hex_encode(digest.as_ref()));

        assert!(verify_github_signature(secret, body, &signature));
        assert!(!verify_github_signature("wrong-secret", body, &signature));
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }
}
