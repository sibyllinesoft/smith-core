//! Shared helpers for gateway binaries that ingest messages from chat platforms
//! into NATS as `BridgeMessageEnvelope` JSON payloads.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tracing::info;

/// Metadata about the message sender.
pub struct SenderInfo {
    pub id: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub is_bot: bool,
}

/// Shared context for gateway → NATS publishing.
pub struct GatewayContext {
    pub nats: async_nats::Client,
    pub ingest_subject: String,
    pub event_secret: Option<String>,
    pub platform: &'static str,
}

impl GatewayContext {
    pub async fn publish_envelope(&self, envelope: Value) -> Result<()> {
        let payload = serde_json::to_vec(&envelope)?;
        self.nats
            .publish(self.ingest_subject.clone(), payload.into())
            .await
            .context("failed to publish to NATS")?;
        self.nats.flush().await.context("failed to flush NATS")?;
        Ok(())
    }
}

/// Build a `BridgeMessageEnvelope` in the shape the daemon expects.
pub fn build_envelope(
    platform: &str,
    team_id: &str,
    channel_id: &str,
    message_id: &str,
    thread_root: &str,
    content: &str,
    sender: &SenderInfo,
    secret: Option<&str>,
    attachments: Vec<Value>,
    thread_history: Vec<Value>,
) -> Value {
    json!({
        "platform": platform,
        "team_id": team_id,
        "team_name": null,
        "channel_id": channel_id,
        "channel_name": null,
        "post_id": message_id,
        "thread_root": thread_root,
        "message": content,
        "props": {},
        "attachments": attachments,
        "timestamp": chrono::Utc::now().timestamp(),
        "secret": secret,
        "sender": {
            "id": sender.id,
            "username": sender.username,
            "display_name": sender.display_name,
            "is_bot": sender.is_bot,
        },
        "thread_history": thread_history,
    })
}

/// Connect to NATS and log success.
pub async fn connect_nats(nats_url: &str) -> Result<async_nats::Client> {
    let nats = async_nats::connect(nats_url)
        .await
        .with_context(|| format!("failed to connect to NATS at {nats_url}"))?;
    info!(url = %nats_url, "Connected to NATS");
    Ok(nats)
}
