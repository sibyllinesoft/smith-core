use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::MatrixConfig;
use crate::error::{ChatBridgeError, Result};
use crate::message::{
    BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, MessageFormat, Participant,
    ParticipantRole,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone)]
pub struct MatrixAdapter {
    id: String,
    label: String,
    client: Client,
    config: MatrixConfig,
}

#[derive(Debug, Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    chunk: Vec<MatrixEvent>,
}

#[derive(Debug, Deserialize)]
struct MatrixEvent {
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    sender: Option<String>,
    #[serde(default, rename = "type")]
    event_type: Option<String>,
    #[serde(default)]
    content: Option<Value>,
    #[serde(default)]
    origin_server_ts: Option<i64>,
}

impl MatrixAdapter {
    pub fn new(id: impl Into<String>, config: MatrixConfig) -> Result<Self> {
        if config.access_token.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Matrix access token cannot be empty".into(),
            ));
        }
        if config.homeserver_url.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Matrix homeserver URL cannot be empty".into(),
            ));
        }

        let client = Client::builder().build()?;
        let id = id.into();
        let label = config.label.clone().unwrap_or_else(|| id.clone());

        Ok(Self {
            id,
            label,
            client,
            config,
        })
    }

    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/_matrix/client/v3{}",
            self.config.homeserver_url.trim_end_matches('/'),
            path,
        )
    }

    fn convert_event(&self, event: MatrixEvent, room_id: &str) -> Option<BridgeMessage> {
        if event.event_type.as_deref() != Some("m.room.message") {
            return None;
        }

        let content = event.content?;
        let text = content.get("body")?.as_str()?.to_string();
        let event_id = event.event_id?;

        let sender = event.sender.unwrap_or_default();
        let is_self = sender == self.config.user_id;
        if is_self {
            return None;
        }

        let timestamp = event
            .origin_server_ts
            .and_then(|ms| DateTime::from_timestamp_millis(ms))
            .unwrap_or_else(Utc::now);

        let msgtype = content
            .get("msgtype")
            .and_then(|v| v.as_str())
            .unwrap_or("m.text");

        let format = if msgtype == "m.text"
            && content.get("format").and_then(|v| v.as_str()) == Some("org.matrix.custom.html")
        {
            MessageFormat::Markdown
        } else {
            MessageFormat::PlainText
        };

        // Extract reply-to if present
        let thread_root = content
            .get("m.relates_to")
            .and_then(|r| r.get("m.in_reply_to"))
            .and_then(|r| r.get("event_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Extract display name from sender MXID: @user:server → user
        let display_name = sender
            .strip_prefix('@')
            .and_then(|s| s.split(':').next())
            .map(|s| s.to_string());

        Some(BridgeMessage {
            id: event_id,
            platform: ChatPlatform::Matrix,
            channel: ChannelAddress::new(room_id),
            sender: Participant {
                id: sender.clone(),
                display_name,
                role: ParticipantRole::User,
                username: Some(sender),
                tags: Vec::new(),
            },
            content: MessageContent {
                text,
                format,
                attachments: Vec::new(),
                extra: HashMap::new(),
            },
            timestamp,
            thread_root,
            identity: None,
            metadata: HashMap::new(),
        })
    }
}

#[async_trait]
impl ChatAdapter for MatrixAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::Matrix
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            supports_threads: true,
            supports_ephemeral: false,
            supports_markdown: true,
        }
    }

    async fn health_check(&self) -> Result<AdapterStatus> {
        let url = self.api_url("/account/whoami");
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.config.access_token)
            .send()
            .await?;

        let ok = response.status().is_success();
        let details = if ok {
            None
        } else {
            Some(format!(
                "Matrix health check returned {}",
                response.status()
            ))
        };

        Ok(AdapterStatus {
            is_online: ok,
            last_checked_at: Utc::now(),
            details,
        })
    }

    async fn fetch_messages(&self, request: FetchRequest) -> Result<Vec<BridgeMessage>> {
        let room_id = &request.channel.channel_id;
        let limit = request.limit.unwrap_or(25);
        let encoded_room = urlencoding::encode(room_id);
        let url = format!(
            "{}?dir=b&limit={limit}",
            self.api_url(&format!("/rooms/{encoded_room}/messages"))
        );

        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.config.access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Matrix fetch messages failed ({status}): {body}"
            )));
        }

        let resp: MessagesResponse = response.json().await?;
        let mut result = Vec::new();
        for event in resp.chunk {
            if let Some(bridge_msg) = self.convert_event(event, room_id) {
                result.push(bridge_msg);
            }
        }

        // Matrix /messages?dir=b returns newest-first; reverse to chronological
        result.reverse();
        Ok(result)
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let room_id = &message.channel.channel_id;
        let txn_id = uuid::Uuid::new_v4().to_string();
        let encoded_room = urlencoding::encode(room_id);
        let url = self.api_url(&format!(
            "/rooms/{encoded_room}/send/m.room.message/{txn_id}"
        ));

        let mut payload = json!({
            "msgtype": "m.text",
            "body": message.content.text,
        });

        if let Some(reply_to) = &message.reply_in_thread {
            payload["m.relates_to"] = json!({
                "m.in_reply_to": {
                    "event_id": reply_to,
                },
            });
        }

        let response = self
            .client
            .put(&url)
            .bearer_auth(&self.config.access_token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Matrix send message failed ({status}): {body}"
            )));
        }

        let resp: Value = response.json().await?;
        let event_id = resp
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&txn_id)
            .to_string();

        Ok(SendReceipt {
            message_id: event_id,
            timestamp: Utc::now(),
            platform: ChatPlatform::Matrix,
            channel: message.channel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_access_token() {
        let cfg = MatrixConfig {
            homeserver_url: "https://matrix.org".into(),
            access_token: "".into(),
            user_id: "@bot:matrix.org".into(),
            default_room_id: None,
            label: None,
        };
        assert!(MatrixAdapter::new("test", cfg).is_err());
    }

    #[test]
    fn rejects_empty_homeserver() {
        let cfg = MatrixConfig {
            homeserver_url: "".into(),
            access_token: "syt_token".into(),
            user_id: "@bot:matrix.org".into(),
            default_room_id: None,
            label: None,
        };
        assert!(MatrixAdapter::new("test", cfg).is_err());
    }

    #[test]
    fn constructs_with_valid_config() {
        let cfg = MatrixConfig {
            homeserver_url: "https://matrix.org".into(),
            access_token: "syt_token".into(),
            user_id: "@bot:matrix.org".into(),
            default_room_id: Some("!room:matrix.org".into()),
            label: None,
        };
        let adapter = MatrixAdapter::new("test", cfg).unwrap();
        assert_eq!(adapter.platform(), ChatPlatform::Matrix);
        assert!(adapter.capabilities().supports_threads);
        assert!(adapter.capabilities().supports_markdown);
    }
}
