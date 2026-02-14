use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::IMessageConfig;
use crate::error::{ChatBridgeError, Result};
use crate::message::{
    Attachment, BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, MessageFormat,
    Participant, ParticipantRole,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone)]
pub struct IMessageAdapter {
    id: String,
    label: String,
    client: Client,
    config: IMessageConfig,
}

#[derive(Debug, Deserialize)]
struct BBMessagesResponse {
    #[serde(default)]
    data: Vec<BBMessage>,
}

#[derive(Debug, Deserialize)]
struct BBMessage {
    #[serde(default)]
    guid: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default, rename = "dateCreated")]
    date_created: Option<i64>,
    #[serde(default, rename = "isFromMe")]
    is_from_me: Option<bool>,
    #[serde(default, rename = "chats")]
    chats: Option<Vec<BBChat>>,
    #[serde(default)]
    handle: Option<BBHandle>,
    #[serde(default)]
    attachments: Option<Vec<BBAttachment>>,
}

#[derive(Debug, Deserialize)]
struct BBChat {
    #[serde(default)]
    guid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BBHandle {
    #[serde(default)]
    address: Option<String>,
    #[serde(default, rename = "firstName")]
    first_name: Option<String>,
    #[serde(default, rename = "lastName")]
    last_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BBAttachment {
    #[serde(default)]
    guid: Option<String>,
    #[serde(default, rename = "transferName")]
    transfer_name: Option<String>,
    #[serde(default, rename = "mimeType")]
    mime_type: Option<String>,
    #[serde(default, rename = "totalBytes")]
    total_bytes: Option<u64>,
}

impl IMessageAdapter {
    pub fn new(id: impl Into<String>, config: IMessageConfig) -> Result<Self> {
        if config.server_url.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "BlueBubbles server URL cannot be empty".into(),
            ));
        }
        if config.server_password.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "BlueBubbles server password cannot be empty".into(),
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
            "{}/api/v1{}?password={}",
            self.config.server_url.trim_end_matches('/'),
            path,
            urlencoding::encode(&self.config.server_password)
        )
    }

    fn convert_message(&self, msg: BBMessage) -> Option<BridgeMessage> {
        let text = msg.text.as_deref()?.to_string();
        if text.is_empty() {
            return None;
        }

        let is_from_me = msg.is_from_me.unwrap_or(false);
        if is_from_me {
            return None;
        }

        let guid = msg.guid.unwrap_or_default();

        let chat_guid = msg
            .chats
            .as_ref()
            .and_then(|c| c.first())
            .and_then(|c| c.guid.clone())
            .unwrap_or_default();

        let (sender_id, display_name) = if let Some(handle) = &msg.handle {
            let addr = handle.address.clone().unwrap_or_default();
            let name = match (&handle.first_name, &handle.last_name) {
                (Some(f), Some(l)) => Some(format!("{f} {l}")),
                (Some(f), None) => Some(f.clone()),
                (None, Some(l)) => Some(l.clone()),
                (None, None) => None,
            };
            (addr, name)
        } else {
            ("unknown".to_string(), None)
        };

        let timestamp = msg
            .date_created
            .and_then(|ms| DateTime::from_timestamp_millis(ms))
            .unwrap_or_else(Utc::now);

        let attachments = msg
            .attachments
            .unwrap_or_default()
            .into_iter()
            .map(|a| Attachment {
                id: a.guid,
                title: a.transfer_name,
                url: String::new(),
                mime_type: a.mime_type,
                size_bytes: a.total_bytes,
            })
            .collect();

        Some(BridgeMessage {
            id: guid,
            platform: ChatPlatform::IMessage,
            channel: ChannelAddress::new(chat_guid),
            sender: Participant {
                id: sender_id,
                display_name,
                role: ParticipantRole::User,
                username: None,
                tags: Vec::new(),
            },
            content: MessageContent {
                text,
                format: MessageFormat::PlainText,
                attachments,
                extra: HashMap::new(),
            },
            timestamp,
            thread_root: None,
            identity: None,
            metadata: HashMap::new(),
        })
    }
}

#[async_trait]
impl ChatAdapter for IMessageAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::IMessage
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            supports_threads: false,
            supports_ephemeral: false,
            supports_markdown: false,
        }
    }

    async fn health_check(&self) -> Result<AdapterStatus> {
        let url = self.api_url("/server/info");
        let response = self.client.get(&url).send().await?;
        let ok = response.status().is_success();
        let details = if ok {
            None
        } else {
            Some(format!(
                "BlueBubbles health check returned {}",
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
        let limit = request.limit.unwrap_or(25);
        let url = format!("{}&limit={limit}&sort=DESC", self.api_url("/message"));

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "BlueBubbles fetch messages failed ({status}): {body}"
            )));
        }

        let resp: BBMessagesResponse = response.json().await?;
        let mut result = Vec::new();
        for msg in resp.data {
            if let Some(bridge_msg) = self.convert_message(msg) {
                result.push(bridge_msg);
            }
        }

        // BB returns newest-first with sort=DESC; reverse to chronological
        result.reverse();
        Ok(result)
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let url = self.api_url("/message/text");

        let payload = json!({
            "chatGuid": message.channel.channel_id,
            "message": message.content.text,
        });

        let response = self.client.post(&url).json(&payload).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "BlueBubbles send message failed ({status}): {body}"
            )));
        }

        let resp: Value = response.json().await?;
        let msg_guid = resp
            .get("data")
            .and_then(|d| d.get("guid"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(SendReceipt {
            message_id: msg_guid,
            timestamp: Utc::now(),
            platform: ChatPlatform::IMessage,
            channel: message.channel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_server_url() {
        let cfg = IMessageConfig {
            server_url: "".into(),
            server_password: "pass".into(),
            label: None,
        };
        assert!(IMessageAdapter::new("test", cfg).is_err());
    }

    #[test]
    fn rejects_empty_password() {
        let cfg = IMessageConfig {
            server_url: "http://localhost:1234".into(),
            server_password: "".into(),
            label: None,
        };
        assert!(IMessageAdapter::new("test", cfg).is_err());
    }

    #[test]
    fn constructs_with_valid_config() {
        let cfg = IMessageConfig {
            server_url: "http://localhost:1234".into(),
            server_password: "pass".into(),
            label: None,
        };
        let adapter = IMessageAdapter::new("test", cfg).unwrap();
        assert_eq!(adapter.platform(), ChatPlatform::IMessage);
        assert!(!adapter.capabilities().supports_threads);
    }
}
