use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::SignalConfig;
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
pub struct SignalAdapter {
    id: String,
    label: String,
    client: Client,
    config: SignalConfig,
}

#[derive(Debug, Deserialize)]
struct SignalMessage {
    #[serde(default)]
    envelope: Option<SignalEnvelope>,
}

#[derive(Debug, Deserialize)]
struct SignalEnvelope {
    #[serde(default)]
    source: Option<String>,
    #[serde(default, rename = "sourceName")]
    source_name: Option<String>,
    #[serde(default)]
    timestamp: Option<i64>,
    #[serde(default, rename = "dataMessage")]
    data_message: Option<SignalDataMessage>,
}

#[derive(Debug, Deserialize)]
struct SignalDataMessage {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    timestamp: Option<i64>,
    #[serde(default, rename = "groupInfo")]
    group_info: Option<SignalGroupInfo>,
    #[serde(default)]
    attachments: Option<Vec<SignalAttachment>>,
}

#[derive(Debug, Deserialize)]
struct SignalGroupInfo {
    #[serde(default, rename = "groupId")]
    group_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignalAttachment {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "contentType")]
    content_type: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    size: Option<u64>,
}

impl SignalAdapter {
    pub fn new(id: impl Into<String>, config: SignalConfig) -> Result<Self> {
        if config.phone_number.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Signal phone number cannot be empty".into(),
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
        format!("{}{}", self.config.signal_cli_url, path)
    }

    fn convert_envelope(
        &self,
        envelope: SignalEnvelope,
        channel: &ChannelAddress,
    ) -> Option<BridgeMessage> {
        let data = envelope.data_message?;
        let text = data.message?;

        let source = envelope.source.unwrap_or_default();
        let ts = data
            .timestamp
            .or(envelope.timestamp)
            .map(|ms| DateTime::from_timestamp_millis(ms).unwrap_or_else(Utc::now))
            .unwrap_or_else(Utc::now);

        let msg_id = format!("{}-{}", source, ts.timestamp_millis());

        let attachments = data
            .attachments
            .unwrap_or_default()
            .into_iter()
            .map(|a| Attachment {
                id: a.id,
                title: a.filename,
                url: String::new(),
                mime_type: a.content_type,
                size_bytes: a.size,
            })
            .collect();

        let channel_id = data
            .group_info
            .and_then(|g| g.group_id)
            .unwrap_or_else(|| channel.channel_id.clone());

        Some(BridgeMessage {
            id: msg_id,
            platform: ChatPlatform::Signal,
            channel: ChannelAddress {
                channel_id,
                ..channel.clone()
            },
            sender: Participant {
                id: source.clone(),
                display_name: envelope.source_name,
                role: ParticipantRole::User,
                username: Some(source),
                tags: Vec::new(),
            },
            content: MessageContent {
                text,
                format: MessageFormat::PlainText,
                attachments,
                extra: HashMap::new(),
            },
            timestamp: ts,
            thread_root: None,
            identity: None,
            metadata: HashMap::new(),
        })
    }
}

#[async_trait]
impl ChatAdapter for SignalAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::Signal
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
        let url = self.api_url("/v1/about");
        let response = self.client.get(&url).send().await?;
        let ok = response.status().is_success();
        let details = if ok {
            None
        } else {
            Some(format!(
                "signal-cli health check returned {}",
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
        let url = self.api_url(&format!(
            "/v1/receive/{}",
            urlencoding::encode(&self.config.phone_number)
        ));
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Signal fetch messages failed ({status}): {body}"
            )));
        }

        let messages: Vec<SignalMessage> = response.json().await?;
        let channel = request.channel.clone();
        let mut result = Vec::new();

        for msg in messages {
            if let Some(envelope) = msg.envelope {
                if let Some(bridge_msg) = self.convert_envelope(envelope, &channel) {
                    result.push(bridge_msg);
                }
            }
        }

        Ok(result)
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let url = self.api_url("/v2/send");

        let payload = json!({
            "message": message.content.text,
            "number": self.config.phone_number,
            "recipients": [message.channel.channel_id],
        });

        let response = self.client.post(&url).json(&payload).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Signal send message failed ({status}): {body}"
            )));
        }

        let resp: Value = response.json().await?;
        let ts_millis = resp
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| Utc::now().timestamp_millis());

        Ok(SendReceipt {
            message_id: ts_millis.to_string(),
            timestamp: DateTime::from_timestamp_millis(ts_millis).unwrap_or_else(Utc::now),
            platform: ChatPlatform::Signal,
            channel: message.channel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SignalConfig;

    #[test]
    fn rejects_empty_phone_number() {
        let cfg = SignalConfig {
            phone_number: "".into(),
            signal_cli_url: "http://localhost:8080".into(),
            label: None,
        };
        assert!(SignalAdapter::new("test", cfg).is_err());
    }

    #[test]
    fn constructs_with_valid_config() {
        let cfg = SignalConfig {
            phone_number: "+15551234567".into(),
            signal_cli_url: "http://localhost:8080".into(),
            label: None,
        };
        let adapter = SignalAdapter::new("test", cfg).unwrap();
        assert_eq!(adapter.platform(), ChatPlatform::Signal);
        assert!(!adapter.capabilities().supports_threads);
    }
}
