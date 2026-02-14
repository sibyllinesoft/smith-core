use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::SlackConfig;
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
pub struct SlackAdapter {
    id: String,
    label: String,
    client: Client,
    config: SlackConfig,
}

impl SlackAdapter {
    pub fn new(id: impl Into<String>, config: SlackConfig) -> Result<Self> {
        if config.bot_token.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Slack bot token cannot be empty".into(),
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

    fn history_url(&self) -> String {
        format!("{}/conversations.history", self.config.api_base_url)
    }

    fn post_message_url(&self) -> String {
        format!("{}/chat.postMessage", self.config.api_base_url)
    }

    fn auth_test_url(&self) -> String {
        format!("{}/auth.test", self.config.api_base_url)
    }

    fn bearer(&self) -> &str {
        &self.config.bot_token
    }

    fn parse_timestamp(ts: &str) -> Result<DateTime<Utc>> {
        let float: f64 = ts.parse().map_err(|err| {
            ChatBridgeError::other(format!("invalid Slack timestamp `{ts}`: {err}"))
        })?;
        let seconds = float.trunc() as i64;
        let nanos = (float.fract() * 1_000_000_000_f64).round() as u32;
        DateTime::<Utc>::from_timestamp(seconds, nanos).ok_or_else(|| {
            ChatBridgeError::other(format!("timestamp out of range for Slack message: {ts}"))
        })
    }

    fn convert_message(
        &self,
        message: SlackMessage,
        channel: &ChannelAddress,
    ) -> Result<BridgeMessage> {
        let ts = Self::parse_timestamp(&message.ts)?;
        let (sender_id, role) = match (message.user.clone(), message.bot_id.clone()) {
            (Some(user), _) => (user, ParticipantRole::User),
            (None, Some(bot)) => (bot, ParticipantRole::Bot),
            _ => ("unknown".to_string(), ParticipantRole::Unknown),
        };

        let mut attachments = Vec::new();
        if let Some(items) = message.files {
            for file in items {
                attachments.push(Attachment {
                    id: file.id,
                    title: file.title,
                    url: file.url_private.unwrap_or_default(),
                    mime_type: file.mimetype,
                    size_bytes: file.size,
                });
            }
        }

        let mut metadata: HashMap<String, Value> = HashMap::new();
        if let Some(subtype) = message.subtype {
            metadata.insert("subtype".to_string(), Value::String(subtype));
        }
        if let Some(blocks) = message.blocks {
            metadata.insert("blocks".to_string(), Value::Array(blocks));
        }
        for (key, value) in message.extra {
            metadata.insert(key, value);
        }

        let mut content = MessageContent::plain(message.text.unwrap_or_default());
        content.attachments = attachments;
        content.extra = metadata.clone();

        Ok(BridgeMessage {
            id: message.ts,
            platform: ChatPlatform::Slack,
            channel: channel.clone(),
            sender: Participant {
                id: sender_id,
                display_name: message.username.clone(),
                role,
                username: message.username,
                tags: Vec::new(),
            },
            content,
            timestamp: ts,
            thread_root: message.thread_ts,
            identity: None,
            metadata,
        })
    }
}

#[async_trait]
impl ChatAdapter for SlackAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::Slack
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            supports_threads: true,
            supports_ephemeral: true,
            supports_markdown: true,
        }
    }

    async fn health_check(&self) -> Result<AdapterStatus> {
        let response = self
            .client
            .post(self.auth_test_url())
            .bearer_auth(self.bearer())
            .send()
            .await?;

        let status = response.status();
        let payload: SlackOkResponse = response.json().await?;
        let ok = payload.ok.unwrap_or(false) && status.is_success();
        let details = payload.error.clone().or_else(|| {
            if ok {
                None
            } else {
                Some(format!("unexpected Slack response: {}", status))
            }
        });

        Ok(AdapterStatus {
            is_online: ok,
            last_checked_at: Utc::now(),
            details,
        })
    }

    async fn fetch_messages(&self, request: FetchRequest) -> Result<Vec<BridgeMessage>> {
        let mut query: Vec<(String, String)> =
            vec![("channel".into(), request.channel.channel_id.clone())];
        if let Some(limit) = request.limit {
            query.push(("limit".to_string(), limit.to_string()));
        }
        if let Some(since) = request.since {
            query.push((
                "oldest".to_string(),
                format!("{}", since.timestamp_millis() as f64 / 1000.0),
            ));
        }

        let response = self
            .client
            .get(self.history_url())
            .bearer_auth(self.bearer())
            .query(&query)
            .send()
            .await?;

        let payload: SlackHistoryResponse = response.json().await?;
        if !payload.ok {
            let error = payload
                .error
                .unwrap_or_else(|| "unknown Slack error".to_string());
            return Err(ChatBridgeError::other(format!(
                "Slack history call failed: {error}"
            )));
        }

        let channel = request.channel.clone();
        let mut result = Vec::new();
        if let Some(messages) = payload.messages {
            for message in messages {
                result.push(self.convert_message(message, &channel)?);
            }
        }

        Ok(result)
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let mut payload = serde_json::Map::new();
        payload.insert(
            "channel".to_string(),
            Value::String(message.channel.channel_id.clone()),
        );
        payload.insert(
            "text".to_string(),
            Value::String(message.content.text.clone()),
        );
        payload.insert(
            "mrkdwn".to_string(),
            Value::Bool(message.content.format == MessageFormat::Markdown),
        );
        if let Some(thread) = message.reply_in_thread {
            payload.insert("thread_ts".to_string(), Value::String(thread));
        }
        if !message.content.attachments.is_empty() {
            let attachments = message
                .content
                .attachments
                .iter()
                .map(|attachment| {
                    json!({
                        "title": attachment.title,
                        "title_link": attachment.url,
                    })
                })
                .collect();
            payload.insert("attachments".to_string(), Value::Array(attachments));
        }

        if let Some(blocks) = message.content.extra.get("blocks") {
            payload.insert("blocks".to_string(), blocks.clone());
        };

        let response = self
            .client
            .post(self.post_message_url())
            .bearer_auth(self.bearer())
            .json(&Value::Object(payload))
            .send()
            .await?;

        let payload: SlackPostMessageResponse = response.json().await?;
        if !payload.ok {
            let error = payload
                .error
                .unwrap_or_else(|| "unknown Slack error".into());
            return Err(ChatBridgeError::other(format!(
                "Slack send message failed: {error}"
            )));
        }

        let ts = payload
            .ts
            .as_ref()
            .ok_or_else(|| ChatBridgeError::other("Slack response missing timestamp"))?;
        let timestamp = Self::parse_timestamp(ts)?;

        Ok(SendReceipt {
            message_id: ts.clone(),
            timestamp,
            platform: ChatPlatform::Slack,
            channel: message.channel,
        })
    }
}

#[derive(Debug, Deserialize)]
struct SlackOkResponse {
    ok: Option<bool>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackHistoryResponse {
    ok: bool,
    error: Option<String>,
    messages: Option<Vec<SlackMessage>>,
}

#[derive(Debug, Deserialize)]
struct SlackMessage {
    ts: String,
    text: Option<String>,
    user: Option<String>,
    bot_id: Option<String>,
    username: Option<String>,
    thread_ts: Option<String>,
    subtype: Option<String>,
    #[serde(default)]
    files: Option<Vec<SlackFile>>,
    #[serde(default)]
    blocks: Option<Vec<Value>>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct SlackFile {
    id: Option<String>,
    title: Option<String>,
    url_private: Option<String>,
    mimetype: Option<String>,
    size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SlackPostMessageResponse {
    ok: bool,
    ts: Option<String>,
    error: Option<String>,
}
