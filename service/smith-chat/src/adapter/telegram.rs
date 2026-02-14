use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::TelegramConfig;
use crate::error::{ChatBridgeError, Result};
use crate::message::{
    Attachment, BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, Participant,
    ParticipantRole,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone)]
pub struct TelegramAdapter {
    id: String,
    label: String,
    client: Client,
    config: TelegramConfig,
}

impl TelegramAdapter {
    pub fn new(id: impl Into<String>, config: TelegramConfig) -> Result<Self> {
        if config.bot_token.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Telegram bot token cannot be empty".into(),
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

    fn api_url(&self, method: &str) -> String {
        format!(
            "https://api.telegram.org/bot{}/{}",
            self.config.bot_token, method
        )
    }

    fn convert_message(
        &self,
        msg: TelegramMessage,
        _channel: &ChannelAddress,
    ) -> Result<BridgeMessage> {
        let timestamp = DateTime::<Utc>::from_timestamp(msg.date, 0).ok_or_else(|| {
            ChatBridgeError::other(format!("invalid Telegram timestamp: {}", msg.date))
        })?;

        let (sender_id, display_name, username, role) = if let Some(from) = msg.from {
            let name = from
                .first_name
                .as_ref()
                .map(|f| {
                    if let Some(l) = &from.last_name {
                        format!("{f} {l}")
                    } else {
                        f.clone()
                    }
                });
            let is_bot = from.is_bot.unwrap_or(false);
            (
                from.id.to_string(),
                name,
                from.username,
                if is_bot {
                    ParticipantRole::Bot
                } else {
                    ParticipantRole::User
                },
            )
        } else {
            ("unknown".to_string(), None, None, ParticipantRole::Unknown)
        };

        let text = msg.text.unwrap_or_default();

        let mut attachments = Vec::new();
        if let Some(doc) = msg.document {
            attachments.push(Attachment {
                id: Some(doc.file_id),
                title: doc.file_name,
                url: String::new(),
                mime_type: doc.mime_type,
                size_bytes: doc.file_size.map(|s| s as u64),
            });
        }

        let mut metadata: HashMap<String, Value> = HashMap::new();
        if let Some(chat) = &msg.chat {
            if let Some(title) = &chat.title {
                metadata.insert("chat_title".to_string(), Value::String(title.clone()));
            }
            if let Some(chat_type) = &chat.r#type {
                metadata.insert("chat_type".to_string(), Value::String(chat_type.clone()));
            }
        }

        let channel = ChannelAddress {
            team_id: None,
            channel_id: msg
                .chat
                .as_ref()
                .map(|c| c.id.to_string())
                .unwrap_or_default(),
            channel_name: msg.chat.as_ref().and_then(|c| c.title.clone()),
            thread_id: msg.message_thread_id.map(|id| id.to_string()),
        };

        let thread_root = msg.reply_to_message.map(|r| r.message_id.to_string());

        Ok(BridgeMessage {
            id: msg.message_id.to_string(),
            platform: ChatPlatform::Telegram,
            channel,
            sender: Participant {
                id: sender_id,
                display_name,
                role,
                username,
                tags: Vec::new(),
            },
            content: MessageContent::plain(text),
            timestamp,
            thread_root,
            identity: None,
            metadata,
        })
    }
}

#[async_trait]
impl ChatAdapter for TelegramAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::Telegram
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
        let response = self
            .client
            .get(self.api_url("getMe"))
            .send()
            .await?;

        let status = response.status();
        let payload: TelegramResponse<TelegramUser> = response.json().await?;
        let ok = payload.ok && status.is_success();

        Ok(AdapterStatus {
            is_online: ok,
            last_checked_at: Utc::now(),
            details: payload.description,
        })
    }

    async fn fetch_messages(&self, request: FetchRequest) -> Result<Vec<BridgeMessage>> {
        // Telegram uses long-polling via getUpdates
        let mut query: Vec<(String, String)> = vec![("timeout".into(), "0".into())];
        if let Some(limit) = request.limit {
            query.push(("limit".to_string(), limit.to_string()));
        }
        if let Some(updates) = &self.config.allowed_updates {
            query.push((
                "allowed_updates".to_string(),
                serde_json::to_string(updates)
                    .unwrap_or_else(|_| "[\"message\"]".to_string()),
            ));
        }

        let response = self
            .client
            .get(self.api_url("getUpdates"))
            .query(&query)
            .send()
            .await?;

        let payload: TelegramResponse<Vec<TelegramUpdate>> = response.json().await?;
        if !payload.ok {
            return Err(ChatBridgeError::other(format!(
                "Telegram getUpdates failed: {}",
                payload.description.unwrap_or_else(|| "unknown error".into())
            )));
        }

        let channel = request.channel.clone();
        let mut result = Vec::new();
        if let Some(updates) = payload.result {
            for update in updates {
                if let Some(msg) = update.message {
                    result.push(self.convert_message(msg, &channel)?);
                }
            }
        }

        Ok(result)
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let mut payload = json!({
            "chat_id": message.channel.channel_id,
            "text": message.content.text,
        });

        if message.content.format == crate::message::MessageFormat::Markdown {
            payload["parse_mode"] = Value::String("MarkdownV2".into());
        }

        if let Some(thread) = &message.reply_in_thread {
            if let Ok(id) = thread.parse::<i64>() {
                payload["reply_to_message_id"] = Value::Number(id.into());
            }
        }

        let response = self
            .client
            .post(self.api_url("sendMessage"))
            .json(&payload)
            .send()
            .await?;

        let resp: TelegramResponse<TelegramMessage> = response.json().await?;
        if !resp.ok {
            return Err(ChatBridgeError::other(format!(
                "Telegram sendMessage failed: {}",
                resp.description.unwrap_or_else(|| "unknown error".into())
            )));
        }

        let msg = resp
            .result
            .ok_or_else(|| ChatBridgeError::other("Telegram response missing result"))?;
        let timestamp = DateTime::<Utc>::from_timestamp(msg.date, 0)
            .unwrap_or_else(Utc::now);

        Ok(SendReceipt {
            message_id: msg.message_id.to_string(),
            timestamp,
            platform: ChatPlatform::Telegram,
            channel: message.channel,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    description: Option<String>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct TelegramUpdate {
    #[allow(dead_code)]
    update_id: i64,
    #[serde(default)]
    message: Option<TelegramMessage>,
}

#[derive(Debug, Deserialize)]
struct TelegramMessage {
    message_id: i64,
    date: i64,
    #[serde(default)]
    from: Option<TelegramUser>,
    #[serde(default)]
    chat: Option<TelegramChat>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    document: Option<TelegramDocument>,
    #[serde(default)]
    reply_to_message: Option<Box<TelegramReplyMessage>>,
    #[serde(default)]
    message_thread_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TelegramUser {
    id: i64,
    #[serde(default)]
    is_bot: Option<bool>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramChat {
    id: i64,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramDocument {
    file_id: String,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default)]
    file_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TelegramReplyMessage {
    message_id: i64,
}
