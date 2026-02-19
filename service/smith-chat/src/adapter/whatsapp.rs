use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::WhatsAppConfig;
use crate::error::{ChatBridgeError, Result};
use crate::message::{
    BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, Participant, ParticipantRole,
};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone)]
pub struct WhatsAppAdapter {
    id: String,
    label: String,
    client: Client,
    config: WhatsAppConfig,
}

impl WhatsAppAdapter {
    pub fn new(id: impl Into<String>, config: WhatsAppConfig) -> Result<Self> {
        if config.access_token.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "WhatsApp access token cannot be empty".into(),
            ));
        }
        if config.phone_number_id.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "WhatsApp phone number ID cannot be empty".into(),
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
            "https://graph.facebook.com/{}/{}/{}",
            self.config.api_version, self.config.phone_number_id, path
        )
    }

    fn phone_url(&self) -> String {
        format!(
            "https://graph.facebook.com/{}/{}",
            self.config.api_version, self.config.phone_number_id
        )
    }

    fn bearer(&self) -> &str {
        &self.config.access_token
    }

    #[allow(dead_code)]
    fn convert_webhook_message(
        &self,
        msg: WhatsAppWebhookMessage,
        contact: Option<&WhatsAppContact>,
    ) -> Result<BridgeMessage> {
        let timestamp = msg
            .timestamp
            .parse::<i64>()
            .ok()
            .and_then(|ts| chrono::DateTime::<Utc>::from_timestamp(ts, 0))
            .unwrap_or_else(Utc::now);

        let (display_name, username) = contact
            .map(|c| (c.profile.as_ref().and_then(|p| p.name.clone()), None))
            .unwrap_or((None, None));

        let text = msg
            .text
            .as_ref()
            .map(|t| t.body.clone())
            .unwrap_or_default();

        let mut metadata: HashMap<String, Value> = HashMap::new();
        if let Some(msg_type) = &msg.r#type {
            metadata.insert("message_type".to_string(), Value::String(msg_type.clone()));
        }
        if let Some(ctx) = &msg.context {
            if let Some(ref_id) = &ctx.message_id {
                metadata.insert("reply_to".to_string(), Value::String(ref_id.clone()));
            }
        }

        let thread_root = msg.context.and_then(|ctx| ctx.message_id);

        Ok(BridgeMessage {
            id: msg.id,
            platform: ChatPlatform::WhatsApp,
            channel: ChannelAddress {
                team_id: None,
                channel_id: msg.from.clone(),
                channel_name: None,
                thread_id: None,
            },
            sender: Participant {
                id: msg.from,
                display_name,
                role: ParticipantRole::User,
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
impl ChatAdapter for WhatsAppAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::WhatsApp
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
        let response = self
            .client
            .get(self.phone_url())
            .bearer_auth(self.bearer())
            .send()
            .await?;

        let ok = response.status().is_success();
        let details = if ok {
            None
        } else {
            Some(format!(
                "WhatsApp health check returned {}",
                response.status()
            ))
        };

        Ok(AdapterStatus {
            is_online: ok,
            last_checked_at: Utc::now(),
            details,
        })
    }

    async fn fetch_messages(&self, _request: FetchRequest) -> Result<Vec<BridgeMessage>> {
        // WhatsApp Cloud API is webhook-only for incoming messages.
        // Polling is not supported; return empty.
        Ok(Vec::new())
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let payload = json!({
            "messaging_product": "whatsapp",
            "to": message.channel.channel_id,
            "type": "text",
            "text": {
                "body": message.content.text,
            }
        });

        let response = self
            .client
            .post(self.api_url("messages"))
            .bearer_auth(self.bearer())
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "WhatsApp send message failed ({status}): {body}"
            )));
        }

        let resp: WhatsAppSendResponse = response.json().await?;
        let message_id = resp
            .messages
            .and_then(|msgs| msgs.into_iter().next())
            .map(|m| m.id)
            .unwrap_or_else(|| "unknown".into());

        Ok(SendReceipt {
            message_id,
            timestamp: Utc::now(),
            platform: ChatPlatform::WhatsApp,
            channel: message.channel,
        })
    }
}

#[derive(Debug, Deserialize)]
struct WhatsAppSendResponse {
    #[serde(default)]
    messages: Option<Vec<WhatsAppMessageId>>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppMessageId {
    id: String,
}

// Webhook payload types — deserialization targets for inbound webhook payloads.
// Structs are constructed by serde, method used by webhook processing.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppWebhookPayload {
    #[serde(default)]
    pub entry: Vec<WhatsAppEntry>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppEntry {
    #[serde(default)]
    pub changes: Vec<WhatsAppChange>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppChange {
    #[serde(default)]
    pub value: Option<WhatsAppChangeValue>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppChangeValue {
    #[serde(default)]
    pub messages: Option<Vec<WhatsAppWebhookMessage>>,
    #[serde(default)]
    pub contacts: Option<Vec<WhatsAppContact>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppWebhookMessage {
    pub id: String,
    pub from: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub text: Option<WhatsAppTextBody>,
    #[serde(default)]
    pub context: Option<WhatsAppMessageContext>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppTextBody {
    pub body: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppMessageContext {
    #[serde(default)]
    pub message_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppContact {
    #[serde(default)]
    pub profile: Option<WhatsAppProfile>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct WhatsAppProfile {
    #[serde(default)]
    pub name: Option<String>,
}
