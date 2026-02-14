use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::TeamsConfig;
use crate::error::{ChatBridgeError, Result};
use crate::message::{
    BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, MessageFormat, Participant,
    ParticipantRole,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct TeamsAdapter {
    id: String,
    label: String,
    client: Client,
    config: TeamsConfig,
    token_cache: Arc<RwLock<Option<CachedToken>>>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

impl TeamsAdapter {
    pub fn new(id: impl Into<String>, config: TeamsConfig) -> Result<Self> {
        if config.client_id.trim().is_empty() || config.client_secret.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Teams client credentials cannot be empty".into(),
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
            token_cache: Arc::new(RwLock::new(None)),
        })
    }

    fn authority_url(&self) -> String {
        format!(
            "{}/{}/oauth2/v2.0/token",
            self.config.authority_url.trim_end_matches('/'),
            self.config.tenant_id
        )
    }

    fn messages_url(&self) -> String {
        format!(
            "{}/teams/{}/channels/{}/messages",
            self.config.graph_base_url.trim_end_matches('/'),
            self.config.team_id,
            self.config.channel_id
        )
    }

    fn message_replies_url(&self, thread_id: &str) -> String {
        format!("{}/{thread_id}/replies", self.messages_url())
    }

    fn channel_url(&self) -> String {
        format!(
            "{}/teams/{}/channels/{}",
            self.config.graph_base_url.trim_end_matches('/'),
            self.config.team_id,
            self.config.channel_id
        )
    }

    async fn access_token(&self) -> Result<String> {
        {
            let guard = self.token_cache.read().await;
            if let Some(token) = guard.as_ref() {
                if token.expires_at > Utc::now() + Duration::seconds(30) {
                    return Ok(token.access_token.clone());
                }
            }
        }

        let form = vec![
            ("client_id".to_string(), self.config.client_id.clone()),
            (
                "client_secret".to_string(),
                self.config.client_secret.clone(),
            ),
            ("scope".to_string(), self.config.scope.clone()),
            ("grant_type".to_string(), "client_credentials".to_string()),
        ];

        let response = self
            .client
            .post(self.authority_url())
            .form(&form)
            .send()
            .await?;

        let payload: TokenResponse = response.json().await?;
        let ttl = payload.expires_in.unwrap_or(3600).saturating_sub(60);
        let expires_at = Utc::now() + Duration::seconds(ttl);
        let access_token = payload
            .access_token
            .ok_or_else(|| ChatBridgeError::Authentication("missing Teams access_token".into()))?;

        let mut guard = self.token_cache.write().await;
        *guard = Some(CachedToken {
            access_token: access_token.clone(),
            expires_at,
        });

        Ok(access_token)
    }

    async fn get(&self, url: String) -> Result<Value> {
        let token = self.access_token().await?;
        let response = self.client.get(url).bearer_auth(token).send().await?;
        Ok(response.json().await?)
    }

    async fn post(&self, url: String, body: Value) -> Result<Value> {
        let token = self.access_token().await?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;
        Ok(response.json().await?)
    }

    fn parse_message(&self, raw: GraphMessage) -> Result<BridgeMessage> {
        let timestamp = raw
            .created_date_time
            .ok_or_else(|| ChatBridgeError::other("Teams message missing timestamp"))?;
        let timestamp = DateTime::parse_from_rfc3339(&timestamp)
            .map_err(|err| ChatBridgeError::other(format!("bad Teams timestamp: {err}")))?
            .with_timezone(&Utc);

        let body = raw.body.unwrap_or_default();
        let text = body.content.unwrap_or_default();
        let mut content = MessageContent::plain(text);
        content.format = match body.content_type.as_deref() {
            Some("html") => MessageFormat::Html,
            Some("text") => MessageFormat::PlainText,
            _ => MessageFormat::Markdown,
        };
        if let Some(content_type) = body.content_type.clone() {
            content
                .extra
                .insert("content_type".to_string(), Value::String(content_type));
        }

        let sender = raw
            .from
            .and_then(|from| from.user)
            .map(|user| Participant {
                id: user.id.unwrap_or_else(|| "unknown".into()),
                display_name: user.display_name,
                role: ParticipantRole::User,
                username: None,
                tags: Vec::new(),
            })
            .unwrap_or(Participant {
                id: "unknown".into(),
                display_name: None,
                role: ParticipantRole::Unknown,
                username: None,
                tags: Vec::new(),
            });

        let mut metadata = HashMap::new();
        if let Some(importance) = raw.importance {
            metadata.insert("importance".to_string(), Value::String(importance));
        }
        if let Some(reactions) = raw.reactions {
            metadata.insert("reactions".to_string(), json!(reactions));
        }

        Ok(BridgeMessage {
            id: raw.id.clone().unwrap_or_else(|| "unknown".into()),
            platform: ChatPlatform::Teams,
            channel: ChannelAddress {
                team_id: Some(self.config.team_id.clone()),
                channel_id: self.config.channel_id.clone(),
                channel_name: None,
                thread_id: raw.reply_to_id.clone(),
            },
            sender,
            content,
            timestamp,
            thread_root: raw.reply_to_id,
            identity: None,
            metadata,
        })
    }

    fn message_payload(content: &MessageContent) -> Value {
        let (content_type, body) = match content.format {
            MessageFormat::Html => ("html", content.text.clone()),
            MessageFormat::Markdown => ("html", markdown_to_html(&content.text)),
            MessageFormat::PlainText => ("text", content.text.clone()),
        };
        json!({
            "body": {
                "contentType": content_type,
                "content": body,
            }
        })
    }
}

#[async_trait]
impl ChatAdapter for TeamsAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::Teams
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
        let response = self.get(self.channel_url()).await?;
        let ok = !response
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty();
        Ok(AdapterStatus {
            is_online: ok,
            last_checked_at: Utc::now(),
            details: if ok { None } else { Some(response.to_string()) },
        })
    }

    async fn fetch_messages(&self, request: FetchRequest) -> Result<Vec<BridgeMessage>> {
        let mut url = self.messages_url();
        let mut query = Vec::new();
        if let Some(limit) = request.limit {
            query.push(format!("$top={limit}"));
        }
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }

        let payload = self.get(url).await?;
        let data: GraphMessageList = serde_json::from_value(payload)?;

        let mut messages = Vec::new();
        for message in data.value.unwrap_or_default() {
            messages.push(self.parse_message(message)?);
        }
        Ok(messages)
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let channel = message.channel.clone();
        let payload = Self::message_payload(&message.content);
        let url = if let Some(thread) = &message.reply_in_thread {
            self.message_replies_url(thread)
        } else {
            self.messages_url()
        };

        let response = self.post(url, payload).await?;
        let message: GraphMessage = serde_json::from_value(response)?;
        let bridge_message = self.parse_message(message)?;

        Ok(SendReceipt {
            message_id: bridge_message.id.clone(),
            timestamp: bridge_message.timestamp,
            platform: ChatPlatform::Teams,
            channel,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
struct GraphMessageList {
    value: Option<Vec<GraphMessage>>,
}

#[derive(Debug, Deserialize)]
struct GraphMessage {
    id: Option<String>,
    #[serde(rename = "replyToId")]
    reply_to_id: Option<String>,
    #[serde(rename = "createdDateTime")]
    created_date_time: Option<String>,
    from: Option<GraphMessageFrom>,
    body: Option<GraphMessageBody>,
    importance: Option<String>,
    reactions: Option<Vec<Value>>,
}

#[derive(Debug, Deserialize)]
struct GraphMessageFrom {
    user: Option<GraphMessageUser>,
}

#[derive(Debug, Deserialize)]
struct GraphMessageUser {
    id: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct GraphMessageBody {
    #[serde(rename = "contentType")]
    content_type: Option<String>,
    content: Option<String>,
}

fn markdown_to_html(markdown: &str) -> String {
    markdown
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', "<br />")
}
