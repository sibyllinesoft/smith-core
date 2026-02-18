use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::GoogleChatConfig;
use crate::error::{ChatBridgeError, Result};
use crate::message::{
    BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, MessageFormat, Participant,
    ParticipantRole,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const GOOGLE_CHAT_API: &str = "https://chat.googleapis.com/v1";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "https://www.googleapis.com/auth/chat.bot";

#[derive(Clone)]
pub struct GoogleChatAdapter {
    id: String,
    label: String,
    client: Client,
    config: GoogleChatConfig,
    cached_token: Arc<Mutex<Option<CachedToken>>>,
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

#[derive(Debug, Deserialize)]
struct GoogleChatMessage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    sender: Option<GoogleChatSender>,
    #[serde(default, rename = "createTime")]
    create_time: Option<String>,
    #[serde(default)]
    thread: Option<GoogleChatThread>,
}

#[derive(Debug, Deserialize)]
struct GoogleChatSender {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(default, rename = "type")]
    sender_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleChatThread {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListMessagesResponse {
    #[serde(default)]
    messages: Vec<GoogleChatMessage>,
}

impl GoogleChatAdapter {
    pub fn new(id: impl Into<String>, config: GoogleChatConfig) -> Result<Self> {
        if config.service_account_json.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Google Chat service account JSON path cannot be empty".into(),
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
            cached_token: Arc::new(Mutex::new(None)),
        })
    }

    async fn get_access_token(&self) -> Result<String> {
        // Check cache
        {
            let cached = self.cached_token.lock().await;
            if let Some(ref token) = *cached {
                if token.expires_at > Utc::now() + chrono::Duration::seconds(60) {
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Load service account key
        let sa_json = if self.config.service_account_json.starts_with('{') {
            self.config.service_account_json.clone()
        } else {
            tokio::fs::read_to_string(&self.config.service_account_json)
                .await
                .map_err(|e| {
                    ChatBridgeError::other(format!("failed to read service account file: {e}"))
                })?
        };

        let sa_key: ServiceAccountKey = serde_json::from_str(&sa_json)
            .map_err(|e| ChatBridgeError::other(format!("invalid service account JSON: {e}")))?;

        let now = Utc::now().timestamp();
        let claims = JwtClaims {
            iss: sa_key.client_email,
            scope: SCOPE.to_string(),
            aud: TOKEN_URL.to_string(),
            iat: now,
            exp: now + 3600,
        };

        let key = EncodingKey::from_rsa_pem(sa_key.private_key.as_bytes())
            .map_err(|e| ChatBridgeError::other(format!("invalid RSA private key: {e}")))?;

        let jwt = encode(&Header::new(Algorithm::RS256), &claims, &key)
            .map_err(|e| ChatBridgeError::other(format!("JWT encoding failed: {e}")))?;

        let resp = self
            .client
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChatBridgeError::Authentication(format!(
                "Google OAuth token request failed ({status}): {body}"
            )));
        }

        let token_resp: TokenResponse = resp.json().await?;
        let expires_in = token_resp.expires_in.unwrap_or(3600);

        let mut cached = self.cached_token.lock().await;
        *cached = Some(CachedToken {
            access_token: token_resp.access_token.clone(),
            expires_at: Utc::now() + chrono::Duration::seconds(expires_in),
        });

        Ok(token_resp.access_token)
    }

    fn convert_message(&self, msg: GoogleChatMessage, space: &str) -> Option<BridgeMessage> {
        let text = msg.text?;
        let msg_name = msg.name.unwrap_or_default();

        // Extract message ID from name like "spaces/xxx/messages/yyy"
        let msg_id = msg_name.rsplit('/').next().unwrap_or(&msg_name).to_string();

        let (sender_id, display_name, role) = if let Some(sender) = msg.sender {
            let is_bot = sender.sender_type.as_deref() == Some("BOT");
            let id = sender
                .name
                .as_deref()
                .and_then(|n| n.rsplit('/').next())
                .unwrap_or("unknown")
                .to_string();
            (
                id,
                sender.display_name,
                if is_bot {
                    ParticipantRole::Bot
                } else {
                    ParticipantRole::User
                },
            )
        } else {
            ("unknown".to_string(), None, ParticipantRole::Unknown)
        };

        let timestamp = msg
            .create_time
            .as_deref()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let thread_root = msg.thread.and_then(|t| {
            t.name
                .as_deref()
                .and_then(|n| n.rsplit('/').next())
                .map(|s| s.to_string())
        });

        Some(BridgeMessage {
            id: msg_id,
            platform: ChatPlatform::GoogleChat,
            channel: ChannelAddress {
                team_id: None,
                channel_id: space.to_string(),
                channel_name: None,
                thread_id: thread_root.clone(),
            },
            sender: Participant {
                id: sender_id,
                display_name,
                role,
                username: None,
                tags: Vec::new(),
            },
            content: MessageContent {
                text,
                format: MessageFormat::Markdown,
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
impl ChatAdapter for GoogleChatAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::GoogleChat
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
        let token = self.get_access_token().await?;
        let url = format!("{}/spaces/{}", GOOGLE_CHAT_API, self.config.space_id);
        let response = self.client.get(&url).bearer_auth(&token).send().await?;

        let ok = response.status().is_success();
        let details = if ok {
            None
        } else {
            Some(format!(
                "Google Chat health check returned {}",
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
        let token = self.get_access_token().await?;
        let space = &request.channel.channel_id;
        let mut url = format!("{}/spaces/{}/messages", GOOGLE_CHAT_API, space);

        if let Some(limit) = request.limit {
            url.push_str(&format!("?pageSize={limit}"));
        }

        let response = self.client.get(&url).bearer_auth(&token).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Google Chat fetch messages failed ({status}): {body}"
            )));
        }

        let resp: ListMessagesResponse = response.json().await?;
        let mut result = Vec::new();
        for msg in resp.messages {
            if let Some(bridge_msg) = self.convert_message(msg, space) {
                result.push(bridge_msg);
            }
        }

        Ok(result)
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let token = self.get_access_token().await?;
        let space = &message.channel.channel_id;
        let url = format!("{}/spaces/{}/messages", GOOGLE_CHAT_API, space);

        let mut payload = json!({
            "text": message.content.text,
        });

        if let Some(thread_key) = &message.reply_in_thread {
            payload["thread"] = json!({ "threadKey": thread_key });
            // messageReplyOption tells the API to reply in the existing thread
            // rather than creating a new one
        }

        let response = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Google Chat send message failed ({status}): {body}"
            )));
        }

        let resp: GoogleChatMessage = response.json().await?;
        let msg_name = resp.name.unwrap_or_default();
        let msg_id = msg_name.rsplit('/').next().unwrap_or(&msg_name).to_string();

        let timestamp = resp
            .create_time
            .as_deref()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        Ok(SendReceipt {
            message_id: msg_id,
            timestamp,
            platform: ChatPlatform::GoogleChat,
            channel: message.channel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_service_account() {
        let cfg = GoogleChatConfig {
            service_account_json: "".into(),
            space_id: "spaces/test".into(),
            label: None,
        };
        assert!(GoogleChatAdapter::new("test", cfg).is_err());
    }

    #[test]
    fn constructs_with_valid_config() {
        let cfg = GoogleChatConfig {
            service_account_json: "/path/to/sa.json".into(),
            space_id: "spaces/test".into(),
            label: None,
        };
        let adapter = GoogleChatAdapter::new("test", cfg).unwrap();
        assert_eq!(adapter.platform(), ChatPlatform::GoogleChat);
        assert!(adapter.capabilities().supports_threads);
    }
}
