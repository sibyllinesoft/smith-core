use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::MattermostConfig;
use crate::error::{ChatBridgeError, Result};
use crate::message::{
    Attachment, BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, MessageFormat,
    Participant, ParticipantRole,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::header::ACCEPT;
use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

const DEFAULT_PLUGIN_ID: &str = "com.smith.mattermost-ai-bridge";
const HEADER_BRIDGE_SECRET: &str = "Mattermost-Bridge-Secret";
const SMITH_BRIDGE_PROP: &str = "smith_bridge_origin";

#[derive(Clone)]
pub struct MattermostAdapter {
    id: String,
    label: String,
    mode: MattermostMode,
    config: MattermostConfig,
}

#[derive(Clone)]
enum MattermostMode {
    Rest(RestMattermostClient),
    AgentBridge(MattermostBridgeClient),
}

#[derive(Clone)]
struct RestMattermostClient {
    client: Client,
}

#[derive(Clone)]
struct MattermostBridgeClient {
    http: Client,
    bridge_base: String,
    webhook_secret: Option<String>,
}

impl MattermostAdapter {
    pub fn new(id: impl Into<String>, config: MattermostConfig) -> Result<Self> {
        let id = id.into();
        let label = config.label.clone().unwrap_or_else(|| id.clone());

        let mode = if config.use_agent_bridge {
            MattermostMode::AgentBridge(MattermostBridgeClient::new(&config)?)
        } else {
            if config.access_token.trim().is_empty() {
                return Err(ChatBridgeError::InvalidConfig(
                    "Mattermost access token cannot be empty".into(),
                ));
            }

            let mut builder = Client::builder();
            if !config.verify_tls {
                builder = builder.danger_accept_invalid_certs(true);
            }
            let client = builder.build()?;
            MattermostMode::Rest(RestMattermostClient { client })
        };

        Ok(Self {
            id,
            label,
            mode,
            config,
        })
    }

    fn rest_api(&self, path: &str) -> String {
        format!(
            "{}/api/v4{}",
            self.config.base_url.trim_end_matches('/'),
            path
        )
    }

    fn parse_timestamp(ms: i64) -> Result<DateTime<Utc>> {
        let seconds = ms / 1000;
        let nanos = ((ms % 1000) * 1_000_000) as u32;
        DateTime::<Utc>::from_timestamp(seconds, nanos)
            .ok_or_else(|| ChatBridgeError::other(format!("invalid Mattermost timestamp: {ms}")))
    }

    fn convert_post(&self, post: MattermostPost) -> Result<BridgeMessage> {
        let timestamp = Self::parse_timestamp(post.create_at)?;
        let mut content = MessageContent::plain(post.message.clone());
        content.format = MessageFormat::Markdown;

        let mut attachments = Vec::new();
        if let Some(metadata) = post.metadata {
            if let Some(files) = metadata.files {
                for file in files {
                    let file_id = file.id.clone();
                    attachments.push(Attachment {
                        id: Some(file_id.clone()),
                        title: Some(file.name.clone()),
                        url: format!(
                            "{}/api/v4/files/{}",
                            self.config.base_url.trim_end_matches('/'),
                            file_id
                        ),
                        mime_type: file.mime_type,
                        size_bytes: Some(file.size as u64),
                    });
                }
            }
        }
        content.attachments = attachments;

        let mut extra = HashMap::new();
        if let Some(props) = post.props {
            extra.insert("props".to_string(), serde_json::to_value(props)?);
        }
        content.extra = extra.clone();

        Ok(BridgeMessage {
            id: post.id.clone(),
            platform: ChatPlatform::Mattermost,
            channel: ChannelAddress {
                team_id: Some(self.config.team_id.clone()),
                channel_id: post.channel_id.clone(),
                channel_name: None,
                thread_id: if post.root_id.is_empty() {
                    None
                } else {
                    Some(post.root_id.clone())
                },
            },
            sender: Participant {
                id: post.user_id,
                display_name: None,
                role: ParticipantRole::User,
                username: None,
                tags: Vec::new(),
            },
            content,
            timestamp,
            thread_root: if post.root_id.is_empty() {
                None
            } else {
                Some(post.root_id)
            },
            identity: None,
            metadata: extra,
        })
    }

    async fn rest_health_check(&self, client: &Client) -> Result<AdapterStatus> {
        let response = client
            .get(self.rest_api("/users/me"))
            .bearer_auth(&self.config.access_token)
            .send()
            .await?;

        Ok(AdapterStatus {
            is_online: response.status().is_success(),
            last_checked_at: Utc::now(),
            details: if response.status().is_success() {
                None
            } else {
                Some(response.text().await.unwrap_or_default())
            },
        })
    }

    async fn rest_fetch_messages(
        &self,
        client: &Client,
        request: FetchRequest,
    ) -> Result<Vec<BridgeMessage>> {
        let mut query: Vec<(String, String)> = Vec::new();
        if let Some(since) = request.since {
            query.push(("since".to_string(), (since.timestamp_millis()).to_string()));
        }
        if let Some(limit) = request.limit {
            query.push(("per_page".to_string(), limit.to_string()));
        }

        let response = client
            .get(
                self.rest_api("/channels/{channel_id}/posts")
                    .replace("{channel_id}", &self.config.channel_id),
            )
            .bearer_auth(&self.config.access_token)
            .query(&query)
            .send()
            .await?;

        let payload: PostsResponse = response.json().await?;
        let mut messages = Vec::new();
        if let Some(order) = payload.order {
            for id in order {
                if let Some(post) = payload.posts.get(&id) {
                    messages.push(self.convert_post(post.clone())?);
                }
            }
        } else {
            for post in payload.posts.into_values() {
                messages.push(self.convert_post(post)?);
            }
        }
        Ok(messages)
    }

    async fn rest_send_message(
        &self,
        client: &Client,
        message: OutgoingMessage,
    ) -> Result<SendReceipt> {
        let mut props = message.metadata.clone();
        props
            .entry(SMITH_BRIDGE_PROP.to_string())
            .or_insert(Value::Bool(true));

        let payload = CreatePostRequest {
            channel_id: message.channel.channel_id.clone(),
            message: message.content.text.clone(),
            root_id: message.reply_in_thread,
            props,
        };

        let response = client
            .post(self.rest_api("/posts"))
            .bearer_auth(&self.config.access_token)
            .json(&payload)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            return Err(ChatBridgeError::other(format!(
                "Mattermost post failed with status {}: {}",
                status, text
            )));
        }
        let post: MattermostPost = serde_json::from_str(&text).map_err(|err| {
            ChatBridgeError::other(format!(
                "failed to decode Mattermost post response: {err}; body={text}"
            ))
        })?;
        let timestamp = Self::parse_timestamp(post.create_at)?;

        let thread_id = if post.root_id.is_empty() {
            post.id.clone()
        } else {
            post.root_id.clone()
        };

        Ok(SendReceipt {
            message_id: post.id.clone(),
            timestamp,
            platform: ChatPlatform::Mattermost,
            channel: ChannelAddress {
                team_id: Some(self.config.team_id.clone()),
                channel_id: post.channel_id,
                channel_name: None,
                thread_id: Some(thread_id),
            },
        })
    }
}

#[async_trait]
impl ChatAdapter for MattermostAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::Mattermost
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
        match &self.mode {
            MattermostMode::Rest(rest) => self.rest_health_check(&rest.client).await,
            MattermostMode::AgentBridge(bridge) => bridge.health_check().await,
        }
    }

    async fn fetch_messages(&self, request: FetchRequest) -> Result<Vec<BridgeMessage>> {
        match &self.mode {
            MattermostMode::Rest(rest) => self.rest_fetch_messages(&rest.client, request).await,
            MattermostMode::AgentBridge(bridge) => {
                self.rest_fetch_messages(bridge.rest_client(), request)
                    .await
            }
        }
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        match &self.mode {
            MattermostMode::Rest(rest) => self.rest_send_message(&rest.client, message).await,
            MattermostMode::AgentBridge(bridge) => {
                self.rest_send_message(bridge.rest_client(), message).await
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct PostsResponse {
    order: Option<Vec<String>>,
    posts: HashMap<String, MattermostPost>,
}

#[derive(Debug, Clone, Deserialize)]
struct MattermostPost {
    id: String,
    #[serde(rename = "create_at")]
    create_at: i64,
    #[serde(rename = "user_id")]
    user_id: String,
    #[serde(rename = "channel_id")]
    channel_id: String,
    #[serde(rename = "root_id")]
    root_id: String,
    message: String,
    #[serde(default)]
    props: Option<HashMap<String, Value>>,
    metadata: Option<MattermostMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
struct MattermostMetadata {
    files: Option<Vec<MattermostFile>>,
}

#[derive(Debug, Clone, Deserialize)]
struct MattermostFile {
    id: String,
    name: String,
    #[serde(rename = "mime_type")]
    mime_type: Option<String>,
    #[serde(rename = "size")]
    size: i64,
}

#[derive(Debug, Serialize)]
struct CreatePostRequest {
    channel_id: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_id: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    props: HashMap<String, Value>,
}

impl MattermostBridgeClient {
    fn new(config: &MattermostConfig) -> Result<Self> {
        if config.access_token.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Mattermost access token cannot be empty when using the AI bridge".into(),
            ));
        }

        let plugin_id = config
            .plugin_id
            .clone()
            .unwrap_or_else(|| DEFAULT_PLUGIN_ID.to_string());

        let base = if let Some(bridge_url) = &config.bridge_url {
            bridge_url.trim_end_matches('/').to_string()
        } else {
            format!(
                "{}/plugins/{}",
                config.base_url.trim_end_matches('/'),
                plugin_id
            )
        };

        let bridge_base = format!("{}/external/bridge", base);

        let mut builder = Client::builder();
        if !config.verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }

        Ok(Self {
            http: builder.build()?,
            bridge_base,
            webhook_secret: config.webhook_secret.clone(),
        })
    }

    async fn request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        let url = format!("{}{}", self.bridge_base, path);
        let mut builder = self
            .http
            .request(method, url)
            .header(ACCEPT, "application/json");

        if let Some(secret) = &self.webhook_secret {
            builder = builder.header(HEADER_BRIDGE_SECRET, secret);
        }

        Ok(builder)
    }

    async fn health_check(&self) -> Result<AdapterStatus> {
        let builder = match self.request(Method::GET, "/agents").await {
            Ok(builder) => builder,
            Err(error) => {
                return Ok(AdapterStatus {
                    is_online: false,
                    last_checked_at: Utc::now(),
                    details: Some(error.to_string()),
                })
            }
        };
        let status = match builder.send().await {
            Ok(response) => {
                let success = response.status().is_success();
                let details = if success {
                    None
                } else {
                    Some(response.text().await.unwrap_or_default())
                };
                AdapterStatus {
                    is_online: success,
                    last_checked_at: Utc::now(),
                    details,
                }
            }
            Err(error) => AdapterStatus {
                is_online: false,
                last_checked_at: Utc::now(),
                details: Some(error.to_string()),
            },
        };

        Ok(status)
    }

    fn rest_client(&self) -> &Client {
        &self.http
    }
}
