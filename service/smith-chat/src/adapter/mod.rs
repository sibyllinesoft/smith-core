use crate::error::Result;
use crate::message::{BridgeMessage, ChannelAddress, ChatPlatform, MessageContent};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub mod discord;
pub mod google_chat;
pub mod imessage;
pub mod matrix;
pub mod mattermost;
pub mod signal;
pub mod slack;
pub mod teams;
pub mod telegram;
pub mod whatsapp;

#[derive(Debug, Clone, Copy, Default)]
pub struct AdapterCapabilities {
    pub supports_threads: bool,
    pub supports_ephemeral: bool,
    pub supports_markdown: bool,
}

#[derive(Debug, Clone)]
pub struct AdapterStatus {
    pub is_online: bool,
    pub last_checked_at: DateTime<Utc>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    pub channel: ChannelAddress,
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub include_threads: bool,
}

impl FetchRequest {
    pub fn for_channel(channel_id: impl Into<String>) -> Self {
        Self {
            channel: ChannelAddress::new(channel_id),
            since: None,
            limit: None,
            include_threads: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    pub channel: ChannelAddress,
    pub content: MessageContent,
    pub reply_in_thread: Option<String>,
    pub metadata: HashMap<String, Value>,
}

impl OutgoingMessage {
    pub fn new(channel: ChannelAddress, content: MessageContent) -> Self {
        Self {
            channel,
            content,
            reply_in_thread: None,
            metadata: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SendReceipt {
    pub message_id: String,
    pub timestamp: DateTime<Utc>,
    pub platform: ChatPlatform,
    pub channel: ChannelAddress,
}

#[async_trait]
pub trait ChatAdapter: Send + Sync {
    fn id(&self) -> &str;
    fn platform(&self) -> ChatPlatform;
    fn label(&self) -> &str;
    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::default()
    }

    async fn health_check(&self) -> Result<AdapterStatus>;
    async fn fetch_messages(&self, request: FetchRequest) -> Result<Vec<BridgeMessage>>;
    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt>;
}
