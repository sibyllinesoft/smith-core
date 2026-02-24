use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatPlatform {
    Slack,
    Teams,
    Mattermost,
    Telegram,
    Discord,
    WhatsApp,
    Signal,
    GoogleChat,
    IMessage,
    Matrix,
    Unknown,
}

impl std::fmt::Display for ChatPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeMessage {
    pub id: String,
    pub platform: ChatPlatform,
    pub channel: ChannelAddress,
    pub sender: Participant,
    pub content: MessageContent,
    pub timestamp: DateTime<Utc>,
    pub thread_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelAddress {
    pub team_id: Option<String>,
    pub channel_id: String,
    pub channel_name: Option<String>,
    pub thread_id: Option<String>,
}

impl ChannelAddress {
    pub fn new(channel_id: impl Into<String>) -> Self {
        Self {
            team_id: None,
            channel_id: channel_id.into(),
            channel_name: None,
            thread_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub id: String,
    pub display_name: Option<String>,
    pub role: ParticipantRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    User,
    Bot,
    System,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContent {
    pub text: String,
    pub format: MessageFormat,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub extra: HashMap<String, Value>,
}

impl MessageContent {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            format: MessageFormat::PlainText,
            attachments: Vec::new(),
            extra: HashMap::new(),
        }
    }

    pub fn markdown(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            format: MessageFormat::Markdown,
            attachments: Vec::new(),
            extra: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageFormat {
    #[default]
    PlainText,
    Markdown,
    Html,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Option<String>,
    pub title: Option<String>,
    pub url: String,
    pub mime_type: Option<String>,
    pub size_bytes: Option<u64>,
}
