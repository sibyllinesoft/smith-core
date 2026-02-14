use crate::message::ChatPlatform;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChatBridgeConfig {
    #[serde(default)]
    pub adapters: Vec<AdapterConfig>,

    /// Optional default polling interval in seconds for adapters that support polling.
    #[serde(default)]
    pub polling_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdapterConfig {
    Slack(SlackConfig),
    Teams(TeamsConfig),
    Mattermost(MattermostConfig),
    Telegram(TelegramConfig),
    Discord(DiscordConfig),
    #[serde(rename = "whatsapp")]
    WhatsApp(WhatsAppConfig),
    Signal(SignalConfig),
    GoogleChat(GoogleChatConfig),
    #[serde(rename = "imessage")]
    IMessage(IMessageConfig),
    Matrix(MatrixConfig),
}

impl AdapterConfig {
    pub fn platform(&self) -> ChatPlatform {
        match self {
            AdapterConfig::Slack(_) => ChatPlatform::Slack,
            AdapterConfig::Teams(_) => ChatPlatform::Teams,
            AdapterConfig::Mattermost(_) => ChatPlatform::Mattermost,
            AdapterConfig::Telegram(_) => ChatPlatform::Telegram,
            AdapterConfig::Discord(_) => ChatPlatform::Discord,
            AdapterConfig::WhatsApp(_) => ChatPlatform::WhatsApp,
            AdapterConfig::Signal(_) => ChatPlatform::Signal,
            AdapterConfig::GoogleChat(_) => ChatPlatform::GoogleChat,
            AdapterConfig::IMessage(_) => ChatPlatform::IMessage,
            AdapterConfig::Matrix(_) => ChatPlatform::Matrix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub bot_token: String,
    #[serde(default)]
    pub app_token: Option<String>,
    #[serde(default)]
    pub signing_secret: Option<String>,
    #[serde(default = "SlackConfig::default_api_base")]
    pub api_base_url: String,
    #[serde(default)]
    pub default_channel: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

impl SlackConfig {
    fn default_api_base() -> String {
        "https://slack.com/api".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "TeamsConfig::default_scope")]
    pub scope: String,
    pub team_id: String,
    pub channel_id: String,
    #[serde(default = "TeamsConfig::default_authority")]
    pub authority_url: String,
    #[serde(default = "TeamsConfig::default_graph_base")]
    pub graph_base_url: String,
    #[serde(default)]
    pub label: Option<String>,
}

impl TeamsConfig {
    fn default_scope() -> String {
        "https://graph.microsoft.com/.default".to_string()
    }

    fn default_authority() -> String {
        "https://login.microsoftonline.com".to_string()
    }

    fn default_graph_base() -> String {
        "https://graph.microsoft.com/v1.0".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MattermostConfig {
    pub base_url: String,
    pub access_token: String,
    pub team_id: String,
    pub channel_id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default = "MattermostConfig::default_verify_tls")]
    pub verify_tls: bool,
    /// When true, leverage the Mattermost AI Agent bridge instead of the raw REST API.
    #[serde(default)]
    pub use_agent_bridge: bool,
    /// Optional Mattermost AI bridge proxy plugin identifier (defaults to `com.smith.mattermost-ai-bridge`).
    #[serde(default)]
    pub plugin_id: Option<String>,
    /// Optional fully-qualified bridge URL override (defaults to the plugin bridge endpoint).
    #[serde(default)]
    pub bridge_url: Option<String>,
    /// Shared secret used when calling the bridge proxy plugin.
    #[serde(default)]
    pub webhook_secret: Option<String>,
    /// Optional identifier used when calling the bridge API (defaults to a Smith-specific value).
    #[serde(default)]
    pub agent_id: Option<String>,
}

impl MattermostConfig {
    fn default_verify_tls() -> bool {
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: String,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub allowed_updates: Option<Vec<String>>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    pub bot_token: String,
    pub application_id: String,
    #[serde(default)]
    pub guild_id: Option<String>,
    #[serde(default)]
    pub intents: Option<u64>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppConfig {
    pub access_token: String,
    pub phone_number_id: String,
    pub business_account_id: String,
    #[serde(default)]
    pub verify_token: Option<String>,
    #[serde(default = "WhatsAppConfig::default_api_version")]
    pub api_version: String,
    #[serde(default)]
    pub label: Option<String>,
}

impl WhatsAppConfig {
    fn default_api_version() -> String {
        "v21.0".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalConfig {
    pub phone_number: String,
    #[serde(default = "SignalConfig::default_signal_cli_url")]
    pub signal_cli_url: String,
    #[serde(default)]
    pub label: Option<String>,
}

impl SignalConfig {
    fn default_signal_cli_url() -> String {
        "http://127.0.0.1:8080".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleChatConfig {
    pub service_account_json: String,
    pub space_id: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IMessageConfig {
    pub server_url: String,
    pub server_password: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixConfig {
    pub homeserver_url: String,
    pub access_token: String,
    pub user_id: String,
    #[serde(default)]
    pub default_room_id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}
