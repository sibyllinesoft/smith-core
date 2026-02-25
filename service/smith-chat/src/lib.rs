//! Smith Chat Bridge Library
//!
//! Provides unified chat platform integration for the Smith platform, enabling
//! bidirectional communication between Smith agents and various messaging platforms.
//!
//! ## Supported Platforms
//!
//! - **Mattermost**: Full integration with webhooks and real-time messaging
//! - **Slack**: Bot API integration with threading support
//! - **Microsoft Teams**: Adaptive cards and channel messaging
//!
//! ## Key Components
//!
//! - **ChatBridge**: Core orchestrator for multi-platform message routing
//! - **Adapters**: Platform-specific implementations (Mattermost, Slack, Teams)
//! - **Message Formatting**: Converts Smith trace data into platform-native formats
//! - **Daemon**: Standalone service runner with tracing and graceful shutdown
//!
//! ## Usage
//!
//! ```rust,ignore
//! use chat_bridge::{ChatBridge, ChatBridgeConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config: ChatBridgeConfig = todo!();
//! let bridge = ChatBridge::build_from_config(config).await?;
//! # Ok(())
//! # }
//! ```

pub mod adapter;
pub mod allowlist;
pub mod bridge;
pub mod config;
pub mod daemon;
pub mod debounce;
pub mod error;
#[cfg(feature = "otel-exporter")]
pub mod exporter;
pub mod format;
pub mod gateway_common;
pub mod identity;
pub mod message;
pub mod pairing_store;
pub mod session_key;
#[cfg(feature = "webhooks")]
pub mod webhook;

pub use adapter::{
    discord::DiscordAdapter, google_chat::GoogleChatAdapter, imessage::IMessageAdapter,
    matrix::MatrixAdapter, mattermost::MattermostAdapter, signal::SignalAdapter,
    slack::SlackAdapter, teams::TeamsAdapter, telegram::TelegramAdapter, whatsapp::WhatsAppAdapter,
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
pub use allowlist::{Allowlist, AllowlistAction, AllowlistConfig, AllowlistMatcher, AllowlistRule};
pub use bridge::ChatBridge;
pub use config::{
    AdapterConfig, ChatBridgeConfig, DiscordConfig, GoogleChatConfig, IMessageConfig, MatrixConfig,
    MattermostConfig, SignalConfig, SlackConfig, TeamsConfig, TelegramConfig, WhatsAppConfig,
};
pub use error::{ChatBridgeError, Result};
#[cfg(feature = "otel-exporter")]
pub use exporter::MattermostTasksExporter;
pub use format::{format_span_message, format_trace_header, SpanPresentation, TraceHeader};
pub use identity::IdentityClaims;
pub use message::{
    Attachment, BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, MessageFormat,
    Participant, ParticipantRole,
};
pub use pairing_store::{DmPolicy, Pairing, PairingStore};
pub use session_key::{SessionKey, SessionScope};

// Re-export daemon interfaces for callers that previously depended on chat-bridge-daemon
pub use daemon::{init_tracing as daemon_init_tracing, run as daemon_run, Cli as DaemonCli};
