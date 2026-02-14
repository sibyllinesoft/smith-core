use crate::message::ChatPlatform;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ChatBridgeError>;

#[derive(Debug, Error)]
pub enum ChatBridgeError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("adapter `{adapter}` not found")]
    AdapterNotFound { adapter: String },

    #[error("authentication failed: {0}")]
    Authentication(String),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("unsupported operation for {platform:?}: {details}")]
    Unsupported {
        platform: ChatPlatform,
        details: String,
    },

    #[error("{0}")]
    Other(String),
}

impl ChatBridgeError {
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }
}
