//! Error types for Smith logging infrastructure

use thiserror::Error;

/// Result type for logging operations
pub type LoggingResult<T> = Result<T, LoggingError>;

/// Errors that can occur in the logging infrastructure
#[derive(Error, Debug)]
pub enum LoggingError {
    /// NATS connection or publish error
    #[error("NATS error: {0}")]
    Nats(#[from] async_nats::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Buffer overflow
    #[error("Log buffer overflow")]
    BufferOverflow,

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Generic error
    #[error("Logging error: {0}")]
    Generic(String),
}

impl From<&str> for LoggingError {
    fn from(s: &str) -> Self {
        LoggingError::Generic(s.to_string())
    }
}

impl From<String> for LoggingError {
    fn from(s: String) -> Self {
        LoggingError::Generic(s)
    }
}
