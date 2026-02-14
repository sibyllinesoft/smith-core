//! Error types for Smith attestation system

use thiserror::Error;

/// Attestation system errors
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Cryptographic signing error: {0}")]
    SigningError(String),

    #[error("Signature verification failed: {0}")]
    VerificationError(String),

    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),

    #[error("Capability bundle error: {0}")]
    PolicyError(String),

    #[error("SLSA provenance error: {0}")]
    ProvenanceError(String),

    #[error("Cosign integration error: {0}")]
    CosignError(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Security policy violation: {0}")]
    SecurityError(String),

    #[error("Attestation metadata error: {0}")]
    MetadataError(String),

    #[error("Supply chain integrity error: {0}")]
    SupplyChainError(String),
}

/// Result type for attestation operations
pub type Result<T> = std::result::Result<T, AttestationError>;

impl From<std::io::Error> for AttestationError {
    fn from(err: std::io::Error) -> Self {
        AttestationError::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for AttestationError {
    fn from(err: serde_json::Error) -> Self {
        AttestationError::MetadataError(format!("JSON serialization error: {}", err))
    }
}
