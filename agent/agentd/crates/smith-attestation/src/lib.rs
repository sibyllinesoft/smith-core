//! Smith Attestation Library
//!
//! Provides cryptographic signing, verification, and supply chain attestation
//! capabilities for the Smith platform. Implements SLSA provenance metadata
//! generation and Cosign integration for capability bundles and container images.
//!
//! # Features
//!
//! - **Capability Bundle Signing**: Cryptographic signatures for capability bundles
//! - **Container Image Verification**: Boot-time signature verification
//! - **SLSA Provenance**: Build attestation metadata generation
//! - **Supply Chain Security**: End-to-end integrity verification
//!
//! # Example
//!
//! ```rust,ignore
//! use smith_attestation::{CapabilitySigner, VerificationResult};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let signer = CapabilitySigner::new().await?;
//! let capability_bytes = std::fs::read("capability_bundle.json")?;
//!
//! // Sign capability bundle
//! let signature = signer.sign_capability_bundle(&capability_bytes).await?;
//!
//! // Verify signature
//! let result = signer
//!     .verify_capability_bundle(&capability_bytes, &signature)
//!     .await?;
//! assert!(result.is_valid());
//! # Ok(())
//! # }
//! ```

pub mod capability;
pub mod errors;
pub mod provenance;
pub mod signatures;
pub mod verification;

#[cfg(feature = "cosign")]
pub mod cosign;

pub use capability::{CapabilityDigest, CapabilitySigner};
pub use errors::{AttestationError, Result};
pub use provenance::{BuildInfo, ProvenanceGenerator, SlsaProvenance};
pub use signatures::{Signature, SignatureMetadata};
pub use verification::{VerificationConfig, VerificationContext, VerificationResult, Verifier};

/// Smith attestation version for compatibility tracking
pub const ATTESTATION_VERSION: &str = "1.0.0";

/// Default attestation configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttestationConfig {
    /// Enable capability bundle signing
    pub enable_capability_signing: bool,

    /// Enable container image verification
    pub enable_image_verification: bool,

    /// Enable SLSA provenance generation
    pub enable_slsa_provenance: bool,

    /// Boot failure on signature verification errors
    pub fail_on_signature_error: bool,

    /// Cosign public key for verification (optional for keyless)
    pub cosign_public_key: Option<String>,

    /// SLSA provenance output directory
    pub provenance_output_dir: String,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            enable_capability_signing: true,
            enable_image_verification: true,
            enable_slsa_provenance: true,
            fail_on_signature_error: true,
            cosign_public_key: None,
            provenance_output_dir: "build/attestation".to_string(),
        }
    }
}

/// Initialize attestation subsystem with configuration
pub async fn initialize_attestation(config: AttestationConfig) -> Result<()> {
    tracing::info!(
        "Initializing Smith attestation subsystem v{}",
        ATTESTATION_VERSION
    );

    // Create attestation output directory
    std::fs::create_dir_all(&config.provenance_output_dir)
        .map_err(|e| AttestationError::IoError(e.to_string()))?;

    // Verify cryptographic capabilities
    if config.enable_capability_signing {
        verify_signing_capabilities().await?;
    }

    if config.enable_image_verification {
        verify_image_verification_capabilities().await?;
    }

    tracing::info!("Smith attestation subsystem initialized successfully");
    Ok(())
}

/// Verify that signing capabilities are available
async fn verify_signing_capabilities() -> Result<()> {
    // Test basic cryptographic operations
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"attestation-test");
    let _hash = hasher.finalize();

    tracing::debug!("Cryptographic signing capabilities verified");
    Ok(())
}

/// Verify that image verification capabilities are available
async fn verify_image_verification_capabilities() -> Result<()> {
    #[cfg(feature = "cosign")]
    {
        // Test cosign client initialization
        let _client = sigstore::cosign::ClientBuilder::default()
            .build()
            .map_err(|e| AttestationError::CosignError(e.to_string()))?;

        tracing::debug!("Cosign verification capabilities verified");
    }

    #[cfg(not(feature = "cosign"))]
    {
        tracing::warn!("Cosign feature disabled - image verification unavailable");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_initialization() {
        let config = AttestationConfig::default();

        // Test initialization with default config
        let result = initialize_attestation(config).await;
        assert!(result.is_ok(), "Attestation initialization should succeed");
    }

    #[test]
    fn test_attestation_config_serialization() {
        let config = AttestationConfig::default();

        // Test that config can be serialized/deserialized
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AttestationConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(
            config.enable_capability_signing,
            deserialized.enable_capability_signing
        );
        assert_eq!(
            config.enable_image_verification,
            deserialized.enable_image_verification
        );
    }
}
