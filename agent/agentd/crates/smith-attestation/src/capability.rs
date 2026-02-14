//! Capability bundle signing and verification
//!
//! Provides cryptographic signing for Smith capability bundles with deterministic
//! digest generation and verification capabilities.

use crate::{AttestationError, Result};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Capability bundle cryptographic signer
#[derive(Debug)]
pub struct CapabilitySigner {
    /// Ed25519 signing key (optional for verification-only mode)
    signing_key: Option<ed25519_dalek::SigningKey>,

    /// Ed25519 verification keys
    #[allow(dead_code)]
    verification_keys: Vec<ed25519_dalek::VerifyingKey>,
}

/// Capability bundle digest with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDigest {
    /// SHA-256 digest of the capability bundle
    pub digest: String,

    /// Bundle content hash (deterministic)
    pub content_hash: String,

    /// Bundle size in bytes
    pub size: u64,

    /// Timestamp when digest was computed
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Capability bundle version
    pub version: String,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Capability bundle signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySignature {
    /// Ed25519 signature bytes (base64 encoded)
    pub signature: String,

    /// Public key used for signing (base64 encoded)
    pub public_key: String,

    /// Signature algorithm identifier
    pub algorithm: String,

    /// Signature timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Capability digest that was signed
    pub digest: CapabilityDigest,
}

impl CapabilitySigner {
    /// Create new capability signer with generated key pair
    pub async fn new() -> Result<Self> {
        use rand_core::OsRng;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verification_key = signing_key.verifying_key();

        Ok(Self {
            signing_key: Some(signing_key),
            verification_keys: vec![verification_key],
        })
    }

    /// Create verification-only signer with public keys
    pub fn verification_only(public_keys: Vec<ed25519_dalek::VerifyingKey>) -> Self {
        Self {
            signing_key: None,
            verification_keys: public_keys,
        }
    }

    /// Load signer from PEM files
    pub async fn from_pem_files<P: AsRef<Path>>(
        private_key_path: Option<P>,
        public_key_path: P,
    ) -> Result<Self> {
        let mut verification_keys = Vec::new();

        // Load public key
        let public_key_bytes = tokio::fs::read(public_key_path.as_ref()).await?;
        let public_key_str = String::from_utf8(public_key_bytes).map_err(|e| {
            AttestationError::ConfigError(format!("Invalid public key encoding: {}", e))
        })?;

        let public_key = Self::parse_public_key(&public_key_str)?;
        verification_keys.push(public_key);

        // Load private key if provided
        let signing_key = if let Some(private_path) = private_key_path {
            let private_key_bytes = tokio::fs::read(private_path.as_ref()).await?;
            let private_key_str = String::from_utf8(private_key_bytes).map_err(|e| {
                AttestationError::ConfigError(format!("Invalid private key encoding: {}", e))
            })?;

            Some(Self::parse_private_key(&private_key_str)?)
        } else {
            None
        };

        Ok(Self {
            signing_key,
            verification_keys,
        })
    }

    /// Generate deterministic digest for capability bundle
    pub fn compute_capability_digest(
        &self,
        bundle_bytes: &[u8],
        version: String,
    ) -> CapabilityDigest {
        // Primary SHA-256 digest
        let mut hasher = Sha256::new();
        hasher.update(bundle_bytes);
        let digest = format!("{:x}", hasher.finalize());

        // Content hash (includes version for determinism)
        let mut content_hasher = Sha256::new();
        content_hasher.update(bundle_bytes);
        content_hasher.update(version.as_bytes());
        let content_hash = format!("{:x}", content_hasher.finalize());

        CapabilityDigest {
            digest,
            content_hash,
            size: bundle_bytes.len() as u64,
            timestamp: chrono::Utc::now(),
            version,
            metadata: HashMap::new(),
        }
    }

    /// Sign capability bundle and return signature
    pub async fn sign_capability_bundle(
        &self,
        bundle_bytes: &[u8],
        version: String,
    ) -> Result<CapabilitySignature> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            AttestationError::SigningError("No signing key available".to_string())
        })?;

        // Compute capability digest
        let digest = self.compute_capability_digest(bundle_bytes, version);

        // Create signature payload (digest + metadata)
        let signature_payload = self.create_signature_payload(&digest)?;

        // Sign the payload
        let signature = signing_key.sign(&signature_payload);

        // Encode public key
        let public_key = base64::encode(signing_key.verifying_key().to_bytes());

        Ok(CapabilitySignature {
            signature: base64::encode(signature.to_bytes()),
            public_key,
            algorithm: "Ed25519".to_string(),
            timestamp: chrono::Utc::now(),
            digest,
        })
    }

    /// Verify capability bundle signature
    pub async fn verify_capability_bundle(
        &self,
        bundle_bytes: &[u8],
        signature: &CapabilitySignature,
    ) -> Result<bool> {
        // Recompute digest to verify integrity
        let computed_digest =
            self.compute_capability_digest(bundle_bytes, signature.digest.version.clone());

        // Verify digest matches
        if computed_digest.digest != signature.digest.digest {
            return Ok(false);
        }

        // Parse signature
        let signature_bytes = base64::decode(&signature.signature).map_err(|e| {
            AttestationError::InvalidSignature(format!("Invalid signature encoding: {}", e))
        })?;

        let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            AttestationError::InvalidSignature(
                "Ed25519 signature must be exactly 64 bytes".to_string(),
            )
        })?;
        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&signature_array);

        // Parse public key
        let public_key_bytes = base64::decode(&signature.public_key).map_err(|e| {
            AttestationError::InvalidSignature(format!("Invalid public key encoding: {}", e))
        })?;

        let public_key =
            ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes.try_into().map_err(
                |_| AttestationError::InvalidSignature("Invalid public key length".to_string()),
            )?)
            .map_err(|e| {
                AttestationError::InvalidSignature(format!("Invalid Ed25519 public key: {}", e))
            })?;

        // Verify signature
        let signature_payload = self.create_signature_payload(&signature.digest)?;

        match public_key.verify_strict(&signature_payload, &ed25519_signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Create signature payload from digest
    fn create_signature_payload(&self, digest: &CapabilityDigest) -> Result<Vec<u8>> {
        let payload = serde_json::to_vec(digest).map_err(|e| {
            AttestationError::SigningError(format!("Failed to serialize digest: {}", e))
        })?;
        Ok(payload)
    }

    /// Parse Ed25519 public key from PEM string
    fn parse_public_key(pem_str: &str) -> Result<ed25519_dalek::VerifyingKey> {
        // Simple base64 decoding for now - in production would use proper PEM parsing
        let key_data = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
            .replace(['\n', ' '], "");

        let key_bytes = base64::decode(key_data).map_err(|e| {
            AttestationError::ConfigError(format!("Invalid public key format: {}", e))
        })?;

        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| {
            AttestationError::ConfigError("Public key must be 32 bytes".to_string())
        })?;

        ed25519_dalek::VerifyingKey::from_bytes(&key_array).map_err(|e| {
            AttestationError::ConfigError(format!("Invalid Ed25519 public key: {}", e))
        })
    }

    /// Parse Ed25519 private key from PEM string  
    fn parse_private_key(pem_str: &str) -> Result<ed25519_dalek::SigningKey> {
        // Simple base64 decoding for now - in production would use proper PEM parsing
        let key_data = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
            .replace(['\n', ' '], "");

        let key_bytes = base64::decode(key_data).map_err(|e| {
            AttestationError::ConfigError(format!("Invalid private key format: {}", e))
        })?;

        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| {
            AttestationError::ConfigError("Private key must be 32 bytes".to_string())
        })?;

        Ok(ed25519_dalek::SigningKey::from_bytes(&key_array))
    }
}

// Base64 encoding utility (using standard base64)
mod base64 {
    use base64::{engine::general_purpose, Engine as _};

    pub fn encode(input: impl AsRef<[u8]>) -> String {
        general_purpose::STANDARD.encode(input)
    }

    pub fn decode(input: impl AsRef<str>) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD.decode(input.as_ref().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_capability_signing_roundtrip() {
        let signer = CapabilitySigner::new().await.unwrap();
        let bundle_bytes = b"test capability bundle content";
        let version = "1.0.0".to_string();

        // Sign bundle
        let signature = signer
            .sign_capability_bundle(bundle_bytes, version)
            .await
            .unwrap();

        // Verify signature
        let is_valid = signer
            .verify_capability_bundle(bundle_bytes, &signature)
            .await
            .unwrap();
        assert!(is_valid);

        // Test with modified content (should fail)
        let modified_bytes = b"modified capability bundle content";
        let is_invalid = signer
            .verify_capability_bundle(modified_bytes, &signature)
            .await
            .unwrap();
        assert!(!is_invalid);
    }

    #[tokio::test]
    async fn test_capability_digest_determinism() {
        let signer = CapabilitySigner::new().await.unwrap();
        let bundle_bytes = b"test capability bundle content";
        let version = "1.0.0".to_string();

        // Generate digest twice
        let digest1 = signer.compute_capability_digest(bundle_bytes, version.clone());
        let digest2 = signer.compute_capability_digest(bundle_bytes, version);

        // Digests should be identical (excluding timestamp)
        assert_eq!(digest1.digest, digest2.digest);
        assert_eq!(digest1.content_hash, digest2.content_hash);
        assert_eq!(digest1.size, digest2.size);
    }
}
