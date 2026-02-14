//! Signature types and utilities for Smith attestation system

use crate::{AttestationError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Generic signature wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Signature algorithm (e.g., "Ed25519", "ECDSA", "RSA")
    pub algorithm: String,

    /// Signature bytes (base64 encoded)
    pub signature: String,

    /// Public key used for signing (base64 encoded)
    pub public_key: String,

    /// Signature metadata
    pub metadata: SignatureMetadata,
}

/// Signature metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMetadata {
    /// Signature timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Signer identity
    pub signer: String,

    /// Signature purpose (e.g., "policy-bundle", "container-image")
    pub purpose: String,

    /// Additional metadata
    pub additional: HashMap<String, String>,
}

/// Signature verification result
#[derive(Debug, Clone)]
pub struct SignatureVerificationResult {
    /// Whether signature is valid
    pub is_valid: bool,

    /// Verification error (if any)
    pub error: Option<String>,

    /// Signature metadata
    pub metadata: SignatureMetadata,
}

impl Signature {
    /// Create new Ed25519 signature
    pub fn ed25519(
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
        metadata: SignatureMetadata,
    ) -> Self {
        Self {
            algorithm: "Ed25519".to_string(),
            signature: base64::encode(signature_bytes),
            public_key: base64::encode(public_key_bytes),
            metadata,
        }
    }

    /// Parse signature bytes
    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        base64::decode(&self.signature).map_err(|e| {
            AttestationError::InvalidSignature(format!("Invalid signature encoding: {}", e))
        })
    }

    /// Parse public key bytes
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        base64::decode(&self.public_key).map_err(|e| {
            AttestationError::InvalidSignature(format!("Invalid public key encoding: {}", e))
        })
    }

    /// Verify signature using Ed25519
    pub fn verify_ed25519(&self, message: &[u8]) -> Result<SignatureVerificationResult> {
        if self.algorithm != "Ed25519" {
            return Ok(SignatureVerificationResult {
                is_valid: false,
                error: Some(format!("Expected Ed25519, got {}", self.algorithm)),
                metadata: self.metadata.clone(),
            });
        }

        // Parse signature
        let signature_bytes = self.signature_bytes()?;
        let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            AttestationError::InvalidSignature(
                "Ed25519 signature must be exactly 64 bytes".to_string(),
            )
        })?;
        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&signature_array);

        // Parse public key
        let public_key_bytes = self.public_key_bytes()?;
        let key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
            AttestationError::InvalidSignature("Ed25519 public key must be 32 bytes".to_string())
        })?;

        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_array).map_err(|e| {
            AttestationError::InvalidSignature(format!("Invalid Ed25519 public key: {}", e))
        })?;

        // Verify signature
        match public_key.verify_strict(message, &ed25519_signature) {
            Ok(()) => Ok(SignatureVerificationResult {
                is_valid: true,
                error: None,
                metadata: self.metadata.clone(),
            }),
            Err(e) => Ok(SignatureVerificationResult {
                is_valid: false,
                error: Some(format!("Ed25519 verification failed: {}", e)),
                metadata: self.metadata.clone(),
            }),
        }
    }
}

impl SignatureMetadata {
    /// Create new signature metadata
    pub fn new(signer: String, purpose: String) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            signer,
            purpose,
            additional: HashMap::new(),
        }
    }

    /// Add additional metadata field
    pub fn with_additional(mut self, key: String, value: String) -> Self {
        self.additional.insert(key, value);
        self
    }
}

impl SignatureVerificationResult {
    /// Create successful verification result
    pub fn success(metadata: SignatureMetadata) -> Self {
        Self {
            is_valid: true,
            error: None,
            metadata,
        }
    }

    /// Create failed verification result
    pub fn failure(error: String, metadata: SignatureMetadata) -> Self {
        Self {
            is_valid: false,
            error: Some(error),
            metadata,
        }
    }
}

// Base64 encoding utility
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
    use rand_core::OsRng;

    #[test]
    fn test_ed25519_signature_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};

        // Generate key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create message and sign it
        let message = b"test message for signing";
        let signature = signing_key.sign(message);

        // Create signature wrapper
        let metadata =
            SignatureMetadata::new("test-signer".to_string(), "test-purpose".to_string());

        let signature_wrapper =
            Signature::ed25519(&signature.to_bytes(), &verifying_key.to_bytes(), metadata);

        // Verify signature
        let result = signature_wrapper.verify_ed25519(message).unwrap();
        assert!(result.is_valid);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_signature_metadata_serialization() {
        let metadata =
            SignatureMetadata::new("test-signer".to_string(), "policy-bundle".to_string())
                .with_additional("version".to_string(), "1.0.0".to_string());

        // Test serialization
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: SignatureMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata.signer, deserialized.signer);
        assert_eq!(metadata.purpose, deserialized.purpose);
        assert_eq!(
            metadata.additional.get("version"),
            deserialized.additional.get("version")
        );
    }
}
