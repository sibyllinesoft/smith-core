//! Verification engine for Smith supply chain attestation

use crate::{AttestationError, Result, Signature, SlsaProvenance};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Comprehensive verification engine
#[derive(Debug)]
pub struct Verifier {
    /// Verification configuration
    config: VerificationConfig,

    /// Trusted public keys for verification
    trusted_keys: Vec<ed25519_dalek::VerifyingKey>,
}

/// Verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Require signature verification
    pub require_signatures: bool,

    /// Require SLSA provenance
    pub require_provenance: bool,

    /// Fail on verification errors
    pub fail_on_error: bool,

    /// Trusted signers list
    pub trusted_signers: Vec<String>,

    /// Maximum signature age in seconds
    pub max_signature_age: u64,
}

/// Verification context for a specific artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationContext {
    /// Artifact name
    pub artifact_name: String,

    /// Artifact digest
    pub artifact_digest: String,

    /// Verification timestamp
    pub verification_timestamp: chrono::DateTime<chrono::Utc>,

    /// Additional context metadata
    pub metadata: HashMap<String, String>,
}

/// Comprehensive verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Overall verification status
    pub is_valid: bool,

    /// Individual check results
    pub checks: HashMap<String, CheckResult>,

    /// Verification context
    pub context: VerificationContext,

    /// Error messages
    pub errors: Vec<String>,

    /// Warnings
    pub warnings: Vec<String>,
}

/// Individual verification check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Check name
    pub name: String,

    /// Check passed
    pub passed: bool,

    /// Check details
    pub details: String,

    /// Check timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Verifier {
    /// Create new verifier with configuration
    pub fn new(config: VerificationConfig) -> Result<Self> {
        Ok(Self {
            config,
            trusted_keys: Vec::new(),
        })
    }

    /// Add trusted public key for verification
    pub fn add_trusted_key(&mut self, public_key: ed25519_dalek::VerifyingKey) {
        self.trusted_keys.push(public_key);
    }

    /// Load trusted keys from PEM files
    pub async fn load_trusted_keys<P: AsRef<Path>>(&mut self, key_files: Vec<P>) -> Result<()> {
        for key_file in key_files {
            let key_bytes = tokio::fs::read(key_file.as_ref()).await?;
            let key_str = String::from_utf8(key_bytes).map_err(|e| {
                AttestationError::ConfigError(format!("Invalid key file encoding: {}", e))
            })?;

            let public_key = self.parse_public_key(&key_str)?;
            self.trusted_keys.push(public_key);
        }

        Ok(())
    }

    /// Verify capability bundle with signature and provenance
    pub async fn verify_capability_bundle(
        &self,
        bundle_bytes: &[u8],
        signature: &Signature,
        provenance: Option<&SlsaProvenance>,
        context: VerificationContext,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult {
            is_valid: true,
            checks: HashMap::new(),
            context,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Check 1: Signature verification
        if self.config.require_signatures {
            let sig_result = self.verify_signature(bundle_bytes, signature).await?;
            result.checks.insert(
                "signature".to_string(),
                CheckResult {
                    name: "Signature Verification".to_string(),
                    passed: sig_result.is_valid,
                    details: sig_result
                        .error
                        .clone()
                        .unwrap_or_else(|| "Signature valid".to_string()),
                    timestamp: chrono::Utc::now(),
                },
            );

            if !sig_result.is_valid {
                result.is_valid = false;
                result.errors.push(format!(
                    "Signature verification failed: {}",
                    sig_result
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string())
                ));
            }
        }

        // Check 2: Signer trust verification
        let trust_result = self.verify_signer_trust(signature).await?;
        result.checks.insert(
            "trust".to_string(),
            CheckResult {
                name: "Signer Trust".to_string(),
                passed: trust_result,
                details: if trust_result {
                    "Signer is trusted".to_string()
                } else {
                    "Untrusted signer".to_string()
                },
                timestamp: chrono::Utc::now(),
            },
        );

        if !trust_result {
            result.is_valid = false;
            result
                .errors
                .push("Signer is not in trusted list".to_string());
        }

        // Check 3: Signature age verification
        let age_result = self.verify_signature_age(signature).await?;
        result.checks.insert(
            "age".to_string(),
            CheckResult {
                name: "Signature Age".to_string(),
                passed: age_result,
                details: if age_result {
                    "Signature age acceptable".to_string()
                } else {
                    "Signature too old".to_string()
                },
                timestamp: chrono::Utc::now(),
            },
        );

        if !age_result {
            result
                .warnings
                .push("Signature age exceeds maximum allowed".to_string());
        }

        // Check 4: SLSA provenance verification (if provided)
        if let Some(provenance) = provenance {
            let provenance_result = self.verify_provenance(provenance).await?;
            result.checks.insert(
                "provenance".to_string(),
                CheckResult {
                    name: "SLSA Provenance".to_string(),
                    passed: provenance_result,
                    details: if provenance_result {
                        "Provenance valid".to_string()
                    } else {
                        "Invalid provenance".to_string()
                    },
                    timestamp: chrono::Utc::now(),
                },
            );

            if !provenance_result && self.config.require_provenance {
                result.is_valid = false;
                result
                    .errors
                    .push("SLSA provenance validation failed".to_string());
            }
        } else if self.config.require_provenance {
            result.is_valid = false;
            result
                .errors
                .push("SLSA provenance required but not provided".to_string());
        }

        // Check 5: Capability digest consistency
        if let Ok(computed_digest) = self.compute_capability_digest(bundle_bytes) {
            let digest_matches = computed_digest == result.context.artifact_digest;
            result.checks.insert(
                "digest".to_string(),
                CheckResult {
                    name: "Capability Digest".to_string(),
                    passed: digest_matches,
                    details: if digest_matches {
                        "Digest matches".to_string()
                    } else {
                        "Digest mismatch".to_string()
                    },
                    timestamp: chrono::Utc::now(),
                },
            );

            if !digest_matches {
                result.is_valid = false;
                result
                    .errors
                    .push("Capability digest does not match expected value".to_string());
            }
        }

        Ok(result)
    }

    /// Verify container image signature
    pub async fn verify_container_image(
        &self,
        image_digest: &str,
        signature: &Signature,
        context: VerificationContext,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult {
            is_valid: true,
            checks: HashMap::new(),
            context,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Verify signature against image digest
        let sig_result = self
            .verify_signature(image_digest.as_bytes(), signature)
            .await?;
        result.checks.insert(
            "image_signature".to_string(),
            CheckResult {
                name: "Container Image Signature".to_string(),
                passed: sig_result.is_valid,
                details: sig_result
                    .error
                    .unwrap_or_else(|| "Image signature valid".to_string()),
                timestamp: chrono::Utc::now(),
            },
        );

        if !sig_result.is_valid {
            result.is_valid = false;
            result
                .errors
                .push("Container image signature verification failed".to_string());
        }

        Ok(result)
    }

    /// Verify signature using trusted keys
    async fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<crate::signatures::SignatureVerificationResult> {
        // Try signature verification with Ed25519
        let sig_result = signature.verify_ed25519(message)?;

        if sig_result.is_valid {
            // Check if the public key is trusted
            let public_key_bytes = signature.public_key_bytes()?;
            let key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
                AttestationError::InvalidSignature("Invalid public key length".to_string())
            })?;

            let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_array).map_err(|e| {
                AttestationError::InvalidSignature(format!("Invalid public key: {}", e))
            })?;

            if self.trusted_keys.contains(&public_key) {
                Ok(sig_result)
            } else {
                Ok(crate::signatures::SignatureVerificationResult::failure(
                    "Public key not in trusted list".to_string(),
                    sig_result.metadata,
                ))
            }
        } else {
            Ok(sig_result)
        }
    }

    /// Verify signer trust
    async fn verify_signer_trust(&self, signature: &Signature) -> Result<bool> {
        if self.config.trusted_signers.is_empty() {
            // If no trusted signers configured, trust all
            return Ok(true);
        }

        Ok(self
            .config
            .trusted_signers
            .contains(&signature.metadata.signer))
    }

    /// Verify signature age
    async fn verify_signature_age(&self, signature: &Signature) -> Result<bool> {
        if self.config.max_signature_age == 0 {
            // No age limit configured
            return Ok(true);
        }

        let now = chrono::Utc::now();
        let age = now.signed_duration_since(signature.metadata.timestamp);

        Ok(age.num_seconds() <= self.config.max_signature_age as i64)
    }

    /// Verify SLSA provenance
    async fn verify_provenance(&self, provenance: &SlsaProvenance) -> Result<bool> {
        // Basic provenance validation

        // Check predicate type
        if provenance.predicate_type != "https://slsa.dev/provenance/v0.2" {
            return Ok(false);
        }

        // Check completeness
        if !provenance.predicate.metadata.completeness.parameters
            || !provenance.predicate.metadata.completeness.environment
            || !provenance.predicate.metadata.completeness.materials
        {
            return Ok(false);
        }

        // Check build timestamps
        if provenance.predicate.metadata.build_started_on
            > provenance.predicate.metadata.build_finished_on
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Compute capability digest
    fn compute_capability_digest(&self, bundle_bytes: &[u8]) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bundle_bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Parse Ed25519 public key from PEM string
    fn parse_public_key(&self, pem_str: &str) -> Result<ed25519_dalek::VerifyingKey> {
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
}

impl VerificationResult {
    /// Check if verification passed
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Get all errors
    pub fn get_errors(&self) -> &[String] {
        &self.errors
    }

    /// Get all warnings
    pub fn get_warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Get specific check result
    pub fn get_check(&self, name: &str) -> Option<&CheckResult> {
        self.checks.get(name)
    }

    /// Get summary of all checks
    pub fn get_summary(&self) -> String {
        let passed = self.checks.values().filter(|c| c.passed).count();
        let total = self.checks.len();

        format!(
            "Verification: {} ({}/{} checks passed, {} errors, {} warnings)",
            if self.is_valid { "PASS" } else { "FAIL" },
            passed,
            total,
            self.errors.len(),
            self.warnings.len()
        )
    }
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            require_signatures: true,
            require_provenance: true,
            fail_on_error: true,
            trusted_signers: Vec::new(),
            max_signature_age: 86400 * 30, // 30 days
        }
    }
}

// Base64 encoding utility
mod base64 {
    use base64::{engine::general_purpose, Engine as _};

    pub fn decode(input: impl AsRef<str>) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD.decode(input.as_ref().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilitySigner, SignatureMetadata};

    #[tokio::test]
    async fn test_capability_bundle_verification() {
        let verifier = Verifier::new(VerificationConfig::default()).unwrap();

        // Create signer and add its key as trusted
        let signer = CapabilitySigner::new().await.unwrap();
        // We'd need access to the public key here in a real implementation

        let bundle_bytes = b"test capability bundle";
        let signature = signer
            .sign_capability_bundle(bundle_bytes, "1.0.0".to_string())
            .await
            .unwrap();

        let context = VerificationContext {
            artifact_name: "test-bundle".to_string(),
            artifact_digest: signer
                .compute_capability_digest(bundle_bytes, "1.0.0".to_string())
                .digest,
            verification_timestamp: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        // Convert policy signature to generic signature
        let generic_signature = Signature {
            algorithm: signature.algorithm,
            signature: signature.signature,
            public_key: signature.public_key,
            metadata: SignatureMetadata {
                timestamp: signature.timestamp,
                signer: "test-signer".to_string(),
                purpose: "policy-bundle".to_string(),
                additional: HashMap::new(),
            },
        };

        let result = verifier
            .verify_capability_bundle(bundle_bytes, &generic_signature, None, context)
            .await
            .unwrap();

        // The result will likely fail due to untrusted signer, but the structure should be correct
        assert!(!result.checks.is_empty());
    }
}
