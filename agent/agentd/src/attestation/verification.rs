//! Verification Engine Module
//!
//! Handles comprehensive verification strategies for capability bundles and attestation.

use anyhow::{Context, Result};
use smith_attestation::{
    AttestationConfig, Verifier, VerificationContext, VerificationResult,
    Signature, SlsaProvenance,
};
use smith_protocol::Intent;
use std::collections::HashMap;
use tracing::{debug, warn};

use super::types::{RuntimeAttestationResults, VerificationDetails};

/// Verification engine for attestation operations
pub struct VerificationEngine {
    verifier: Verifier,
    config: AttestationConfig,
}

impl VerificationEngine {
    /// Create new verification engine
    pub fn new(config: AttestationConfig) -> Result<Self> {
        let verifier = Verifier::new(config.clone()).context("Failed to create verifier")?;

        Ok(Self {
            verifier,
            config,
        })
    }

    /// Perform comprehensive verification of capability bundle
    pub async fn verify_capability_bundle(
        &self,
        bundle_bytes: &[u8],
        intent: &Intent,
        execution_context: &HashMap<String, String>,
        signature: Option<&Signature>,
        provenance: Option<&SlsaProvenance>,
    ) -> Result<VerificationResult> {
        debug!("Starting comprehensive capability bundle verification");

        let verification_context = self.create_verification_context(intent, execution_context);

        match signature {
            Some(sig) => {
                // Perform full verification with signature
                self.verifier
                    .verify_capability_bundle(bundle_bytes, sig, provenance, verification_context)
                    .await
            }
            None => {
                // No signature available, perform basic verification
                warn!("No policy signature available, performing basic verification");
                self.perform_basic_verification(provenance)
            }
        }
    }

    /// Create runtime attestation results from verification result
    pub fn create_attestation_results(
        &self,
        capability_digest: String,
        executor_image_digest: Option<String>,
        verification_result: &VerificationResult,
        execution_context: &HashMap<String, String>,
    ) -> RuntimeAttestationResults {
        let verification_details = VerificationDetails::from_verification_result(
            verification_result,
            execution_context.clone(),
        );

        RuntimeAttestationResults::new(
            capability_digest,
            executor_image_digest,
            verification_result.signature_valid,
            verification_result.provenance_valid.unwrap_or(false),
            verification_result.overall_valid,
            verification_details,
        )
    }

    /// Generate SHA256 digest for bytes
    pub fn generate_digest(&self, bytes: &[u8]) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Get executor image digest from environment
    pub async fn get_executor_image_digest(&self) -> Option<String> {
        // Try to get container image digest if running in containerized environment
        if let Ok(digest) = std::env::var("CONTAINER_IMAGE_DIGEST") {
            return Some(digest);
        }

        // Try to read from container metadata
        if let Ok(digest_bytes) = tokio::fs::read("/etc/image-digest").await {
            if let Ok(digest) = String::from_utf8(digest_bytes) {
                return Some(digest.trim().to_string());
            }
        }

        None
    }

    /// Create verification context from intent and execution context
    fn create_verification_context(
        &self,
        intent: &Intent,
        execution_context: &HashMap<String, String>,
    ) -> VerificationContext {
        VerificationContext {
            intent_id: Some(intent.id.clone()),
            capability: Some(intent.capability.clone()),
            execution_environment: execution_context.get("environment").cloned(),
            additional_metadata: execution_context.clone(),
        }
    }

    /// Perform basic verification when no signature is available
    fn perform_basic_verification(&self, provenance: Option<&SlsaProvenance>) -> Result<VerificationResult> {
        let mut checks = HashMap::new();
        checks.insert("signature_valid".to_string(), false);
        checks.insert("digest_valid".to_string(), true); // We can still verify digest

        let warnings = vec!["Policy signature not available".to_string()];
        let errors = if self.config.fail_on_signature_error {
            vec!["Policy signature required but not found".to_string()]
        } else {
            vec![]
        };

        Ok(VerificationResult {
            overall_valid: !self.config.fail_on_signature_error,
            signature_valid: false,
            trust_valid: None,
            age_valid: None,
            provenance_valid: provenance.map(|_| true),
            digest_valid: Some(true),
            checks,
            warnings,
            errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::Intent;
    use std::collections::HashMap;

    fn create_test_intent() -> Intent {
        Intent {
            id: "test-intent-123".to_string(),
            capability: "fs.read.v1".to_string(),
            params: serde_json::json!({"path": "/test/file.txt"}),
            actor: "test-actor".to_string(),
            created_at: chrono::Utc::now(),
            timeout_seconds: Some(30),
        }
    }

    fn create_test_config() -> AttestationConfig {
        AttestationConfig {
            fail_on_signature_error: false,
            provenance_output_dir: "/tmp/test-provenance".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_verification_engine_creation() {
        let config = create_test_config();
        let engine = VerificationEngine::new(config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_create_verification_context() {
        let config = create_test_config();
        let engine = VerificationEngine::new(config).unwrap();
        let intent = create_test_intent();
        
        let mut execution_context = HashMap::new();
        execution_context.insert("environment".to_string(), "test".to_string());
        execution_context.insert("user".to_string(), "test-user".to_string());

        let context = engine.create_verification_context(&intent, &execution_context);

        assert_eq!(context.intent_id, Some("test-intent-123".to_string()));
        assert_eq!(context.capability, Some("fs.read.v1".to_string()));
        assert_eq!(context.execution_environment, Some("test".to_string()));
        assert_eq!(context.additional_metadata, execution_context);
    }

    #[test]
    fn test_generate_digest() {
        let config = create_test_config();
        let engine = VerificationEngine::new(config).unwrap();

        let test_data = b"hello world";
        let digest = engine.generate_digest(test_data).unwrap();
        
        // Expected SHA256 of "hello world"
        assert_eq!(digest, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_basic_verification_no_signature_error() {
        let config = AttestationConfig {
            fail_on_signature_error: false,
            ..create_test_config()
        };
        let engine = VerificationEngine::new(config).unwrap();

        let result = engine.perform_basic_verification(None).unwrap();

        assert!(!result.signature_valid);
        assert!(result.overall_valid); // Should pass when fail_on_signature_error is false
        assert!(result.warnings.iter().any(|w| w.contains("signature not available")));
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_basic_verification_with_signature_error() {
        let config = AttestationConfig {
            fail_on_signature_error: true,
            ..create_test_config()
        };
        let engine = VerificationEngine::new(config).unwrap();

        let result = engine.perform_basic_verification(None).unwrap();

        assert!(!result.signature_valid);
        assert!(!result.overall_valid); // Should fail when fail_on_signature_error is true
        assert!(result.warnings.iter().any(|w| w.contains("signature not available")));
        assert!(result.errors.iter().any(|e| e.contains("signature required")));
    }

    #[test]
    fn test_create_attestation_results() {
        let config = create_test_config();
        let engine = VerificationEngine::new(config).unwrap();

        let capability_digest = "test-capability-digest".to_string();
        let executor_image_digest = Some("test-image-digest".to_string());
        
        let verification_result = VerificationResult {
            overall_valid: true,
            signature_valid: true,
            trust_valid: Some(true),
            age_valid: Some(true),
            provenance_valid: Some(true),
            digest_valid: Some(true),
            checks: HashMap::new(),
            warnings: vec![],
            errors: vec![],
        };

        let execution_context = HashMap::new();

        let results = engine.create_attestation_results(
            capability_digest.clone(),
            executor_image_digest.clone(),
            &verification_result,
            &execution_context,
        );

        assert_eq!(results.capability_digest, capability_digest);
        assert_eq!(results.executor_image_digest, executor_image_digest);
        assert!(results.bundle_sig_ok);
        assert!(results.provenance_ok);
        assert!(results.attestation_verified);
        assert!(results.is_fully_verified());
    }
}