//! Attestation Types Module
//!
//! Contains shared types and structures used across attestation modules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Runtime attestation results included in execution outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAttestationResults {
    /// Capability bundle digest verification
    pub capability_digest: String,
    /// Executor image digest (if available)
    pub executor_image_digest: Option<String>,
    /// Capability bundle signature verification result
    pub bundle_sig_ok: bool,
    /// SLSA provenance verification result
    pub provenance_ok: bool,
    /// Overall attestation verification status
    pub attestation_verified: bool,
    /// Timestamp of attestation verification
    pub verified_at: chrono::DateTime<chrono::Utc>,
    /// Verification details for audit trail
    pub verification_details: VerificationDetails,
}

/// Detailed verification information for audit purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    /// Individual check results
    pub checks: HashMap<String, bool>,
    /// Verification warnings (non-fatal issues)
    pub warnings: Vec<String>,
    /// Verification errors (fatal issues)
    pub errors: Vec<String>,
    /// Verification context metadata
    pub context: HashMap<String, String>,
}

impl RuntimeAttestationResults {
    /// Create new attestation results
    pub fn new(
        capability_digest: String,
        executor_image_digest: Option<String>,
        bundle_sig_ok: bool,
        provenance_ok: bool,
        attestation_verified: bool,
        verification_details: VerificationDetails,
    ) -> Self {
        Self {
            capability_digest,
            executor_image_digest,
            bundle_sig_ok,
            provenance_ok,
            attestation_verified,
            verified_at: chrono::Utc::now(),
            verification_details,
        }
    }

    /// Check if attestation is fully verified
    pub fn is_fully_verified(&self) -> bool {
        self.attestation_verified && self.bundle_sig_ok && self.provenance_ok
    }

    /// Get verification summary
    pub fn get_summary(&self) -> String {
        format!(
            "Attestation: {}, Signature: {}, Provenance: {}",
            if self.attestation_verified { "✓" } else { "✗" },
            if self.bundle_sig_ok { "✓" } else { "✗" },
            if self.provenance_ok { "✓" } else { "✗" }
        )
    }
}

impl VerificationDetails {
    /// Create new verification details
    pub fn new(
        checks: HashMap<String, bool>,
        warnings: Vec<String>,
        errors: Vec<String>,
        context: HashMap<String, String>,
    ) -> Self {
        Self {
            checks,
            warnings,
            errors,
            context,
        }
    }

    /// Create verification details from verification result
    pub fn from_verification_result(
        result: &smith_attestation::VerificationResult,
        context: HashMap<String, String>,
    ) -> Self {
        Self {
            checks: result.checks.clone(),
            warnings: result.warnings.clone(),
            errors: result.errors.clone(),
            context,
        }
    }

    /// Check if there are any errors
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Check if there are any warnings
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Get the number of passed checks
    pub fn passed_checks_count(&self) -> usize {
        self.checks.values().filter(|&&passed| passed).count()
    }

    /// Get the number of failed checks
    pub fn failed_checks_count(&self) -> usize {
        self.checks.values().filter(|&&passed| !passed).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_attestation_results_creation() {
        let details = VerificationDetails::new(
            HashMap::new(),
            vec!["Warning message".to_string()],
            vec![],
            HashMap::new(),
        );

        let results = RuntimeAttestationResults::new(
            "digest123".to_string(),
            Some("image_digest456".to_string()),
            true,
            true,
            true,
            details,
        );

        assert_eq!(results.capability_digest, "digest123");
        assert_eq!(results.executor_image_digest, Some("image_digest456".to_string()));
        assert!(results.bundle_sig_ok);
        assert!(results.provenance_ok);
        assert!(results.attestation_verified);
        assert!(results.is_fully_verified());
    }

    #[test]
    fn test_runtime_attestation_results_partial_failure() {
        let details = VerificationDetails::new(
            HashMap::new(),
            vec![],
            vec!["Signature failed".to_string()],
            HashMap::new(),
        );

        let results = RuntimeAttestationResults::new(
            "digest123".to_string(),
            None,
            false, // signature failed
            true,
            false, // overall failed
            details,
        );

        assert!(!results.is_fully_verified());
        assert!(results.get_summary().contains("✗"));
    }

    #[test]
    fn test_verification_details() {
        let mut checks = HashMap::new();
        checks.insert("signature_valid".to_string(), true);
        checks.insert("digest_valid".to_string(), false);

        let details = VerificationDetails::new(
            checks,
            vec!["Warning".to_string()],
            vec!["Error".to_string()],
            HashMap::new(),
        );

        assert!(details.has_warnings());
        assert!(details.has_errors());
        assert_eq!(details.passed_checks_count(), 1);
        assert_eq!(details.failed_checks_count(), 1);
    }
}