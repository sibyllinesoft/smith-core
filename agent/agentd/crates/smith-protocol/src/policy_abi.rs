//! Policy ABI Version Management for Smith Platform
//!
//! This module provides versioning and compatibility checking for capability bundles,
//! ensuring deterministic startup failures when ABI mismatches occur.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Current supported Policy ABI version
/// This must be incremented when capability bundle schema changes in breaking ways
pub const CURRENT_POLICY_ABI_VERSION: u32 = 1;

/// Policy ABI version information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyAbiVersion {
    /// Major version - incompatible changes
    pub major: u32,
    /// Minor version - backward compatible additions
    pub minor: u32,
    /// Patch version - bug fixes and clarifications
    pub patch: u32,
}

impl PolicyAbiVersion {
    /// Create a new PolicyAbiVersion
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Get the current supported ABI version
    pub fn current() -> Self {
        Self::new(CURRENT_POLICY_ABI_VERSION, 0, 0)
    }

    /// Check if this version is compatible with the current ABI
    pub fn is_compatible(&self) -> bool {
        self.major == CURRENT_POLICY_ABI_VERSION
    }

    /// Check if this version is exactly the current version
    pub fn is_current(&self) -> bool {
        *self == Self::current()
    }

    /// Convert to version string for display
    pub fn to_version_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// Parse from version string (e.g., "1.0.0")
    pub fn from_version_string(version: &str) -> Result<Self, PolicyAbiError> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err(PolicyAbiError::InvalidVersionFormat(version.to_string()));
        }

        let major = parts[0]
            .parse::<u32>()
            .map_err(|_| PolicyAbiError::InvalidVersionFormat(version.to_string()))?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|_| PolicyAbiError::InvalidVersionFormat(version.to_string()))?;
        let patch = parts[2]
            .parse::<u32>()
            .map_err(|_| PolicyAbiError::InvalidVersionFormat(version.to_string()))?;

        Ok(Self::new(major, minor, patch))
    }
}

impl fmt::Display for PolicyAbiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_version_string())
    }
}

/// Capability bundle header with ABI version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityBundleHeader {
    /// ABI version of this bundle
    pub abi_version: PolicyAbiVersion,
    /// Bundle format version (separate from ABI)
    pub bundle_version: String,
    /// Bundle creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// SHA256 digest of bundle content (excluding header)
    pub content_digest: String,
    /// Bundle metadata
    pub metadata: CapabilityBundleMetadata,
}

/// Metadata about the capability bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityBundleMetadata {
    /// Human-readable bundle name
    pub name: String,
    /// Bundle description
    pub description: Option<String>,
    /// Organization that created this bundle
    pub organization: Option<String>,
    /// Git commit hash when bundle was created
    pub git_commit: Option<String>,
    /// Build environment information
    pub build_info: Option<String>,
}

/// Policy ABI validation errors
#[derive(Debug, Error)]
pub enum PolicyAbiError {
    #[error(
        "Incompatible Policy ABI version: bundle={bundle_version}, supported={supported_version}"
    )]
    IncompatibleVersion {
        bundle_version: PolicyAbiVersion,
        supported_version: PolicyAbiVersion,
    },

    #[error("Invalid version format: {0}")]
    InvalidVersionFormat(String),

    #[error("Missing ABI version in capability bundle")]
    MissingAbiVersion,

    #[error("Capability bundle validation failed: {0}")]
    ValidationFailed(String),

    #[error("Capability bundle deserialization failed: {0}")]
    DeserializationFailed(String),
}

/// Policy ABI validator for startup checks
pub struct PolicyAbiValidator;

impl PolicyAbiValidator {
    /// Validate capability bundle ABI version on startup
    ///
    /// This function MUST be called during admission controller startup.
    /// It will return an error if the bundle ABI version is incompatible,
    /// causing deterministic startup failure.
    pub fn validate_startup_compatibility(
        bundle_json: &str,
    ) -> Result<CapabilityBundleHeader, PolicyAbiError> {
        // Parse just the header to check ABI version
        let bundle_value: serde_json::Value = serde_json::from_str(bundle_json)
            .map_err(|e| PolicyAbiError::DeserializationFailed(e.to_string()))?;

        // Extract ABI version from bundle
        let abi_version = Self::extract_abi_version(&bundle_value)?;

        // Check compatibility
        if !abi_version.is_compatible() {
            return Err(PolicyAbiError::IncompatibleVersion {
                bundle_version: abi_version.clone(),
                supported_version: PolicyAbiVersion::current(),
            });
        }

        // Parse full header if ABI is compatible
        let header: CapabilityBundleHeader = serde_json::from_value(
            bundle_value
                .get("header")
                .ok_or(PolicyAbiError::MissingAbiVersion)?
                .clone(),
        )
        .map_err(|e| PolicyAbiError::DeserializationFailed(e.to_string()))?;

        Ok(header)
    }

    /// Extract ABI version from bundle JSON
    fn extract_abi_version(
        bundle_value: &serde_json::Value,
    ) -> Result<PolicyAbiVersion, PolicyAbiError> {
        let header = bundle_value
            .get("header")
            .ok_or(PolicyAbiError::MissingAbiVersion)?;

        let abi_version: PolicyAbiVersion = serde_json::from_value(
            header
                .get("abi_version")
                .ok_or(PolicyAbiError::MissingAbiVersion)?
                .clone(),
        )
        .map_err(|e| PolicyAbiError::DeserializationFailed(e.to_string()))?;

        Ok(abi_version)
    }

    /// Generate ABI change detection hash for CI validation
    ///
    /// This hash should be stored in CI and compared against new builds
    /// to detect breaking ABI changes.
    pub fn generate_abi_hash() -> String {
        use sha2::{Digest, Sha256};

        // Create deterministic representation of current ABI
        let abi_repr = format!(
            "POLICY_ABI_V{}_CURRENT_VERSION_{}_FIELDS_{}",
            CURRENT_POLICY_ABI_VERSION,
            PolicyAbiVersion::current().to_version_string(),
            "header,abi_version,bundle_version,created_at,content_digest,metadata"
        );

        let mut hasher = Sha256::new();
        hasher.update(abi_repr.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Validate that a capability bundle schema hasn't changed in breaking ways
    pub fn validate_abi_stability(old_hash: &str, new_hash: &str) -> Result<(), PolicyAbiError> {
        if old_hash != new_hash {
            return Err(PolicyAbiError::ValidationFailed(format!(
                "ABI hash mismatch: expected {} but got {}. This indicates a breaking change to the Policy ABI.",
                old_hash, new_hash
            )));
        }
        Ok(())
    }
}

/// Helper trait for capability bundle validation
pub trait CapabilityBundleValidation {
    /// Validate ABI compatibility during bundle loading
    fn validate_abi_compatibility(&self) -> Result<(), PolicyAbiError>;
}

// Implementation for any type that can provide capability bundle JSON
impl CapabilityBundleValidation for String {
    fn validate_abi_compatibility(&self) -> Result<(), PolicyAbiError> {
        PolicyAbiValidator::validate_startup_compatibility(self)?;
        Ok(())
    }
}

impl CapabilityBundleValidation for &str {
    fn validate_abi_compatibility(&self) -> Result<(), PolicyAbiError> {
        PolicyAbiValidator::validate_startup_compatibility(self)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_policy_abi_version_creation() {
        let version = PolicyAbiVersion::new(1, 2, 3);
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
        assert_eq!(version.to_version_string(), "1.2.3");
    }

    #[test]
    fn test_current_version() {
        let current = PolicyAbiVersion::current();
        assert_eq!(current.major, CURRENT_POLICY_ABI_VERSION);
        assert_eq!(current.minor, 0);
        assert_eq!(current.patch, 0);
    }

    #[test]
    fn test_version_compatibility() {
        let current = PolicyAbiVersion::current();
        assert!(current.is_compatible());
        assert!(current.is_current());

        let incompatible = PolicyAbiVersion::new(CURRENT_POLICY_ABI_VERSION + 1, 0, 0);
        assert!(!incompatible.is_compatible());
        assert!(!incompatible.is_current());

        let older_compatible = PolicyAbiVersion::new(CURRENT_POLICY_ABI_VERSION, 1, 5);
        assert!(older_compatible.is_compatible());
        assert!(!older_compatible.is_current());
    }

    #[test]
    fn test_version_string_parsing() {
        let version = PolicyAbiVersion::from_version_string("2.1.5").unwrap();
        assert_eq!(version.major, 2);
        assert_eq!(version.minor, 1);
        assert_eq!(version.patch, 5);

        // Test invalid formats
        assert!(PolicyAbiVersion::from_version_string("1.2").is_err());
        assert!(PolicyAbiVersion::from_version_string("invalid").is_err());
        assert!(PolicyAbiVersion::from_version_string("1.x.3").is_err());
    }

    #[test]
    fn test_compatible_bundle_validation() {
        let current_version = PolicyAbiVersion::current();
        let bundle_json = json!({
            "header": {
                "abi_version": current_version,
                "bundle_version": "1.0.0",
                "created_at": "2024-01-01T00:00:00Z",
                "content_digest": "abc123",
                "metadata": {
                    "name": "test-bundle",
                    "description": "Test capability bundle",
                    "organization": "Smith Team",
                    "git_commit": "abc123",
                    "build_info": "test-build"
                }
            },
            "atoms": {},
            "macros": {},
            "playbooks": {}
        })
        .to_string();

        let result = PolicyAbiValidator::validate_startup_compatibility(&bundle_json);
        assert!(result.is_ok());

        let header = result.unwrap();
        assert_eq!(header.abi_version, current_version);
        assert_eq!(header.metadata.name, "test-bundle");
    }

    #[test]
    fn test_incompatible_bundle_validation() {
        let incompatible_version = PolicyAbiVersion::new(CURRENT_POLICY_ABI_VERSION + 1, 0, 0);
        let bundle_json = json!({
            "header": {
                "abi_version": incompatible_version,
                "bundle_version": "2.0.0",
                "created_at": "2024-01-01T00:00:00Z",
                "content_digest": "def456",
                "metadata": {
                    "name": "future-bundle"
                }
            }
        })
        .to_string();

        let result = PolicyAbiValidator::validate_startup_compatibility(&bundle_json);
        assert!(result.is_err());

        match result.unwrap_err() {
            PolicyAbiError::IncompatibleVersion {
                bundle_version,
                supported_version,
            } => {
                assert_eq!(bundle_version, incompatible_version);
                assert_eq!(supported_version, PolicyAbiVersion::current());
            }
            _ => panic!("Expected IncompatibleVersion error"),
        }
    }

    #[test]
    fn test_missing_abi_version() {
        let bundle_json = json!({
            "header": {
                "bundle_version": "1.0.0"
                // Missing abi_version
            }
        })
        .to_string();

        let result = PolicyAbiValidator::validate_startup_compatibility(&bundle_json);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyAbiError::MissingAbiVersion
        ));
    }

    #[test]
    fn test_abi_hash_generation() {
        let hash1 = PolicyAbiValidator::generate_abi_hash();
        let hash2 = PolicyAbiValidator::generate_abi_hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);

        // Hash should be valid SHA256 (64 hex chars)
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_abi_stability_validation() {
        let hash = "abc123def456";

        // Same hash should validate
        assert!(PolicyAbiValidator::validate_abi_stability(hash, hash).is_ok());

        // Different hash should fail
        let result = PolicyAbiValidator::validate_abi_stability(hash, "different");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyAbiError::ValidationFailed(_)
        ));
    }

    #[test]
    fn test_bundle_validation_trait() {
        let current_version = PolicyAbiVersion::current();
        let bundle_json = json!({
            "header": {
                "abi_version": current_version,
                "bundle_version": "1.0.0",
                "created_at": "2024-01-01T00:00:00Z",
                "content_digest": "test123",
                "metadata": {
                    "name": "trait-test-bundle"
                }
            }
        })
        .to_string();

        // Test trait implementation
        assert!(bundle_json.validate_abi_compatibility().is_ok());
        assert!(bundle_json.as_str().validate_abi_compatibility().is_ok());
    }

    #[test]
    fn test_capability_bundle_header_serialization() {
        let header = CapabilityBundleHeader {
            abi_version: PolicyAbiVersion::current(),
            bundle_version: "1.0.0".to_string(),
            created_at: chrono::Utc::now(),
            content_digest: "test-digest".to_string(),
            metadata: CapabilityBundleMetadata {
                name: "test-bundle".to_string(),
                description: Some("Test description".to_string()),
                organization: Some("Smith Team".to_string()),
                git_commit: Some("abc123".to_string()),
                build_info: Some("test-build".to_string()),
            },
        };

        // Test serialization roundtrip
        let json = serde_json::to_string(&header).unwrap();
        let deserialized: CapabilityBundleHeader = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.abi_version, header.abi_version);
        assert_eq!(deserialized.bundle_version, header.bundle_version);
        assert_eq!(deserialized.metadata.name, header.metadata.name);
    }
}
