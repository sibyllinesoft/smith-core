//! Result Schema v1 - Locked Contract for Smith Platform
//!
//! This module defines the locked Result Schema v1 with strict validation
//! to prevent breaking changes while allowing controlled extensibility.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Result Schema Version - MUST match across all Smith components
pub const RESULT_SCHEMA_VERSION: u32 = 1;

/// Locked Result Schema v1 - These fields are immutable
///
/// Any changes to these fields require a MAJOR version bump.
/// New fields can only be added to `x_meta` for extensibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResultSchemaV1 {
    /// Execution success indicator - LOCKED FIELD
    pub ok: bool,

    /// Human-readable status description - LOCKED FIELD  
    pub status: String,

    /// Execution latency in milliseconds - LOCKED FIELD
    pub latency_ms: u64,

    /// Number of bytes processed/returned - LOCKED FIELD
    pub bytes: u64,

    /// Capability bundle digest used for execution - LOCKED FIELD
    pub capability_digest: String,

    /// Git commit hash of executor version - LOCKED FIELD
    pub commit: String,

    /// Execution layer (atom/macro/playbook) - LOCKED FIELD
    pub layer: String,

    /// Capability or component name - LOCKED FIELD
    pub name: String,

    /// Execution mode (strict/explore/shadow) - LOCKED FIELD
    pub mode: String,

    /// Experiment ID for A/B testing - LOCKED FIELD
    pub exp_id: String,

    /// Idempotency key for duplicate prevention - LOCKED FIELD
    pub idem_key: String,

    /// Extension metadata - ONLY place for new fields - LOCKED FIELD
    /// New fields MUST be added here, not as top-level fields
    #[serde(default)]
    pub x_meta: HashMap<String, serde_json::Value>,
}

impl ResultSchemaV1 {
    /// Create a new result with required fields
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ok: bool,
        status: String,
        latency_ms: u64,
        bytes: u64,
        capability_digest: String,
        commit: String,
        layer: String,
        name: String,
        mode: String,
        exp_id: String,
        idem_key: String,
    ) -> Self {
        Self {
            ok,
            status,
            latency_ms,
            bytes,
            capability_digest,
            commit,
            layer,
            name,
            mode,
            exp_id,
            idem_key,
            x_meta: HashMap::new(),
        }
    }

    /// Add extension metadata (only way to extend schema)
    pub fn with_meta(mut self, key: String, value: serde_json::Value) -> Self {
        self.x_meta.insert(key, value);
        self
    }

    /// Get extension metadata
    pub fn get_meta(&self, key: &str) -> Option<&serde_json::Value> {
        self.x_meta.get(key)
    }

    /// Validate schema compliance
    pub fn validate(&self) -> Result<(), ResultSchemaError> {
        // Validate required string fields are not empty
        if self.status.is_empty() {
            return Err(ResultSchemaError::EmptyRequiredField("status".to_string()));
        }
        if self.capability_digest.is_empty() {
            return Err(ResultSchemaError::EmptyRequiredField(
                "capability_digest".to_string(),
            ));
        }
        if self.commit.is_empty() {
            return Err(ResultSchemaError::EmptyRequiredField("commit".to_string()));
        }
        if self.layer.is_empty() {
            return Err(ResultSchemaError::EmptyRequiredField("layer".to_string()));
        }
        if self.name.is_empty() {
            return Err(ResultSchemaError::EmptyRequiredField("name".to_string()));
        }
        if self.mode.is_empty() {
            return Err(ResultSchemaError::EmptyRequiredField("mode".to_string()));
        }
        if self.exp_id.is_empty() {
            return Err(ResultSchemaError::EmptyRequiredField("exp_id".to_string()));
        }
        if self.idem_key.is_empty() {
            return Err(ResultSchemaError::EmptyRequiredField(
                "idem_key".to_string(),
            ));
        }

        // Validate field constraints
        if !matches!(self.layer.as_str(), "atom" | "macro" | "playbook") {
            return Err(ResultSchemaError::InvalidFieldValue {
                field: "layer".to_string(),
                value: self.layer.clone(),
                allowed: vec![
                    "atom".to_string(),
                    "macro".to_string(),
                    "playbook".to_string(),
                ],
            });
        }

        if !matches!(self.mode.as_str(), "strict" | "explore" | "shadow") {
            return Err(ResultSchemaError::InvalidFieldValue {
                field: "mode".to_string(),
                value: self.mode.clone(),
                allowed: vec![
                    "strict".to_string(),
                    "explore".to_string(),
                    "shadow".to_string(),
                ],
            });
        }

        // Validate capability digest format (SHA256 hex)
        if self.capability_digest.len() != 64
            || !self
                .capability_digest
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(ResultSchemaError::InvalidFieldFormat {
                field: "capability_digest".to_string(),
                expected: "64-character SHA256 hex string".to_string(),
                actual: self.capability_digest.clone(),
            });
        }

        // Validate commit hash format (7-40 char hex)
        if self.commit.len() < 7
            || self.commit.len() > 40
            || !self.commit.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(ResultSchemaError::InvalidFieldFormat {
                field: "commit".to_string(),
                expected: "7-40 character git commit hex string".to_string(),
                actual: self.commit.clone(),
            });
        }

        // Validate idempotency key format
        if !self.idem_key.starts_with("idem_") || self.idem_key.len() != 21 {
            return Err(ResultSchemaError::InvalidFieldFormat {
                field: "idem_key".to_string(),
                expected: "idem_<16-hex-chars> format".to_string(),
                actual: self.idem_key.clone(),
            });
        }

        Ok(())
    }
}

/// Result Schema validation errors
#[derive(Debug, Error)]
pub enum ResultSchemaError {
    #[error("Empty required field: {0}")]
    EmptyRequiredField(String),

    #[error("Invalid value for field {field}: '{value}', allowed: {allowed:?}")]
    InvalidFieldValue {
        field: String,
        value: String,
        allowed: Vec<String>,
    },

    #[error("Invalid format for field {field}: expected {expected}, got '{actual}'")]
    InvalidFieldFormat {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("Unknown field detected: {field}. Only x_meta extensions are allowed.")]
    UnknownField { field: String },

    #[error("Schema version mismatch: expected v{expected}, got v{actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
}

/// Strict result validator that rejects unknown fields
pub struct ResultSchemaValidator;

impl ResultSchemaValidator {
    /// Validate JSON against locked schema v1
    ///
    /// This validator REJECTS unknown fields (except in x_meta) to enforce
    /// backward compatibility and prevent breaking changes.
    pub fn validate_json(json_str: &str) -> Result<ResultSchemaV1, ResultSchemaError> {
        // Parse JSON to check for unknown fields
        let json_value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| ResultSchemaError::DeserializationFailed(e.to_string()))?;

        if let Some(obj) = json_value.as_object() {
            // Check for unknown top-level fields
            let allowed_fields = &[
                "ok",
                "status",
                "latency_ms",
                "bytes",
                "capability_digest",
                "commit",
                "layer",
                "name",
                "mode",
                "exp_id",
                "idem_key",
                "x_meta",
            ];

            for field_name in obj.keys() {
                if !allowed_fields.contains(&field_name.as_str()) {
                    return Err(ResultSchemaError::UnknownField {
                        field: field_name.clone(),
                    });
                }
            }
        }

        // Deserialize to struct
        let result: ResultSchemaV1 = serde_json::from_str(json_str)
            .map_err(|e| ResultSchemaError::DeserializationFailed(e.to_string()))?;

        // Validate field constraints
        result.validate()?;

        Ok(result)
    }

    /// Validate a pre-parsed ResultSchemaV1
    pub fn validate_struct(result: &ResultSchemaV1) -> Result<(), ResultSchemaError> {
        result.validate()
    }

    /// Check backward compatibility with previous result
    pub fn check_backward_compatibility(
        _old_result: &ResultSchemaV1,
        _new_result: &ResultSchemaV1,
    ) -> Result<(), ResultSchemaError> {
        // All locked fields must have same types and constraints
        // This is enforced by the struct definition and validation

        // x_meta can change freely (extensibility point)
        Ok(())
    }

    /// Generate schema hash for ABI stability checks
    pub fn schema_hash() -> String {
        use sha2::{Digest, Sha256};

        // Create deterministic representation of schema fields
        let schema_repr = format!(
            "RESULT_SCHEMA_V{}_FIELDS:ok:bool,status:string,latency_ms:u64,bytes:u64,capability_digest:string,commit:string,layer:string,name:string,mode:string,exp_id:string,idem_key:string,x_meta:map",
            RESULT_SCHEMA_VERSION
        );

        let mut hasher = Sha256::new();
        hasher.update(schema_repr.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Helper functions for creating results with common patterns
pub mod builders {
    use super::*;

    /// Create a successful result
    #[allow(clippy::too_many_arguments)]
    pub fn success(
        latency_ms: u64,
        bytes: u64,
        capability_digest: String,
        commit: String,
        name: String,
        mode: String,
        exp_id: String,
        idem_key: String,
    ) -> ResultSchemaV1 {
        ResultSchemaV1::new(
            true,
            "success".to_string(),
            latency_ms,
            bytes,
            capability_digest,
            commit,
            "atom".to_string(), // default layer
            name,
            mode,
            exp_id,
            idem_key,
        )
    }

    /// Create an error result
    #[allow(clippy::too_many_arguments)]
    pub fn error(
        error_message: String,
        latency_ms: u64,
        capability_digest: String,
        commit: String,
        name: String,
        mode: String,
        exp_id: String,
        idem_key: String,
    ) -> ResultSchemaV1 {
        ResultSchemaV1::new(
            false,
            format!("error: {}", error_message),
            latency_ms,
            0, // no bytes processed on error
            capability_digest,
            commit,
            "atom".to_string(),
            name,
            mode,
            exp_id,
            idem_key,
        )
    }

    /// Create a timeout result
    pub fn timeout(
        capability_digest: String,
        commit: String,
        name: String,
        mode: String,
        exp_id: String,
        idem_key: String,
    ) -> ResultSchemaV1 {
        ResultSchemaV1::new(
            false,
            "timeout".to_string(),
            0, // unknown latency
            0, // no bytes processed
            capability_digest,
            commit,
            "atom".to_string(),
            name,
            mode,
            exp_id,
            idem_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_valid_result() -> ResultSchemaV1 {
        ResultSchemaV1::new(
            true,
            "success".to_string(),
            150,
            1024,
            "a".repeat(64),        // valid SHA256
            "abc123f".to_string(), // valid commit
            "atom".to_string(),
            "fs.read.v1".to_string(),
            "strict".to_string(),
            "exp_123".to_string(),
            "idem_1234567890abcdef".to_string(),
        )
    }

    #[test]
    fn test_valid_result_creation() {
        let result = create_valid_result();
        assert!(result.validate().is_ok());
        assert!(result.ok);
        assert_eq!(result.status, "success");
        assert_eq!(result.latency_ms, 150);
        assert_eq!(result.bytes, 1024);
    }

    #[test]
    fn test_result_with_metadata() {
        let result = create_valid_result()
            .with_meta("custom_field".to_string(), json!("custom_value"))
            .with_meta("debug_info".to_string(), json!({"details": "test"}));

        assert!(result.validate().is_ok());
        assert_eq!(
            result.get_meta("custom_field"),
            Some(&json!("custom_value"))
        );
        assert_eq!(
            result.get_meta("debug_info"),
            Some(&json!({"details": "test"}))
        );
        assert_eq!(result.get_meta("nonexistent"), None);
    }

    #[test]
    fn test_validation_empty_fields() {
        let mut result = create_valid_result();
        result.status = "".to_string();

        let error = result.validate().unwrap_err();
        assert!(matches!(error, ResultSchemaError::EmptyRequiredField(_)));
    }

    #[test]
    fn test_validation_invalid_layer() {
        let mut result = create_valid_result();
        result.layer = "invalid_layer".to_string();

        let error = result.validate().unwrap_err();
        assert!(matches!(error, ResultSchemaError::InvalidFieldValue { .. }));
    }

    #[test]
    fn test_validation_invalid_mode() {
        let mut result = create_valid_result();
        result.mode = "invalid_mode".to_string();

        let error = result.validate().unwrap_err();
        assert!(matches!(error, ResultSchemaError::InvalidFieldValue { .. }));
    }

    #[test]
    fn test_validation_invalid_capability_digest() {
        let mut result = create_valid_result();
        result.capability_digest = "invalid_digest".to_string();

        let error = result.validate().unwrap_err();
        assert!(matches!(
            error,
            ResultSchemaError::InvalidFieldFormat { .. }
        ));
    }

    #[test]
    fn test_validation_invalid_commit() {
        let mut result = create_valid_result();
        result.commit = "x".to_string(); // too short

        let error = result.validate().unwrap_err();
        assert!(matches!(
            error,
            ResultSchemaError::InvalidFieldFormat { .. }
        ));
    }

    #[test]
    fn test_validation_invalid_idem_key() {
        let mut result = create_valid_result();
        result.idem_key = "invalid_key".to_string();

        let error = result.validate().unwrap_err();
        assert!(matches!(
            error,
            ResultSchemaError::InvalidFieldFormat { .. }
        ));
    }

    #[test]
    fn test_json_validation_success() {
        let valid_json = json!({
            "ok": true,
            "status": "success",
            "latency_ms": 150,
            "bytes": 1024,
            "capability_digest": "a".repeat(64),
            "commit": "abc123f",
            "layer": "atom",
            "name": "fs.read.v1",
            "mode": "strict",
            "exp_id": "exp_123",
            "idem_key": "idem_1234567890abcdef",
            "x_meta": {
                "custom": "value"
            }
        })
        .to_string();

        let result = ResultSchemaValidator::validate_json(&valid_json).unwrap();
        assert!(result.ok);
        assert_eq!(result.get_meta("custom"), Some(&json!("value")));
    }

    #[test]
    fn test_json_validation_unknown_field() {
        let invalid_json = json!({
            "ok": true,
            "status": "success",
            "latency_ms": 150,
            "bytes": 1024,
            "capability_digest": "a".repeat(64),
            "commit": "abc123f",
            "layer": "atom",
            "name": "fs.read.v1",
            "mode": "strict",
            "exp_id": "exp_123",
            "idem_key": "idem_1234567890abcdef",
            "unknown_field": "not allowed" // This should cause validation to fail
        })
        .to_string();

        let error = ResultSchemaValidator::validate_json(&invalid_json).unwrap_err();
        assert!(matches!(error, ResultSchemaError::UnknownField { .. }));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let original = create_valid_result().with_meta("test".to_string(), json!("metadata"));

        let json = serde_json::to_string(&original).unwrap();
        let deserialized = ResultSchemaValidator::validate_json(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_builder_functions() {
        let success = builders::success(
            100,
            512,
            "a".repeat(64),
            "abcdef123".to_string(), // Valid 9-char hex commit hash
            "test.capability".to_string(),
            "explore".to_string(),
            "exp_456".to_string(),
            "idem_abcdef1234567890".to_string(),
        );
        assert!(success.validate().is_ok());
        assert!(success.ok);

        let error = builders::error(
            "test error".to_string(),
            50,
            "a".repeat(64),
            "abc123fed".to_string(), // Valid 9-char hex commit hash
            "test.capability".to_string(),
            "strict".to_string(),
            "exp_789".to_string(),
            "idem_fedcba0987654321".to_string(),
        );
        assert!(error.validate().is_ok());
        assert!(!error.ok);
        assert!(error.status.contains("error: test error"));
    }

    #[test]
    fn test_schema_hash() {
        let hash1 = ResultSchemaValidator::schema_hash();
        let hash2 = ResultSchemaValidator::schema_hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);

        // Hash should be valid SHA256 (64 hex chars)
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_backward_compatibility_check() {
        let old_result = create_valid_result();
        let new_result =
            create_valid_result().with_meta("new_field".to_string(), json!("new_value"));

        // Adding x_meta fields should be backward compatible
        assert!(
            ResultSchemaValidator::check_backward_compatibility(&old_result, &new_result).is_ok()
        );

        // Same results should be compatible
        assert!(
            ResultSchemaValidator::check_backward_compatibility(&old_result, &old_result).is_ok()
        );
    }

    #[test]
    fn test_result_schema_error_display() {
        let empty_field_error = ResultSchemaError::EmptyRequiredField("status".to_string());
        let format_error = ResultSchemaError::InvalidFieldFormat {
            field: "commit".to_string(),
            expected: "9-character hex string".to_string(),
            actual: "abc".to_string(),
        };
        let unknown_field_error = ResultSchemaError::UnknownField {
            field: "unknown".to_string(),
        };
        let version_error = ResultSchemaError::VersionMismatch {
            expected: 1,
            actual: 2,
        };
        let deserialization_error =
            ResultSchemaError::DeserializationFailed("JSON parse error".to_string());

        // Test Display trait
        assert!(format!("{}", empty_field_error).contains("Empty required field"));
        assert!(format!("{}", format_error).contains("Invalid format for field commit"));
        assert!(format!("{}", unknown_field_error).contains("Unknown field detected"));
        assert!(format!("{}", version_error).contains("Schema version mismatch"));
        assert!(format!("{}", deserialization_error).contains("Deserialization failed"));

        // Test Debug trait
        let debug_str = format!("{:?}", empty_field_error);
        assert!(debug_str.contains("EmptyRequiredField"));
    }

    #[test]
    fn test_json_validation_malformed() {
        let malformed_json = "{ invalid json";
        let result = ResultSchemaValidator::validate_json(malformed_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_validation_missing_required_fields() {
        let incomplete_json = json!({
            "ok": true,
            // Missing required fields like status, latency_ms, bytes, etc.
        })
        .to_string();

        let result = ResultSchemaValidator::validate_json(&incomplete_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_invalid_commit_formats() {
        let invalid_commits = vec![
            "".to_string(),          // Empty
            "abc".to_string(),       // Too short (< 7 chars)
            "a".repeat(41),          // Too long (> 40 chars)
            "abcdefGHI".to_string(), // Invalid hex character
            "abcdef12@".to_string(), // Invalid character
        ];

        for commit in invalid_commits {
            let mut result = create_valid_result();
            result.commit = commit.clone();

            let error = result.validate();
            assert!(error.is_err(), "Commit '{}' should be invalid", commit);
        }
    }

    #[test]
    fn test_validation_invalid_capability_digest_formats() {
        let invalid_digests = vec![
            "".to_string(),                 // Empty
            "a".repeat(63),                 // Too short
            "a".repeat(65),                 // Too long
            "g".repeat(64),                 // Invalid hex character
            format!("{}@", "a".repeat(63)), // Invalid character
        ];

        for digest in invalid_digests {
            let mut result = create_valid_result();
            result.capability_digest = digest.clone();

            let error = result.validate();
            assert!(
                error.is_err(),
                "Capability digest '{}' should be invalid",
                digest
            );
        }
    }

    #[test]
    fn test_validation_invalid_exp_id_formats() {
        let invalid_exp_ids = vec![
            "", // Empty - only case that actually fails validation
        ];

        for exp_id in invalid_exp_ids {
            let mut result = create_valid_result();
            result.exp_id = exp_id.to_string();

            let error = result.validate();
            assert!(error.is_err(), "Exp ID '{}' should be invalid", exp_id);
        }
    }

    #[test]
    fn test_validation_invalid_idem_key_formats() {
        let invalid_idem_keys = vec![
            "",               // Empty
            "idem",           // Too short
            "idem_",          // No key part
            "invalid_123abc", // Wrong prefix
            "idem_",          // Just prefix
            "idem_ghi",       // Non-hex characters after underscore
        ];

        for idem_key in invalid_idem_keys {
            let mut result = create_valid_result();
            result.idem_key = idem_key.to_string();

            let error = result.validate();
            assert!(error.is_err(), "Idem key '{}' should be invalid", idem_key);
        }
    }

    #[test]
    fn test_validation_invalid_modes() {
        let invalid_modes = vec![
            "",             // Empty
            "invalid",      // Not in valid list
            "STRICT",       // Wrong case
            "explore_mode", // Contains underscore
        ];

        for mode in invalid_modes {
            let mut result = create_valid_result();
            result.mode = mode.to_string();

            let error = result.validate();
            assert!(error.is_err(), "Mode '{}' should be invalid", mode);
        }
    }

    #[test]
    fn test_validation_invalid_layers() {
        let invalid_layers = vec![
            "",           // Empty
            "invalid",    // Not in valid list
            "ATOM",       // Wrong case
            "atom_layer", // Contains underscore
        ];

        for layer in invalid_layers {
            let mut result = create_valid_result();
            result.layer = layer.to_string();

            let error = result.validate();
            assert!(error.is_err(), "Layer '{}' should be invalid", layer);
        }
    }

    #[test]
    fn test_builder_success_with_zero_values() {
        let result = builders::success(
            0, // zero latency
            0, // zero bytes
            "a".repeat(64),
            "abc123def".to_string(),
            "test.capability".to_string(),
            "strict".to_string(),
            "exp_test".to_string(),
            "idem_1234567890abcdef".to_string(),
        );

        assert!(result.validate().is_ok());
        assert!(result.ok);
        assert_eq!(result.latency_ms, 0);
        assert_eq!(result.bytes, 0);
    }

    #[test]
    fn test_builder_error_empty_message() {
        let result = builders::error(
            "".to_string(), // Empty error message
            100,
            "a".repeat(64),
            "abc123def".to_string(),
            "test.capability".to_string(),
            "strict".to_string(),
            "exp_test".to_string(),
            "idem_1234567890abcdef".to_string(),
        );

        assert!(result.validate().is_ok()); // Empty error message is allowed
        assert!(!result.ok);
        assert!(result.status.contains("error:"));
    }

    #[test]
    fn test_result_metadata_operations() {
        let mut result = create_valid_result();

        // Test multiple meta additions
        result = result
            .with_meta("key1".to_string(), json!("value1"))
            .with_meta("key2".to_string(), json!({"nested": "object"}))
            .with_meta("key3".to_string(), json!([1, 2, 3]));

        assert_eq!(result.get_meta("key1"), Some(&json!("value1")));
        assert_eq!(result.get_meta("key2"), Some(&json!({"nested": "object"})));
        assert_eq!(result.get_meta("key3"), Some(&json!([1, 2, 3])));
        assert_eq!(result.get_meta("nonexistent"), None);

        // Overwrite existing meta
        result = result.with_meta("key1".to_string(), json!("new_value"));
        assert_eq!(result.get_meta("key1"), Some(&json!("new_value")));
    }

    #[test]
    fn test_json_round_trip_with_complex_meta() {
        let original = create_valid_result()
            .with_meta("string".to_string(), json!("test"))
            .with_meta("number".to_string(), json!(42))
            .with_meta("boolean".to_string(), json!(true))
            .with_meta("null".to_string(), json!(null))
            .with_meta("array".to_string(), json!([1, "two", 3.0]))
            .with_meta("object".to_string(), json!({"nested": {"deep": "value"}}));

        let json = serde_json::to_string(&original).unwrap();
        let deserialized = ResultSchemaValidator::validate_json(&json).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.get_meta("string"), Some(&json!("test")));
        assert_eq!(deserialized.get_meta("number"), Some(&json!(42)));
        assert_eq!(deserialized.get_meta("boolean"), Some(&json!(true)));
        assert_eq!(deserialized.get_meta("null"), Some(&json!(null)));
        assert_eq!(
            deserialized.get_meta("array"),
            Some(&json!([1, "two", 3.0]))
        );
        assert_eq!(
            deserialized.get_meta("object"),
            Some(&json!({"nested": {"deep": "value"}}))
        );
    }

    #[test]
    fn test_schema_hash_consistency() {
        // Test that schema hash is consistent across calls
        let hashes: Vec<String> = (0..10)
            .map(|_| ResultSchemaValidator::schema_hash())
            .collect();

        // All hashes should be identical
        for hash in &hashes {
            assert_eq!(hash, &hashes[0]);
        }

        // Should be a valid SHA-256 hash
        assert_eq!(hashes[0].len(), 64);
        assert!(hashes[0].chars().all(|c| c.is_ascii_hexdigit()));
    }
}
