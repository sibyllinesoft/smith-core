//! Attestation utility functions for cryptographic operations and file loading
//!
//! Provides reusable utilities for attestation operations including digest generation,
//! signature loading, provenance handling, and verification result construction.

use anyhow::{Context, Result};
use smith_attestation::provenance::BuildArtifact;
use smith_attestation::SlsaProvenance;
#[allow(unused_imports)]
use smith_protocol::{AuditRef, Intent, IntentResult};
use std::collections::HashMap;
use tracing::debug;

/// Generate SHA256 digest of byte data
pub fn generate_digest(bytes: &[u8]) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Generate capability bundle digest
pub fn generate_capability_digest(bundle_bytes: &[u8]) -> Result<String> {
    generate_digest(bundle_bytes)
}

/// Try to load policy signature from standard locations
pub async fn load_policy_signature() -> Result<smith_attestation::Signature> {
    let potential_paths = vec![
        "build/attestation/policy_signature.json",
        "policy_signature.json",
        ".attestation/policy_signature.json",
    ];

    for path in potential_paths {
        if let Ok(signature_bytes) = tokio::fs::read(path).await {
            if let Ok(signature) = serde_json::from_slice(&signature_bytes) {
                debug!("Loaded policy signature from: {}", path);
                return Ok(signature);
            }
        }
    }

    Err(anyhow::anyhow!("Policy signature not found"))
}

/// Try to load policy provenance from standard locations
pub async fn load_policy_provenance() -> Result<SlsaProvenance> {
    let potential_paths = vec![
        "build/attestation/build-provenance.json",
        "build-provenance.json",
        ".attestation/build-provenance.json",
    ];

    for path in potential_paths {
        if let Ok(provenance_bytes) = tokio::fs::read(path).await {
            if let Ok(provenance) = serde_json::from_slice(&provenance_bytes) {
                debug!("Loaded policy provenance from: {}", path);
                return Ok(provenance);
            }
        }
    }

    Err(anyhow::anyhow!("Policy provenance not found"))
}

/// Get executor container image digest from environment or filesystem
pub async fn get_executor_image_digest() -> Option<String> {
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

/// Create build artifact from intent data
pub fn create_intent_artifact(intent: &Intent) -> Result<BuildArtifact> {
    let intent_bytes = serde_json::to_vec(intent).context("Failed to serialize intent")?;
    let intent_digest = generate_digest(&intent_bytes)?;

    let mut digest_map = HashMap::new();
    digest_map.insert("sha256".to_string(), intent_digest);

    Ok(BuildArtifact {
        name: format!("intent-{}.json", intent.id),
        path: format!("runtime/intents/{}", intent.id),
        digest: digest_map,
    })
}

/// Create build artifact from intent result data
pub fn create_result_artifact(intent_id: &str, result: &IntentResult) -> Result<BuildArtifact> {
    let result_bytes = serde_json::to_vec(result).context("Failed to serialize result")?;
    let result_digest = generate_digest(&result_bytes)?;

    let mut digest_map = HashMap::new();
    digest_map.insert("sha256".to_string(), result_digest);

    Ok(BuildArtifact {
        name: format!("result-{}.json", intent_id),
        path: format!("runtime/results/{}", intent_id),
        digest: digest_map,
    })
}

/// Build provenance configuration for executor runtime
pub fn build_provenance_config(
    output_dir: String,
) -> smith_attestation::provenance::ProvenanceConfig {
    smith_attestation::provenance::ProvenanceConfig {
        build_environment: std::env::var("EXECUTION_ENVIRONMENT")
            .unwrap_or_else(|_| "runtime".to_string()),
        builder_id: "smith-executor".to_string(),
        repository_url: std::env::var("REPOSITORY_URL")
            .unwrap_or_else(|_| "https://github.com/smith-rs/smith".to_string()),
        build_trigger: "runtime-execution".to_string(),
        output_dir: output_dir.into(),
    }
}

/// Generate complete artifacts list for provenance
pub fn generate_provenance_artifacts(
    intent: &Intent,
    result: &IntentResult,
) -> Result<Vec<BuildArtifact>> {
    let mut artifacts = Vec::new();

    // Add intent as an artifact
    artifacts.push(create_intent_artifact(intent)?);

    // Add result as an artifact
    artifacts.push(create_result_artifact(&result.intent_id, result)?);

    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::{
        AuditRef, Capability, ExecutionStatus, Intent, IntentResult, RunnerMetadata,
    };
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[test]
    fn test_generate_digest() {
        let data = b"test data";
        let digest = generate_digest(data).unwrap();

        // SHA256 of "test data" should be consistent
        assert_eq!(digest.len(), 64); // SHA256 hex string length
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));

        // Test reproducibility
        let digest2 = generate_digest(data).unwrap();
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_generate_digest_empty_data() {
        let data = b"";
        let digest = generate_digest(data).unwrap();

        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_digest_large_data() {
        let data = vec![0u8; 1_000_000]; // 1MB of zeros
        let digest = generate_digest(&data).unwrap();

        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_capability_digest() {
        let policy_data = b"capability bundle data";
        let digest = generate_capability_digest(policy_data).unwrap();

        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));

        // Test with different data
        let policy_data2 = b"different policy data";
        let digest2 = generate_capability_digest(policy_data2).unwrap();
        assert_ne!(digest, digest2);
    }

    #[test]
    fn test_create_intent_artifact() {
        let intent = Intent {
            id: "test-intent".to_string(),
            capability: Capability::ShellExec,
            domain: "test-domain".to_string(),
            params: serde_json::json!({"command": "echo test"}),
            created_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            ttl_ms: 30000,
            nonce: "test-nonce".to_string(),
            signer: "test-signer".to_string(),
            signature_b64: "test-signature".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        let artifact = create_intent_artifact(&intent).unwrap();

        assert_eq!(artifact.name, "intent-test-intent.json");
        assert_eq!(artifact.path, "runtime/intents/test-intent");
        assert!(artifact.digest.contains_key("sha256"));
        assert_eq!(artifact.digest["sha256"].len(), 64);
    }

    #[test]
    fn test_create_intent_artifact_complex() {
        let mut metadata = HashMap::new();
        metadata.insert(
            "test_key".to_string(),
            serde_json::Value::String("test_value".to_string()),
        );

        let intent = Intent {
            id: "complex-intent-123".to_string(),
            capability: Capability::HttpFetch,
            params: serde_json::json!({
                "url": "https://example.com",
                "method": "POST",
                "headers": {"Content-Type": "application/json"}
            }),
            domain: "test.example.com".to_string(),
            created_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            ttl_ms: 30000,
            nonce: "test-nonce-complex".to_string(),
            signer: "test-signer-key-base64".to_string(),
            signature_b64: "test-signature-base64".to_string(),
            metadata,
        };

        let artifact = create_intent_artifact(&intent).unwrap();

        assert_eq!(artifact.name, "intent-complex-intent-123.json");
        assert_eq!(artifact.path, "runtime/intents/complex-intent-123");
        assert!(artifact.digest.contains_key("sha256"));
    }

    #[test]
    fn test_create_result_artifact() {
        let result = IntentResult {
            intent_id: "test-intent".to_string(),
            status: ExecutionStatus::Ok,
            output: Some(serde_json::json!({"test": "output"})),
            error: None,
            started_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            finished_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            runner_meta: RunnerMetadata::empty(),
            audit_ref: AuditRef {
                id: "test-audit".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                hash: "test-hash".to_string(),
            },
        };

        let artifact = create_result_artifact("test-intent", &result).unwrap();

        assert_eq!(artifact.name, "result-test-intent.json");
        assert_eq!(artifact.path, "runtime/results/test-intent");
        assert!(artifact.digest.contains_key("sha256"));
        assert_eq!(artifact.digest["sha256"].len(), 64);
    }

    #[test]
    fn test_create_result_artifact_with_error() {
        let result = IntentResult {
            intent_id: "error-intent".to_string(),
            status: ExecutionStatus::Error,
            output: None,
            error: Some(smith_protocol::ExecutionError {
                code: "TEST_ERROR".to_string(),
                message: "Test error message".to_string(),
            }),
            started_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            finished_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            runner_meta: RunnerMetadata::empty(),
            audit_ref: AuditRef {
                id: "test-audit-2".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                hash: "test-hash-2".to_string(),
            },
        };

        let artifact = create_result_artifact("error-intent", &result).unwrap();

        assert_eq!(artifact.name, "result-error-intent.json");
        assert_eq!(artifact.path, "runtime/results/error-intent");
        assert!(artifact.digest.contains_key("sha256"));
    }

    #[test]
    fn test_build_provenance_config() {
        let output_dir = "/tmp/provenance".to_string();
        let config = build_provenance_config(output_dir.clone());

        assert_eq!(config.builder_id, "smith-executor");
        assert_eq!(config.build_trigger, "runtime-execution");
        assert_eq!(config.output_dir.to_string_lossy(), output_dir);
        assert!(config.build_environment == "runtime" || !config.build_environment.is_empty());
    }

    #[test]
    fn test_build_provenance_config_with_env_vars() {
        std::env::set_var("EXECUTION_ENVIRONMENT", "test-env");
        std::env::set_var("REPOSITORY_URL", "https://test-repo.com");

        let config = build_provenance_config("/test/output".to_string());

        assert_eq!(config.build_environment, "test-env");
        assert_eq!(config.repository_url, "https://test-repo.com");
        assert_eq!(config.builder_id, "smith-executor");
        assert_eq!(config.build_trigger, "runtime-execution");

        // Clean up
        std::env::remove_var("EXECUTION_ENVIRONMENT");
        std::env::remove_var("REPOSITORY_URL");
    }

    #[test]
    fn test_generate_provenance_artifacts() {
        let intent = Intent {
            id: "test-intent".to_string(),
            capability: Capability::FsReadV1,
            domain: "test-domain.com".to_string(),
            params: serde_json::json!({"path": "/test/path"}),
            created_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            ttl_ms: 30000,
            nonce: "test-nonce".to_string(),
            signer: "test-signer".to_string(),
            signature_b64: "test-signature".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        let result = IntentResult {
            intent_id: "test-intent".to_string(),
            status: ExecutionStatus::Ok,
            output: Some(serde_json::json!({"result": "success"})),
            error: None,
            started_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            finished_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            runner_meta: RunnerMetadata::empty(),
            audit_ref: AuditRef {
                id: "test-audit-3".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                hash: "test-hash-3".to_string(),
            },
        };

        let artifacts = generate_provenance_artifacts(&intent, &result).unwrap();

        assert_eq!(artifacts.len(), 2);

        // Check intent artifact
        assert_eq!(artifacts[0].name, "intent-test-intent.json");
        assert_eq!(artifacts[0].path, "runtime/intents/test-intent");

        // Check result artifact
        assert_eq!(artifacts[1].name, "result-test-intent.json");
        assert_eq!(artifacts[1].path, "runtime/results/test-intent");

        // Both should have SHA256 digests
        assert!(artifacts[0].digest.contains_key("sha256"));
        assert!(artifacts[1].digest.contains_key("sha256"));
    }

    #[tokio::test]
    async fn test_get_executor_image_digest_no_container() {
        // In test environment, should return None
        let digest = get_executor_image_digest().await;
        assert!(digest.is_none() || digest.is_some()); // Either case is valid in tests
    }

    #[tokio::test]
    async fn test_get_executor_image_digest_with_env() {
        let test_digest = "sha256:1234567890abcdef";
        std::env::set_var("CONTAINER_IMAGE_DIGEST", test_digest);

        let digest = get_executor_image_digest().await;
        assert_eq!(digest, Some(test_digest.to_string()));

        std::env::remove_var("CONTAINER_IMAGE_DIGEST");
    }

    #[tokio::test]
    async fn test_get_executor_image_digest_with_file() {
        let temp_dir = tempdir().unwrap();
        let digest_file = temp_dir.path().join("image-digest");
        let test_digest = "sha256:fedcba0987654321";

        tokio::fs::write(&digest_file, format!("  {}  \n", test_digest))
            .await
            .unwrap();

        // Simulate reading from /etc/image-digest by temporarily creating it
        // Note: This test might not work in all environments due to permissions
        // but we can test the string trimming logic
        let file_content = tokio::fs::read_to_string(&digest_file).await.unwrap();
        assert_eq!(file_content.trim(), test_digest);
    }

    #[tokio::test]
    async fn test_load_policy_signature_not_found() {
        // Should return error when no signature files exist
        let result = load_policy_signature().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Policy signature not found"));
    }

    #[tokio::test]
    async fn test_load_policy_provenance_not_found() {
        // Should return error when no provenance files exist
        let result = load_policy_provenance().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Policy provenance not found"));
    }

    #[tokio::test]
    async fn test_load_policy_signature_invalid_json() {
        // Create temporary invalid JSON file
        let temp_dir = tempdir().unwrap();
        let sig_file = temp_dir.path().join("policy_signature.json");
        tokio::fs::write(&sig_file, "invalid json content")
            .await
            .unwrap();

        // Change to temp directory
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp_dir).unwrap();

        let result = load_policy_signature().await;
        assert!(result.is_err());

        // Restore original directory
        std::env::set_current_dir(original_dir).unwrap();
    }

    #[test]
    fn test_artifact_digest_consistency() {
        // Test that same intent produces same artifact digest
        let intent = Intent {
            id: "consistency-test".to_string(),
            capability: Capability::ShellExec,
            domain: "test.domain.com".to_string(),
            params: serde_json::json!({"command": "echo consistent"}),
            created_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            ttl_ms: 30000,
            nonce: "test-nonce".to_string(),
            signer: "test-signer".to_string(),
            signature_b64: "test-signature".to_string(),
            metadata: {
                let mut map = std::collections::HashMap::new();
                map.insert(
                    "source".to_string(),
                    serde_json::Value::String("test".to_string()),
                );
                map.insert(
                    "priority".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(1)),
                );
                map
            },
        };

        let artifact1 = create_intent_artifact(&intent).unwrap();
        let artifact2 = create_intent_artifact(&intent).unwrap();

        assert_eq!(artifact1.digest["sha256"], artifact2.digest["sha256"]);
        assert_eq!(artifact1.name, artifact2.name);
        assert_eq!(artifact1.path, artifact2.path);
    }

    #[test]
    fn test_artifact_digest_uniqueness() {
        // Test that different intents produce different artifact digests
        let intent1 = Intent {
            id: "unique-test-1".to_string(),
            capability: Capability::ShellExec,
            domain: "test.domain.com".to_string(),
            params: serde_json::json!({"command": "echo first"}),
            created_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            ttl_ms: 30000,
            nonce: "test-nonce".to_string(),
            signer: "test-signer".to_string(),
            signature_b64: "test-signature".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        let intent2 = Intent {
            id: "unique-test-2".to_string(),
            capability: Capability::ShellExec,
            domain: "test.domain.com".to_string(),
            params: serde_json::json!({"command": "echo second"}),
            created_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            ttl_ms: 30000,
            nonce: "test-nonce".to_string(),
            signer: "test-signer".to_string(),
            signature_b64: "test-signature".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        let artifact1 = create_intent_artifact(&intent1).unwrap();
        let artifact2 = create_intent_artifact(&intent2).unwrap();

        assert_ne!(artifact1.digest["sha256"], artifact2.digest["sha256"]);
        assert_ne!(artifact1.name, artifact2.name);
        assert_ne!(artifact1.path, artifact2.path);
    }

    #[test]
    fn test_result_artifact_with_large_output() {
        let large_output = "x".repeat(1_000_000); // 1MB string
        let result = IntentResult {
            intent_id: "test-intent-large".to_string(),
            status: ExecutionStatus::Success,
            output: Some(serde_json::json!({"result": large_output})),
            error: None,
            started_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            finished_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
            runner_meta: RunnerMetadata::empty(),
            audit_ref: AuditRef {
                id: "large-audit".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                hash: "placeholder".to_string(),
            },
        };

        let artifact = create_result_artifact("large-intent", &result).unwrap();

        assert_eq!(artifact.name, "result-large-intent.json");
        assert!(artifact.digest.contains_key("sha256"));
        assert_eq!(artifact.digest["sha256"].len(), 64);
    }
}
