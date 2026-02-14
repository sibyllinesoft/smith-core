//! Runtime Provenance Generation Module
//!
//! Handles generation and management of runtime provenance for intent executions.

use anyhow::{Context, Result};
use smith_attestation::{
    ProvenanceGenerator, SlsaProvenance,
    provenance::{ProvenanceConfig, BuildArtifact, BuildInfo}
};
use smith_protocol::{Intent, IntentResult};
use std::collections::HashMap;
use tracing::{debug, info};

use super::types::RuntimeAttestationResults;

/// Runtime provenance generator for intent executions
pub struct RuntimeProvenanceGenerator {
    generator: ProvenanceGenerator,
}

impl RuntimeProvenanceGenerator {
    /// Create new runtime provenance generator
    pub fn new(output_dir: String) -> Self {
        let provenance_config = ProvenanceConfig {
            build_environment: std::env::var("EXECUTION_ENVIRONMENT")
                .unwrap_or_else(|_| "runtime".to_string()),
            builder_id: "smith-executor".to_string(),
            repository_url: std::env::var("REPOSITORY_URL")
                .unwrap_or_else(|_| "https://github.com/smith-rs/smith".to_string()),
            build_trigger: "runtime-execution".to_string(),
            output_dir,
        };

        let generator = ProvenanceGenerator::new(provenance_config);

        Self { generator }
    }

    /// Create provenance generator with custom configuration
    pub fn with_config(config: ProvenanceConfig) -> Self {
        let generator = ProvenanceGenerator::new(config);
        Self { generator }
    }

    /// Generate runtime provenance for intent execution
    pub async fn generate_runtime_provenance(
        &self,
        intent: &Intent,
        result: &IntentResult,
        _attestation_results: &RuntimeAttestationResults,
    ) -> Result<SlsaProvenance> {
        debug!("Generating runtime provenance for intent: {}", intent.id);

        let build_info = self.collect_runtime_build_info().await?;
        let artifacts = self.create_execution_artifacts(intent, result).await?;

        // Generate provenance
        let provenance = self
            .generator
            .generate_provenance(&build_info, artifacts)
            .await
            .context("Failed to generate runtime provenance")?;

        // Save runtime provenance
        let provenance_file = format!("runtime-provenance-{}.json", intent.id);
        self.save_provenance(&provenance, &provenance_file).await?;

        info!("Runtime provenance generated for intent: {}", intent.id);

        Ok(provenance)
    }

    /// Save provenance to file
    pub async fn save_provenance(&self, provenance: &SlsaProvenance, filename: &str) -> Result<()> {
        self.generator
            .save_provenance(provenance, filename)
            .await
            .context("Failed to save runtime provenance")
    }

    /// Collect runtime build information
    async fn collect_runtime_build_info(&self) -> Result<BuildInfo> {
        ProvenanceGenerator::collect_build_info()
            .await
            .context("Failed to collect runtime build information")
    }

    /// Create artifacts representing the intent execution
    async fn create_execution_artifacts(
        &self,
        intent: &Intent,
        result: &IntentResult,
    ) -> Result<Vec<BuildArtifact>> {
        let mut artifacts = Vec::new();

        // Add intent as an artifact
        let intent_artifact = self.create_intent_artifact(intent).await?;
        artifacts.push(intent_artifact);

        // Add result as an artifact
        let result_artifact = self.create_result_artifact(result, &intent.id).await?;
        artifacts.push(result_artifact);

        Ok(artifacts)
    }

    /// Create artifact for intent
    async fn create_intent_artifact(&self, intent: &Intent) -> Result<BuildArtifact> {
        let intent_bytes = serde_json::to_vec(intent).context("Failed to serialize intent")?;
        let intent_digest = self.generate_sha256_digest(&intent_bytes)?;

        let mut digest_map = HashMap::new();
        digest_map.insert("sha256".to_string(), intent_digest);

        Ok(BuildArtifact {
            name: format!("intent-{}.json", intent.id),
            path: format!("runtime/intents/{}", intent.id),
            digest: digest_map,
        })
    }

    /// Create artifact for result
    async fn create_result_artifact(&self, result: &IntentResult, intent_id: &str) -> Result<BuildArtifact> {
        let result_bytes = serde_json::to_vec(result).context("Failed to serialize result")?;
        let result_digest = self.generate_sha256_digest(&result_bytes)?;

        let mut digest_map = HashMap::new();
        digest_map.insert("sha256".to_string(), result_digest);

        Ok(BuildArtifact {
            name: format!("result-{}.json", intent_id),
            path: format!("runtime/results/{}", intent_id),
            digest: digest_map,
        })
    }

    /// Generate SHA256 digest for bytes
    fn generate_sha256_digest(&self, bytes: &[u8]) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Get provenance output directory
    pub fn get_output_dir(&self) -> &str {
        &self.generator.config.output_dir
    }

    /// Get builder ID
    pub fn get_builder_id(&self) -> &str {
        &self.generator.config.builder_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::{Intent, IntentResult, ExecutionStatus};
    use tempfile::tempdir;

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

    fn create_test_result() -> IntentResult {
        IntentResult {
            id: "test-intent-123".to_string(),
            status: ExecutionStatus::Ok,
            data: serde_json::json!({"content": "file content"}),
            artifacts: vec![],
            created_at: chrono::Utc::now(),
            duration_ms: Some(150),
        }
    }

    fn create_test_attestation_results() -> RuntimeAttestationResults {
        use super::super::types::VerificationDetails;
        
        let details = VerificationDetails::new(
            HashMap::new(),
            vec![],
            vec![],
            HashMap::new(),
        );

        RuntimeAttestationResults::new(
            "test-digest".to_string(),
            Some("test-image-digest".to_string()),
            true,
            true,
            true,
            details,
        )
    }

    #[test]
    fn test_runtime_provenance_generator_creation() {
        let temp_dir = tempdir().unwrap();
        let output_dir = temp_dir.path().to_string_lossy().to_string();
        
        let generator = RuntimeProvenanceGenerator::new(output_dir.clone());
        assert_eq!(generator.get_output_dir(), output_dir);
        assert_eq!(generator.get_builder_id(), "smith-executor");
    }

    #[test]
    fn test_runtime_provenance_generator_with_config() {
        let temp_dir = tempdir().unwrap();
        let config = ProvenanceConfig {
            build_environment: "test-env".to_string(),
            builder_id: "custom-builder".to_string(),
            repository_url: "https://example.com/repo".to_string(),
            build_trigger: "custom-trigger".to_string(),
            output_dir: temp_dir.path().to_string_lossy().to_string(),
        };

        let generator = RuntimeProvenanceGenerator::with_config(config.clone());
        assert_eq!(generator.get_output_dir(), config.output_dir);
        assert_eq!(generator.get_builder_id(), "custom-builder");
    }

    #[test]
    fn test_generate_sha256_digest() {
        let temp_dir = tempdir().unwrap();
        let generator = RuntimeProvenanceGenerator::new(
            temp_dir.path().to_string_lossy().to_string()
        );

        let test_data = b"hello world";
        let digest = generator.generate_sha256_digest(test_data).unwrap();
        
        // Expected SHA256 of "hello world"
        assert_eq!(digest, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[tokio::test]
    async fn test_create_intent_artifact() {
        let temp_dir = tempdir().unwrap();
        let generator = RuntimeProvenanceGenerator::new(
            temp_dir.path().to_string_lossy().to_string()
        );

        let intent = create_test_intent();
        let artifact = generator.create_intent_artifact(&intent).await.unwrap();

        assert_eq!(artifact.name, "intent-test-intent-123.json");
        assert_eq!(artifact.path, "runtime/intents/test-intent-123");
        assert!(artifact.digest.contains_key("sha256"));
        assert!(!artifact.digest["sha256"].is_empty());
    }

    #[tokio::test]
    async fn test_create_result_artifact() {
        let temp_dir = tempdir().unwrap();
        let generator = RuntimeProvenanceGenerator::new(
            temp_dir.path().to_string_lossy().to_string()
        );

        let result = create_test_result();
        let artifact = generator.create_result_artifact(&result, "test-intent-123").await.unwrap();

        assert_eq!(artifact.name, "result-test-intent-123.json");
        assert_eq!(artifact.path, "runtime/results/test-intent-123");
        assert!(artifact.digest.contains_key("sha256"));
        assert!(!artifact.digest["sha256"].is_empty());
    }

    #[tokio::test]
    async fn test_create_execution_artifacts() {
        let temp_dir = tempdir().unwrap();
        let generator = RuntimeProvenanceGenerator::new(
            temp_dir.path().to_string_lossy().to_string()
        );

        let intent = create_test_intent();
        let result = create_test_result();
        
        let artifacts = generator.create_execution_artifacts(&intent, &result).await.unwrap();

        assert_eq!(artifacts.len(), 2);
        
        // Check intent artifact
        assert!(artifacts.iter().any(|a| a.name.starts_with("intent-")));
        
        // Check result artifact
        assert!(artifacts.iter().any(|a| a.name.starts_with("result-")));
    }
}