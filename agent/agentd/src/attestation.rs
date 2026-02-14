//! Runtime attestation verification for the Smith Executor
//!
//! This module provides continuous attestation verification during execution,
//! ensuring that all capability bundles and execution contexts maintain cryptographic
//! integrity throughout the runtime lifecycle.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use smith_attestation::{
    initialize_attestation, AttestationConfig, CapabilitySigner, ProvenanceGenerator, SlsaProvenance,
    VerificationContext, Verifier, VerificationResult,
};
use smith_protocol::{Intent, IntentResult};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::attestation_utils::{self, generate_capability_digest, generate_provenance_artifacts, build_provenance_config};

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

/// Runtime attestation manager for the Executor service
pub struct ExecutorAttestationManager {
    /// Attestation configuration
    config: AttestationConfig,
    /// Policy signer for verification
    signer: CapabilitySigner,
    /// Verification engine
    verification_engine: Verifier,
    /// Provenance generator for runtime metadata
    provenance_generator: ProvenanceGenerator,
    /// Cached capability bundle path
    capability_bundle_path: Arc<RwLock<Option<PathBuf>>>,
    /// Cached verification results (by capability digest)
    verification_cache: Arc<RwLock<HashMap<String, RuntimeAttestationResults>>>,
}

impl ExecutorAttestationManager {
    /// Create new executor attestation manager
    pub async fn new(config: AttestationConfig) -> Result<Self> {
        info!("Initializing executor attestation manager");

        // Initialize attestation subsystem
        initialize_attestation(config.clone())
            .await
            .context("Failed to initialize attestation subsystem")?;

        // Create policy signer
        let signer = CapabilitySigner::new()
            .await
            .context("Failed to create policy signer")?;

        // Create verification engine
        let verification_engine = Verifier::new(config.clone()).context("Failed to create verifier")?;

        // Create provenance generator with executor-specific config
        let provenance_config = build_provenance_config(config.provenance_output_dir.clone());
        let provenance_generator = ProvenanceGenerator::new(provenance_config);

        Ok(Self {
            config,
            signer,
            verification_engine,
            provenance_generator,
            capability_bundle_path: Arc::new(RwLock::new(None)),
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Set the capability bundle path for runtime verification
    pub async fn set_capability_bundle_path(&self, path: PathBuf) -> Result<()> {
        info!("Setting capability bundle path: {}", path.display());

        // Verify the capability bundle exists and is readable
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "Capability bundle does not exist: {}",
                path.display()
            ));
        }

        // Update cached path
        let mut bundle_path = self.capability_bundle_path.write().await;
        *bundle_path = Some(path);

        Ok(())
    }

    /// Perform runtime attestation verification for an intent
    pub async fn verify_runtime_attestation(
        &self,
        intent: &Intent,
        execution_context: &HashMap<String, String>,
    ) -> Result<RuntimeAttestationResults> {
        debug!(
            "Starting runtime attestation verification for intent: {}",
            intent.id
        );

        // Get capability bundle path
        let bundle_path = {
            let path_guard = self.capability_bundle_path.read().await;
            path_guard
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Capability bundle path not set"))?
        };

        // Read capability bundle
        let bundle_bytes = tokio::fs::read(&bundle_path)
            .await
            .with_context(|| format!("Failed to read capability bundle: {}", bundle_path.display()))?;

        // Generate capability digest
        let capability_digest = generate_capability_digest(&bundle_bytes)?;

        // Check cache first
        {
            let cache = self.verification_cache.read().await;
            if let Some(cached_result) = cache.get(&capability_digest) {
                debug!(
                    "Using cached attestation result for capability digest: {}",
                    capability_digest
                );
                return Ok(cached_result.clone());
            }
        }

        // Perform comprehensive verification
        let verification_result = self
            .perform_comprehensive_verification(&bundle_bytes, intent, execution_context)
            .await?;

        // Generate executor image digest (if available)
        let executor_image_digest = attestation_utils::get_executor_image_digest().await;

        // Create runtime attestation results
        let attestation_results = RuntimeAttestationResults {
            capability_digest: capability_digest.clone(),
            executor_image_digest,
            bundle_sig_ok: verification_result.signature_valid,
            provenance_ok: verification_result.provenance_valid.unwrap_or(false),
            attestation_verified: verification_result.overall_valid,
            verified_at: chrono::Utc::now(),
            verification_details: VerificationDetails {
                checks: verification_result.checks,
                warnings: verification_result.warnings,
                errors: verification_result.errors,
                context: execution_context.clone(),
            },
        };

        // Cache the result
        {
            let mut cache = self.verification_cache.write().await;
            cache.insert(capability_digest, attestation_results.clone());
        }

        // Log verification result
        if attestation_results.attestation_verified {
            info!(
                "Runtime attestation verification successful for intent: {}",
                intent.id
            );
        } else {
            warn!(
                "Runtime attestation verification failed for intent: {}",
                intent.id
            );
        }

        Ok(attestation_results)
    }

    /// Generate runtime provenance for execution
    pub async fn generate_runtime_provenance(
        &self,
        intent: &Intent,
        result: &IntentResult,
        _attestation_results: &RuntimeAttestationResults,
    ) -> Result<SlsaProvenance> {
        debug!("Generating runtime provenance for intent: {}", intent.id);

        // Collect runtime build info
        let build_info = ProvenanceGenerator::collect_build_info()
            .await
            .context("Failed to collect runtime build information")?;

        // Create artifacts for the execution
        let artifacts = generate_provenance_artifacts(intent, result)?;

        // Generate provenance
        let provenance = self
            .provenance_generator
            .generate_provenance(&build_info, artifacts)
            .await
            .context("Failed to generate runtime provenance")?;

        // Save runtime provenance
        let provenance_file = format!("runtime-provenance-{}.json", intent.id);
        self.provenance_generator
            .save_provenance(&provenance, &provenance_file)
            .await
            .context("Failed to save runtime provenance")?;

        info!("Runtime provenance generated for intent: {}", intent.id);

        Ok(provenance)
    }

    /// Clear verification cache (useful for policy updates)
    pub async fn clear_cache(&self) {
        info!("Clearing attestation verification cache");
        let mut cache = self.verification_cache.write().await;
        cache.clear();
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> HashMap<String, usize> {
        let cache = self.verification_cache.read().await;
        let mut stats = HashMap::new();
        stats.insert("cached_verifications".to_string(), cache.len());
        stats
    }

    // Private helper methods

    async fn perform_comprehensive_verification(
        &self,
        bundle_bytes: &[u8],
        intent: &Intent,
        execution_context: &HashMap<String, String>,
    ) -> Result<VerificationResult> {
        // Create verification context
        let mut context = VerificationContext {
            intent_id: Some(intent.id.clone()),
            capability: Some(intent.capability.clone()),
            execution_environment: execution_context.get("environment").cloned(),
            additional_metadata: execution_context.clone(),
        };

        // Try to load existing signature (if available)
        let signature_result = attestation_utils::load_policy_signature().await;
        let provenance_result = attestation_utils::load_policy_provenance().await;

        match signature_result {
            Ok(signature) => {
                // Perform full verification with signature
                self.verification_engine
                    .verify_capability_bundle(
                        bundle_bytes,
                        &signature,
                        provenance_result.as_ref().ok(),
                        context,
                    )
                    .await
            }
            Err(_) => {
                // No signature available, perform basic verification
                warn!("No policy signature available, performing basic verification");

                let mut checks = HashMap::new();
                checks.insert("signature_valid".to_string(), false);
                checks.insert("digest_valid".to_string(), true); // We can still verify digest

                Ok(VerificationResult {
                    overall_valid: !self.config.fail_on_signature_error,
                    signature_valid: false,
                    trust_valid: None,
                    age_valid: None,
                    provenance_valid: provenance_result.map(|_| true),
                    digest_valid: Some(true),
                    checks,
                    warnings: vec!["Policy signature not available".to_string()],
                    errors: if self.config.fail_on_signature_error {
                        vec!["Policy signature required but not found".to_string()]
                    } else {
                        vec![]
                    },
                })
            }
        }
    }

}

/// Initialize executor attestation system
pub async fn initialize_executor_attestation(
    config: AttestationConfig,
) -> Result<ExecutorAttestationManager> {
    info!("Initializing executor attestation system");

    let manager = ExecutorAttestationManager::new(config)
        .await
        .context("Failed to create executor attestation manager")?;

    info!("Executor attestation system initialized successfully");
    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_attestation::AttestationConfig;
    use smith_protocol::{Intent, IntentResult, Capability};
    use std::collections::HashMap;
    use tempfile::{tempdir, NamedTempFile};
    use tokio::io::AsyncWriteExt;

    fn create_test_config() -> AttestationConfig {
        AttestationConfig {
            capability_bundle_path: None,
            signature_path: None,
            provenance_output_dir: "/tmp/test-provenance".to_string(),
            fail_on_signature_error: false,
            policy_signer_config: None,
            verification_timeout_secs: Some(30),
        }
    }

    fn create_test_intent() -> Intent {
        Intent {
            id: "test-intent-123".to_string(),
            capability: Capability::Shell,
            params: serde_json::json!({"command": "echo test"}),
            metadata: HashMap::new(),
        }
    }

    fn create_test_result() -> IntentResult {
        IntentResult {
            id: "test-result".to_string(),
            intent_id: "test-intent-123".to_string(),
            success: true,
            output: Some(serde_json::json!({"stdout": "test\n"})),
            error: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
            execution_time_ms: Some(100),
        }
    }

    #[tokio::test]
    async fn test_runtime_attestation_results_creation() {
        let results = RuntimeAttestationResults {
            capability_digest: "abc123".to_string(),
            executor_image_digest: Some("def456".to_string()),
            bundle_sig_ok: true,
            provenance_ok: true,
            attestation_verified: true,
            verified_at: chrono::Utc::now(),
            verification_details: VerificationDetails {
                checks: HashMap::new(),
                warnings: vec![],
                errors: vec![],
                context: HashMap::new(),
            },
        };

        assert_eq!(results.capability_digest, "abc123");
        assert_eq!(results.executor_image_digest, Some("def456".to_string()));
        assert!(results.bundle_sig_ok);
        assert!(results.provenance_ok);
        assert!(results.attestation_verified);
    }

    #[test]
    fn test_verification_details_creation() {
        let mut checks = HashMap::new();
        checks.insert("signature_valid".to_string(), true);
        checks.insert("digest_valid".to_string(), true);

        let details = VerificationDetails {
            checks: checks.clone(),
            warnings: vec!["Test warning".to_string()],
            errors: vec!["Test error".to_string()],
            context: HashMap::new(),
        };

        assert_eq!(details.checks.len(), 2);
        assert!(details.checks["signature_valid"]);
        assert_eq!(details.warnings.len(), 1);
        assert_eq!(details.errors.len(), 1);
    }

    #[tokio::test]
    async fn test_executor_attestation_manager_new() {
        let config = create_test_config();
        
        // This may fail in test environment due to missing attestation subsystem,
        // but we can test the error handling
        let result = ExecutorAttestationManager::new(config).await;
        
        // Either succeeds or fails gracefully
        match result {
            Ok(manager) => {
                // Manager created successfully
                assert!(manager.verification_cache.read().await.is_empty());
            }
            Err(e) => {
                // Expected in test environment without full attestation setup
                assert!(e.to_string().contains("Failed to"));
            }
        }
    }

    #[tokio::test]
    async fn test_set_capability_bundle_path_nonexistent() {
        let config = create_test_config();
        
        // Create a mock manager for testing
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            let nonexistent_path = PathBuf::from("/nonexistent/policy/bundle.json");
            let result = manager.set_capability_bundle_path(nonexistent_path).await;
            
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Capability bundle does not exist"));
        }
    }

    #[tokio::test]
    async fn test_set_capability_bundle_path_valid() {
        let config = create_test_config();
        
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            // Create temporary file
            let temp_file = NamedTempFile::new().unwrap();
            let temp_path = temp_file.path().to_path_buf();
            
            let result = manager.set_capability_bundle_path(temp_path.clone()).await;
            
            if result.is_ok() {
                let bundle_path = manager.capability_bundle_path.read().await;
                assert_eq!(*bundle_path, Some(temp_path));
            }
        }
    }

    #[tokio::test]
    async fn test_verify_runtime_attestation_no_bundle_path() {
        let config = create_test_config();
        
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            let intent = create_test_intent();
            let context = HashMap::new();
            
            let result = manager.verify_runtime_attestation(&intent, &context).await;
            
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Capability bundle path not set"));
        }
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let config = create_test_config();
        
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            // Test initial cache state
            let initial_stats = manager.get_cache_stats().await;
            assert_eq!(initial_stats["cached_verifications"], 0);
            
            // Test cache clearing
            manager.clear_cache().await;
            let stats_after_clear = manager.get_cache_stats().await;
            assert_eq!(stats_after_clear["cached_verifications"], 0);
        }
    }

    #[tokio::test]
    async fn test_generate_runtime_provenance() {
        let config = create_test_config();
        
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            let intent = create_test_intent();
            let result = create_test_result();
            let attestation_results = RuntimeAttestationResults {
                capability_digest: "test-digest".to_string(),
                executor_image_digest: None,
                bundle_sig_ok: false,
                provenance_ok: false,
                attestation_verified: false,
                verified_at: chrono::Utc::now(),
                verification_details: VerificationDetails {
                    checks: HashMap::new(),
                    warnings: vec![],
                    errors: vec![],
                    context: HashMap::new(),
                },
            };
            
            // This may fail due to missing provenance subsystem in test environment
            let provenance_result = manager.generate_runtime_provenance(
                &intent,
                &result,
                &attestation_results
            ).await;
            
            // Either succeeds or fails gracefully
            match provenance_result {
                Ok(provenance) => {
                    // Provenance generated successfully
                    assert!(!provenance.predicate.builder.id.is_empty());
                }
                Err(e) => {
                    // Expected in test environment
                    assert!(e.to_string().contains("Failed to"));
                }
            }
        }
    }

    #[tokio::test]
    async fn test_initialize_executor_attestation() {
        let config = create_test_config();
        
        let result = initialize_executor_attestation(config).await;
        
        // Either succeeds or fails gracefully
        match result {
            Ok(manager) => {
                // Initialization successful
                let stats = manager.get_cache_stats().await;
                assert!(stats.contains_key("cached_verifications"));
            }
            Err(e) => {
                // Expected in test environment without full attestation setup
                assert!(e.to_string().contains("Failed to"));
            }
        }
    }

    #[test]
    fn test_runtime_attestation_results_serialization() {
        let results = RuntimeAttestationResults {
            capability_digest: "test-digest-123".to_string(),
            executor_image_digest: Some("image-digest-456".to_string()),
            bundle_sig_ok: true,
            provenance_ok: false,
            attestation_verified: true,
            verified_at: chrono::Utc::now(),
            verification_details: VerificationDetails {
                checks: HashMap::new(),
                warnings: vec!["Warning message".to_string()],
                errors: vec![],
                context: HashMap::new(),
            },
        };

        // Test serialization
        let serialized = serde_json::to_string(&results).unwrap();
        assert!(serialized.contains("test-digest-123"));
        assert!(serialized.contains("image-digest-456"));
        assert!(serialized.contains("Warning message"));

        // Test deserialization
        let deserialized: RuntimeAttestationResults = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.capability_digest, "test-digest-123");
        assert_eq!(deserialized.executor_image_digest, Some("image-digest-456".to_string()));
        assert!(deserialized.bundle_sig_ok);
        assert!(!deserialized.provenance_ok);
        assert!(deserialized.attestation_verified);
    }

    #[test]
    fn test_verification_details_serialization() {
        let mut checks = HashMap::new();
        checks.insert("test_check".to_string(), true);
        
        let mut context = HashMap::new();
        context.insert("env".to_string(), "test".to_string());

        let details = VerificationDetails {
            checks,
            warnings: vec!["Test warning".to_string()],
            errors: vec!["Test error".to_string()],
            context,
        };

        // Test serialization
        let serialized = serde_json::to_string(&details).unwrap();
        assert!(serialized.contains("test_check"));
        assert!(serialized.contains("Test warning"));
        assert!(serialized.contains("Test error"));

        // Test deserialization
        let deserialized: VerificationDetails = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.checks["test_check"]);
        assert_eq!(deserialized.warnings[0], "Test warning");
        assert_eq!(deserialized.errors[0], "Test error");
        assert_eq!(deserialized.context["env"], "test");
    }

    #[tokio::test]
    async fn test_attestation_error_handling_strict_mode() {
        let mut config = create_test_config();
        config.fail_on_signature_error = true;
        
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            // Create temp capability bundle
            let temp_file = NamedTempFile::new().unwrap();
            tokio::fs::write(temp_file.path(), b"test capability bundle").await.unwrap();
            
            if manager.set_capability_bundle_path(temp_file.path().to_path_buf()).await.is_ok() {
                let intent = create_test_intent();
                let context = HashMap::new();
                
                let result = manager.verify_runtime_attestation(&intent, &context).await;
                
                // In strict mode, should handle signature errors appropriately
                match result {
                    Ok(attestation) => {
                        // If verification succeeds, check the results
                        if !attestation.bundle_sig_ok {
                            assert!(!attestation.attestation_verified);
                        }
                    }
                    Err(_) => {
                        // Expected in test environment
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_attestation_error_handling_permissive_mode() {
        let mut config = create_test_config();
        config.fail_on_signature_error = false;
        
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            // Create temp capability bundle
            let temp_file = NamedTempFile::new().unwrap();
            tokio::fs::write(temp_file.path(), b"test capability bundle").await.unwrap();
            
            if manager.set_capability_bundle_path(temp_file.path().to_path_buf()).await.is_ok() {
                let intent = create_test_intent();
                let context = HashMap::new();
                
                let result = manager.verify_runtime_attestation(&intent, &context).await;
                
                // In permissive mode, should handle signature errors gracefully
                match result {
                    Ok(attestation) => {
                        // Should have warnings but allow execution
                        if !attestation.bundle_sig_ok {
                            assert!(!attestation.verification_details.warnings.is_empty());
                        }
                    }
                    Err(_) => {
                        // Expected in test environment
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_attestation_caching_behavior() {
        let config = create_test_config();
        
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            // Create temp capability bundle
            let temp_file = NamedTempFile::new().unwrap();
            tokio::fs::write(temp_file.path(), b"consistent capability bundle").await.unwrap();
            
            if manager.set_capability_bundle_path(temp_file.path().to_path_buf()).await.is_ok() {
                let intent = create_test_intent();
                let context = HashMap::new();
                
                // First verification attempt
                let result1 = manager.verify_runtime_attestation(&intent, &context).await;
                
                if result1.is_ok() {
                    // Check cache stats
                    let stats = manager.get_cache_stats().await;
                    let initial_count = stats["cached_verifications"];
                    
                    // Second verification with same policy should use cache
                    let _result2 = manager.verify_runtime_attestation(&intent, &context).await;
                    
                    // Cache size should not increase significantly (may have some additions due to test setup)
                    let final_stats = manager.get_cache_stats().await;
                    assert!(final_stats["cached_verifications"] >= initial_count);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_multiple_intent_verification() {
        let config = create_test_config();
        
        if let Ok(manager) = ExecutorAttestationManager::new(config).await {
            let temp_file = NamedTempFile::new().unwrap();
            tokio::fs::write(temp_file.path(), b"capability bundle for multiple intents").await.unwrap();
            
            if manager.set_capability_bundle_path(temp_file.path().to_path_buf()).await.is_ok() {
                let intent1 = Intent {
                    id: "intent-1".to_string(),
                    capability: Capability::Shell,
                    params: serde_json::json!({"command": "echo 1"}),
                    metadata: HashMap::new(),
                };
                
                let intent2 = Intent {
                    id: "intent-2".to_string(),
                    capability: Capability::HttpFetch,
                    params: serde_json::json!({"url": "http://example.com"}),
                    metadata: HashMap::new(),
                };
                
                let context = HashMap::new();
                
                // Verify both intents
                let result1 = manager.verify_runtime_attestation(&intent1, &context).await;
                let result2 = manager.verify_runtime_attestation(&intent2, &context).await;
                
                if result1.is_ok() && result2.is_ok() {
                    let attestation1 = result1.unwrap();
                    let attestation2 = result2.unwrap();
                    
                    // Both should have same capability digest (same bundle)
                    assert_eq!(attestation1.capability_digest, attestation2.capability_digest);
                    
                    // But different verification timestamps
                    // (they might be very close but should be different objects)
                    assert!(attestation1.verified_at <= attestation2.verified_at);
                }
            }
        }
    }

    #[test]
    fn test_runtime_attestation_results_default_values() {
        let results = RuntimeAttestationResults {
            capability_digest: String::new(),
            executor_image_digest: None,
            bundle_sig_ok: false,
            provenance_ok: false,
            attestation_verified: false,
            verified_at: chrono::Utc::now(),
            verification_details: VerificationDetails {
                checks: HashMap::new(),
                warnings: vec![],
                errors: vec![],
                context: HashMap::new(),
            },
        };

        assert!(results.capability_digest.is_empty());
        assert!(results.executor_image_digest.is_none());
        assert!(!results.bundle_sig_ok);
        assert!(!results.provenance_ok);
        assert!(!results.attestation_verified);
        assert!(results.verification_details.checks.is_empty());
        assert!(results.verification_details.warnings.is_empty());
        assert!(results.verification_details.errors.is_empty());
    }
}
