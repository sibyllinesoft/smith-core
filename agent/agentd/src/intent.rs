use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smith_protocol::ExecutionLimits;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Canonical intent envelope that agents sign
/// All fields are required and immutable
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Intent {
    /// Unique intent identifier (UUIDv4)
    pub id: Uuid,
    /// Timestamp when intent was signed (epoch milliseconds)
    pub ts_ms: u64,
    /// Time-to-live in seconds (e.g., 60)
    pub ttl_s: u32,
    /// Monotonic sequence per intent ID, starts at 1
    pub seq: u32,
    /// 128-bit hex nonce for replay protection
    pub nonce: String,
    /// Capability identifier (e.g., "fs.read", "http.fetch")
    pub capability: String,
    /// Schema version (e.g., 1)
    pub version: u32,
    /// Primary resource target (capability-specific)
    pub resource: String,
    /// Capability-specific parameters
    pub params: serde_json::Value,
    /// Execution constraints (e.g., max_bytes, timeout)
    pub constraints: serde_json::Value,
    /// Actor information and claims
    pub actor: Actor,
    /// Base64 Ed25519 signature over canonical JSON
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Actor {
    /// JWT token with scoped claims
    pub jwt: String,
    /// Tenant identifier
    pub tenant: String,
    /// Signing key identifier (maps to public key)
    pub key_id: String,
}

/// Result message sent to results.<intent_id> subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResult {
    pub intent_id: Uuid,
    pub seq: u32,
    pub status: IntentStatus,
    pub code: String,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub decision: PolicyDecision,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub artifacts: Vec<Artifact>,
    pub retry_after_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IntentStatus {
    Ok,
    Denied,
    Error,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allow: bool,
    pub capability_digest: String,
    pub runner_digest: String,
    pub limits_applied: ExecutionLimits,
    pub scope: serde_json::Value,
    pub transforms: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub sha256: String,
    pub size: u64,
    pub storage_uri: String,
}

/// Standardized error codes for intent processing failures
/// These codes map to specific failure modes for consistent error handling
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    // Admission pipeline errors
    SigVerifyFail,
    IntentExpired,
    ReplayDetected,
    SchemaInvalid,
    PolicyDeny,

    // Resource access errors
    ResourceNotAllowed,
    LimitsExceeded,

    // Sandbox initialization errors
    SandboxInitFail,
    SecureExecError,

    // Runtime execution errors
    RunnerError,

    // Infrastructure errors
    ResultPublishFail,
}

impl ErrorCode {
    /// Convert error code to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::SigVerifyFail => "SIG_VERIFY_FAIL",
            ErrorCode::IntentExpired => "INTENT_EXPIRED",
            ErrorCode::ReplayDetected => "REPLAY_DETECTED",
            ErrorCode::SchemaInvalid => "SCHEMA_INVALID",
            ErrorCode::PolicyDeny => "POLICY_DENY",
            ErrorCode::ResourceNotAllowed => "RESOURCE_NOT_ALLOWED",
            ErrorCode::LimitsExceeded => "LIMITS_EXCEEDED",
            ErrorCode::SandboxInitFail => "SANDBOX_INIT_FAIL",
            ErrorCode::SecureExecError => "SECURE_EXEC_ERROR",
            ErrorCode::RunnerError => "RUNNER_ERROR",
            ErrorCode::ResultPublishFail => "RESULT_PUBLISH_FAIL",
        }
    }

    /// Parse error code from string representation
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "SIG_VERIFY_FAIL" => Some(ErrorCode::SigVerifyFail),
            "INTENT_EXPIRED" => Some(ErrorCode::IntentExpired),
            "REPLAY_DETECTED" => Some(ErrorCode::ReplayDetected),
            "SCHEMA_INVALID" => Some(ErrorCode::SchemaInvalid),
            "POLICY_DENY" => Some(ErrorCode::PolicyDeny),
            "RESOURCE_NOT_ALLOWED" => Some(ErrorCode::ResourceNotAllowed),
            "LIMITS_EXCEEDED" => Some(ErrorCode::LimitsExceeded),
            "SANDBOX_INIT_FAIL" => Some(ErrorCode::SandboxInitFail),
            "SECURE_EXEC_ERROR" => Some(ErrorCode::SecureExecError),
            "RUNNER_ERROR" => Some(ErrorCode::RunnerError),
            "RESULT_PUBLISH_FAIL" => Some(ErrorCode::ResultPublishFail),
            _ => None,
        }
    }

    /// Get human-readable description of the error
    pub fn description(&self) -> &'static str {
        match self {
            ErrorCode::SigVerifyFail => "Digital signature verification failed",
            ErrorCode::IntentExpired => "Intent has exceeded its time-to-live",
            ErrorCode::ReplayDetected => "Intent nonce has been seen before (replay attack)",
            ErrorCode::SchemaInvalid => "Intent does not match capability schema",
            ErrorCode::PolicyDeny => "Policy engine denied the intent",
            ErrorCode::ResourceNotAllowed => "Requested resource is not in allowlist",
            ErrorCode::LimitsExceeded => "Intent exceeds configured resource limits",
            ErrorCode::SandboxInitFail => "Failed to initialize security sandbox",
            ErrorCode::SecureExecError => "Security violation during execution (seccomp/Landlock)",
            ErrorCode::RunnerError => "Capability-specific execution error",
            ErrorCode::ResultPublishFail => "Failed to publish result to NATS",
        }
    }

    /// Determine if this error should trigger a retry
    pub fn is_retryable(&self) -> bool {
        match self {
            // Network/infrastructure failures that may be transient
            ErrorCode::ResultPublishFail => true,

            // All other errors are permanent failures
            _ => false,
        }
    }

    /// Get suggested retry delay in milliseconds for retryable errors
    pub fn retry_delay_ms(&self) -> Option<u64> {
        if !self.is_retryable() {
            return None;
        }

        match self {
            ErrorCode::ResultPublishFail => Some(1000), // 1 second
            _ => None,
        }
    }
}

impl Intent {
    /// Create a new intent with required fields
    /// Used mainly for testing - production intents come from agents
    pub fn new(
        capability: String,
        version: u32,
        resource: String,
        params: serde_json::Value,
        constraints: serde_json::Value,
        actor: Actor,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            ts_ms: chrono::Utc::now().timestamp_millis() as u64,
            ttl_s: 60, // Default 1 minute TTL
            seq: 1,
            nonce: generate_nonce(),
            capability,
            version,
            resource,
            params,
            constraints,
            actor,
            signature: String::new(), // Will be set during signing
        }
    }

    /// Canonicalize intent for signature verification
    /// Returns deterministic JSON bytes with sorted keys, no whitespace
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        // Create a copy without signature for canonicalization
        let mut intent_for_signing = self.clone();
        intent_for_signing.signature = String::new();

        // Convert to canonical JSON using BTreeMap to ensure key ordering
        let canonical_value = serde_json::to_value(&intent_for_signing)?;
        self.canonicalize_json_value(&canonical_value)
    }

    /// Recursively canonicalize JSON value to ensure deterministic serialization
    fn canonicalize_json_value(&self, value: &serde_json::Value) -> Result<Vec<u8>> {
        match value {
            serde_json::Value::Object(map) => {
                // Convert to BTreeMap for sorted keys
                let btree_map: BTreeMap<String, serde_json::Value> =
                    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

                // Serialize with compact formatting (no whitespace)
                serde_json::to_vec(&btree_map).context("Failed to serialize canonical JSON")
            }
            _ => {
                // For non-object values, serialize directly
                serde_json::to_vec(value).context("Failed to serialize JSON value")
            }
        }
    }

    /// Sign the intent with Ed25519 private key
    /// Returns base64-encoded signature
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<()> {
        let canonical_bytes = self.canonical_bytes()?;
        let signature = signing_key.sign(&canonical_bytes);
        self.signature = BASE64.encode(signature.to_bytes());
        Ok(())
    }

    /// Verify Ed25519 signature using public key
    pub fn verify_signature(&self, public_key: &VerifyingKey) -> Result<bool> {
        if self.signature.is_empty() {
            return Ok(false);
        }

        // Decode signature from base64
        let signature_bytes = BASE64
            .decode(&self.signature)
            .context("Failed to decode signature from base64")?;

        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;

        // Get canonical bytes for verification
        let canonical_bytes = self.canonical_bytes()?;

        // Verify signature
        match public_key.verify(&canonical_bytes, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Check if intent has expired based on timestamp and TTL
    pub fn is_expired(&self) -> bool {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let expiry_ms = self.ts_ms + (self.ttl_s as u64 * 1000);
        now_ms > expiry_ms
    }

    /// Calculate content hash for idempotency and audit
    pub fn content_hash(&self) -> Result<String> {
        let canonical_bytes = self.canonical_bytes()?;
        let hash = Sha256::digest(&canonical_bytes);
        Ok(hex::encode(hash))
    }

    /// Validate basic intent structure
    pub fn validate_structure(&self) -> Result<()> {
        // Validate ID format
        if self.id.is_nil() {
            return Err(anyhow::anyhow!("Intent ID cannot be nil"));
        }

        // Validate timestamp is reasonable (not too far in future/past)
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let max_clock_skew_ms = 300_000; // 5 minutes

        if self.ts_ms > now_ms + max_clock_skew_ms {
            return Err(anyhow::anyhow!("Intent timestamp too far in future"));
        }

        if now_ms > self.ts_ms + max_clock_skew_ms && self.is_expired() {
            return Err(anyhow::anyhow!("Intent has expired"));
        }

        // Validate TTL is reasonable
        if self.ttl_s == 0 || self.ttl_s > 3600 {
            return Err(anyhow::anyhow!("TTL must be between 1 and 3600 seconds"));
        }

        // Validate sequence number
        if self.seq == 0 {
            return Err(anyhow::anyhow!("Sequence number must be > 0"));
        }

        // Validate nonce format (128-bit hex = 32 hex chars)
        if self.nonce.len() != 32 || !self.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!("Nonce must be 32-character hex string"));
        }

        // Validate capability format
        if self.capability.is_empty() || !self.capability.contains('.') {
            return Err(anyhow::anyhow!(
                "Capability must be in format 'category.action'"
            ));
        }

        // Validate version is reasonable
        if self.version == 0 || self.version > 100 {
            return Err(anyhow::anyhow!("Version must be between 1 and 100"));
        }

        // Validate resource is not empty
        if self.resource.is_empty() {
            return Err(anyhow::anyhow!("Resource cannot be empty"));
        }

        // Validate actor fields
        if self.actor.jwt.is_empty() {
            return Err(anyhow::anyhow!("Actor JWT cannot be empty"));
        }

        if self.actor.tenant.is_empty() {
            return Err(anyhow::anyhow!("Actor tenant cannot be empty"));
        }

        if self.actor.key_id.is_empty() {
            return Err(anyhow::anyhow!("Actor key_id cannot be empty"));
        }

        // Validate signature is present
        if self.signature.is_empty() {
            return Err(anyhow::anyhow!("Signature cannot be empty"));
        }

        Ok(())
    }
}

/// Generate cryptographically secure 128-bit nonce as hex string
fn generate_nonce() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Parse intent from JSON bytes with validation
pub fn parse_intent(json_bytes: &[u8]) -> Result<Intent> {
    let intent: Intent =
        serde_json::from_slice(json_bytes).context("Failed to parse intent JSON")?;

    intent
        .validate_structure()
        .context("Intent structure validation failed")?;

    Ok(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn create_test_intent() -> Intent {
        Intent::new(
            "fs.read".to_string(),
            1,
            "/srv/logs/app.log".to_string(),
            json!({"offset": 0, "len": 4096}),
            json!({"max_bytes": 1048576}),
            Actor {
                jwt: "test.jwt.token".to_string(),
                tenant: "acme".to_string(),
                key_id: "agent-key-01".to_string(),
            },
        )
    }

    #[test]
    fn test_intent_creation_and_validation() {
        let intent = create_test_intent();

        // Should fail validation because signature is empty
        assert!(intent.validate_structure().is_err());
    }

    #[test]
    fn test_canonical_serialization() {
        let intent = create_test_intent();
        let canonical_bytes = intent.canonical_bytes().unwrap();

        // Should be deterministic
        let canonical_bytes2 = intent.canonical_bytes().unwrap();
        assert_eq!(canonical_bytes, canonical_bytes2);

        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_slice(&canonical_bytes).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn test_signing_and_verification() {
        let mut intent = create_test_intent();

        // Generate test key pair
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        // Sign intent
        intent.sign(&signing_key).unwrap();
        assert!(!intent.signature.is_empty());

        // Verify signature
        assert!(intent.verify_signature(&verifying_key).unwrap());

        // Verify with wrong key should fail
        let wrong_key = SigningKey::generate(&mut rand_core::OsRng);
        let wrong_verifying_key = wrong_key.verifying_key();
        assert!(!intent.verify_signature(&wrong_verifying_key).unwrap());
    }

    #[test]
    fn test_signature_tampering_detection() {
        let mut intent = create_test_intent();

        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        // Sign original intent
        intent.sign(&signing_key).unwrap();
        assert!(intent.verify_signature(&verifying_key).unwrap());

        // Tamper with resource
        intent.resource = "/etc/passwd".to_string();

        // Verification should fail
        assert!(!intent.verify_signature(&verifying_key).unwrap());
    }

    #[test]
    fn test_expiry_check() {
        let mut intent = create_test_intent();

        // Fresh intent should not be expired
        assert!(!intent.is_expired());

        // Intent in the past should be expired
        intent.ts_ms = chrono::Utc::now().timestamp_millis() as u64 - 120_000; // 2 minutes ago
        intent.ttl_s = 60; // 1 minute TTL
        assert!(intent.is_expired());
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Should be different
        assert_ne!(nonce1, nonce2);

        // Should be 32 hex characters
        assert_eq!(nonce1.len(), 32);
        assert!(nonce1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_content_hash_stability() {
        let intent1 = create_test_intent();
        let intent2 = create_test_intent();

        // Different intents should have different hashes
        assert_ne!(
            intent1.content_hash().unwrap(),
            intent2.content_hash().unwrap()
        );

        // Same intent should have same hash
        assert_eq!(
            intent1.content_hash().unwrap(),
            intent1.content_hash().unwrap()
        );
    }

    #[test]
    fn test_json_roundtrip() {
        let mut intent = create_test_intent();
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        // Serialize to JSON
        let json_bytes = serde_json::to_vec(&intent).unwrap();

        // Parse back from JSON
        let parsed_intent = parse_intent(&json_bytes).unwrap();

        // Should be identical
        assert_eq!(intent, parsed_intent);
    }

    // ==================== ErrorCode Tests ====================

    #[test]
    fn test_error_code_as_str() {
        assert_eq!(ErrorCode::SigVerifyFail.as_str(), "SIG_VERIFY_FAIL");
        assert_eq!(ErrorCode::IntentExpired.as_str(), "INTENT_EXPIRED");
        assert_eq!(ErrorCode::ReplayDetected.as_str(), "REPLAY_DETECTED");
        assert_eq!(ErrorCode::SchemaInvalid.as_str(), "SCHEMA_INVALID");
        assert_eq!(ErrorCode::PolicyDeny.as_str(), "POLICY_DENY");
        assert_eq!(
            ErrorCode::ResourceNotAllowed.as_str(),
            "RESOURCE_NOT_ALLOWED"
        );
        assert_eq!(ErrorCode::LimitsExceeded.as_str(), "LIMITS_EXCEEDED");
        assert_eq!(ErrorCode::SandboxInitFail.as_str(), "SANDBOX_INIT_FAIL");
        assert_eq!(ErrorCode::SecureExecError.as_str(), "SECURE_EXEC_ERROR");
        assert_eq!(ErrorCode::RunnerError.as_str(), "RUNNER_ERROR");
        assert_eq!(ErrorCode::ResultPublishFail.as_str(), "RESULT_PUBLISH_FAIL");
    }

    #[test]
    fn test_error_code_from_str() {
        assert_eq!(
            ErrorCode::from_str("SIG_VERIFY_FAIL"),
            Some(ErrorCode::SigVerifyFail)
        );
        assert_eq!(
            ErrorCode::from_str("INTENT_EXPIRED"),
            Some(ErrorCode::IntentExpired)
        );
        assert_eq!(
            ErrorCode::from_str("REPLAY_DETECTED"),
            Some(ErrorCode::ReplayDetected)
        );
        assert_eq!(
            ErrorCode::from_str("SCHEMA_INVALID"),
            Some(ErrorCode::SchemaInvalid)
        );
        assert_eq!(
            ErrorCode::from_str("POLICY_DENY"),
            Some(ErrorCode::PolicyDeny)
        );
        assert_eq!(
            ErrorCode::from_str("RESOURCE_NOT_ALLOWED"),
            Some(ErrorCode::ResourceNotAllowed)
        );
        assert_eq!(
            ErrorCode::from_str("LIMITS_EXCEEDED"),
            Some(ErrorCode::LimitsExceeded)
        );
        assert_eq!(
            ErrorCode::from_str("SANDBOX_INIT_FAIL"),
            Some(ErrorCode::SandboxInitFail)
        );
        assert_eq!(
            ErrorCode::from_str("SECURE_EXEC_ERROR"),
            Some(ErrorCode::SecureExecError)
        );
        assert_eq!(
            ErrorCode::from_str("RUNNER_ERROR"),
            Some(ErrorCode::RunnerError)
        );
        assert_eq!(
            ErrorCode::from_str("RESULT_PUBLISH_FAIL"),
            Some(ErrorCode::ResultPublishFail)
        );
        assert_eq!(ErrorCode::from_str("UNKNOWN_CODE"), None);
        assert_eq!(ErrorCode::from_str(""), None);
    }

    #[test]
    fn test_error_code_description() {
        assert!(ErrorCode::SigVerifyFail.description().contains("signature"));
        assert!(ErrorCode::IntentExpired
            .description()
            .contains("time-to-live"));
        assert!(ErrorCode::ReplayDetected.description().contains("replay"));
        assert!(ErrorCode::SchemaInvalid.description().contains("schema"));
        assert!(ErrorCode::PolicyDeny.description().contains("denied"));
        assert!(ErrorCode::ResourceNotAllowed
            .description()
            .contains("allowlist"));
        assert!(ErrorCode::LimitsExceeded.description().contains("limits"));
        assert!(ErrorCode::SandboxInitFail.description().contains("sandbox"));
        assert!(ErrorCode::SecureExecError
            .description()
            .contains("Security"));
        assert!(ErrorCode::RunnerError.description().contains("execution"));
        assert!(ErrorCode::ResultPublishFail.description().contains("NATS"));
    }

    #[test]
    fn test_error_code_is_retryable() {
        // Only ResultPublishFail should be retryable
        assert!(ErrorCode::ResultPublishFail.is_retryable());

        // All others should not be retryable
        assert!(!ErrorCode::SigVerifyFail.is_retryable());
        assert!(!ErrorCode::IntentExpired.is_retryable());
        assert!(!ErrorCode::ReplayDetected.is_retryable());
        assert!(!ErrorCode::SchemaInvalid.is_retryable());
        assert!(!ErrorCode::PolicyDeny.is_retryable());
        assert!(!ErrorCode::ResourceNotAllowed.is_retryable());
        assert!(!ErrorCode::LimitsExceeded.is_retryable());
        assert!(!ErrorCode::SandboxInitFail.is_retryable());
        assert!(!ErrorCode::SecureExecError.is_retryable());
        assert!(!ErrorCode::RunnerError.is_retryable());
    }

    #[test]
    fn test_error_code_retry_delay_ms() {
        // ResultPublishFail should have a retry delay
        assert_eq!(ErrorCode::ResultPublishFail.retry_delay_ms(), Some(1000));

        // Non-retryable errors should have no delay
        assert_eq!(ErrorCode::SigVerifyFail.retry_delay_ms(), None);
        assert_eq!(ErrorCode::IntentExpired.retry_delay_ms(), None);
        assert_eq!(ErrorCode::ReplayDetected.retry_delay_ms(), None);
        assert_eq!(ErrorCode::SchemaInvalid.retry_delay_ms(), None);
        assert_eq!(ErrorCode::PolicyDeny.retry_delay_ms(), None);
        assert_eq!(ErrorCode::ResourceNotAllowed.retry_delay_ms(), None);
        assert_eq!(ErrorCode::LimitsExceeded.retry_delay_ms(), None);
        assert_eq!(ErrorCode::SandboxInitFail.retry_delay_ms(), None);
        assert_eq!(ErrorCode::SecureExecError.retry_delay_ms(), None);
        assert_eq!(ErrorCode::RunnerError.retry_delay_ms(), None);
    }

    #[test]
    fn test_error_code_equality() {
        assert_eq!(ErrorCode::SigVerifyFail, ErrorCode::SigVerifyFail);
        assert_ne!(ErrorCode::SigVerifyFail, ErrorCode::IntentExpired);
    }

    #[test]
    fn test_error_code_debug() {
        let error = ErrorCode::PolicyDeny;
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("PolicyDeny"));
    }

    #[test]
    fn test_error_code_clone() {
        let error1 = ErrorCode::LimitsExceeded;
        let error2 = error1.clone();
        assert_eq!(error1, error2);
    }

    // ==================== IntentStatus Tests ====================

    #[test]
    fn test_intent_status_serialization() {
        let status = IntentStatus::Ok;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"ok\"");

        let status = IntentStatus::Denied;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"denied\"");

        let status = IntentStatus::Error;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"error\"");

        let status = IntentStatus::Expired;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"expired\"");
    }

    #[test]
    fn test_intent_status_deserialization() {
        let status: IntentStatus = serde_json::from_str("\"ok\"").unwrap();
        assert!(matches!(status, IntentStatus::Ok));

        let status: IntentStatus = serde_json::from_str("\"denied\"").unwrap();
        assert!(matches!(status, IntentStatus::Denied));

        let status: IntentStatus = serde_json::from_str("\"error\"").unwrap();
        assert!(matches!(status, IntentStatus::Error));

        let status: IntentStatus = serde_json::from_str("\"expired\"").unwrap();
        assert!(matches!(status, IntentStatus::Expired));
    }

    // ==================== Actor Tests ====================

    #[test]
    fn test_actor_serialization() {
        let actor = Actor {
            jwt: "eyJhbGciOiJIUzI1NiJ9.test".to_string(),
            tenant: "acme-corp".to_string(),
            key_id: "key-123".to_string(),
        };

        let json = serde_json::to_string(&actor).unwrap();
        assert!(json.contains("acme-corp"));
        assert!(json.contains("key-123"));

        let parsed: Actor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tenant, "acme-corp");
        assert_eq!(parsed.key_id, "key-123");
    }

    #[test]
    fn test_actor_equality() {
        let actor1 = Actor {
            jwt: "jwt1".to_string(),
            tenant: "tenant1".to_string(),
            key_id: "key1".to_string(),
        };
        let actor2 = Actor {
            jwt: "jwt1".to_string(),
            tenant: "tenant1".to_string(),
            key_id: "key1".to_string(),
        };
        let actor3 = Actor {
            jwt: "jwt2".to_string(),
            tenant: "tenant1".to_string(),
            key_id: "key1".to_string(),
        };

        assert_eq!(actor1, actor2);
        assert_ne!(actor1, actor3);
    }

    // ==================== Artifact Tests ====================

    #[test]
    fn test_artifact_serialization() {
        let artifact = Artifact {
            name: "output.log".to_string(),
            sha256: "abc123def456".to_string(),
            size: 1024,
            storage_uri: "s3://bucket/path/output.log".to_string(),
        };

        let json = serde_json::to_string(&artifact).unwrap();
        assert!(json.contains("output.log"));
        assert!(json.contains("1024"));

        let parsed: Artifact = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "output.log");
        assert_eq!(parsed.size, 1024);
    }

    // ==================== PolicyDecision Tests ====================

    #[test]
    fn test_policy_decision_serialization() {
        let decision = PolicyDecision {
            allow: true,
            capability_digest: "sha256:abc123".to_string(),
            runner_digest: "sha256:def456".to_string(),
            limits_applied: smith_protocol::ExecutionLimits::default(),
            scope: json!({"resources": ["fs.read"]}),
            transforms: Some(json!({"path_rewrite": true})),
        };

        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("true")); // allow
        assert!(json.contains("sha256:abc123"));

        let parsed: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert!(parsed.allow);
        assert_eq!(parsed.capability_digest, "sha256:abc123");
    }

    #[test]
    fn test_policy_decision_no_transforms() {
        let decision = PolicyDecision {
            allow: false,
            capability_digest: "sha256:cap".to_string(),
            runner_digest: "sha256:run".to_string(),
            limits_applied: smith_protocol::ExecutionLimits::default(),
            scope: json!({}),
            transforms: None,
        };

        let json = serde_json::to_string(&decision).unwrap();
        let parsed: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert!(!parsed.allow);
        assert!(parsed.transforms.is_none());
    }

    // ==================== IntentResult Tests ====================

    #[test]
    fn test_intent_result_serialization() {
        let result = IntentResult {
            intent_id: Uuid::new_v4(),
            seq: 1,
            status: IntentStatus::Ok,
            code: "SUCCESS".to_string(),
            started_at_ms: 1000,
            ended_at_ms: 2000,
            decision: PolicyDecision {
                allow: true,
                capability_digest: "sha256:cap".to_string(),
                runner_digest: "sha256:run".to_string(),
                limits_applied: smith_protocol::ExecutionLimits::default(),
                scope: json!({}),
                transforms: None,
            },
            stdout: Some("output text".to_string()),
            stderr: None,
            artifacts: vec![],
            retry_after_ms: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("output text"));
        assert!(json.contains("SUCCESS"));

        let parsed: IntentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "SUCCESS");
        assert!(parsed.stdout.is_some());
    }

    #[test]
    fn test_intent_result_with_retry() {
        let result = IntentResult {
            intent_id: Uuid::new_v4(),
            seq: 1,
            status: IntentStatus::Error,
            code: "RESULT_PUBLISH_FAIL".to_string(),
            started_at_ms: 1000,
            ended_at_ms: 2000,
            decision: PolicyDecision {
                allow: true,
                capability_digest: "sha256:cap".to_string(),
                runner_digest: "sha256:run".to_string(),
                limits_applied: smith_protocol::ExecutionLimits::default(),
                scope: json!({}),
                transforms: None,
            },
            stdout: None,
            stderr: Some("connection failed".to_string()),
            artifacts: vec![],
            retry_after_ms: Some(1000),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: IntentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.retry_after_ms, Some(1000));
        assert!(parsed.stderr.is_some());
    }

    // ==================== Intent Validation Tests ====================

    #[test]
    fn test_validate_nil_id() {
        let mut intent = create_test_intent();
        intent.id = Uuid::nil();
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nil"));
    }

    #[test]
    fn test_validate_zero_ttl() {
        let mut intent = create_test_intent();
        intent.ttl_s = 0;
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TTL"));
    }

    #[test]
    fn test_validate_excessive_ttl() {
        let mut intent = create_test_intent();
        intent.ttl_s = 7200; // More than 1 hour
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TTL"));
    }

    #[test]
    fn test_validate_zero_sequence() {
        let mut intent = create_test_intent();
        intent.seq = 0;
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Sequence"));
    }

    #[test]
    fn test_validate_invalid_nonce_length() {
        let mut intent = create_test_intent();
        intent.nonce = "abc".to_string(); // Too short
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nonce"));
    }

    #[test]
    fn test_validate_invalid_nonce_chars() {
        let mut intent = create_test_intent();
        intent.nonce = "gggggggggggggggggggggggggggggggg".to_string(); // Invalid hex
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hex"));
    }

    #[test]
    fn test_validate_empty_capability() {
        let mut intent = create_test_intent();
        intent.capability = "".to_string();
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Capability"));
    }

    #[test]
    fn test_validate_capability_without_dot() {
        let mut intent = create_test_intent();
        intent.capability = "fsread".to_string(); // Missing dot
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("category.action"));
    }

    #[test]
    fn test_validate_zero_version() {
        let mut intent = create_test_intent();
        intent.version = 0;
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Version"));
    }

    #[test]
    fn test_validate_excessive_version() {
        let mut intent = create_test_intent();
        intent.version = 101; // More than 100
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Version"));
    }

    #[test]
    fn test_validate_empty_resource() {
        let mut intent = create_test_intent();
        intent.resource = "".to_string();
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Resource"));
    }

    #[test]
    fn test_validate_empty_jwt() {
        let mut intent = create_test_intent();
        intent.actor.jwt = "".to_string();
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("JWT"));
    }

    #[test]
    fn test_validate_empty_tenant() {
        let mut intent = create_test_intent();
        intent.actor.tenant = "".to_string();
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tenant"));
    }

    #[test]
    fn test_validate_empty_key_id() {
        let mut intent = create_test_intent();
        intent.actor.key_id = "".to_string();
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key_id"));
    }

    #[test]
    fn test_validate_future_timestamp() {
        let mut intent = create_test_intent();
        intent.ts_ms = chrono::Utc::now().timestamp_millis() as u64 + 600_000; // 10 min in future
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        intent.sign(&signing_key).unwrap();

        let result = intent.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("future"));
    }

    #[test]
    fn test_verify_empty_signature() {
        let intent = create_test_intent();
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        // Signature is empty by default
        let result = intent.verify_signature(&verifying_key).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_invalid_signature_base64() {
        let mut intent = create_test_intent();
        intent.signature = "not-valid-base64!!!".to_string();

        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        let result = intent.verify_signature(&verifying_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_signature_length() {
        let mut intent = create_test_intent();
        intent.signature = "YWJjZGVm".to_string(); // Valid base64 but wrong length

        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        let result = intent.verify_signature(&verifying_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_intent_invalid_json() {
        let result = parse_intent(b"not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse"));
    }
}
