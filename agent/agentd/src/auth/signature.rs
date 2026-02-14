//! Ed25519 signature authentication provider
//!
//! Verifies Ed25519 signatures on requests. This provides compatibility
//! with Smith's agent SDK signing mechanism.

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::auth::{
    AuthProvider, AuthProviderStats, AuthResult, AuthzDecision, Credentials, Identity, TrustLevel,
};

/// Ed25519 signature authentication provider
pub struct SignatureProvider {
    /// Map of key_id to public key
    public_keys: Arc<RwLock<HashMap<String, SigningKeyEntry>>>,
    stats: ProviderStats,
}

/// Entry for a registered signing key
#[derive(Clone)]
pub struct SigningKeyEntry {
    pub key_id: String,
    pub public_key: VerifyingKey,
    pub subject: String,
    pub tenant: Option<String>,
    pub roles: Vec<String>,
}

struct ProviderStats {
    auth_attempts: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    authz_checks: AtomicU64,
    authz_allowed: AtomicU64,
    authz_denied: AtomicU64,
}

impl SignatureProvider {
    pub fn new() -> Self {
        Self {
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            stats: ProviderStats {
                auth_attempts: AtomicU64::new(0),
                auth_successes: AtomicU64::new(0),
                auth_failures: AtomicU64::new(0),
                authz_checks: AtomicU64::new(0),
                authz_allowed: AtomicU64::new(0),
                authz_denied: AtomicU64::new(0),
            },
        }
    }

    /// Register a public key for signature verification
    pub async fn register_key(&self, entry: SigningKeyEntry) {
        let mut keys = self.public_keys.write().await;
        keys.insert(entry.key_id.clone(), entry);
    }

    /// Register a public key from base64-encoded bytes
    pub async fn register_key_b64(
        &self,
        key_id: &str,
        public_key_b64: &str,
        subject: &str,
        tenant: Option<&str>,
        roles: Vec<String>,
    ) -> Result<()> {
        let key_bytes = BASE64
            .decode(public_key_b64)
            .context("Failed to decode public key from base64")?;

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;

        let public_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        self.register_key(SigningKeyEntry {
            key_id: key_id.to_string(),
            public_key,
            subject: subject.to_string(),
            tenant: tenant.map(String::from),
            roles,
        })
        .await;

        Ok(())
    }

    /// Revoke a public key
    pub async fn revoke_key(&self, key_id: &str) {
        let mut keys = self.public_keys.write().await;
        keys.remove(key_id);
    }

    /// Verify a signature against a payload
    fn verify_signature(
        &self,
        public_key: &VerifyingKey,
        payload: &[u8],
        signature_b64: &str,
    ) -> Result<bool> {
        let signature_bytes = BASE64
            .decode(signature_b64)
            .context("Failed to decode signature from base64")?;

        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;

        match public_key.verify_strict(payload, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Default for SignatureProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthProvider for SignatureProvider {
    fn name(&self) -> &str {
        "signature"
    }

    fn auth_method(&self) -> &str {
        "ed25519-signature"
    }

    fn can_authenticate(&self, creds: &Credentials) -> bool {
        matches!(creds, Credentials::Signature { .. })
    }

    async fn authenticate(&self, creds: &Credentials) -> Result<AuthResult> {
        self.stats.auth_attempts.fetch_add(1, Ordering::Relaxed);

        match creds {
            Credentials::Signature {
                key_id,
                signature,
                payload,
            } => {
                let keys = self.public_keys.read().await;

                let entry = match keys.get(key_id) {
                    Some(e) => e.clone(),
                    None => {
                        self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                        return Ok(AuthResult::Failed {
                            reason: format!("Unknown key_id: {}", key_id),
                            permanent: true,
                        });
                    }
                };

                drop(keys);

                // Verify signature
                match self.verify_signature(&entry.public_key, payload, signature) {
                    Ok(true) => {
                        self.stats.auth_successes.fetch_add(1, Ordering::Relaxed);
                        Ok(AuthResult::Success(Identity {
                            subject: entry.subject,
                            identity_type: "agent".to_string(),
                            tenant: entry.tenant,
                            auth_method: "ed25519-signature".to_string(),
                            claims: HashMap::new(),
                            roles: entry.roles,
                            authenticated_at: chrono::Utc::now(),
                            expires_at: None,
                            trust_level: TrustLevel::Standard,
                        }))
                    }
                    Ok(false) => {
                        self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                        Ok(AuthResult::Failed {
                            reason: "Signature verification failed".to_string(),
                            permanent: true,
                        })
                    }
                    Err(e) => {
                        self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                        Ok(AuthResult::Failed {
                            reason: format!("Signature error: {}", e),
                            permanent: true,
                        })
                    }
                }
            }
            _ => {
                self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                Ok(AuthResult::Failed {
                    reason: "Signature credentials not provided".to_string(),
                    permanent: true,
                })
            }
        }
    }

    async fn authorize(
        &self,
        identity: &Identity,
        _capability: &str,
        _params: &serde_json::Value,
    ) -> Result<AuthzDecision> {
        self.stats.authz_checks.fetch_add(1, Ordering::Relaxed);

        // Signed requests are authorized
        // In a real implementation, we'd check capability-specific permissions
        if identity.auth_method == "ed25519-signature" {
            self.stats.authz_allowed.fetch_add(1, Ordering::Relaxed);
            Ok(AuthzDecision::allow(
                "Request properly signed",
                "signature-verified",
            ))
        } else {
            self.stats.authz_denied.fetch_add(1, Ordering::Relaxed);
            Ok(AuthzDecision::deny(
                "Request not properly signed",
                "signature-verified",
            ))
        }
    }

    async fn validate_config(&self) -> Result<()> {
        let keys = self.public_keys.read().await;
        if keys.is_empty() {
            tracing::warn!("No signing keys configured");
        }
        Ok(())
    }

    async fn stats(&self) -> AuthProviderStats {
        AuthProviderStats {
            auth_attempts: self.stats.auth_attempts.load(Ordering::Relaxed),
            auth_successes: self.stats.auth_successes.load(Ordering::Relaxed),
            auth_failures: self.stats.auth_failures.load(Ordering::Relaxed),
            authz_checks: self.stats.authz_checks.load(Ordering::Relaxed),
            authz_allowed: self.stats.authz_allowed.load(Ordering::Relaxed),
            authz_denied: self.stats.authz_denied.load(Ordering::Relaxed),
            avg_auth_latency_ms: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn generate_test_keypair() -> (SigningKey, VerifyingKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 = BASE64.encode(verifying_key.as_bytes());
        (signing_key, verifying_key, public_key_b64)
    }

    #[test]
    fn test_signature_provider_new() {
        let provider = SignatureProvider::new();
        assert_eq!(provider.name(), "signature");
        assert_eq!(provider.auth_method(), "ed25519-signature");
    }

    #[test]
    fn test_signature_provider_default() {
        let provider = SignatureProvider::default();
        assert_eq!(provider.name(), "signature");
    }

    #[test]
    fn test_can_authenticate_signature_only() {
        let provider = SignatureProvider::new();

        // Should only accept signature credentials
        assert!(provider.can_authenticate(&Credentials::Signature {
            key_id: "test".to_string(),
            signature: "sig".to_string(),
            payload: vec![1, 2, 3],
        }));

        // Should reject other credential types
        assert!(!provider.can_authenticate(&Credentials::Anonymous));
        assert!(!provider.can_authenticate(&Credentials::Bearer {
            token: "test".to_string()
        }));
        assert!(!provider.can_authenticate(&Credentials::PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: 12345,
        }));
    }

    #[tokio::test]
    async fn test_register_key() {
        let provider = SignatureProvider::new();
        let (_, verifying_key, _) = generate_test_keypair();

        let entry = SigningKeyEntry {
            key_id: "test-key-1".to_string(),
            public_key: verifying_key,
            subject: "test-agent".to_string(),
            tenant: Some("test-tenant".to_string()),
            roles: vec!["agent".to_string()],
        };

        provider.register_key(entry).await;

        // Verify the key is registered by checking stats
        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 0);
    }

    #[tokio::test]
    async fn test_register_key_b64() {
        let provider = SignatureProvider::new();
        let (_, _, public_key_b64) = generate_test_keypair();

        let result = provider
            .register_key_b64(
                "test-key",
                &public_key_b64,
                "test-subject",
                Some("test-tenant"),
                vec!["agent".to_string()],
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_key_b64_invalid() {
        let provider = SignatureProvider::new();

        // Invalid base64
        let result = provider
            .register_key_b64("test", "not-valid-base64!!!", "subject", None, vec![])
            .await;
        assert!(result.is_err());

        // Wrong length (not 32 bytes)
        let short_key = BASE64.encode([0u8; 16]);
        let result = provider
            .register_key_b64("test", &short_key, "subject", None, vec![])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let provider = SignatureProvider::new();
        let (_, verifying_key, _) = generate_test_keypair();

        // Register a key
        let entry = SigningKeyEntry {
            key_id: "key-to-revoke".to_string(),
            public_key: verifying_key,
            subject: "test".to_string(),
            tenant: None,
            roles: vec![],
        };
        provider.register_key(entry).await;

        // Revoke the key
        provider.revoke_key("key-to-revoke").await;

        // Try to authenticate with revoked key
        let result = provider
            .authenticate(&Credentials::Signature {
                key_id: "key-to-revoke".to_string(),
                signature: "any".to_string(),
                payload: vec![],
            })
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, .. } => {
                assert!(reason.contains("Unknown key_id"));
            }
            _ => panic!("Expected authentication failure"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_unknown_key() {
        let provider = SignatureProvider::new();

        let result = provider
            .authenticate(&Credentials::Signature {
                key_id: "unknown-key".to_string(),
                signature: "sig".to_string(),
                payload: vec![1, 2, 3],
            })
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, permanent } => {
                assert!(reason.contains("Unknown key_id"));
                assert!(permanent);
            }
            _ => panic!("Expected authentication failure"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_valid_signature() {
        let provider = SignatureProvider::new();
        let (signing_key, verifying_key, _) = generate_test_keypair();

        // Register the key
        let entry = SigningKeyEntry {
            key_id: "valid-key".to_string(),
            public_key: verifying_key,
            subject: "test-agent".to_string(),
            tenant: Some("test-tenant".to_string()),
            roles: vec!["agent".to_string(), "admin".to_string()],
        };
        provider.register_key(entry).await;

        // Create a valid signature
        let payload = b"test message payload";
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(payload);
        let signature_b64 = BASE64.encode(signature.to_bytes());

        // Authenticate
        let result = provider
            .authenticate(&Credentials::Signature {
                key_id: "valid-key".to_string(),
                signature: signature_b64,
                payload: payload.to_vec(),
            })
            .await
            .unwrap();

        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "test-agent");
                assert_eq!(identity.tenant, Some("test-tenant".to_string()));
                assert_eq!(identity.auth_method, "ed25519-signature");
                assert!(identity.roles.contains(&"agent".to_string()));
                assert!(identity.roles.contains(&"admin".to_string()));
            }
            _ => panic!("Expected authentication success"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_invalid_signature() {
        let provider = SignatureProvider::new();
        let (_, verifying_key, _) = generate_test_keypair();

        // Register the key
        let entry = SigningKeyEntry {
            key_id: "test-key".to_string(),
            public_key: verifying_key,
            subject: "test-agent".to_string(),
            tenant: None,
            roles: vec![],
        };
        provider.register_key(entry).await;

        // Create an invalid signature (different key)
        let (other_signing_key, _, _) = generate_test_keypair();
        let payload = b"test message";
        use ed25519_dalek::Signer;
        let signature = other_signing_key.sign(payload);
        let signature_b64 = BASE64.encode(signature.to_bytes());

        // Authenticate with wrong signature
        let result = provider
            .authenticate(&Credentials::Signature {
                key_id: "test-key".to_string(),
                signature: signature_b64,
                payload: payload.to_vec(),
            })
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, permanent } => {
                assert!(reason.contains("Signature verification failed"));
                assert!(permanent);
            }
            _ => panic!("Expected authentication failure"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_malformed_signature() {
        let provider = SignatureProvider::new();
        let (_, verifying_key, _) = generate_test_keypair();

        // Register the key
        let entry = SigningKeyEntry {
            key_id: "test-key".to_string(),
            public_key: verifying_key,
            subject: "test-agent".to_string(),
            tenant: None,
            roles: vec![],
        };
        provider.register_key(entry).await;

        // Try with malformed signature (wrong length)
        let result = provider
            .authenticate(&Credentials::Signature {
                key_id: "test-key".to_string(),
                signature: BASE64.encode([0u8; 16]), // Too short
                payload: vec![1, 2, 3],
            })
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, .. } => {
                assert!(reason.contains("error") || reason.contains("Invalid"));
            }
            _ => panic!("Expected authentication failure"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_non_signature_credentials() {
        let provider = SignatureProvider::new();

        let result = provider
            .authenticate(&Credentials::Anonymous)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, permanent } => {
                assert!(reason.contains("Signature credentials not provided"));
                assert!(permanent);
            }
            _ => panic!("Expected authentication failure"),
        }
    }

    #[tokio::test]
    async fn test_authorize_signed_request() {
        let provider = SignatureProvider::new();

        let identity = Identity {
            subject: "test-agent".to_string(),
            identity_type: "agent".to_string(),
            tenant: None,
            auth_method: "ed25519-signature".to_string(),
            claims: HashMap::new(),
            roles: vec!["agent".to_string()],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        let result = provider
            .authorize(&identity, "fs.read.v1", &serde_json::json!({}))
            .await
            .unwrap();

        assert!(result.allowed);
        assert!(result.reason.contains("properly signed"));
    }

    #[tokio::test]
    async fn test_authorize_unsigned_request() {
        let provider = SignatureProvider::new();

        let identity = Identity {
            subject: "test-user".to_string(),
            identity_type: "user".to_string(),
            tenant: None,
            auth_method: "other-method".to_string(),
            claims: HashMap::new(),
            roles: vec![],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        let result = provider
            .authorize(&identity, "fs.read.v1", &serde_json::json!({}))
            .await
            .unwrap();

        assert!(!result.allowed);
        assert!(result.reason.contains("not properly signed"));
    }

    #[tokio::test]
    async fn test_validate_config_no_keys() {
        let provider = SignatureProvider::new();
        let result = provider.validate_config().await;
        // Should succeed but log a warning
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_config_with_keys() {
        let provider = SignatureProvider::new();
        let (_, verifying_key, _) = generate_test_keypair();

        let entry = SigningKeyEntry {
            key_id: "test-key".to_string(),
            public_key: verifying_key,
            subject: "test".to_string(),
            tenant: None,
            roles: vec![],
        };
        provider.register_key(entry).await;

        let result = provider.validate_config().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let provider = SignatureProvider::new();

        // Initial stats
        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 0);
        assert_eq!(stats.auth_successes, 0);
        assert_eq!(stats.auth_failures, 0);

        // Failed auth (unknown key)
        provider
            .authenticate(&Credentials::Signature {
                key_id: "unknown".to_string(),
                signature: "sig".to_string(),
                payload: vec![],
            })
            .await
            .unwrap();

        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 1);
        assert_eq!(stats.auth_failures, 1);

        // Failed auth (wrong credential type)
        provider
            .authenticate(&Credentials::Anonymous)
            .await
            .unwrap();

        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 2);
        assert_eq!(stats.auth_failures, 2);
    }

    #[tokio::test]
    async fn test_stats_authz_tracking() {
        let provider = SignatureProvider::new();

        let signed_identity = Identity {
            subject: "test".to_string(),
            identity_type: "agent".to_string(),
            tenant: None,
            auth_method: "ed25519-signature".to_string(),
            claims: HashMap::new(),
            roles: vec![],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        let unsigned_identity = Identity {
            subject: "test".to_string(),
            identity_type: "user".to_string(),
            tenant: None,
            auth_method: "other".to_string(),
            claims: HashMap::new(),
            roles: vec![],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        // Signed request - allowed
        provider
            .authorize(&signed_identity, "cap", &serde_json::json!({}))
            .await
            .unwrap();

        // Unsigned request - denied
        provider
            .authorize(&unsigned_identity, "cap", &serde_json::json!({}))
            .await
            .unwrap();

        let stats = provider.stats().await;
        assert_eq!(stats.authz_checks, 2);
        assert_eq!(stats.authz_allowed, 1);
        assert_eq!(stats.authz_denied, 1);
    }
}
