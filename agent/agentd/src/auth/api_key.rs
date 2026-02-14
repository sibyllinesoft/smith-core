//! API key authentication provider
//!
//! Simple API key validation against a configured set of keys.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::auth::{
    AuthProvider, AuthProviderStats, AuthResult, AuthzDecision, Credentials, Identity, TrustLevel,
};

/// API key authentication provider
pub struct ApiKeyProvider {
    /// Map of API key to identity information
    keys: Arc<RwLock<HashMap<String, ApiKeyEntry>>>,
    stats: ProviderStats,
}

/// Entry for a registered API key
#[derive(Clone)]
pub struct ApiKeyEntry {
    pub key_id: String,
    pub subject: String,
    pub tenant: Option<String>,
    pub roles: Vec<String>,
    pub trust_level: TrustLevel,
}

struct ProviderStats {
    auth_attempts: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    authz_checks: AtomicU64,
    authz_allowed: AtomicU64,
    authz_denied: AtomicU64,
}

impl ApiKeyProvider {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
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

    /// Register an API key
    pub async fn register_key(&self, api_key: &str, entry: ApiKeyEntry) {
        let mut keys = self.keys.write().await;
        keys.insert(api_key.to_string(), entry);
    }

    /// Remove an API key
    pub async fn revoke_key(&self, api_key: &str) {
        let mut keys = self.keys.write().await;
        keys.remove(api_key);
    }

    fn extract_token<'a>(&self, creds: &'a Credentials) -> Option<&'a str> {
        match creds {
            Credentials::Bearer { token } => {
                // Strip "Bearer " prefix if present
                if let Some(stripped) = token.strip_prefix("Bearer ") {
                    Some(stripped)
                } else {
                    Some(token)
                }
            }
            _ => None,
        }
    }
}

impl Default for ApiKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthProvider for ApiKeyProvider {
    fn name(&self) -> &str {
        "api-key"
    }

    fn auth_method(&self) -> &str {
        "api-key"
    }

    fn can_authenticate(&self, creds: &Credentials) -> bool {
        matches!(creds, Credentials::Bearer { .. })
    }

    async fn authenticate(&self, creds: &Credentials) -> Result<AuthResult> {
        self.stats.auth_attempts.fetch_add(1, Ordering::Relaxed);

        let api_key = match self.extract_token(creds) {
            Some(k) => k,
            None => {
                self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                return Ok(AuthResult::Failed {
                    reason: "API key not provided".to_string(),
                    permanent: true,
                });
            }
        };

        let keys = self.keys.read().await;
        match keys.get(api_key) {
            Some(entry) => {
                self.stats.auth_successes.fetch_add(1, Ordering::Relaxed);
                Ok(AuthResult::Success(Identity {
                    subject: entry.subject.clone(),
                    identity_type: "service".to_string(),
                    tenant: entry.tenant.clone(),
                    auth_method: "api-key".to_string(),
                    claims: HashMap::new(),
                    roles: entry.roles.clone(),
                    authenticated_at: chrono::Utc::now(),
                    expires_at: None,
                    trust_level: entry.trust_level,
                }))
            }
            None => {
                self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                Ok(AuthResult::Failed {
                    reason: "Invalid API key".to_string(),
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

        // Simple authorization - if authenticated with API key, allow
        self.stats.authz_allowed.fetch_add(1, Ordering::Relaxed);
        Ok(AuthzDecision::allow(
            "API key holder authorized",
            "api-key-allow",
        ))
    }

    async fn validate_config(&self) -> Result<()> {
        let keys = self.keys.read().await;
        if keys.is_empty() {
            tracing::warn!("No API keys configured");
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

    #[test]
    fn test_api_key_provider_new() {
        let provider = ApiKeyProvider::new();
        assert_eq!(provider.name(), "api-key");
        assert_eq!(provider.auth_method(), "api-key");
    }

    #[test]
    fn test_api_key_provider_default() {
        let provider = ApiKeyProvider::default();
        assert_eq!(provider.name(), "api-key");
    }

    #[test]
    fn test_can_authenticate_bearer() {
        let provider = ApiKeyProvider::new();
        let creds = Credentials::Bearer {
            token: "test-key".to_string(),
        };
        assert!(provider.can_authenticate(&creds));
    }

    #[test]
    fn test_can_authenticate_non_bearer() {
        let provider = ApiKeyProvider::new();
        let creds = Credentials::Anonymous;
        assert!(!provider.can_authenticate(&creds));
    }

    #[tokio::test]
    async fn test_register_and_authenticate() {
        let provider = ApiKeyProvider::new();

        let entry = ApiKeyEntry {
            key_id: "key-1".to_string(),
            subject: "test-subject".to_string(),
            tenant: Some("test-tenant".to_string()),
            roles: vec!["admin".to_string()],
            trust_level: TrustLevel::Standard,
        };

        provider.register_key("secret-key-123", entry).await;

        let creds = Credentials::Bearer {
            token: "secret-key-123".to_string(),
        };

        let result = provider.authenticate(&creds).await.unwrap();
        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "test-subject");
                assert_eq!(identity.tenant, Some("test-tenant".to_string()));
                assert_eq!(identity.roles, vec!["admin".to_string()]);
            }
            AuthResult::Failed { reason, .. } => {
                panic!("Expected success, got failure: {}", reason);
            }
            AuthResult::Challenge { .. } => panic!("Unexpected challenge"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_invalid_key() {
        let provider = ApiKeyProvider::new();

        let creds = Credentials::Bearer {
            token: "invalid-key".to_string(),
        };

        let result = provider.authenticate(&creds).await.unwrap();
        match result {
            AuthResult::Success(_) => {
                panic!("Expected failure for invalid key");
            }
            AuthResult::Failed { reason, permanent } => {
                assert!(reason.contains("Invalid API key"));
                assert!(permanent);
            }
            AuthResult::Challenge { .. } => panic!("Unexpected challenge"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_no_credentials() {
        let provider = ApiKeyProvider::new();
        let creds = Credentials::Anonymous;

        let result = provider.authenticate(&creds).await.unwrap();
        match result {
            AuthResult::Success(_) => {
                panic!("Expected failure for no credentials");
            }
            AuthResult::Failed { reason, .. } => {
                assert!(reason.contains("API key not provided"));
            }
            AuthResult::Challenge { .. } => panic!("Unexpected challenge"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_bearer_prefix() {
        let provider = ApiKeyProvider::new();

        let entry = ApiKeyEntry {
            key_id: "key-1".to_string(),
            subject: "test-subject".to_string(),
            tenant: None,
            roles: vec![],
            trust_level: TrustLevel::Standard,
        };

        provider.register_key("my-api-key", entry).await;

        // Test with "Bearer " prefix
        let creds = Credentials::Bearer {
            token: "Bearer my-api-key".to_string(),
        };

        let result = provider.authenticate(&creds).await.unwrap();
        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "test-subject");
            }
            AuthResult::Failed { reason, .. } => {
                panic!("Expected success, got failure: {}", reason);
            }
            AuthResult::Challenge { .. } => panic!("Unexpected challenge"),
        }
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let provider = ApiKeyProvider::new();

        let entry = ApiKeyEntry {
            key_id: "key-1".to_string(),
            subject: "test-subject".to_string(),
            tenant: None,
            roles: vec![],
            trust_level: TrustLevel::Standard,
        };

        provider.register_key("test-key", entry).await;

        // First authentication should succeed
        let creds = Credentials::Bearer {
            token: "test-key".to_string(),
        };
        let result = provider.authenticate(&creds).await.unwrap();
        assert!(matches!(result, AuthResult::Success(_)));

        // Revoke the key
        provider.revoke_key("test-key").await;

        // Now authentication should fail
        let result = provider.authenticate(&creds).await.unwrap();
        assert!(matches!(result, AuthResult::Failed { .. }));
    }

    #[tokio::test]
    async fn test_authorize() {
        let provider = ApiKeyProvider::new();

        let identity = Identity {
            subject: "test".to_string(),
            identity_type: "service".to_string(),
            tenant: None,
            auth_method: "api-key".to_string(),
            claims: HashMap::new(),
            roles: vec![],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        let result = provider
            .authorize(&identity, "fs.read", &serde_json::json!({}))
            .await
            .unwrap();

        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_validate_config_empty() {
        let provider = ApiKeyProvider::new();
        let result = provider.validate_config().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stats() {
        let provider = ApiKeyProvider::new();

        // Do some operations
        let entry = ApiKeyEntry {
            key_id: "key-1".to_string(),
            subject: "test".to_string(),
            tenant: None,
            roles: vec![],
            trust_level: TrustLevel::Standard,
        };
        provider.register_key("key1", entry).await;

        let creds = Credentials::Bearer {
            token: "key1".to_string(),
        };
        let _ = provider.authenticate(&creds).await;

        let creds_invalid = Credentials::Bearer {
            token: "invalid".to_string(),
        };
        let _ = provider.authenticate(&creds_invalid).await;

        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 2);
        assert_eq!(stats.auth_successes, 1);
        assert_eq!(stats.auth_failures, 1);
    }

    #[test]
    fn test_api_key_entry_clone() {
        let entry = ApiKeyEntry {
            key_id: "key-1".to_string(),
            subject: "subject".to_string(),
            tenant: Some("tenant".to_string()),
            roles: vec!["admin".to_string()],
            trust_level: TrustLevel::Elevated,
        };

        let cloned = entry.clone();
        assert_eq!(cloned.key_id, entry.key_id);
        assert_eq!(cloned.subject, entry.subject);
    }
}
