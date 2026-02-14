//! Permissive auth provider for development
//!
//! This provider allows all requests without authentication.
//! Only use in development or trusted environments.

use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::core::auth::{
    AuthProvider, AuthProviderStats, AuthResult, AuthzDecision, Credentials, Identity, TrustLevel,
};

/// Permissive auth provider that allows all requests
pub struct AllowAllProvider {
    stats: ProviderStats,
}

struct ProviderStats {
    auth_attempts: AtomicU64,
    authz_checks: AtomicU64,
}

impl AllowAllProvider {
    pub fn new() -> Self {
        tracing::warn!(
            "AllowAllProvider enabled - all requests will be allowed without authentication"
        );
        Self {
            stats: ProviderStats {
                auth_attempts: AtomicU64::new(0),
                authz_checks: AtomicU64::new(0),
            },
        }
    }
}

impl Default for AllowAllProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthProvider for AllowAllProvider {
    fn name(&self) -> &str {
        "allow-all"
    }

    fn auth_method(&self) -> &str {
        "allow-all"
    }

    fn can_authenticate(&self, _creds: &Credentials) -> bool {
        true // Can handle any credentials
    }

    async fn authenticate(&self, _creds: &Credentials) -> Result<AuthResult> {
        self.stats.auth_attempts.fetch_add(1, Ordering::Relaxed);

        Ok(AuthResult::Success(Identity {
            subject: "anonymous".to_string(),
            identity_type: "anonymous".to_string(),
            tenant: None,
            auth_method: "allow-all".to_string(),
            claims: std::collections::HashMap::new(),
            roles: vec!["user".to_string()],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        }))
    }

    async fn authorize(
        &self,
        _identity: &Identity,
        _capability: &str,
        _params: &serde_json::Value,
    ) -> Result<AuthzDecision> {
        self.stats.authz_checks.fetch_add(1, Ordering::Relaxed);

        Ok(AuthzDecision::allow(
            "Development mode - all requests allowed",
            "allow-all",
        ))
    }

    async fn validate_config(&self) -> Result<()> {
        Ok(())
    }

    async fn stats(&self) -> AuthProviderStats {
        let attempts = self.stats.auth_attempts.load(Ordering::Relaxed);
        AuthProviderStats {
            auth_attempts: attempts,
            auth_successes: attempts, // All succeed
            auth_failures: 0,
            authz_checks: self.stats.authz_checks.load(Ordering::Relaxed),
            authz_allowed: self.stats.authz_checks.load(Ordering::Relaxed), // All allowed
            authz_denied: 0,
            avg_auth_latency_ms: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_allow_all_provider_new() {
        let provider = AllowAllProvider::new();
        assert_eq!(provider.name(), "allow-all");
        assert_eq!(provider.auth_method(), "allow-all");
    }

    #[test]
    fn test_allow_all_provider_default() {
        let provider = AllowAllProvider::default();
        assert_eq!(provider.name(), "allow-all");
    }

    #[test]
    fn test_can_authenticate_accepts_all() {
        let provider = AllowAllProvider::new();

        // Should accept any credential type
        assert!(provider.can_authenticate(&Credentials::Anonymous));
        assert!(provider.can_authenticate(&Credentials::Bearer {
            token: "test".to_string()
        }));
        assert!(provider.can_authenticate(&Credentials::PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: 12345,
        }));
        assert!(provider.can_authenticate(&Credentials::Signature {
            key_id: "test".to_string(),
            signature: "sig".to_string(),
            payload: vec![1, 2, 3],
        }));
    }

    #[tokio::test]
    async fn test_authenticate_anonymous() {
        let provider = AllowAllProvider::new();
        let result = provider
            .authenticate(&Credentials::Anonymous)
            .await
            .unwrap();

        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "anonymous");
                assert_eq!(identity.identity_type, "anonymous");
                assert_eq!(identity.auth_method, "allow-all");
                assert!(identity.roles.contains(&"user".to_string()));
                assert!(identity.tenant.is_none());
                assert_eq!(identity.trust_level, TrustLevel::Standard);
            }
            _ => panic!("Expected authentication success"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_with_bearer_token() {
        let provider = AllowAllProvider::new();
        let result = provider
            .authenticate(&Credentials::Bearer {
                token: "any-token".to_string(),
            })
            .await
            .unwrap();

        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "anonymous");
            }
            _ => panic!("Expected authentication success"),
        }
    }

    #[tokio::test]
    async fn test_authorize_always_allows() {
        let provider = AllowAllProvider::new();
        let identity = Identity {
            subject: "test-user".to_string(),
            identity_type: "user".to_string(),
            tenant: None,
            auth_method: "allow-all".to_string(),
            claims: HashMap::new(),
            roles: vec!["user".to_string()],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        let result = provider
            .authorize(&identity, "fs.read.v1", &serde_json::json!({}))
            .await
            .unwrap();

        assert!(result.allowed);
        assert!(result.reason.contains("Development mode"));
    }

    #[tokio::test]
    async fn test_authorize_any_capability() {
        let provider = AllowAllProvider::new();
        let identity = Identity {
            subject: "test".to_string(),
            identity_type: "user".to_string(),
            tenant: None,
            auth_method: "test".to_string(),
            claims: HashMap::new(),
            roles: vec![],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        // Should allow any capability
        for capability in &["fs.read.v1", "http.fetch.v1", "shell.exec.v1", "unknown"] {
            let result = provider
                .authorize(&identity, capability, &serde_json::json!({}))
                .await
                .unwrap();
            assert!(result.allowed, "Should allow capability: {}", capability);
        }
    }

    #[tokio::test]
    async fn test_validate_config() {
        let provider = AllowAllProvider::new();
        let result = provider.validate_config().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let provider = AllowAllProvider::new();

        // Initial stats should be zero
        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 0);
        assert_eq!(stats.auth_successes, 0);
        assert_eq!(stats.auth_failures, 0);
        assert_eq!(stats.authz_checks, 0);

        // Authenticate multiple times
        provider
            .authenticate(&Credentials::Anonymous)
            .await
            .unwrap();
        provider
            .authenticate(&Credentials::Anonymous)
            .await
            .unwrap();

        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 2);
        assert_eq!(stats.auth_successes, 2); // All succeed in allow-all
        assert_eq!(stats.auth_failures, 0);
    }

    #[tokio::test]
    async fn test_stats_authz_tracking() {
        let provider = AllowAllProvider::new();
        let identity = Identity {
            subject: "test".to_string(),
            identity_type: "user".to_string(),
            tenant: None,
            auth_method: "allow-all".to_string(),
            claims: HashMap::new(),
            roles: vec![],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        // Authorize multiple times
        provider
            .authorize(&identity, "cap1", &serde_json::json!({}))
            .await
            .unwrap();
        provider
            .authorize(&identity, "cap2", &serde_json::json!({}))
            .await
            .unwrap();
        provider
            .authorize(&identity, "cap3", &serde_json::json!({}))
            .await
            .unwrap();

        let stats = provider.stats().await;
        assert_eq!(stats.authz_checks, 3);
        assert_eq!(stats.authz_allowed, 3); // All allowed in allow-all
        assert_eq!(stats.authz_denied, 0);
    }
}
