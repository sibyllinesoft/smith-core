//! JWT authentication provider
//!
//! Validates JSON Web Tokens and extracts identity claims.

use anyhow::{Context, Result};
use async_trait::async_trait;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::auth::{
    AuthProvider, AuthProviderStats, AuthResult, AuthzDecision, Credentials, Identity, TrustLevel,
};

/// JWT authentication provider
pub struct JwtProvider {
    config: JwtConfig,
    stats: ProviderStats,
}

/// JWT provider configuration
#[derive(Clone)]
pub struct JwtConfig {
    /// Verification key (secret or public key)
    pub verification_key: String,
    /// Expected issuer (optional)
    pub issuer: Option<String>,
    /// Expected audience (optional)
    pub audience: Option<String>,
    /// Algorithms to accept
    pub algorithms: Vec<Algorithm>,
    /// Leeway for time-based claims (seconds)
    pub leeway_seconds: u64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            verification_key: String::new(),
            issuer: None,
            audience: None,
            algorithms: vec![Algorithm::HS256, Algorithm::RS256],
            leeway_seconds: 60,
        }
    }
}

/// Standard JWT claims
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    /// Subject (user identifier)
    sub: Option<String>,
    /// Issuer
    iss: Option<String>,
    /// Audience
    aud: Option<String>,
    /// Expiration time
    exp: Option<i64>,
    /// Issued at
    iat: Option<i64>,
    /// Not before
    nbf: Option<i64>,
    /// JWT ID
    jti: Option<String>,
    /// Tenant (custom claim)
    tenant: Option<String>,
    /// Roles (custom claim)
    roles: Option<Vec<String>>,
    /// Additional claims
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

struct ProviderStats {
    auth_attempts: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    authz_checks: AtomicU64,
    authz_allowed: AtomicU64,
    authz_denied: AtomicU64,
}

impl JwtProvider {
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config,
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

    /// Create with default configuration (for development)
    pub fn new_with_defaults() -> Self {
        Self::new(JwtConfig::default())
    }

    fn extract_token<'a>(&self, creds: &'a Credentials) -> Option<&'a str> {
        match creds {
            Credentials::Bearer { token } => Some(token),
            _ => None,
        }
    }
}

#[async_trait]
impl AuthProvider for JwtProvider {
    fn name(&self) -> &str {
        "jwt"
    }

    fn auth_method(&self) -> &str {
        "jwt"
    }

    fn can_authenticate(&self, creds: &Credentials) -> bool {
        matches!(creds, Credentials::Bearer { .. })
    }

    async fn authenticate(&self, creds: &Credentials) -> Result<AuthResult> {
        self.stats.auth_attempts.fetch_add(1, Ordering::Relaxed);

        let token = match self.extract_token(creds) {
            Some(t) => t,
            None => {
                self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                return Ok(AuthResult::Failed {
                    reason: "JWT token not provided".to_string(),
                    permanent: true,
                });
            }
        };

        // Build validation
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = self.config.leeway_seconds;

        if let Some(ref iss) = self.config.issuer {
            validation.set_issuer(&[iss]);
        }

        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
        }

        // Decode and validate
        let key = if self.config.verification_key.is_empty() {
            // Development mode - accept any token structure but don't verify signature
            tracing::warn!("JWT verification key not configured - token signature not verified");
            DecodingKey::from_secret(b"development-key")
        } else {
            DecodingKey::from_secret(self.config.verification_key.as_bytes())
        };

        match decode::<JwtClaims>(token, &key, &validation) {
            Ok(token_data) => {
                self.stats.auth_successes.fetch_add(1, Ordering::Relaxed);

                let claims = token_data.claims;
                let subject = claims.sub.unwrap_or_else(|| "unknown".to_string());

                Ok(AuthResult::Success(Identity {
                    subject: subject.clone(),
                    identity_type: "user".to_string(),
                    tenant: claims.tenant,
                    auth_method: "jwt".to_string(),
                    claims: claims.extra,
                    roles: claims.roles.unwrap_or_default(),
                    authenticated_at: chrono::Utc::now(),
                    expires_at: claims
                        .exp
                        .map(|exp| chrono::DateTime::from_timestamp(exp, 0))
                        .flatten(),
                    trust_level: TrustLevel::Standard,
                }))
            }
            Err(e) => {
                self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                Ok(AuthResult::Failed {
                    reason: format!("JWT validation failed: {}", e),
                    permanent: true,
                })
            }
        }
    }

    async fn authorize(
        &self,
        identity: &Identity,
        capability: &str,
        _params: &serde_json::Value,
    ) -> Result<AuthzDecision> {
        self.stats.authz_checks.fetch_add(1, Ordering::Relaxed);

        // Basic role-based authorization
        // In a real implementation, this would check against a policy engine
        if identity.has_role("admin") || identity.has_role("user") {
            self.stats.authz_allowed.fetch_add(1, Ordering::Relaxed);
            Ok(AuthzDecision::allow("User has required role", "jwt-rbac"))
        } else {
            self.stats.authz_denied.fetch_add(1, Ordering::Relaxed);
            Ok(AuthzDecision::deny(
                "User does not have required role",
                "jwt-rbac",
            ))
        }
    }

    async fn validate_config(&self) -> Result<()> {
        if self.config.verification_key.is_empty() {
            tracing::warn!("JWT verification key not configured - running in development mode");
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
    fn test_jwt_provider_new() {
        let config = JwtConfig::default();
        let provider = JwtProvider::new(config);
        assert_eq!(provider.name(), "jwt");
        assert_eq!(provider.auth_method(), "jwt");
    }

    #[test]
    fn test_jwt_provider_new_with_defaults() {
        let provider = JwtProvider::new_with_defaults();
        assert_eq!(provider.name(), "jwt");
    }

    #[test]
    fn test_jwt_config_default() {
        let config = JwtConfig::default();
        assert!(config.verification_key.is_empty());
        assert!(config.issuer.is_none());
        assert!(config.audience.is_none());
        assert_eq!(config.leeway_seconds, 60);
        assert!(!config.algorithms.is_empty());
    }

    #[test]
    fn test_can_authenticate_bearer() {
        let provider = JwtProvider::new_with_defaults();
        let creds = Credentials::Bearer {
            token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9".to_string(),
        };
        assert!(provider.can_authenticate(&creds));
    }

    #[test]
    fn test_can_authenticate_non_bearer() {
        let provider = JwtProvider::new_with_defaults();
        let creds = Credentials::Anonymous;
        assert!(!provider.can_authenticate(&creds));
    }

    #[tokio::test]
    async fn test_authenticate_no_credentials() {
        let provider = JwtProvider::new_with_defaults();
        let creds = Credentials::Anonymous;

        let result = provider.authenticate(&creds).await.unwrap();
        match result {
            AuthResult::Success(_) => {
                panic!("Expected failure for no credentials");
            }
            AuthResult::Failed { reason, permanent } => {
                assert!(reason.contains("JWT token not provided"));
                assert!(permanent);
            }
            AuthResult::Challenge { .. } => panic!("Unexpected challenge"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_invalid_token() {
        let provider = JwtProvider::new_with_defaults();
        let creds = Credentials::Bearer {
            token: "invalid-jwt-token".to_string(),
        };

        let result = provider.authenticate(&creds).await.unwrap();
        match result {
            AuthResult::Success(_) => {
                panic!("Expected failure for invalid token");
            }
            AuthResult::Failed { reason, permanent } => {
                assert!(reason.contains("JWT validation failed"));
                assert!(permanent);
            }
            AuthResult::Challenge { .. } => {
                panic!("Unexpected challenge response");
            }
        }
    }

    #[tokio::test]
    async fn test_authenticate_valid_token() {
        // Create a valid JWT token
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test-secret-key";
        let config = JwtConfig {
            verification_key: secret.to_string(),
            ..Default::default()
        };
        let provider = JwtProvider::new(config);

        let claims = JwtClaims {
            sub: Some("test-user".to_string()),
            iss: None,
            aud: None,
            exp: Some(chrono::Utc::now().timestamp() + 3600), // 1 hour from now
            iat: Some(chrono::Utc::now().timestamp()),
            nbf: None,
            jti: None,
            tenant: Some("test-tenant".to_string()),
            roles: Some(vec!["user".to_string()]),
            extra: HashMap::new(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let creds = Credentials::Bearer { token };
        let result = provider.authenticate(&creds).await.unwrap();

        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "test-user");
                assert_eq!(identity.tenant, Some("test-tenant".to_string()));
                assert_eq!(identity.roles, vec!["user".to_string()]);
                assert_eq!(identity.auth_method, "jwt");
            }
            AuthResult::Failed { reason, .. } => {
                panic!("Expected success, got failure: {}", reason);
            }
            AuthResult::Challenge { .. } => {
                panic!("Unexpected challenge response");
            }
        }
    }

    #[tokio::test]
    async fn test_authorize_with_admin_role() {
        let provider = JwtProvider::new_with_defaults();

        let identity = Identity {
            subject: "test".to_string(),
            identity_type: "user".to_string(),
            tenant: None,
            auth_method: "jwt".to_string(),
            claims: HashMap::new(),
            roles: vec!["admin".to_string()],
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
    async fn test_authorize_with_user_role() {
        let provider = JwtProvider::new_with_defaults();

        let identity = Identity {
            subject: "test".to_string(),
            identity_type: "user".to_string(),
            tenant: None,
            auth_method: "jwt".to_string(),
            claims: HashMap::new(),
            roles: vec!["user".to_string()],
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
    async fn test_authorize_without_role() {
        let provider = JwtProvider::new_with_defaults();

        let identity = Identity {
            subject: "test".to_string(),
            identity_type: "user".to_string(),
            tenant: None,
            auth_method: "jwt".to_string(),
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

        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_validate_config() {
        let provider = JwtProvider::new_with_defaults();
        let result = provider.validate_config().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stats() {
        let provider = JwtProvider::new_with_defaults();

        let creds = Credentials::Bearer {
            token: "invalid".to_string(),
        };
        let _ = provider.authenticate(&creds).await;

        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 1);
        assert_eq!(stats.auth_failures, 1);
    }
}
