//! Authentication provider traits
//!
//! This module defines the core traits for authentication providers that
//! verify client identity and authorize capability access. Implementations include:
//! - `MtlsProvider`: Client certificate authentication
//! - `JwtProvider`: JSON Web Token validation
//! - `ApiKeyProvider`: API key authentication
//! - `PeerCredProvider`: Unix socket peer credentials (SO_PEERCRED)
//! - `SignatureProvider`: Ed25519 request signing (Smith compatibility)

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Credentials extracted from a request
#[derive(Debug, Clone)]
pub enum Credentials {
    /// No credentials provided
    Anonymous,

    /// Bearer token (JWT or API key)
    Bearer { token: String },

    /// Client certificate
    Certificate {
        subject: String,
        issuer: String,
        fingerprint: String,
        /// DER-encoded certificate bytes
        der: Vec<u8>,
    },

    /// Unix peer credentials
    PeerCredentials { uid: u32, gid: u32, pid: u32 },

    /// Ed25519 signed request
    Signature {
        key_id: String,
        signature: String,
        /// The signed payload (for verification)
        payload: Vec<u8>,
    },

    /// Multiple credentials (for fallback/combination)
    Multiple(Vec<Credentials>),
}

impl Credentials {
    /// Check if any credentials are present
    pub fn is_anonymous(&self) -> bool {
        matches!(self, Credentials::Anonymous)
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        match self {
            Credentials::Anonymous => "anonymous".to_string(),
            Credentials::Bearer { .. } => "bearer token".to_string(),
            Credentials::Certificate { subject, .. } => format!("certificate: {}", subject),
            Credentials::PeerCredentials { uid, .. } => format!("peer uid:{}", uid),
            Credentials::Signature { key_id, .. } => format!("signature key:{}", key_id),
            Credentials::Multiple(creds) => {
                format!("multiple ({} methods)", creds.len())
            }
        }
    }
}

/// Authenticated identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique subject identifier
    pub subject: String,

    /// Identity type (e.g., "user", "service", "agent")
    pub identity_type: String,

    /// Tenant/organization identifier
    pub tenant: Option<String>,

    /// Authentication method used
    pub auth_method: String,

    /// Additional claims from the authentication
    pub claims: HashMap<String, serde_json::Value>,

    /// Roles assigned to this identity
    pub roles: Vec<String>,

    /// When authentication occurred
    pub authenticated_at: chrono::DateTime<chrono::Utc>,

    /// When the identity expires (if applicable)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Trust level (for graduated trust)
    pub trust_level: TrustLevel,
}

impl Identity {
    /// Create a new identity
    pub fn new(subject: &str, identity_type: &str, auth_method: &str) -> Self {
        Self {
            subject: subject.to_string(),
            identity_type: identity_type.to_string(),
            tenant: None,
            auth_method: auth_method.to_string(),
            claims: HashMap::new(),
            roles: vec![],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        }
    }

    /// Check if the identity has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if the identity has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            chrono::Utc::now() > expires
        } else {
            false
        }
    }

    /// Get a claim value
    pub fn get_claim<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.claims
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

/// Trust level for graduated authorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Untrusted - minimal permissions
    Untrusted = 0,
    /// Low trust - basic read operations only
    Low = 1,
    /// Standard trust - normal operations
    Standard = 2,
    /// Elevated trust - sensitive operations
    Elevated = 3,
    /// Full trust - all operations including admin
    Full = 4,
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::Standard
    }
}

/// Authorization decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzDecision {
    /// Whether access is allowed
    pub allowed: bool,

    /// Reason for the decision
    pub reason: String,

    /// Policy that made the decision
    pub policy: String,

    /// Any constraints applied (e.g., rate limits, path restrictions)
    pub constraints: Option<AuthzConstraints>,

    /// Audit information
    pub audit_info: Option<AuditInfo>,
}

impl AuthzDecision {
    /// Create an allow decision
    pub fn allow(reason: &str, policy: &str) -> Self {
        Self {
            allowed: true,
            reason: reason.to_string(),
            policy: policy.to_string(),
            constraints: None,
            audit_info: None,
        }
    }

    /// Create a deny decision
    pub fn deny(reason: &str, policy: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_string(),
            policy: policy.to_string(),
            constraints: None,
            audit_info: None,
        }
    }

    /// Add constraints to the decision
    pub fn with_constraints(mut self, constraints: AuthzConstraints) -> Self {
        self.constraints = Some(constraints);
        self
    }
}

/// Constraints applied by authorization
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthzConstraints {
    /// Maximum output size allowed
    pub max_output_bytes: Option<u64>,

    /// Maximum execution time allowed
    pub max_duration_ms: Option<u64>,

    /// Paths that must be filtered out of results
    pub filtered_paths: Vec<String>,

    /// Rate limit (requests per minute)
    pub rate_limit_rpm: Option<u32>,

    /// Whether results should be redacted
    pub redact_output: bool,

    /// Custom constraints (policy-specific)
    pub custom: HashMap<String, serde_json::Value>,
}

/// Audit information for authorization decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditInfo {
    /// Unique audit event ID
    pub audit_id: String,

    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Additional context for audit
    pub context: HashMap<String, String>,
}

/// Authentication result
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication successful
    Success(Identity),

    /// Authentication failed
    Failed {
        reason: String,
        /// Whether this is a permanent failure (vs. temporary like rate limiting)
        permanent: bool,
    },

    /// More information needed (e.g., for multi-factor)
    Challenge {
        challenge_type: String,
        challenge_data: serde_json::Value,
    },
}

impl AuthResult {
    pub fn is_success(&self) -> bool {
        matches!(self, AuthResult::Success(_))
    }

    pub fn identity(&self) -> Option<&Identity> {
        match self {
            AuthResult::Success(id) => Some(id),
            _ => None,
        }
    }
}

/// Trait for authentication providers
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Get the name of this provider
    fn name(&self) -> &str;

    /// Get the authentication method this provider handles
    fn auth_method(&self) -> &str;

    /// Check if this provider can handle the given credentials
    fn can_authenticate(&self, creds: &Credentials) -> bool;

    /// Authenticate using the provided credentials
    async fn authenticate(&self, creds: &Credentials) -> Result<AuthResult>;

    /// Authorize an authenticated identity for a capability
    ///
    /// This performs policy evaluation to determine if the identity
    /// is allowed to use the specified capability with the given parameters.
    async fn authorize(
        &self,
        identity: &Identity,
        capability: &str,
        params: &serde_json::Value,
    ) -> Result<AuthzDecision>;

    /// Validate that the provider is properly configured
    async fn validate_config(&self) -> Result<()>;

    /// Get provider-specific statistics
    async fn stats(&self) -> AuthProviderStats;
}

/// Statistics for an auth provider
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthProviderStats {
    /// Total authentication attempts
    pub auth_attempts: u64,

    /// Successful authentications
    pub auth_successes: u64,

    /// Failed authentications
    pub auth_failures: u64,

    /// Total authorization checks
    pub authz_checks: u64,

    /// Allowed authorization decisions
    pub authz_allowed: u64,

    /// Denied authorization decisions
    pub authz_denied: u64,

    /// Average authentication latency in milliseconds
    pub avg_auth_latency_ms: f64,
}

/// Chain of auth providers that tries each in sequence
pub struct AuthProviderChain {
    providers: Vec<Box<dyn AuthProvider>>,
}

impl AuthProviderChain {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn add_provider(mut self, provider: Box<dyn AuthProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Try to authenticate using each provider in sequence
    pub async fn authenticate(&self, creds: &Credentials) -> Result<AuthResult> {
        for provider in &self.providers {
            if provider.can_authenticate(creds) {
                let result = provider.authenticate(creds).await?;
                if result.is_success() {
                    return Ok(result);
                }
            }
        }

        Ok(AuthResult::Failed {
            reason: "No provider could authenticate the credentials".to_string(),
            permanent: true,
        })
    }
}

impl Default for AuthProviderChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Credentials Tests =====

    #[test]
    fn test_credentials_anonymous() {
        let creds = Credentials::Anonymous;
        assert!(creds.is_anonymous());
        assert_eq!(creds.description(), "anonymous");
    }

    #[test]
    fn test_credentials_bearer() {
        let creds = Credentials::Bearer {
            token: "test-token".to_string(),
        };
        assert!(!creds.is_anonymous());
        assert_eq!(creds.description(), "bearer token");
    }

    #[test]
    fn test_credentials_certificate() {
        let creds = Credentials::Certificate {
            subject: "CN=test-user".to_string(),
            issuer: "CN=test-ca".to_string(),
            fingerprint: "abc123".to_string(),
            der: vec![1, 2, 3],
        };
        assert!(!creds.is_anonymous());
        assert_eq!(creds.description(), "certificate: CN=test-user");
    }

    #[test]
    fn test_credentials_peer_credentials() {
        let creds = Credentials::PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: 12345,
        };
        assert!(!creds.is_anonymous());
        assert_eq!(creds.description(), "peer uid:1000");
    }

    #[test]
    fn test_credentials_signature() {
        let creds = Credentials::Signature {
            key_id: "key-123".to_string(),
            signature: "sig-abc".to_string(),
            payload: vec![1, 2, 3],
        };
        assert!(!creds.is_anonymous());
        assert_eq!(creds.description(), "signature key:key-123");
    }

    #[test]
    fn test_credentials_multiple() {
        let creds = Credentials::Multiple(vec![
            Credentials::Anonymous,
            Credentials::Bearer {
                token: "test".to_string(),
            },
        ]);
        assert!(!creds.is_anonymous());
        assert_eq!(creds.description(), "multiple (2 methods)");
    }

    // ===== Identity Tests =====

    #[test]
    fn test_identity_new() {
        let identity = Identity::new("user-123", "user", "jwt");
        assert_eq!(identity.subject, "user-123");
        assert_eq!(identity.identity_type, "user");
        assert_eq!(identity.auth_method, "jwt");
        assert!(identity.tenant.is_none());
        assert!(identity.roles.is_empty());
        assert_eq!(identity.trust_level, TrustLevel::Standard);
    }

    #[test]
    fn test_identity_has_role() {
        let mut identity = Identity::new("user-123", "user", "jwt");
        identity.roles = vec!["admin".to_string(), "user".to_string()];

        assert!(identity.has_role("admin"));
        assert!(identity.has_role("user"));
        assert!(!identity.has_role("superuser"));
    }

    #[test]
    fn test_identity_is_expired_none() {
        let identity = Identity::new("user-123", "user", "jwt");
        // No expiry set, so should not be expired
        assert!(!identity.is_expired());
    }

    #[test]
    fn test_identity_is_expired_future() {
        let mut identity = Identity::new("user-123", "user", "jwt");
        identity.expires_at = Some(chrono::Utc::now() + chrono::Duration::hours(1));
        assert!(!identity.is_expired());
    }

    #[test]
    fn test_identity_is_expired_past() {
        let mut identity = Identity::new("user-123", "user", "jwt");
        identity.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        assert!(identity.is_expired());
    }

    #[test]
    fn test_identity_get_claim() {
        let mut identity = Identity::new("user-123", "user", "jwt");
        identity
            .claims
            .insert("email".to_string(), serde_json::json!("user@example.com"));
        identity
            .claims
            .insert("level".to_string(), serde_json::json!(5));

        let email: Option<String> = identity.get_claim("email");
        assert_eq!(email, Some("user@example.com".to_string()));

        let level: Option<i32> = identity.get_claim("level");
        assert_eq!(level, Some(5));

        let missing: Option<String> = identity.get_claim("nonexistent");
        assert!(missing.is_none());
    }

    // ===== TrustLevel Tests =====

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Untrusted < TrustLevel::Low);
        assert!(TrustLevel::Low < TrustLevel::Standard);
        assert!(TrustLevel::Standard < TrustLevel::Elevated);
        assert!(TrustLevel::Elevated < TrustLevel::Full);
    }

    #[test]
    fn test_trust_level_default() {
        let level = TrustLevel::default();
        assert_eq!(level, TrustLevel::Standard);
    }

    #[test]
    fn test_trust_level_values() {
        assert_eq!(TrustLevel::Untrusted as i32, 0);
        assert_eq!(TrustLevel::Low as i32, 1);
        assert_eq!(TrustLevel::Standard as i32, 2);
        assert_eq!(TrustLevel::Elevated as i32, 3);
        assert_eq!(TrustLevel::Full as i32, 4);
    }

    // ===== AuthzDecision Tests =====

    #[test]
    fn test_authz_decision_allow() {
        let decision = AuthzDecision::allow("User is authorized", "default-policy");
        assert!(decision.allowed);
        assert_eq!(decision.reason, "User is authorized");
        assert_eq!(decision.policy, "default-policy");
        assert!(decision.constraints.is_none());
    }

    #[test]
    fn test_authz_decision_deny() {
        let decision = AuthzDecision::deny("Access forbidden", "security-policy");
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "Access forbidden");
        assert_eq!(decision.policy, "security-policy");
    }

    #[test]
    fn test_authz_decision_with_constraints() {
        let constraints = AuthzConstraints {
            max_output_bytes: Some(1024),
            max_duration_ms: Some(5000),
            rate_limit_rpm: Some(60),
            ..Default::default()
        };

        let decision = AuthzDecision::allow("Allowed with limits", "rate-limit-policy")
            .with_constraints(constraints);

        assert!(decision.constraints.is_some());
        let c = decision.constraints.unwrap();
        assert_eq!(c.max_output_bytes, Some(1024));
        assert_eq!(c.max_duration_ms, Some(5000));
        assert_eq!(c.rate_limit_rpm, Some(60));
    }

    // ===== AuthzConstraints Tests =====

    #[test]
    fn test_authz_constraints_default() {
        let constraints = AuthzConstraints::default();
        assert!(constraints.max_output_bytes.is_none());
        assert!(constraints.max_duration_ms.is_none());
        assert!(constraints.filtered_paths.is_empty());
        assert!(constraints.rate_limit_rpm.is_none());
        assert!(!constraints.redact_output);
        assert!(constraints.custom.is_empty());
    }

    // ===== AuthResult Tests =====

    #[test]
    fn test_auth_result_success() {
        let identity = Identity::new("user-123", "user", "jwt");
        let result = AuthResult::Success(identity);

        assert!(result.is_success());
        assert!(result.identity().is_some());
        assert_eq!(result.identity().unwrap().subject, "user-123");
    }

    #[test]
    fn test_auth_result_failed() {
        let result = AuthResult::Failed {
            reason: "Invalid token".to_string(),
            permanent: true,
        };

        assert!(!result.is_success());
        assert!(result.identity().is_none());
    }

    #[test]
    fn test_auth_result_challenge() {
        let result = AuthResult::Challenge {
            challenge_type: "totp".to_string(),
            challenge_data: serde_json::json!({"message": "Enter 2FA code"}),
        };

        assert!(!result.is_success());
        assert!(result.identity().is_none());
    }

    // ===== AuthProviderChain Tests =====

    #[test]
    fn test_auth_provider_chain_new() {
        let chain = AuthProviderChain::new();
        assert!(chain.providers.is_empty());
    }

    #[test]
    fn test_auth_provider_chain_default() {
        let chain = AuthProviderChain::default();
        assert!(chain.providers.is_empty());
    }

    // ===== AuthProviderStats Tests =====

    #[test]
    fn test_auth_provider_stats_default() {
        let stats = AuthProviderStats::default();
        assert_eq!(stats.auth_attempts, 0);
        assert_eq!(stats.auth_successes, 0);
        assert_eq!(stats.auth_failures, 0);
        assert_eq!(stats.authz_checks, 0);
        assert_eq!(stats.authz_allowed, 0);
        assert_eq!(stats.authz_denied, 0);
        assert_eq!(stats.avg_auth_latency_ms, 0.0);
    }

    // ===== Serialization Tests =====

    #[test]
    fn test_identity_serialization() {
        let identity = Identity::new("user-123", "service", "mtls");
        let json = serde_json::to_string(&identity).unwrap();
        let deserialized: Identity = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.subject, identity.subject);
        assert_eq!(deserialized.identity_type, identity.identity_type);
        assert_eq!(deserialized.auth_method, identity.auth_method);
    }

    #[test]
    fn test_trust_level_serialization() {
        let level = TrustLevel::Elevated;
        let json = serde_json::to_string(&level).unwrap();
        let deserialized: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, TrustLevel::Elevated);
    }

    #[test]
    fn test_authz_decision_serialization() {
        let decision = AuthzDecision::allow("test reason", "test-policy");
        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: AuthzDecision = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.allowed, decision.allowed);
        assert_eq!(deserialized.reason, decision.reason);
        assert_eq!(deserialized.policy, decision.policy);
    }

    #[test]
    fn test_audit_info_creation() {
        let audit = AuditInfo {
            audit_id: "audit-123".to_string(),
            timestamp: chrono::Utc::now(),
            context: HashMap::new(),
        };

        assert_eq!(audit.audit_id, "audit-123");
        assert!(audit.context.is_empty());
    }
}
