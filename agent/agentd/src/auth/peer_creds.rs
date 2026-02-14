//! Unix peer credentials authentication provider
//!
//! Extracts identity from Unix socket peer credentials (SO_PEERCRED).
//! This is useful for local IPC where the connecting process can be
//! identified by its UID/GID/PID.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::core::auth::{
    AuthProvider, AuthProviderStats, AuthResult, AuthzDecision, Credentials, Identity, TrustLevel,
};

/// Unix peer credentials authentication provider
pub struct PeerCredProvider {
    /// Mapping of UID to identity name (optional)
    uid_map: HashMap<u32, String>,
    /// UIDs that are trusted (granted elevated access)
    trusted_uids: Vec<u32>,
    stats: ProviderStats,
}

struct ProviderStats {
    auth_attempts: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    authz_checks: AtomicU64,
    authz_allowed: AtomicU64,
    authz_denied: AtomicU64,
}

impl PeerCredProvider {
    pub fn new() -> Self {
        Self {
            uid_map: HashMap::new(),
            trusted_uids: vec![0], // Root is trusted by default
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

    /// Add a UID to identity mapping
    pub fn map_uid(&mut self, uid: u32, name: String) {
        self.uid_map.insert(uid, name);
    }

    /// Add a trusted UID
    pub fn trust_uid(&mut self, uid: u32) {
        if !self.trusted_uids.contains(&uid) {
            self.trusted_uids.push(uid);
        }
    }

    /// Get username for UID (falls back to "uid:N")
    fn uid_to_name(&self, uid: u32) -> String {
        self.uid_map
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| format!("uid:{}", uid))
    }

    fn is_trusted(&self, uid: u32) -> bool {
        self.trusted_uids.contains(&uid)
    }
}

impl Default for PeerCredProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthProvider for PeerCredProvider {
    fn name(&self) -> &str {
        "peer-credentials"
    }

    fn auth_method(&self) -> &str {
        "peer-credentials"
    }

    fn can_authenticate(&self, creds: &Credentials) -> bool {
        matches!(creds, Credentials::PeerCredentials { .. })
    }

    async fn authenticate(&self, creds: &Credentials) -> Result<AuthResult> {
        self.stats.auth_attempts.fetch_add(1, Ordering::Relaxed);

        match creds {
            Credentials::PeerCredentials { uid, gid, pid } => {
                self.stats.auth_successes.fetch_add(1, Ordering::Relaxed);

                let subject = self.uid_to_name(*uid);
                let trust_level = if self.is_trusted(*uid) {
                    TrustLevel::Elevated
                } else {
                    TrustLevel::Standard
                };

                let mut claims = HashMap::new();
                claims.insert("uid".to_string(), serde_json::json!(uid));
                claims.insert("gid".to_string(), serde_json::json!(gid));
                claims.insert("pid".to_string(), serde_json::json!(pid));

                Ok(AuthResult::Success(Identity {
                    subject,
                    identity_type: "local-process".to_string(),
                    tenant: None,
                    auth_method: "peer-credentials".to_string(),
                    claims,
                    roles: if self.is_trusted(*uid) {
                        vec!["admin".to_string(), "user".to_string()]
                    } else {
                        vec!["user".to_string()]
                    },
                    authenticated_at: chrono::Utc::now(),
                    expires_at: None,
                    trust_level,
                }))
            }
            _ => {
                self.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                Ok(AuthResult::Failed {
                    reason: "Peer credentials not provided".to_string(),
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

        // For peer credentials, we trust local processes
        // In a real implementation, we might check against capability-specific policies
        if identity.trust_level >= TrustLevel::Standard {
            self.stats.authz_allowed.fetch_add(1, Ordering::Relaxed);
            Ok(AuthzDecision::allow(
                "Local process authorized",
                "peer-creds-local",
            ))
        } else {
            self.stats.authz_denied.fetch_add(1, Ordering::Relaxed);
            Ok(AuthzDecision::deny(
                "Insufficient trust level",
                "peer-creds-local",
            ))
        }
    }

    async fn validate_config(&self) -> Result<()> {
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
    fn test_peer_cred_provider_new() {
        let provider = PeerCredProvider::new();
        assert_eq!(provider.name(), "peer-credentials");
        assert_eq!(provider.auth_method(), "peer-credentials");
        // Root (UID 0) is trusted by default
        assert!(provider.is_trusted(0));
    }

    #[test]
    fn test_peer_cred_provider_default() {
        let provider = PeerCredProvider::default();
        assert_eq!(provider.name(), "peer-credentials");
    }

    #[test]
    fn test_can_authenticate_peer_creds_only() {
        let provider = PeerCredProvider::new();

        // Should only accept peer credentials
        assert!(provider.can_authenticate(&Credentials::PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: 12345,
        }));

        // Should reject other credential types
        assert!(!provider.can_authenticate(&Credentials::Anonymous));
        assert!(!provider.can_authenticate(&Credentials::Bearer {
            token: "test".to_string()
        }));
        assert!(!provider.can_authenticate(&Credentials::Signature {
            key_id: "test".to_string(),
            signature: "sig".to_string(),
            payload: vec![1, 2, 3],
        }));
    }

    #[test]
    fn test_map_uid() {
        let mut provider = PeerCredProvider::new();

        // Initially no mapping
        assert_eq!(provider.uid_to_name(1000), "uid:1000");

        // Add mapping
        provider.map_uid(1000, "alice".to_string());
        assert_eq!(provider.uid_to_name(1000), "alice");

        // Unknown UID still falls back
        assert_eq!(provider.uid_to_name(1001), "uid:1001");
    }

    #[test]
    fn test_trust_uid() {
        let mut provider = PeerCredProvider::new();

        // Root is trusted by default
        assert!(provider.is_trusted(0));
        assert!(!provider.is_trusted(1000));

        // Add trusted UID
        provider.trust_uid(1000);
        assert!(provider.is_trusted(1000));

        // Adding same UID again shouldn't duplicate
        provider.trust_uid(1000);
        assert_eq!(provider.trusted_uids.len(), 2);
    }

    #[test]
    fn test_uid_to_name_with_map() {
        let mut provider = PeerCredProvider::new();
        provider.map_uid(0, "root".to_string());
        provider.map_uid(1000, "bob".to_string());
        provider.map_uid(65534, "nobody".to_string());

        assert_eq!(provider.uid_to_name(0), "root");
        assert_eq!(provider.uid_to_name(1000), "bob");
        assert_eq!(provider.uid_to_name(65534), "nobody");
        assert_eq!(provider.uid_to_name(9999), "uid:9999");
    }

    #[tokio::test]
    async fn test_authenticate_peer_credentials() {
        let provider = PeerCredProvider::new();

        let result = provider
            .authenticate(&Credentials::PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            })
            .await
            .unwrap();

        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "uid:1000");
                assert_eq!(identity.identity_type, "local-process");
                assert_eq!(identity.auth_method, "peer-credentials");
                assert_eq!(identity.trust_level, TrustLevel::Standard);
                assert!(identity.roles.contains(&"user".to_string()));
                assert!(!identity.roles.contains(&"admin".to_string()));

                // Check claims
                assert_eq!(identity.claims.get("uid"), Some(&serde_json::json!(1000)));
                assert_eq!(identity.claims.get("gid"), Some(&serde_json::json!(1000)));
                assert_eq!(identity.claims.get("pid"), Some(&serde_json::json!(12345)));
            }
            _ => panic!("Expected authentication success"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_root_elevated() {
        let provider = PeerCredProvider::new();

        let result = provider
            .authenticate(&Credentials::PeerCredentials {
                uid: 0,
                gid: 0,
                pid: 1,
            })
            .await
            .unwrap();

        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "uid:0");
                assert_eq!(identity.trust_level, TrustLevel::Elevated);
                assert!(identity.roles.contains(&"admin".to_string()));
                assert!(identity.roles.contains(&"user".to_string()));
            }
            _ => panic!("Expected authentication success"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_with_uid_map() {
        let mut provider = PeerCredProvider::new();
        provider.map_uid(1000, "smith-agent".to_string());

        let result = provider
            .authenticate(&Credentials::PeerCredentials {
                uid: 1000,
                gid: 100,
                pid: 9876,
            })
            .await
            .unwrap();

        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.subject, "smith-agent");
            }
            _ => panic!("Expected authentication success"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_trusted_uid() {
        let mut provider = PeerCredProvider::new();
        provider.trust_uid(1000);

        let result = provider
            .authenticate(&Credentials::PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: 5555,
            })
            .await
            .unwrap();

        match result {
            AuthResult::Success(identity) => {
                assert_eq!(identity.trust_level, TrustLevel::Elevated);
                assert!(identity.roles.contains(&"admin".to_string()));
            }
            _ => panic!("Expected authentication success"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_non_peer_creds() {
        let provider = PeerCredProvider::new();

        let result = provider
            .authenticate(&Credentials::Anonymous)
            .await
            .unwrap();

        match result {
            AuthResult::Failed { reason, permanent } => {
                assert!(reason.contains("Peer credentials not provided"));
                assert!(permanent);
            }
            _ => panic!("Expected authentication failure"),
        }
    }

    #[tokio::test]
    async fn test_authorize_standard_trust() {
        let provider = PeerCredProvider::new();

        let identity = Identity {
            subject: "uid:1000".to_string(),
            identity_type: "local-process".to_string(),
            tenant: None,
            auth_method: "peer-credentials".to_string(),
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
        assert!(result.reason.contains("Local process authorized"));
    }

    #[tokio::test]
    async fn test_authorize_elevated_trust() {
        let provider = PeerCredProvider::new();

        let identity = Identity {
            subject: "root".to_string(),
            identity_type: "local-process".to_string(),
            tenant: None,
            auth_method: "peer-credentials".to_string(),
            claims: HashMap::new(),
            roles: vec!["admin".to_string(), "user".to_string()],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Elevated,
        };

        let result = provider
            .authorize(&identity, "shell.exec.v1", &serde_json::json!({}))
            .await
            .unwrap();

        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_validate_config() {
        let provider = PeerCredProvider::new();
        let result = provider.validate_config().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let provider = PeerCredProvider::new();

        // Initial stats
        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 0);
        assert_eq!(stats.auth_successes, 0);
        assert_eq!(stats.auth_failures, 0);

        // Successful auth
        provider
            .authenticate(&Credentials::PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: 1234,
            })
            .await
            .unwrap();

        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 1);
        assert_eq!(stats.auth_successes, 1);
        assert_eq!(stats.auth_failures, 0);

        // Failed auth
        provider
            .authenticate(&Credentials::Anonymous)
            .await
            .unwrap();

        let stats = provider.stats().await;
        assert_eq!(stats.auth_attempts, 2);
        assert_eq!(stats.auth_successes, 1);
        assert_eq!(stats.auth_failures, 1);
    }

    #[tokio::test]
    async fn test_stats_authz_tracking() {
        let provider = PeerCredProvider::new();

        let identity = Identity {
            subject: "test".to_string(),
            identity_type: "local-process".to_string(),
            tenant: None,
            auth_method: "peer-credentials".to_string(),
            claims: HashMap::new(),
            roles: vec!["user".to_string()],
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
            trust_level: TrustLevel::Standard,
        };

        // Make some authz calls
        provider
            .authorize(&identity, "cap1", &serde_json::json!({}))
            .await
            .unwrap();
        provider
            .authorize(&identity, "cap2", &serde_json::json!({}))
            .await
            .unwrap();

        let stats = provider.stats().await;
        assert_eq!(stats.authz_checks, 2);
        assert_eq!(stats.authz_allowed, 2);
        assert_eq!(stats.authz_denied, 0);
    }
}
