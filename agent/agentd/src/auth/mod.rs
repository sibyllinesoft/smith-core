//! Authentication provider implementations
//!
//! This module contains concrete implementations of the `AuthProvider` trait:
//! - `JwtProvider`: JSON Web Token validation
//! - `ApiKeyProvider`: API key authentication
//! - `PeerCredProvider`: Unix socket peer credentials
//! - `SignatureProvider`: Ed25519 request signing (Smith compatibility)
//! - `AllowAllProvider`: Permissive provider for development

pub mod allow_all;
pub mod api_key;
pub mod jwt;
pub mod peer_creds;
pub mod signature;

pub use allow_all::AllowAllProvider;
pub use api_key::ApiKeyProvider;
pub use jwt::JwtProvider;
pub use peer_creds::PeerCredProvider;
pub use signature::SignatureProvider;

use crate::core::auth::{AuthProvider, AuthProviderChain, AuthResult, Credentials};
use std::sync::Arc;

/// Create a default auth provider chain for development
pub fn development_auth_chain() -> AuthProviderChain {
    AuthProviderChain::new().add_provider(Box::new(AllowAllProvider::new()))
}

/// Create an auth provider chain from configuration
pub fn create_auth_chain(providers: &[String]) -> AuthProviderChain {
    let mut chain = AuthProviderChain::new();

    for provider_name in providers {
        match provider_name.as_str() {
            "allow-all" | "permissive" => {
                chain = chain.add_provider(Box::new(AllowAllProvider::new()));
            }
            "jwt" => {
                // JWT provider needs configuration - use defaults for now
                chain = chain.add_provider(Box::new(JwtProvider::new_with_defaults()));
            }
            "api-key" => {
                chain = chain.add_provider(Box::new(ApiKeyProvider::new()));
            }
            "peer-creds" | "peer-credentials" => {
                chain = chain.add_provider(Box::new(PeerCredProvider::new()));
            }
            "signature" | "ed25519" => {
                chain = chain.add_provider(Box::new(SignatureProvider::new()));
            }
            _ => {
                tracing::warn!("Unknown auth provider: {}", provider_name);
            }
        }
    }

    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_development_auth_chain() {
        // Just verify it creates without panic
        let _chain = development_auth_chain();
    }

    #[test]
    fn test_create_auth_chain_empty() {
        let _chain = create_auth_chain(&[]);
    }

    #[test]
    fn test_create_auth_chain_allow_all() {
        let _chain = create_auth_chain(&["allow-all".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_permissive() {
        let _chain = create_auth_chain(&["permissive".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_jwt() {
        let _chain = create_auth_chain(&["jwt".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_api_key() {
        let _chain = create_auth_chain(&["api-key".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_peer_creds() {
        let _chain = create_auth_chain(&["peer-creds".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_peer_credentials() {
        let _chain = create_auth_chain(&["peer-credentials".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_signature() {
        let _chain = create_auth_chain(&["signature".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_ed25519() {
        let _chain = create_auth_chain(&["ed25519".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_unknown() {
        // Unknown providers are skipped (with a warning log)
        let _chain = create_auth_chain(&["unknown-provider".to_string()]);
    }

    #[test]
    fn test_create_auth_chain_multiple() {
        let _chain = create_auth_chain(&[
            "allow-all".to_string(),
            "jwt".to_string(),
            "api-key".to_string(),
        ]);
    }

    #[test]
    fn test_create_auth_chain_with_unknown() {
        // Unknown should be skipped
        let _chain = create_auth_chain(&[
            "allow-all".to_string(),
            "unknown".to_string(),
            "jwt".to_string(),
        ]);
    }
}
