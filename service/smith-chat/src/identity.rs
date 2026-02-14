use crate::error::{ChatBridgeError, Result};
use crate::message::ChatPlatform;
use crate::pairing_store::Pairing;
use crate::session_key::SessionKey;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Identity claims attached to messages flowing through the chat bridge.
///
/// These map to `x-oc-*` headers when passed through ext_authz or injected
/// into upstream request metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityClaims {
    /// Chat platform (x-oc-channel)
    pub channel: ChatPlatform,
    /// Platform-specific user identifier (x-oc-principal)
    pub principal: String,
    /// Session key string (x-oc-session)
    pub session: String,
    /// Group identifier if in a group conversation (x-oc-group-id)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// Group display name (x-oc-group-name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    /// User display name (x-oc-display-name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Smith agent ID this session is paired with
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// When this identity was issued (JWT `iat`)
    #[serde(rename = "iat")]
    pub issued_at: DateTime<Utc>,
    /// When this identity expires (JWT `exp`)
    #[serde(rename = "exp")]
    pub expires_at: DateTime<Utc>,
}

impl IdentityClaims {
    /// Build identity claims from a pairing and session key.
    pub fn from_pairing(
        pairing: &Pairing,
        session_key: &SessionKey,
        display_name: Option<String>,
        group_name: Option<String>,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        let group_id = match &session_key.scope {
            crate::session_key::SessionScope::Group { group_id } => Some(group_id.clone()),
            _ => None,
        };

        Self {
            channel: pairing.platform,
            principal: pairing.user_id.clone(),
            session: session_key.to_key_string(),
            group_id,
            group_name,
            display_name,
            agent_id: Some(pairing.agent_id.clone()),
            issued_at: now,
            expires_at: now + ttl,
        }
    }

    /// Build identity claims directly from message context (no pairing required).
    pub fn from_context(
        platform: ChatPlatform,
        user_id: &str,
        session_key: &SessionKey,
        display_name: Option<String>,
        group_name: Option<String>,
        agent_id: Option<String>,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        let group_id = match &session_key.scope {
            crate::session_key::SessionScope::Group { group_id } => Some(group_id.clone()),
            _ => None,
        };

        Self {
            channel: platform,
            principal: user_id.to_string(),
            session: session_key.to_key_string(),
            group_id,
            group_name,
            display_name,
            agent_id,
            issued_at: now,
            expires_at: now + ttl,
        }
    }

    /// Encode the claims as a signed JWT.
    pub fn to_jwt(&self, secret: &[u8]) -> Result<String> {
        let token = encode(
            &Header::default(),
            &JwtClaims::from(self),
            &EncodingKey::from_secret(secret),
        )
        .map_err(|err| ChatBridgeError::other(format!("failed to encode JWT: {err}")))?;
        Ok(token)
    }

    /// Decode and verify a JWT into identity claims.
    pub fn from_jwt(token: &str, secret: &[u8]) -> Result<Self> {
        let data = decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(secret),
            &Validation::default(),
        )
        .map_err(|err| ChatBridgeError::other(format!("failed to decode JWT: {err}")))?;
        Ok(data.claims.into())
    }

    /// Convert to a metadata map suitable for embedding in messages or headers.
    pub fn to_metadata(&self) -> HashMap<String, Value> {
        let mut map = HashMap::new();
        map.insert(
            "x-oc-channel".to_string(),
            Value::String(format!("{:?}", self.channel).to_lowercase()),
        );
        map.insert(
            "x-oc-principal".to_string(),
            Value::String(self.principal.clone()),
        );
        map.insert(
            "x-oc-session".to_string(),
            Value::String(self.session.clone()),
        );
        if let Some(gid) = &self.group_id {
            map.insert("x-oc-group-id".to_string(), Value::String(gid.clone()));
        }
        if let Some(gn) = &self.group_name {
            map.insert("x-oc-group-name".to_string(), Value::String(gn.clone()));
        }
        if let Some(dn) = &self.display_name {
            map.insert("x-oc-display-name".to_string(), Value::String(dn.clone()));
        }
        if let Some(aid) = &self.agent_id {
            map.insert("x-oc-agent-id".to_string(), Value::String(aid.clone()));
        }
        map
    }
}

/// Internal JWT claims structure with numeric timestamps for jsonwebtoken compat.
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    channel: ChatPlatform,
    principal: String,
    session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    iat: i64,
    exp: i64,
}

impl From<&IdentityClaims> for JwtClaims {
    fn from(claims: &IdentityClaims) -> Self {
        Self {
            channel: claims.channel,
            principal: claims.principal.clone(),
            session: claims.session.clone(),
            group_id: claims.group_id.clone(),
            group_name: claims.group_name.clone(),
            display_name: claims.display_name.clone(),
            agent_id: claims.agent_id.clone(),
            iat: claims.issued_at.timestamp(),
            exp: claims.expires_at.timestamp(),
        }
    }
}

impl From<JwtClaims> for IdentityClaims {
    fn from(claims: JwtClaims) -> Self {
        Self {
            channel: claims.channel,
            principal: claims.principal,
            session: claims.session,
            group_id: claims.group_id,
            group_name: claims.group_name,
            display_name: claims.display_name,
            agent_id: claims.agent_id,
            issued_at: DateTime::<Utc>::from_timestamp(claims.iat, 0).unwrap_or_else(Utc::now),
            expires_at: DateTime::<Utc>::from_timestamp(claims.exp, 0).unwrap_or_else(Utc::now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_key::{SessionKey, SessionScope};

    #[test]
    fn test_jwt_roundtrip() {
        let session_key = SessionKey {
            agent_id: "agent-1".into(),
            channel: ChatPlatform::Telegram,
            scope: SessionScope::Dm {
                recipient_id: "user42".into(),
            },
        };

        let claims = IdentityClaims::from_context(
            ChatPlatform::Telegram,
            "user42",
            &session_key,
            Some("Alice".into()),
            None,
            Some("agent-1".into()),
            Duration::hours(1),
        );

        let secret = b"test-secret-key";
        let token = claims.to_jwt(secret).unwrap();
        let decoded = IdentityClaims::from_jwt(&token, secret).unwrap();

        assert_eq!(decoded.channel, ChatPlatform::Telegram);
        assert_eq!(decoded.principal, "user42");
        assert_eq!(decoded.agent_id.as_deref(), Some("agent-1"));
        assert_eq!(decoded.display_name.as_deref(), Some("Alice"));
        assert_eq!(decoded.session, session_key.to_key_string());
    }

    #[test]
    fn test_to_metadata() {
        let session_key = SessionKey {
            agent_id: "a".into(),
            channel: ChatPlatform::Discord,
            scope: SessionScope::Group {
                group_id: "g1".into(),
            },
        };

        let claims = IdentityClaims::from_context(
            ChatPlatform::Discord,
            "user1",
            &session_key,
            Some("Bob".into()),
            Some("Dev Team".into()),
            Some("a".into()),
            Duration::hours(1),
        );

        let meta = claims.to_metadata();
        assert_eq!(meta["x-oc-channel"].as_str(), Some("discord"));
        assert_eq!(meta["x-oc-principal"].as_str(), Some("user1"));
        assert_eq!(meta["x-oc-group-id"].as_str(), Some("g1"));
        assert_eq!(meta["x-oc-group-name"].as_str(), Some("Dev Team"));
        assert_eq!(meta["x-oc-display-name"].as_str(), Some("Bob"));
        assert_eq!(meta["x-oc-agent-id"].as_str(), Some("a"));
    }

    #[test]
    fn test_expired_jwt_rejected() {
        let session_key = SessionKey {
            agent_id: "a".into(),
            channel: ChatPlatform::Slack,
            scope: SessionScope::Dm {
                recipient_id: "u".into(),
            },
        };

        let mut claims = IdentityClaims::from_context(
            ChatPlatform::Slack,
            "u",
            &session_key,
            None,
            None,
            None,
            Duration::hours(1),
        );
        // Backdate to make it expired
        claims.issued_at = Utc::now() - Duration::hours(3);
        claims.expires_at = Utc::now() - Duration::hours(2);

        let secret = b"test-secret";
        let token = claims.to_jwt(secret).unwrap();
        assert!(IdentityClaims::from_jwt(&token, secret).is_err());
    }
}
