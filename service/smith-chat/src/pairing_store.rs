use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::Rng;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};

use crate::message::ChatPlatform;

/// Policy governing how DMs are handled before processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmPolicy {
    /// Users must submit a pairing code before messages are processed.
    Pairing,
    /// Users must be on an allowlist to send messages.
    Allowlist,
    /// All DMs are processed without restriction.
    Open,
}

impl Default for DmPolicy {
    fn default() -> Self {
        Self::Open
    }
}

impl std::str::FromStr for DmPolicy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pairing" => Ok(Self::Pairing),
            "allowlist" => Ok(Self::Allowlist),
            "open" => Ok(Self::Open),
            other => Err(format!("unknown DM policy: {other}")),
        }
    }
}

/// A pairing record linking a chat platform user to a Smith agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pairing {
    pub code: String,
    pub agent_id: String,
    pub platform: ChatPlatform,
    pub user_id: String,
    pub channel_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Redis-backed store for managing pairing codes and active pairings.
pub struct PairingStore {
    manager: ConnectionManager,
    /// TTL for unredeemed pairing codes (seconds).
    pub code_ttl_secs: u64,
    /// TTL for active (redeemed) pairings (seconds).
    pub pairing_ttl_secs: u64,
}

impl PairingStore {
    pub async fn new(
        redis_url: &str,
        code_ttl_secs: u64,
        pairing_ttl_secs: u64,
    ) -> Result<Self> {
        let client = redis::Client::open(redis_url.to_string())
            .with_context(|| format!("failed to open redis for pairing store: {redis_url}"))?;
        let manager = client
            .get_connection_manager()
            .await
            .context("failed to connect to redis for pairing store")?;
        Ok(Self {
            manager,
            code_ttl_secs,
            pairing_ttl_secs,
        })
    }

    /// Generate a short alphanumeric pairing code and store it mapped to `agent_id`.
    pub async fn create_code(&self, agent_id: &str) -> Result<String> {
        let code = generate_code();
        let key = Self::code_key(&code);
        let mut conn = self.manager.clone();
        conn.set_ex::<_, _, ()>(&key, agent_id, self.code_ttl_secs)
            .await
            .context("failed to store pairing code in redis")?;
        Ok(code)
    }

    /// Attempt to redeem a pairing code. If valid, creates an active pairing
    /// and deletes the code. Returns `None` if the code is expired or invalid.
    pub async fn redeem_code(
        &self,
        code: &str,
        platform: ChatPlatform,
        user_id: &str,
        channel_id: &str,
    ) -> Result<Option<Pairing>> {
        let code_key = Self::code_key(code);
        let mut conn = self.manager.clone();

        let agent_id: Option<String> = conn
            .get(&code_key)
            .await
            .context("failed to read pairing code from redis")?;

        let Some(agent_id) = agent_id else {
            return Ok(None);
        };

        // Delete the code so it can't be reused
        conn.del::<_, ()>(&code_key)
            .await
            .context("failed to delete redeemed pairing code")?;

        let now = Utc::now();
        let pairing = Pairing {
            code: code.to_string(),
            agent_id,
            platform,
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::seconds(self.pairing_ttl_secs as i64),
            metadata: serde_json::Value::Null,
        };

        let active_key = Self::active_key(platform, user_id);
        let payload = serde_json::to_string(&pairing)?;
        conn.set_ex::<_, _, ()>(&active_key, &payload, self.pairing_ttl_secs)
            .await
            .context("failed to store active pairing")?;

        Ok(Some(pairing))
    }

    /// Look up an existing active pairing for a platform user.
    pub async fn lookup_pairing(
        &self,
        platform: ChatPlatform,
        user_id: &str,
    ) -> Result<Option<Pairing>> {
        let key = Self::active_key(platform, user_id);
        let mut conn = self.manager.clone();
        let raw: Option<String> = conn
            .get(&key)
            .await
            .context("failed to read active pairing from redis")?;

        match raw {
            Some(data) => {
                let pairing: Pairing = serde_json::from_str(&data)
                    .context("failed to deserialize pairing record")?;
                Ok(Some(pairing))
            }
            None => Ok(None),
        }
    }

    /// Revoke an active pairing for a platform user.
    pub async fn revoke(&self, platform: ChatPlatform, user_id: &str) -> Result<()> {
        let key = Self::active_key(platform, user_id);
        let mut conn = self.manager.clone();
        conn.del::<_, ()>(&key)
            .await
            .context("failed to revoke pairing")?;
        Ok(())
    }

    fn code_key(code: &str) -> String {
        format!("chatbridge:pairing:code:{code}")
    }

    fn active_key(platform: ChatPlatform, user_id: &str) -> String {
        let platform_str = format!("{platform:?}").to_lowercase();
        format!("chatbridge:pairing:active:{platform_str}:{user_id}")
    }
}

/// Generate a 6-character alphanumeric code.
fn generate_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_format() {
        let code = generate_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_dm_policy_from_str() {
        assert_eq!("pairing".parse::<DmPolicy>().unwrap(), DmPolicy::Pairing);
        assert_eq!("allowlist".parse::<DmPolicy>().unwrap(), DmPolicy::Allowlist);
        assert_eq!("open".parse::<DmPolicy>().unwrap(), DmPolicy::Open);
        assert!("unknown".parse::<DmPolicy>().is_err());
    }

    #[test]
    fn test_code_key_format() {
        assert_eq!(
            PairingStore::code_key("ABC123"),
            "chatbridge:pairing:code:ABC123"
        );
    }

    #[test]
    fn test_active_key_format() {
        let key = PairingStore::active_key(ChatPlatform::Telegram, "user42");
        assert_eq!(key, "chatbridge:pairing:active:telegram:user42");
    }
}
