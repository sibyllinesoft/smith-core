use crate::error::{ChatBridgeError, Result};
use crate::message::ChatPlatform;
use serde::{Deserialize, Serialize};

/// Scope of a session: either a group conversation or a direct message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionScope {
    Group { group_id: String },
    Dm { recipient_id: String },
}

/// A typed session key for routing messages to the correct agent session.
///
/// Format: `agent:<agent_id>:<channel>:<scope_type>:<scope_id>`
///
/// Examples:
/// - `agent:abc:telegram:dm:user123`
/// - `agent:abc:discord:group:guild-chan-42`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    pub agent_id: String,
    pub channel: ChatPlatform,
    pub scope: SessionScope,
}

impl SessionKey {
    /// Serialize to the canonical key string format.
    pub fn to_key_string(&self) -> String {
        let channel = format!("{:?}", self.channel).to_lowercase();
        match &self.scope {
            SessionScope::Group { group_id } => {
                format!("agent:{}:{}:group:{}", self.agent_id, channel, group_id)
            }
            SessionScope::Dm { recipient_id } => {
                format!("agent:{}:{}:dm:{}", self.agent_id, channel, recipient_id)
            }
        }
    }

    /// Parse a session key from its canonical string form.
    pub fn parse(key: &str) -> Result<Self> {
        let parts: Vec<&str> = key.splitn(5, ':').collect();
        if parts.len() != 5 || parts[0] != "agent" {
            return Err(ChatBridgeError::other(format!(
                "invalid session key format: {key}"
            )));
        }

        let agent_id = parts[1].to_string();
        let channel = parse_platform(parts[2])?;
        let scope = match parts[3] {
            "group" => SessionScope::Group {
                group_id: parts[4].to_string(),
            },
            "dm" => SessionScope::Dm {
                recipient_id: parts[4].to_string(),
            },
            other => {
                return Err(ChatBridgeError::other(format!(
                    "unknown session scope type: {other}"
                )));
            }
        };

        Ok(Self {
            agent_id,
            channel,
            scope,
        })
    }
}

fn parse_platform(s: &str) -> Result<ChatPlatform> {
    match s.to_lowercase().as_str() {
        "slack" => Ok(ChatPlatform::Slack),
        "teams" => Ok(ChatPlatform::Teams),
        "mattermost" => Ok(ChatPlatform::Mattermost),
        "telegram" => Ok(ChatPlatform::Telegram),
        "discord" => Ok(ChatPlatform::Discord),
        "whatsapp" => Ok(ChatPlatform::WhatsApp),
        "unknown" => Ok(ChatPlatform::Unknown),
        other => Err(ChatBridgeError::other(format!(
            "unknown chat platform: {other}"
        ))),
    }
}

impl std::fmt::Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_key_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dm_key_roundtrip() {
        let key = SessionKey {
            agent_id: "abc".into(),
            channel: ChatPlatform::Telegram,
            scope: SessionScope::Dm {
                recipient_id: "user123".into(),
            },
        };
        let s = key.to_key_string();
        assert_eq!(s, "agent:abc:telegram:dm:user123");

        let parsed = SessionKey::parse(&s).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn test_group_key_roundtrip() {
        let key = SessionKey {
            agent_id: "xyz".into(),
            channel: ChatPlatform::Discord,
            scope: SessionScope::Group {
                group_id: "guild-42".into(),
            },
        };
        let s = key.to_key_string();
        assert_eq!(s, "agent:xyz:discord:group:guild-42");

        let parsed = SessionKey::parse(&s).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn test_parse_invalid() {
        assert!(SessionKey::parse("invalid").is_err());
        assert!(SessionKey::parse("agent:a:telegram:unknown:x").is_err());
        assert!(SessionKey::parse("notanagent:a:telegram:dm:x").is_err());
    }

    #[test]
    fn test_display() {
        let key = SessionKey {
            agent_id: "a".into(),
            channel: ChatPlatform::WhatsApp,
            scope: SessionScope::Dm {
                recipient_id: "phone".into(),
            },
        };
        assert_eq!(format!("{key}"), "agent:a:whatsapp:dm:phone");
    }
}
