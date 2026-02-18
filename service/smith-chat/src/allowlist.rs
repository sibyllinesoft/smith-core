use crate::message::{ChatPlatform, Participant};
use serde::{Deserialize, Serialize};

/// Action to take when a rule matches (or as the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistAction {
    Allow,
    Deny,
}

/// Top-level allowlist configuration, typically loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    /// Action to take when no rule matches.
    #[serde(default = "AllowlistConfig::default_action")]
    pub default_action: AllowlistAction,
    /// Rules evaluated in order; first match wins.
    #[serde(default)]
    pub rules: Vec<AllowlistRule>,
}

impl AllowlistConfig {
    fn default_action() -> AllowlistAction {
        AllowlistAction::Deny
    }
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            default_action: AllowlistAction::Deny,
            rules: Vec::new(),
        }
    }
}

/// A single allowlist rule with an action and matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistRule {
    pub action: AllowlistAction,
    pub matcher: AllowlistMatcher,
}

/// Matchers for identifying participants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AllowlistMatcher {
    /// Matches everything.
    Wildcard,
    /// Match by platform user ID (exact).
    UserId { user_id: String },
    /// Match by username (exact, case-insensitive).
    Username { username: String },
    /// Match by display name (glob-style pattern).
    DisplayName { pattern: String },
    /// Match by tag (exact).
    Tag { tag: String },
    /// Match by platform.
    Platform { platform: ChatPlatform },
}

/// Evaluator wrapping an `AllowlistConfig`.
#[derive(Debug, Clone)]
pub struct Allowlist {
    config: AllowlistConfig,
}

impl Allowlist {
    pub fn new(config: AllowlistConfig) -> Self {
        Self { config }
    }

    /// Evaluate a participant against the allowlist rules.
    /// First matching rule wins; if none match, the default action applies.
    pub fn evaluate(&self, participant: &Participant, platform: ChatPlatform) -> AllowlistAction {
        for rule in &self.config.rules {
            if Self::matches(&rule.matcher, participant, platform) {
                return rule.action;
            }
        }
        self.config.default_action
    }

    fn matches(
        matcher: &AllowlistMatcher,
        participant: &Participant,
        platform: ChatPlatform,
    ) -> bool {
        match matcher {
            AllowlistMatcher::Wildcard => true,
            AllowlistMatcher::UserId { user_id } => participant.id == *user_id,
            AllowlistMatcher::Username { username } => participant
                .username
                .as_ref()
                .map(|u| u.eq_ignore_ascii_case(username))
                .unwrap_or(false),
            AllowlistMatcher::DisplayName { pattern } => participant
                .display_name
                .as_ref()
                .map(|name| glob_match(pattern, name))
                .unwrap_or(false),
            AllowlistMatcher::Tag { tag } => participant.tags.iter().any(|t| t == tag),
            AllowlistMatcher::Platform {
                platform: rule_platform,
            } => platform == *rule_platform,
        }
    }
}

/// Simple glob matching supporting `*` as a wildcard for any sequence of characters.
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let value = value.to_lowercase();

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match value[pos..].find(part) {
            Some(found) => {
                // First part must match at start
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }

    // Last part must match at end (unless pattern ends with *)
    if !pattern.ends_with('*') {
        return pos == value.len();
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::ParticipantRole;

    fn make_participant(id: &str, username: Option<&str>, tags: Vec<&str>) -> Participant {
        Participant {
            id: id.to_string(),
            display_name: Some(format!("User {id}")),
            role: ParticipantRole::User,
            username: username.map(|s| s.to_string()),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_wildcard_matches_everything() {
        let allowlist = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Deny,
            rules: vec![AllowlistRule {
                action: AllowlistAction::Allow,
                matcher: AllowlistMatcher::Wildcard,
            }],
        });

        let p = make_participant("123", None, vec![]);
        assert_eq!(
            allowlist.evaluate(&p, ChatPlatform::Telegram),
            AllowlistAction::Allow
        );
    }

    #[test]
    fn test_user_id_match() {
        let allowlist = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Deny,
            rules: vec![AllowlistRule {
                action: AllowlistAction::Allow,
                matcher: AllowlistMatcher::UserId {
                    user_id: "user42".into(),
                },
            }],
        });

        let allowed = make_participant("user42", None, vec![]);
        let denied = make_participant("user99", None, vec![]);
        assert_eq!(
            allowlist.evaluate(&allowed, ChatPlatform::Discord),
            AllowlistAction::Allow
        );
        assert_eq!(
            allowlist.evaluate(&denied, ChatPlatform::Discord),
            AllowlistAction::Deny
        );
    }

    #[test]
    fn test_username_case_insensitive() {
        let allowlist = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Deny,
            rules: vec![AllowlistRule {
                action: AllowlistAction::Allow,
                matcher: AllowlistMatcher::Username {
                    username: "Admin".into(),
                },
            }],
        });

        let p = make_participant("1", Some("admin"), vec![]);
        assert_eq!(
            allowlist.evaluate(&p, ChatPlatform::Telegram),
            AllowlistAction::Allow
        );
    }

    #[test]
    fn test_tag_match() {
        let allowlist = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Deny,
            rules: vec![AllowlistRule {
                action: AllowlistAction::Allow,
                matcher: AllowlistMatcher::Tag { tag: "vip".into() },
            }],
        });

        let vip = make_participant("1", None, vec!["vip", "beta"]);
        let regular = make_participant("2", None, vec!["beta"]);
        assert_eq!(
            allowlist.evaluate(&vip, ChatPlatform::Slack),
            AllowlistAction::Allow
        );
        assert_eq!(
            allowlist.evaluate(&regular, ChatPlatform::Slack),
            AllowlistAction::Deny
        );
    }

    #[test]
    fn test_platform_match() {
        let allowlist = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Deny,
            rules: vec![AllowlistRule {
                action: AllowlistAction::Allow,
                matcher: AllowlistMatcher::Platform {
                    platform: ChatPlatform::Telegram,
                },
            }],
        });

        let p = make_participant("1", None, vec![]);
        assert_eq!(
            allowlist.evaluate(&p, ChatPlatform::Telegram),
            AllowlistAction::Allow
        );
        assert_eq!(
            allowlist.evaluate(&p, ChatPlatform::Discord),
            AllowlistAction::Deny
        );
    }

    #[test]
    fn test_first_match_wins() {
        let allowlist = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Allow,
            rules: vec![
                AllowlistRule {
                    action: AllowlistAction::Deny,
                    matcher: AllowlistMatcher::UserId {
                        user_id: "blocked".into(),
                    },
                },
                AllowlistRule {
                    action: AllowlistAction::Allow,
                    matcher: AllowlistMatcher::Wildcard,
                },
            ],
        });

        let blocked = make_participant("blocked", None, vec![]);
        let other = make_participant("other", None, vec![]);
        assert_eq!(
            allowlist.evaluate(&blocked, ChatPlatform::Slack),
            AllowlistAction::Deny
        );
        assert_eq!(
            allowlist.evaluate(&other, ChatPlatform::Slack),
            AllowlistAction::Allow
        );
    }

    #[test]
    fn test_display_name_glob() {
        let allowlist = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Deny,
            rules: vec![AllowlistRule {
                action: AllowlistAction::Allow,
                matcher: AllowlistMatcher::DisplayName {
                    pattern: "Admin*".into(),
                },
            }],
        });

        let mut p = make_participant("1", None, vec![]);
        p.display_name = Some("Administrator".into());
        assert_eq!(
            allowlist.evaluate(&p, ChatPlatform::Slack),
            AllowlistAction::Allow
        );

        p.display_name = Some("Regular User".into());
        assert_eq!(
            allowlist.evaluate(&p, ChatPlatform::Slack),
            AllowlistAction::Deny
        );
    }

    #[test]
    fn test_glob_match_fn() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("hello*", "hello world"));
        assert!(glob_match("*world", "hello world"));
        assert!(glob_match("he*ld", "hello world"));
        assert!(!glob_match("hello", "hello world"));
        assert!(glob_match("hello", "hello"));
        assert!(glob_match("*o*o*", "foo bar boo"));
    }

    #[test]
    fn test_default_action_when_no_rules() {
        let deny_by_default = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Deny,
            rules: vec![],
        });

        let allow_by_default = Allowlist::new(AllowlistConfig {
            default_action: AllowlistAction::Allow,
            rules: vec![],
        });

        let p = make_participant("1", None, vec![]);
        assert_eq!(
            deny_by_default.evaluate(&p, ChatPlatform::Slack),
            AllowlistAction::Deny
        );
        assert_eq!(
            allow_by_default.evaluate(&p, ChatPlatform::Slack),
            AllowlistAction::Allow
        );
    }
}
