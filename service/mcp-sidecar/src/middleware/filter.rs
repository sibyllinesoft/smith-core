use regex::Regex;
use serde_json::Value;

use super::config::FilterDef;

#[derive(Debug)]
pub enum FilterResult {
    Allow,
    Deny(String),
}

/// Evaluate a chain of filters against the given arguments.
/// Returns `Deny` on the first failing filter (short-circuit).
pub fn evaluate_filters(args: &Value, filters: &[FilterDef]) -> FilterResult {
    for filter in filters {
        match filter {
            FilterDef::Block { matcher, message } => {
                if let Some(val) = args.get(&matcher.key) {
                    let val_str = match val {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    match Regex::new(&matcher.pattern) {
                        Ok(re) => {
                            if re.is_match(&val_str) {
                                return FilterResult::Deny(message.clone());
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                pattern = %matcher.pattern,
                                error = %e,
                                "invalid block filter regex, skipping"
                            );
                        }
                    }
                }
            }
            FilterDef::Require { key, message } => {
                let missing = match args.get(key) {
                    None => true,
                    Some(Value::Null) => true,
                    _ => false,
                };
                if missing {
                    return FilterResult::Deny(message.clone());
                }
            }
        }
    }
    FilterResult::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use super::super::config::MatchDef;

    #[test]
    fn allow_when_no_filters() {
        let args = json!({"foo": "bar"});
        assert!(matches!(evaluate_filters(&args, &[]), FilterResult::Allow));
    }

    #[test]
    fn require_blocks_missing_key() {
        let args = json!({"other": "val"});
        let filters = vec![FilterDef::Require {
            key: "query".into(),
            message: "need query".into(),
        }];
        assert!(matches!(
            evaluate_filters(&args, &filters),
            FilterResult::Deny(_)
        ));
    }

    #[test]
    fn require_allows_present_key() {
        let args = json!({"query": "hello"});
        let filters = vec![FilterDef::Require {
            key: "query".into(),
            message: "need query".into(),
        }];
        assert!(matches!(
            evaluate_filters(&args, &filters),
            FilterResult::Allow
        ));
    }

    #[test]
    fn require_blocks_null_key() {
        let args = json!({"query": null});
        let filters = vec![FilterDef::Require {
            key: "query".into(),
            message: "need query".into(),
        }];
        assert!(matches!(
            evaluate_filters(&args, &filters),
            FilterResult::Deny(_)
        ));
    }

    #[test]
    fn block_denies_matching_pattern() {
        let args = json!({"path": "/etc/passwd"});
        let filters = vec![FilterDef::Block {
            matcher: MatchDef {
                key: "path".into(),
                pattern: "^/etc/.*".into(),
            },
            message: "forbidden".into(),
        }];
        assert!(matches!(
            evaluate_filters(&args, &filters),
            FilterResult::Deny(_)
        ));
    }

    #[test]
    fn block_allows_non_matching() {
        let args = json!({"path": "/home/user"});
        let filters = vec![FilterDef::Block {
            matcher: MatchDef {
                key: "path".into(),
                pattern: "^/etc/.*".into(),
            },
            message: "forbidden".into(),
        }];
        assert!(matches!(
            evaluate_filters(&args, &filters),
            FilterResult::Allow
        ));
    }

    #[test]
    fn block_allows_when_key_absent() {
        let args = json!({"other": "val"});
        let filters = vec![FilterDef::Block {
            matcher: MatchDef {
                key: "path".into(),
                pattern: "^/etc/.*".into(),
            },
            message: "forbidden".into(),
        }];
        assert!(matches!(
            evaluate_filters(&args, &filters),
            FilterResult::Allow
        ));
    }
}
