use anyhow::{bail, Result};
use regex::Regex;
use serde_json::Value;

use super::config::TransformDef;

/// Apply input-phase transforms (inject, default, rename, remove) to arguments.
pub fn apply_input_transforms(args: &mut Value, transforms: &[TransformDef]) -> Result<()> {
    let obj = match args.as_object_mut() {
        Some(o) => o,
        None => bail!("arguments must be a JSON object"),
    };

    for t in transforms {
        match t {
            TransformDef::Inject { key, value } => {
                obj.insert(key.clone(), Value::String(value.clone()));
            }
            TransformDef::Default { key, value } => {
                if !obj.contains_key(key) || obj.get(key) == Some(&Value::Null) {
                    obj.insert(key.clone(), Value::String(value.clone()));
                }
            }
            TransformDef::Rename { from, to } => {
                if let Some(val) = obj.remove(from) {
                    obj.insert(to.clone(), val);
                }
            }
            TransformDef::Remove { key } => {
                obj.remove(key);
            }
            // output-only transforms are no-ops in input phase
            TransformDef::Extract { .. }
            | TransformDef::Redact { .. }
            | TransformDef::Template { .. } => {}
        }
    }
    Ok(())
}

/// Apply output-phase transforms (extract, redact, template) to a result value.
pub fn apply_output_transforms(result: &mut Value, transforms: &[TransformDef]) -> Result<()> {
    for t in transforms {
        match t {
            TransformDef::Extract { pointer } => {
                let extracted = result
                    .pointer(pointer)
                    .cloned()
                    .unwrap_or(Value::Null);
                *result = extracted;
            }
            TransformDef::Redact {
                pattern,
                replacement,
            } => {
                let re = Regex::new(pattern)
                    .map_err(|e| anyhow::anyhow!("invalid redact regex '{}': {}", pattern, e))?;
                redact_strings(result, &re, replacement);
            }
            TransformDef::Template { template } => {
                let serialized = serde_json::to_string(result)?;
                let rendered = template.replace("{{value}}", &serialized);
                *result = match serde_json::from_str(&rendered) {
                    Ok(v) => v,
                    Err(_) => Value::String(rendered),
                };
            }
            // input-only transforms are no-ops in output phase
            TransformDef::Inject { .. }
            | TransformDef::Default { .. }
            | TransformDef::Rename { .. }
            | TransformDef::Remove { .. } => {}
        }
    }
    Ok(())
}

/// Recursively replace regex matches in all string values within the JSON tree.
fn redact_strings(value: &mut Value, re: &Regex, replacement: &str) {
    match value {
        Value::String(s) => {
            let replaced = re.replace_all(s, replacement);
            if replaced != *s {
                *s = replaced.into_owned();
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_strings(item, re, replacement);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                redact_strings(val, re, replacement);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Input transforms ────────────────────────────────────────────────

    #[test]
    fn inject_overwrites() {
        let mut args = json!({"key": "old"});
        let transforms = vec![TransformDef::Inject {
            key: "key".into(),
            value: "new".into(),
        }];
        apply_input_transforms(&mut args, &transforms).unwrap();
        assert_eq!(args["key"], "new");
    }

    #[test]
    fn inject_adds_missing() {
        let mut args = json!({});
        let transforms = vec![TransformDef::Inject {
            key: "api_key".into(),
            value: "secret".into(),
        }];
        apply_input_transforms(&mut args, &transforms).unwrap();
        assert_eq!(args["api_key"], "secret");
    }

    #[test]
    fn default_sets_when_absent() {
        let mut args = json!({});
        let transforms = vec![TransformDef::Default {
            key: "timeout".into(),
            value: "30".into(),
        }];
        apply_input_transforms(&mut args, &transforms).unwrap();
        assert_eq!(args["timeout"], "30");
    }

    #[test]
    fn default_skips_when_present() {
        let mut args = json!({"timeout": "60"});
        let transforms = vec![TransformDef::Default {
            key: "timeout".into(),
            value: "30".into(),
        }];
        apply_input_transforms(&mut args, &transforms).unwrap();
        assert_eq!(args["timeout"], "60");
    }

    #[test]
    fn default_overwrites_null() {
        let mut args = json!({"timeout": null});
        let transforms = vec![TransformDef::Default {
            key: "timeout".into(),
            value: "30".into(),
        }];
        apply_input_transforms(&mut args, &transforms).unwrap();
        assert_eq!(args["timeout"], "30");
    }

    #[test]
    fn rename_moves_key() {
        let mut args = json!({"query": "hello"});
        let transforms = vec![TransformDef::Rename {
            from: "query".into(),
            to: "search_query".into(),
        }];
        apply_input_transforms(&mut args, &transforms).unwrap();
        assert_eq!(args.get("query"), None);
        assert_eq!(args["search_query"], "hello");
    }

    #[test]
    fn rename_noop_when_absent() {
        let mut args = json!({"other": "val"});
        let transforms = vec![TransformDef::Rename {
            from: "query".into(),
            to: "search_query".into(),
        }];
        apply_input_transforms(&mut args, &transforms).unwrap();
        assert_eq!(args, json!({"other": "val"}));
    }

    #[test]
    fn remove_deletes_key() {
        let mut args = json!({"secret": "123", "keep": "yes"});
        let transforms = vec![TransformDef::Remove {
            key: "secret".into(),
        }];
        apply_input_transforms(&mut args, &transforms).unwrap();
        assert_eq!(args.get("secret"), None);
        assert_eq!(args["keep"], "yes");
    }

    // ── Output transforms ───────────────────────────────────────────────

    #[test]
    fn extract_json_pointer() {
        let mut result = json!({"results": [1, 2, 3], "meta": {}});
        let transforms = vec![TransformDef::Extract {
            pointer: "/results".into(),
        }];
        apply_output_transforms(&mut result, &transforms).unwrap();
        assert_eq!(result, json!([1, 2, 3]));
    }

    #[test]
    fn extract_missing_pointer_gives_null() {
        let mut result = json!({"a": 1});
        let transforms = vec![TransformDef::Extract {
            pointer: "/missing".into(),
        }];
        apply_output_transforms(&mut result, &transforms).unwrap();
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn redact_replaces_matches() {
        let mut result = json!({"key": "my token is sk-abcdefghijklmnopqrstuvwxyz"});
        let transforms = vec![TransformDef::Redact {
            pattern: "sk-[a-zA-Z0-9]{20,}".into(),
            replacement: "***".into(),
        }];
        apply_output_transforms(&mut result, &transforms).unwrap();
        assert_eq!(result["key"], "my token is ***");
    }

    #[test]
    fn redact_recursive() {
        let mut result = json!({
            "a": "sk-abcdefghijklmnopqrstuvwxyz",
            "b": ["sk-abcdefghijklmnopqrstuvwxyz"],
            "c": {"nested": "sk-abcdefghijklmnopqrstuvwxyz"}
        });
        let transforms = vec![TransformDef::Redact {
            pattern: "sk-[a-zA-Z0-9]{20,}".into(),
            replacement: "[REDACTED]".into(),
        }];
        apply_output_transforms(&mut result, &transforms).unwrap();
        assert_eq!(result["a"], "[REDACTED]");
        assert_eq!(result["b"][0], "[REDACTED]");
        assert_eq!(result["c"]["nested"], "[REDACTED]");
    }

    #[test]
    fn template_wraps_output() {
        let mut result = json!({"items": [1, 2]});
        let transforms = vec![TransformDef::Template {
            template: r#"{"wrapped": {{value}}, "version": 2}"#.into(),
        }];
        apply_output_transforms(&mut result, &transforms).unwrap();
        assert_eq!(result["wrapped"]["items"], json!([1, 2]));
        assert_eq!(result["version"], 2);
    }

    #[test]
    fn template_falls_back_to_string() {
        let mut result = json!("hello");
        let transforms = vec![TransformDef::Template {
            template: "Result: {{value}}".into(),
        }];
        apply_output_transforms(&mut result, &transforms).unwrap();
        assert_eq!(result, "Result: \"hello\"");
    }
}
