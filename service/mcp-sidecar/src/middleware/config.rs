use std::collections::HashMap;

use serde::Deserialize;

use super::env::interpolate_env;

// ── Top-level config ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MiddlewareConfig {
    #[serde(default)]
    pub global: GlobalMiddleware,
    #[serde(default)]
    pub tools: HashMap<String, ToolMiddleware>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GlobalMiddleware {
    #[serde(default)]
    pub input: TransformChain,
    #[serde(default)]
    pub output: TransformChain,
    #[serde(default)]
    pub filters: Vec<FilterDef>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ToolMiddleware {
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub input: TransformChain,
    #[serde(default)]
    pub output: TransformChain,
    #[serde(default)]
    pub filters: Vec<FilterDef>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TransformChain {
    #[serde(default)]
    pub transforms: Vec<TransformDef>,
}

// ── Transform definitions ───────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransformDef {
    Inject {
        key: String,
        value: String,
    },
    Default {
        key: String,
        value: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Remove {
        key: String,
    },
    Extract {
        pointer: String,
    },
    Redact {
        pattern: String,
        #[serde(default = "default_replacement")]
        replacement: String,
    },
    Template {
        template: String,
    },
}

fn default_replacement() -> String {
    "***".to_string()
}

// ── Filter definitions ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FilterDef {
    Block {
        #[serde(rename = "match")]
        matcher: MatchDef,
        message: String,
    },
    Require {
        key: String,
        message: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatchDef {
    pub key: String,
    pub pattern: String,
}

// ── Env interpolation pass ──────────────────────────────────────────────

impl MiddlewareConfig {
    /// Replace all `${VAR}` references in string fields with env values.
    pub fn interpolate_env(&mut self) {
        interpolate_global(&mut self.global);
        for tool in self.tools.values_mut() {
            interpolate_tool(tool);
        }
    }
}

fn interpolate_global(g: &mut GlobalMiddleware) {
    interpolate_transforms(&mut g.input.transforms);
    interpolate_transforms(&mut g.output.transforms);
    interpolate_filters(&mut g.filters);
}

fn interpolate_tool(t: &mut ToolMiddleware) {
    interpolate_transforms(&mut t.input.transforms);
    interpolate_transforms(&mut t.output.transforms);
    interpolate_filters(&mut t.filters);
}

fn interpolate_transforms(transforms: &mut [TransformDef]) {
    for t in transforms.iter_mut() {
        match t {
            TransformDef::Inject { key, value } => {
                *key = interpolate_env(key);
                *value = interpolate_env(value);
            }
            TransformDef::Default { key, value } => {
                *key = interpolate_env(key);
                *value = interpolate_env(value);
            }
            TransformDef::Rename { from, to } => {
                *from = interpolate_env(from);
                *to = interpolate_env(to);
            }
            TransformDef::Remove { key } => {
                *key = interpolate_env(key);
            }
            TransformDef::Extract { pointer } => {
                *pointer = interpolate_env(pointer);
            }
            TransformDef::Redact {
                pattern,
                replacement,
            } => {
                *pattern = interpolate_env(pattern);
                *replacement = interpolate_env(replacement);
            }
            TransformDef::Template { template } => {
                *template = interpolate_env(template);
            }
        }
    }
}

fn interpolate_filters(filters: &mut [FilterDef]) {
    for f in filters.iter_mut() {
        match f {
            FilterDef::Block { matcher, message } => {
                matcher.key = interpolate_env(&matcher.key);
                matcher.pattern = interpolate_env(&matcher.pattern);
                *message = interpolate_env(message);
            }
            FilterDef::Require { key, message } => {
                *key = interpolate_env(key);
                *message = interpolate_env(message);
            }
        }
    }
}
