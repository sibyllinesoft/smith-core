pub mod config;
pub mod env;
pub mod filter;
pub mod transform;

use std::path::Path;

use anyhow::{Context, Result};

pub use config::MiddlewareConfig;

impl MiddlewareConfig {
    /// Load middleware config from a TOML file, performing env var interpolation.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read middleware config: {}", path.display()))?;

        let mut config: MiddlewareConfig = toml::from_str(&content)
            .with_context(|| format!("failed to parse middleware config: {}", path.display()))?;

        config.interpolate_env();

        tracing::info!(
            path = %path.display(),
            global_input_transforms = config.global.input.transforms.len(),
            global_output_transforms = config.global.output.transforms.len(),
            global_filters = config.global.filters.len(),
            tool_overrides = config.tools.len(),
            "loaded middleware config"
        );

        Ok(config)
    }
}
