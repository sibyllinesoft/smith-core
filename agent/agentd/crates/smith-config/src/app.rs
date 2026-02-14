use anyhow::{Context, Result};
use once_cell::sync::OnceCell;

use crate::Config;

/// Global, lazily-initialized configuration cache.
///
/// Loads configuration once from the environment (including overrides) and
/// shares the resulting `Config` across all callers. This avoids repeated
/// env/file parsing throughout the process and centralizes configuration
/// injection at startup.
static GLOBAL_CONFIG: OnceCell<Config> = OnceCell::new();

/// Load configuration from the environment and cache it for subsequent calls.
///
/// The first caller populates the cache; later callers get the same instance.
pub fn load_from_env() -> Result<&'static Config> {
    GLOBAL_CONFIG.get_or_try_init(|| {
        let mut config = Config::from_env().context("Failed to load configuration")?;
        if let Err(err) = config.apply_env_overrides() {
            tracing::warn!(error = %err, "Failed to apply environment overrides; continuing with base config");
        }
        Ok(config)
    })
}

/// Get the cached configuration, assuming it has been loaded via `load_from_env`.
/// Panics if called before initialization.
pub fn get() -> &'static Config {
    GLOBAL_CONFIG
        .get()
        .expect("Config not initialized; call load_from_env first")
}
