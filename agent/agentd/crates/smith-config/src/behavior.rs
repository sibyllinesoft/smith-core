//! Behavior pack configuration management
//!
//! This module handles loading, validation, and hot-reloading of behavior packs
//! that define which capabilities are enabled for different execution modes.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Execution mode for behavior packs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum BehaviorMode {
    /// Strict mode: No direct atom usage, macros/playbooks only
    #[default]
    Strict,
    /// Explore mode: Direct atom usage allowed with risk/cost multipliers  
    Explore,
    /// Shadow mode: No actual execution, logging and metrics only
    Shadow,
}

/// Capability enablement configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnabledCapabilities {
    /// Enabled atomic capabilities
    pub atoms: Vec<String>,
    /// Enabled macro capabilities
    pub macros: Vec<String>,
    /// Enabled playbook capabilities
    pub playbooks: Vec<String>,
}

/// Parameter overrides for specific capabilities
pub type CapabilityParams = HashMap<String, serde_json::Value>;

/// Guard configuration for capability layers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    /// Atom-level guards
    pub atoms: Option<AtomGuards>,
    /// Macro-level guards
    pub macros: Option<MacroGuards>,
    /// Playbook-level guards
    pub playbooks: Option<PlaybookGuards>,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            atoms: Some(AtomGuards::default()),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        }
    }
}

/// Guards specific to atomic capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomGuards {
    /// Default maximum bytes for file operations
    pub default_max_bytes: u64,
    /// Require justification for direct atom usage
    pub require_justification: bool,
}

impl Default for AtomGuards {
    fn default() -> Self {
        Self {
            default_max_bytes: 1048576, // 1MB default
            require_justification: true,
        }
    }
}

/// Guards specific to macro capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroGuards {
    /// Template validation level
    pub template_validation: ValidationLevel,
}

impl Default for MacroGuards {
    fn default() -> Self {
        Self {
            template_validation: ValidationLevel::Strict,
        }
    }
}

/// Guards specific to playbook capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookGuards {
    /// Allow parallel execution of playbook steps
    pub parallel_execution: bool,
    /// Maximum number of steps in a playbook
    pub max_steps: u32,
}

impl Default for PlaybookGuards {
    fn default() -> Self {
        Self {
            parallel_execution: false,
            max_steps: 10,
        }
    }
}

/// Validation strictness levels
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    Strict,
    Permissive,
}

/// Behavior pack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPack {
    /// Unique name for this behavior pack
    pub name: String,

    /// Execution mode
    pub mode: BehaviorMode,

    /// Enabled capabilities
    pub enable: EnabledCapabilities,

    /// Parameter overrides for specific capabilities
    #[serde(default)]
    pub params: CapabilityParams,

    /// Guard configuration
    #[serde(default)]
    pub guards: GuardConfig,
}

/// Behavior pack manager with hot-reload support
#[derive(Debug)]
pub struct BehaviorPackManager {
    /// Directory containing behavior pack YAML files
    config_dir: PathBuf,
    /// Currently loaded behavior packs
    packs: HashMap<String, BehaviorPack>,
    /// Last modification times for hot-reload detection
    file_times: HashMap<PathBuf, SystemTime>,
    /// Polling interval for hot-reload
    poll_interval: Duration,
}

impl BehaviorPackManager {
    /// Create a new behavior pack manager
    pub fn new<P: AsRef<Path>>(config_dir: P) -> Self {
        Self {
            config_dir: config_dir.as_ref().to_path_buf(),
            packs: HashMap::new(),
            file_times: HashMap::new(),
            poll_interval: Duration::from_secs(5), // 5 second polling as specified
        }
    }

    /// Load all behavior packs from the config directory
    pub fn load_all(&mut self) -> Result<()> {
        let entries = std::fs::read_dir(&self.config_dir).with_context(|| {
            format!(
                "Failed to read behavior config directory: {}",
                self.config_dir.display()
            )
        })?;

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("yaml")
                || path.extension().and_then(|s| s.to_str()) == Some("yml")
            {
                self.load_pack(&path)?;
            }
        }

        Ok(())
    }

    /// Load a single behavior pack from file
    pub fn load_pack(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read behavior pack file: {}", path.display()))?;

        let pack: BehaviorPack = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse behavior pack YAML: {}", path.display()))?;

        // Validate the behavior pack
        pack.validate()?;

        // Update file modification time
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;

        if let Ok(modified) = metadata.modified() {
            self.file_times.insert(path.to_path_buf(), modified);
        }

        // Store the loaded pack
        self.packs.insert(pack.name.clone(), pack);

        tracing::info!("Loaded behavior pack from {}", path.display());
        Ok(())
    }

    /// Get a behavior pack by name
    pub fn get_pack(&self, name: &str) -> Option<&BehaviorPack> {
        self.packs.get(name)
    }

    /// List all loaded behavior pack names
    pub fn list_packs(&self) -> Vec<String> {
        self.packs.keys().cloned().collect()
    }

    /// Check for file changes and reload if necessary
    pub fn check_and_reload(&mut self) -> Result<Vec<String>> {
        let mut reloaded = Vec::new();

        let entries = match std::fs::read_dir(&self.config_dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(reloaded), // Directory doesn't exist or not readable
        };

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("yaml")
                || path.extension().and_then(|s| s.to_str()) == Some("yml")
            {
                let metadata = match std::fs::metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(_) => continue, // File may have been deleted
                };

                if let Ok(modified) = metadata.modified() {
                    let needs_reload = match self.file_times.get(&path) {
                        Some(last_modified) => modified > *last_modified,
                        None => true, // New file
                    };

                    if needs_reload {
                        match self.load_pack(&path) {
                            Ok(()) => {
                                let filename = path
                                    .file_stem()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                reloaded.push(filename);
                                tracing::info!("Reloaded behavior pack: {}", path.display());
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to reload behavior pack {}: {}",
                                    path.display(),
                                    e
                                );
                                // Continue with last-known-good configuration
                            }
                        }
                    }
                }
            }
        }

        Ok(reloaded)
    }

    /// Get the polling interval for hot-reload
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Set the polling interval for hot-reload
    pub fn set_poll_interval(&mut self, interval: Duration) {
        self.poll_interval = interval;
    }

    /// Get all loaded behavior packs
    pub fn all_packs(&self) -> &HashMap<String, BehaviorPack> {
        &self.packs
    }
}

impl BehaviorPack {
    /// Validate the behavior pack configuration
    pub fn validate(&self) -> Result<()> {
        // Validate name is not empty
        if self.name.is_empty() {
            return Err(anyhow::anyhow!("Behavior pack name cannot be empty"));
        }

        // Validate mode-specific constraints
        match self.mode {
            BehaviorMode::Strict => {
                if !self.enable.atoms.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Strict mode cannot enable direct atom usage, but {} atoms were enabled",
                        self.enable.atoms.len()
                    ));
                }
            }
            BehaviorMode::Explore => {
                // Explore mode allows atoms but should have justification requirement
                if let Some(ref atom_guards) = self.guards.atoms {
                    if !atom_guards.require_justification {
                        tracing::warn!(
                            "Explore mode behavior pack '{}' does not require justification for atom usage",
                            self.name
                        );
                    }
                }
            }
            BehaviorMode::Shadow => {
                // Shadow mode allows everything since it doesn't execute
            }
        }

        // Validate guard configurations
        if let Some(ref atom_guards) = self.guards.atoms {
            if atom_guards.default_max_bytes == 0 {
                return Err(anyhow::anyhow!("default_max_bytes cannot be zero"));
            }
            if atom_guards.default_max_bytes > 100 * 1024 * 1024 {
                tracing::warn!(
                    "Large default_max_bytes ({} bytes) in behavior pack '{}'",
                    atom_guards.default_max_bytes,
                    self.name
                );
            }
        }

        if let Some(ref playbook_guards) = self.guards.playbooks {
            if playbook_guards.max_steps == 0 {
                return Err(anyhow::anyhow!("max_steps cannot be zero"));
            }
            if playbook_guards.max_steps > 100 {
                tracing::warn!(
                    "Large max_steps ({}) in behavior pack '{}'",
                    playbook_guards.max_steps,
                    self.name
                );
            }
        }

        // Validate parameters are valid JSON objects
        for (cap_name, params) in &self.params {
            if !params.is_object() {
                return Err(anyhow::anyhow!(
                    "Parameters for capability '{}' must be a JSON object, got: {:?}",
                    cap_name,
                    params
                ));
            }
        }

        Ok(())
    }

    /// Check if a specific atom is enabled in this behavior pack
    pub fn is_atom_enabled(&self, atom_name: &str) -> bool {
        self.enable.atoms.contains(&atom_name.to_string())
    }

    /// Check if a specific macro is enabled in this behavior pack
    pub fn is_macro_enabled(&self, macro_name: &str) -> bool {
        self.enable.macros.contains(&macro_name.to_string())
    }

    /// Check if a specific playbook is enabled in this behavior pack
    pub fn is_playbook_enabled(&self, playbook_name: &str) -> bool {
        self.enable.playbooks.contains(&playbook_name.to_string())
    }

    /// Get parameter overrides for a specific capability
    pub fn get_params(&self, capability_name: &str) -> Option<&serde_json::Value> {
        self.params.get(capability_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_behavior_pack_validation() {
        let pack = BehaviorPack {
            name: "test-pack".to_string(),
            mode: BehaviorMode::Strict,
            enable: EnabledCapabilities {
                atoms: vec![], // Strict mode should have no atoms
                macros: vec!["test.macro".to_string()],
                playbooks: vec!["test.playbook".to_string()],
            },
            params: HashMap::new(),
            guards: GuardConfig::default(),
        };

        assert!(pack.validate().is_ok());
    }

    #[test]
    fn test_strict_mode_validation_fails_with_atoms() {
        let pack = BehaviorPack {
            name: "test-pack".to_string(),
            mode: BehaviorMode::Strict,
            enable: EnabledCapabilities {
                atoms: vec!["fs.read.v1".to_string()], // Should fail in strict mode
                macros: vec![],
                playbooks: vec![],
            },
            params: HashMap::new(),
            guards: GuardConfig::default(),
        };

        assert!(pack.validate().is_err());
    }

    #[test]
    fn test_behavior_pack_manager() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let mut manager = BehaviorPackManager::new(temp_dir.path());

        // Create a test behavior pack file
        let pack_content = r#"
name: "test-pack"
mode: strict
enable:
  atoms: []
  macros: ["test.macro"]
  playbooks: ["test.playbook"]
params: {}
guards:
  atoms:
    default_max_bytes: 1048576
    require_justification: true
"#;

        let pack_path = temp_dir.path().join("test-pack.yaml");
        std::fs::write(&pack_path, pack_content)?;

        // Load the pack
        manager.load_all()?;

        // Verify it was loaded
        assert!(manager.get_pack("test-pack").is_some());
        assert_eq!(manager.list_packs(), vec!["test-pack"]);

        Ok(())
    }
}
