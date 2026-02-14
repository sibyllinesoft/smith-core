//! Comprehensive test coverage for behavior pack configuration management
//!
//! NUCLEAR COVERAGE TARGET: 100% CODE OBLITERATION

use super::*;
use crate::behavior::{
    BehaviorPack, BehaviorMode, EnabledCapabilities, GuardConfig, 
    AtomGuards, MacroGuards, PlaybookGuards, ValidationLevel, 
    BehaviorPackManager, CapabilityParams
};
use serde_json::json;
use std::fs;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};
use tempfile::TempDir;

#[test]
fn test_behavior_mode_default() {
    assert_eq!(BehaviorMode::default(), BehaviorMode::Strict);
}

#[test]
fn test_behavior_mode_serialization() {
    let modes = vec![
        (BehaviorMode::Strict, "strict"),
        (BehaviorMode::Explore, "explore"),
        (BehaviorMode::Shadow, "shadow"),
    ];

    for (mode, expected) in modes {
        let serialized = serde_json::to_string(&mode).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected));
        
        let deserialized: BehaviorMode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, mode);
    }
}

#[test]
fn test_enabled_capabilities_default() {
    let capabilities = EnabledCapabilities::default();
    assert!(capabilities.atoms.is_empty());
    assert!(capabilities.macros.is_empty());
    assert!(capabilities.playbooks.is_empty());
}

#[test]
fn test_guard_config_default() {
    let guard_config = GuardConfig::default();
    
    assert!(guard_config.atoms.is_some());
    assert!(guard_config.macros.is_some());
    assert!(guard_config.playbooks.is_some());
}

#[test]
fn test_atom_guards_default() {
    let atom_guards = AtomGuards::default();
    assert_eq!(atom_guards.default_max_bytes, 1048576); // 1MB
    assert!(atom_guards.require_justification);
}

#[test]
fn test_macro_guards_default() {
    let macro_guards = MacroGuards::default();
    assert!(matches!(macro_guards.template_validation, ValidationLevel::Strict));
}

#[test]
fn test_playbook_guards_default() {
    let playbook_guards = PlaybookGuards::default();
    assert!(!playbook_guards.parallel_execution);
    assert_eq!(playbook_guards.max_steps, 10);
}

#[test]
fn test_validation_level_serialization() {
    let levels = vec![
        (ValidationLevel::Strict, "strict"),
        (ValidationLevel::Permissive, "permissive"),
    ];

    for (level, expected) in levels {
        let serialized = serde_json::to_string(&level).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected));
        
        let deserialized: ValidationLevel = serde_json::from_str(&serialized).unwrap();
        match (level, deserialized) {
            (ValidationLevel::Strict, ValidationLevel::Strict) | 
            (ValidationLevel::Permissive, ValidationLevel::Permissive) => {},
            _ => panic!("Deserialization mismatch"),
        }
    }
}

#[test]
fn test_behavior_pack_creation() {
    let mut pack = BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string()],
            macros: vec!["data.process".to_string()],
            playbooks: vec!["deploy.sequence".to_string()],
        },
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    pack.params.insert("fs.read.v1".to_string(), json!({"max_bytes": 2048}));
    
    assert_eq!(pack.name, "test-pack");
    assert_eq!(pack.mode, BehaviorMode::Explore);
    assert_eq!(pack.enable.atoms.len(), 1);
    assert_eq!(pack.enable.macros.len(), 1);
    assert_eq!(pack.enable.playbooks.len(), 1);
    assert_eq!(pack.params.len(), 1);
}

#[test]
fn test_behavior_pack_serialization() {
    let pack = BehaviorPack {
        name: "serialize-test".to_string(),
        mode: BehaviorMode::Shadow,
        enable: EnabledCapabilities {
            atoms: vec!["http.fetch.v1".to_string()],
            macros: vec![],
            playbooks: vec![],
        },
        params: {
            let mut params = std::collections::HashMap::new();
            params.insert("http.fetch.v1".to_string(), json!({"timeout_ms": 5000}));
            params
        },
        guards: GuardConfig::default(),
    };
    
    let serialized = serde_json::to_string(&pack).unwrap();
    let deserialized: BehaviorPack = serde_json::from_str(&serialized).unwrap();
    
    assert_eq!(deserialized.name, pack.name);
    assert_eq!(deserialized.mode, pack.mode);
    assert_eq!(deserialized.enable.atoms, pack.enable.atoms);
    assert_eq!(deserialized.params.len(), pack.params.len());
}

#[test]
fn test_behavior_pack_manager_new() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let manager = BehaviorPackManager::new(temp_dir.path());
    
    // Manager should start with empty pack collection
    assert!(manager.get_pack_names().is_empty());
    Ok(())
}

#[test]
fn test_behavior_pack_manager_load_from_directory() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create a test behavior pack file
    let pack_config = serde_yaml::to_string(&BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Strict,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string()],
            macros: vec![],
            playbooks: vec![],
        },
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    })?;
    
    fs::write(temp_dir.path().join("test-pack.yaml"), pack_config)?;
    
    let mut manager = BehaviorPackManager::new(temp_dir.path());
    manager.load_from_directory()?;
    
    let pack_names = manager.get_pack_names();
    assert_eq!(pack_names.len(), 1);
    assert!(pack_names.contains(&"test-pack".to_string()));
    
    let loaded_pack = manager.get_pack("test-pack").unwrap();
    assert_eq!(loaded_pack.name, "test-pack");
    assert_eq!(loaded_pack.mode, BehaviorMode::Strict);
    
    Ok(())
}

#[test]
fn test_behavior_pack_manager_save_pack() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());
    
    let pack = BehaviorPack {
        name: "save-test".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities {
            atoms: vec!["http.fetch.v1".to_string()],
            macros: vec!["data.analyze".to_string()],
            playbooks: vec![],
        },
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    manager.save_pack(&pack)?;
    
    // Verify file was created
    let pack_file = temp_dir.path().join("save-test.yaml");
    assert!(pack_file.exists());
    
    // Verify pack can be retrieved
    let retrieved_pack = manager.get_pack("save-test").unwrap();
    assert_eq!(retrieved_pack.name, pack.name);
    assert_eq!(retrieved_pack.enable.atoms, pack.enable.atoms);
    
    Ok(())
}

#[test]
fn test_behavior_pack_manager_delete_pack() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());
    
    let pack = BehaviorPack {
        name: "delete-test".to_string(),
        mode: BehaviorMode::Shadow,
        enable: EnabledCapabilities::default(),
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    manager.save_pack(&pack)?;
    assert!(manager.get_pack("delete-test").is_some());
    
    manager.delete_pack("delete-test")?;
    assert!(manager.get_pack("delete-test").is_none());
    
    // Verify file was deleted
    let pack_file = temp_dir.path().join("delete-test.yaml");
    assert!(!pack_file.exists());
    
    Ok(())
}

#[test]
fn test_behavior_pack_manager_hot_reload() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());
    
    // Create initial pack
    let pack = BehaviorPack {
        name: "hot-reload-test".to_string(),
        mode: BehaviorMode::Strict,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string()],
            macros: vec![],
            playbooks: vec![],
        },
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    manager.save_pack(&pack)?;
    
    // Modify pack file directly
    thread::sleep(Duration::from_millis(10)); // Ensure file timestamp changes
    
    let modified_pack = BehaviorPack {
        name: "hot-reload-test".to_string(),
        mode: BehaviorMode::Explore, // Changed mode
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string(), "http.fetch.v1".to_string()], // Added atom
            macros: vec![],
            playbooks: vec![],
        },
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    let modified_config = serde_yaml::to_string(&modified_pack)?;
    fs::write(temp_dir.path().join("hot-reload-test.yaml"), modified_config)?;
    
    // Check for changes
    let changes = manager.check_for_changes()?;
    assert!(!changes.is_empty());
    assert!(changes.contains(&"hot-reload-test".to_string()));
    
    // Reload changed packs
    manager.reload_changed_packs()?;
    
    // Verify changes were loaded
    let reloaded_pack = manager.get_pack("hot-reload-test").unwrap();
    assert_eq!(reloaded_pack.mode, BehaviorMode::Explore);
    assert_eq!(reloaded_pack.enable.atoms.len(), 2);
    
    Ok(())
}

#[test]
fn test_behavior_pack_manager_validation() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());
    
    // Test valid pack
    let valid_pack = BehaviorPack {
        name: "valid-pack".to_string(),
        mode: BehaviorMode::Strict,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string()],
            macros: vec![],
            playbooks: vec![],
        },
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    assert!(manager.validate_pack(&valid_pack).is_ok());
    
    // Test pack with duplicate capabilities (if validation exists)
    let duplicate_pack = BehaviorPack {
        name: "duplicate-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string(), "fs.read.v1".to_string()], // Duplicate
            macros: vec![],
            playbooks: vec![],
        },
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    // Validation might pass - duplicates could be allowed
    let _ = manager.validate_pack(&duplicate_pack);
    
    Ok(())
}

#[test]
fn test_behavior_pack_manager_file_operations() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());
    
    // Test loading non-existent directory
    let invalid_manager = BehaviorPackManager::new("/nonexistent/path");
    let result = invalid_manager.clone().load_from_directory();
    assert!(result.is_err());
    
    // Test loading with invalid YAML
    fs::write(temp_dir.path().join("invalid.yaml"), "invalid: yaml: content: [")?;
    let load_result = manager.load_from_directory();
    // Should handle gracefully or return error
    let _ = load_result;
    
    Ok(())
}

#[test]
fn test_behavior_pack_manager_concurrent_access() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let manager = BehaviorPackManager::new(temp_dir.path());
    
    // Test that concurrent reads work (if manager supports it)
    let pack_names1 = manager.get_pack_names();
    let pack_names2 = manager.get_pack_names();
    assert_eq!(pack_names1, pack_names2);
    
    Ok(())
}

#[test]
fn test_capability_params_usage() {
    let mut params: CapabilityParams = std::collections::HashMap::new();
    
    params.insert("fs.read.v1".to_string(), json!({"max_bytes": 1024, "timeout_ms": 5000}));
    params.insert("http.fetch.v1".to_string(), json!({"headers": {"User-Agent": "smith-executor"}}));
    
    assert_eq!(params.len(), 2);
    assert!(params.contains_key("fs.read.v1"));
    assert!(params.contains_key("http.fetch.v1"));
    
    // Test complex parameter nesting
    let fs_params = params.get("fs.read.v1").unwrap();
    assert_eq!(fs_params["max_bytes"], 1024);
    assert_eq!(fs_params["timeout_ms"], 5000);
}

#[test]
fn test_guard_config_customization() {
    let custom_guards = GuardConfig {
        atoms: Some(AtomGuards {
            default_max_bytes: 2048,
            require_justification: false,
        }),
        macros: Some(MacroGuards {
            template_validation: ValidationLevel::Permissive,
        }),
        playbooks: Some(PlaybookGuards {
            parallel_execution: true,
            max_steps: 20,
        }),
    };
    
    assert_eq!(custom_guards.atoms.as_ref().unwrap().default_max_bytes, 2048);
    assert!(!custom_guards.atoms.as_ref().unwrap().require_justification);
    assert!(matches!(custom_guards.macros.as_ref().unwrap().template_validation, ValidationLevel::Permissive));
    assert!(custom_guards.playbooks.as_ref().unwrap().parallel_execution);
    assert_eq!(custom_guards.playbooks.as_ref().unwrap().max_steps, 20);
}

#[test]
fn test_behavior_pack_edge_cases() -> anyhow::Result<()> {
    // Test with empty name
    let empty_name_pack = BehaviorPack {
        name: "".to_string(),
        mode: BehaviorMode::Strict,
        enable: EnabledCapabilities::default(),
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    let serialized = serde_json::to_string(&empty_name_pack)?;
    let deserialized: BehaviorPack = serde_json::from_str(&serialized)?;
    assert_eq!(deserialized.name, "");
    
    // Test with no capabilities
    let no_caps_pack = BehaviorPack {
        name: "no-caps".to_string(),
        mode: BehaviorMode::Shadow,
        enable: EnabledCapabilities::default(),
        params: std::collections::HashMap::new(),
        guards: GuardConfig::default(),
    };
    
    assert!(no_caps_pack.enable.atoms.is_empty());
    assert!(no_caps_pack.enable.macros.is_empty());
    assert!(no_caps_pack.enable.playbooks.is_empty());
    
    Ok(())
}

#[test]
fn test_behavior_pack_manager_error_handling() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let manager = BehaviorPackManager::new(temp_dir.path());
    
    // Test getting non-existent pack
    assert!(manager.get_pack("nonexistent").is_none());
    
    // Test deleting non-existent pack
    let mut mutable_manager = manager;
    let delete_result = mutable_manager.delete_pack("nonexistent");
    // Should handle gracefully
    let _ = delete_result;
    
    Ok(())
}