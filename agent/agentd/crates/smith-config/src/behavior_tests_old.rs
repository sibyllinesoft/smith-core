//! Comprehensive test coverage for behavior pack configuration management
//!
//! NUCLEAR COVERAGE TARGET: 100% CODE OBLITERATION

use super::*;
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
    let enabled = EnabledCapabilities::default();
    assert!(enabled.atoms.is_empty());
    assert!(enabled.macros.is_empty());
    assert!(enabled.playbooks.is_empty());
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
        assert!(matches!((deserialized, &level), 
            (ValidationLevel::Strict, ValidationLevel::Strict) | 
            (ValidationLevel::Permissive, ValidationLevel::Permissive)));
    }
}

#[test]
fn test_behavior_pack_validation_empty_name() {
    let pack = BehaviorPack {
        name: "".to_string(), // Empty name should fail
        mode: BehaviorMode::Strict,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig::default(),
    };

    let result = pack.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

#[test]
fn test_behavior_pack_validation_explore_mode_with_atoms() {
    let pack = BehaviorPack {
        name: "explore-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string()],
            macros: vec![],
            playbooks: vec![],
        },
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 1024,
                require_justification: false, // This should trigger a warning
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    // Should not fail validation but will log a warning
    assert!(pack.validate().is_ok());
}

#[test]
fn test_behavior_pack_validation_shadow_mode() {
    let pack = BehaviorPack {
        name: "shadow-pack".to_string(),
        mode: BehaviorMode::Shadow,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string()], // Shadow mode allows everything
            macros: vec!["test.macro".to_string()],
            playbooks: vec!["test.playbook".to_string()],
        },
        params: HashMap::new(),
        guards: GuardConfig::default(),
    };

    assert!(pack.validate().is_ok());
}

#[test]
fn test_behavior_pack_validation_zero_max_bytes() {
    let pack = BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 0, // Should fail
                require_justification: true,
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    let result = pack.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be zero"));
}

#[test]
fn test_behavior_pack_validation_large_max_bytes() {
    let pack = BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 200 * 1024 * 1024, // 200MB - should trigger warning
                require_justification: true,
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    // Should not fail but will log a warning
    assert!(pack.validate().is_ok());
}

#[test]
fn test_behavior_pack_validation_zero_max_steps() {
    let pack = BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards::default()),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards {
                parallel_execution: true,
                max_steps: 0, // Should fail
            }),
        },
    };

    let result = pack.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be zero"));
}

#[test]
fn test_behavior_pack_validation_large_max_steps() {
    let pack = BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards::default()),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards {
                parallel_execution: true,
                max_steps: 150, // Should trigger warning
            }),
        },
    };

    // Should not fail but will log a warning
    assert!(pack.validate().is_ok());
}

#[test]
fn test_behavior_pack_validation_invalid_params() {
    let pack = BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: {
            let mut params = HashMap::new();
            params.insert("fs.read.v1".to_string(), json!("not an object")); // Should fail
            params
        },
        guards: GuardConfig::default(),
    };

    let result = pack.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("must be a JSON object"));
}

#[test]
fn test_behavior_pack_validation_valid_params() {
    let pack = BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: {
            let mut params = HashMap::new();
            params.insert("fs.read.v1".to_string(), json!({"max_bytes": 1024})); // Valid object
            params
        },
        guards: GuardConfig::default(),
    };

    assert!(pack.validate().is_ok());
}

#[test]
fn test_behavior_pack_capability_checks() {
    let pack = BehaviorPack {
        name: "test-pack".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string(), "http.fetch.v1".to_string()],
            macros: vec!["data.analyze".to_string()],
            playbooks: vec!["security.audit".to_string()],
        },
        params: {
            let mut params = HashMap::new();
            params.insert("fs.read.v1".to_string(), json!({"max_bytes": 2048}));
            params
        },
        guards: GuardConfig::default(),
    };

    // Test atom checks
    assert!(pack.is_atom_enabled("fs.read.v1"));
    assert!(pack.is_atom_enabled("http.fetch.v1"));
    assert!(!pack.is_atom_enabled("sql.query.v1"));

    // Test macro checks
    assert!(pack.is_macro_enabled("data.analyze"));
    assert!(!pack.is_macro_enabled("data.process"));

    // Test playbook checks
    assert!(pack.is_playbook_enabled("security.audit"));
    assert!(!pack.is_playbook_enabled("performance.test"));

    // Test parameter retrieval
    assert!(pack.get_params("fs.read.v1").is_some());
    assert!(pack.get_params("http.fetch.v1").is_none());
    
    let fs_params = pack.get_params("fs.read.v1").unwrap();
    assert_eq!(fs_params["max_bytes"], 2048);
}

#[test]
fn test_behavior_pack_manager_new() {
    let temp_dir = TempDir::new().unwrap();
    let manager = BehaviorPackManager::new(temp_dir.path());
    
    assert_eq!(manager.config_dir, temp_dir.path());
    assert!(manager.packs.is_empty());
    assert!(manager.file_times.is_empty());
    assert_eq!(manager.poll_interval, Duration::from_secs(5));
}

#[test]
fn test_behavior_pack_manager_empty_directory() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    // Loading from empty directory should succeed
    manager.load_all()?;
    assert!(manager.list_packs().is_empty());

    Ok(())
}

#[test]
fn test_behavior_pack_manager_missing_directory() {
    let temp_dir = TempDir::new().unwrap();
    let missing_path = temp_dir.path().join("missing");
    let mut manager = BehaviorPackManager::new(&missing_path);

    // Should fail to load from missing directory
    let result = manager.load_all();
    assert!(result.is_err());
}

#[test]
fn test_behavior_pack_manager_yaml_and_yml_files() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    // Create both .yaml and .yml files
    let pack_yaml_content = r#"
name: "yaml-pack"
mode: strict
enable:
  atoms: []
  macros: ["test.macro"]
  playbooks: []
"#;

    let pack_yml_content = r#"
name: "yml-pack"
mode: explore
enable:
  atoms: ["fs.read.v1"]
  macros: []
  playbooks: []
"#;

    fs::write(temp_dir.path().join("pack1.yaml"), pack_yaml_content)?;
    fs::write(temp_dir.path().join("pack2.yml"), pack_yml_content)?;
    
    // Create a non-YAML file that should be ignored
    fs::write(temp_dir.path().join("readme.txt"), "This should be ignored")?;

    manager.load_all()?;

    assert_eq!(manager.list_packs().len(), 2);
    assert!(manager.get_pack("yaml-pack").is_some());
    assert!(manager.get_pack("yml-pack").is_some());

    Ok(())
}

#[test]
fn test_behavior_pack_manager_invalid_yaml() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    // Create invalid YAML file
    let invalid_yaml = r#"
name: "invalid-pack"
mode: invalid_mode_that_does_not_exist
"#;

    fs::write(temp_dir.path().join("invalid.yaml"), invalid_yaml)?;

    // Should fail to load invalid YAML
    let result = manager.load_all();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_behavior_pack_manager_invalid_behavior_pack() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    // Create YAML that parses but fails validation
    let invalid_pack = r#"
name: ""
mode: strict
enable:
  atoms: []
  macros: []
  playbooks: []
"#;

    fs::write(temp_dir.path().join("invalid-pack.yaml"), invalid_pack)?;

    // Should fail validation
    let result = manager.load_all();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_behavior_pack_manager_load_single_pack() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    let pack_content = r#"
name: "single-pack"
mode: explore
enable:
  atoms: ["fs.read.v1"]
  macros: ["data.process"]
  playbooks: ["security.check"]
params:
  "fs.read.v1":
    max_bytes: 4096
guards:
  atoms:
    default_max_bytes: 2048
    require_justification: true
  playbooks:
    parallel_execution: true
    max_steps: 5
"#;

    let pack_path = temp_dir.path().join("single.yaml");
    fs::write(&pack_path, pack_content)?;

    manager.load_pack(&pack_path)?;

    assert_eq!(manager.list_packs(), vec!["single-pack"]);
    
    let pack = manager.get_pack("single-pack").unwrap();
    assert_eq!(pack.name, "single-pack");
    assert!(matches!(pack.mode, BehaviorMode::Explore));
    assert!(pack.is_atom_enabled("fs.read.v1"));
    assert!(pack.is_macro_enabled("data.process"));
    assert!(pack.is_playbook_enabled("security.check"));

    Ok(())
}

#[test]
fn test_behavior_pack_manager_hot_reload() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    let pack_path = temp_dir.path().join("reload-test.yaml");
    
    // Initial pack
    let initial_content = r#"
name: "reload-pack"
mode: strict
enable:
  atoms: []
  macros: ["test.macro"]
  playbooks: []
"#;

    fs::write(&pack_path, initial_content)?;
    manager.load_all()?;

    assert!(manager.get_pack("reload-pack").is_some());
    let pack = manager.get_pack("reload-pack").unwrap();
    assert!(matches!(pack.mode, BehaviorMode::Strict));

    // Wait a bit to ensure different modification time
    thread::sleep(Duration::from_millis(100));

    // Update the pack
    let updated_content = r#"
name: "reload-pack"
mode: explore
enable:
  atoms: ["fs.read.v1"]
  macros: ["test.macro"]
  playbooks: []
"#;

    fs::write(&pack_path, updated_content)?;

    // Check for reload
    let reloaded = manager.check_and_reload()?;
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0], "reload-test");

    // Verify the pack was actually updated
    let pack = manager.get_pack("reload-pack").unwrap();
    assert!(matches!(pack.mode, BehaviorMode::Explore));
    assert!(pack.is_atom_enabled("fs.read.v1"));

    Ok(())
}

#[test]
fn test_behavior_pack_manager_hot_reload_no_changes() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    let pack_content = r#"
name: "no-change-pack"
mode: strict
enable:
  atoms: []
  macros: []
  playbooks: []
"#;

    let pack_path = temp_dir.path().join("no-change.yaml");
    fs::write(&pack_path, pack_content)?;
    manager.load_all()?;

    // Check for reload with no changes
    let reloaded = manager.check_and_reload()?;
    assert!(reloaded.is_empty());

    Ok(())
}

#[test]
fn test_behavior_pack_manager_hot_reload_new_file() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    // Start with empty directory
    manager.load_all()?;
    assert!(manager.list_packs().is_empty());

    // Add a new file
    let pack_content = r#"
name: "new-pack"
mode: shadow
enable:
  atoms: ["fs.read.v1"]
  macros: []
  playbooks: []
"#;

    let pack_path = temp_dir.path().join("new-pack.yaml");
    fs::write(&pack_path, pack_content)?;

    // Check for reload - should detect new file
    let reloaded = manager.check_and_reload()?;
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0], "new-pack");

    assert!(manager.get_pack("new-pack").is_some());

    Ok(())
}

#[test]
fn test_behavior_pack_manager_hot_reload_missing_directory() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let missing_path = temp_dir.path().join("missing");
    let mut manager = BehaviorPackManager::new(&missing_path);

    // Should handle missing directory gracefully
    let reloaded = manager.check_and_reload()?;
    assert!(reloaded.is_empty());

    Ok(())
}

#[test]
fn test_behavior_pack_manager_hot_reload_invalid_file() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    // Create a valid pack first
    let valid_content = r#"
name: "valid-pack"
mode: strict
enable:
  atoms: []
  macros: []
  playbooks: []
"#;

    let pack_path = temp_dir.path().join("test-pack.yaml");
    fs::write(&pack_path, valid_content)?;
    manager.load_all()?;

    // Wait and then corrupt the file
    thread::sleep(Duration::from_millis(100));
    fs::write(&pack_path, "invalid yaml content [[[[")?;

    // Should handle invalid file gracefully and keep last-known-good config
    let reloaded = manager.check_and_reload()?;
    assert!(reloaded.is_empty()); // No successful reloads

    // Original pack should still be available
    assert!(manager.get_pack("valid-pack").is_some());

    Ok(())
}

#[test]
fn test_behavior_pack_manager_poll_interval() {
    let temp_dir = TempDir::new().unwrap();
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    assert_eq!(manager.poll_interval(), Duration::from_secs(5));

    manager.set_poll_interval(Duration::from_secs(10));
    assert_eq!(manager.poll_interval(), Duration::from_secs(10));
}

#[test]
fn test_behavior_pack_manager_all_packs() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    // Create multiple packs
    let pack1_content = r#"
name: "pack1"
mode: strict
enable:
  atoms: []
  macros: ["macro1"]
  playbooks: []
"#;

    let pack2_content = r#"
name: "pack2"
mode: explore
enable:
  atoms: ["atom1"]
  macros: []
  playbooks: ["playbook1"]
"#;

    fs::write(temp_dir.path().join("pack1.yaml"), pack1_content)?;
    fs::write(temp_dir.path().join("pack2.yaml"), pack2_content)?;

    manager.load_all()?;

    let all_packs = manager.all_packs();
    assert_eq!(all_packs.len(), 2);
    assert!(all_packs.contains_key("pack1"));
    assert!(all_packs.contains_key("pack2"));

    Ok(())
}

#[test]
fn test_behavior_pack_manager_file_metadata_error_handling() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut manager = BehaviorPackManager::new(temp_dir.path());

    // Create a pack file
    let pack_content = r#"
name: "test-pack"
mode: strict
enable:
  atoms: []
  macros: []
  playbooks: []
"#;

    let pack_path = temp_dir.path().join("test-pack.yaml");
    fs::write(&pack_path, pack_content)?;

    manager.load_all()?;

    // Simulate a file that gets deleted during reload check
    fs::remove_file(&pack_path)?;

    // Should handle missing file gracefully during reload check
    let reloaded = manager.check_and_reload()?;
    assert!(reloaded.is_empty());

    Ok(())
}

#[test]
fn test_capability_params_type_alias() {
    let mut params: CapabilityParams = HashMap::new();
    params.insert("test.capability".to_string(), json!({"param": "value"}));
    
    assert_eq!(params.len(), 1);
    assert!(params.contains_key("test.capability"));
}

#[test]
fn test_behavior_pack_serde_round_trip() -> anyhow::Result<()> {
    let pack = BehaviorPack {
        name: "serde-test".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities {
            atoms: vec!["fs.read.v1".to_string()],
            macros: vec!["data.process".to_string()],
            playbooks: vec!["security.audit".to_string()],
        },
        params: {
            let mut params = HashMap::new();
            params.insert("fs.read.v1".to_string(), json!({"max_bytes": 1024}));
            params
        },
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 2048,
                require_justification: true,
            }),
            macros: Some(MacroGuards {
                template_validation: ValidationLevel::Permissive,
            }),
            playbooks: Some(PlaybookGuards {
                parallel_execution: true,
                max_steps: 15,
            }),
        },
    };

    // Serialize to YAML
    let yaml_str = serde_yaml::to_string(&pack)?;
    
    // Deserialize back
    let deserialized: BehaviorPack = serde_yaml::from_str(&yaml_str)?;
    
    // Verify round-trip integrity
    assert_eq!(pack.name, deserialized.name);
    assert!(matches!((pack.mode, deserialized.mode), 
        (BehaviorMode::Explore, BehaviorMode::Explore)));
    assert_eq!(pack.enable.atoms, deserialized.enable.atoms);
    assert_eq!(pack.enable.macros, deserialized.enable.macros);
    assert_eq!(pack.enable.playbooks, deserialized.enable.playbooks);

    Ok(())
}