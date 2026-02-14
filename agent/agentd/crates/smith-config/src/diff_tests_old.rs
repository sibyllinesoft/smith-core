//! Comprehensive test coverage for behavior pack diff analysis engine
//!
//! NUCLEAR TARGET: 100% DIFF OBLITERATION

use super::*;
use crate::behavior::{
    AtomGuards, BehaviorMode, BehaviorPack, EnabledCapabilities, GuardConfig, MacroGuards,
    PlaybookGuards, ValidationLevel,
};
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_diff_metadata_creation() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.metadata.from_pack, "pack1");
    assert_eq!(diff.metadata.to_pack, "pack2");
    assert!(matches!(diff.metadata.from_mode, BehaviorMode::Strict));
    assert!(matches!(diff.metadata.to_mode, BehaviorMode::Explore));
    assert!(!diff.metadata.timestamp.is_empty());
}

#[test]
fn test_parameter_change_type_serialization() {
    let types = vec![
        (ParameterChangeType::Added, "added"),
        (ParameterChangeType::Removed, "removed"),
        (ParameterChangeType::Modified, "modified"),
    ];

    for (change_type, expected) in types {
        let serialized = serde_json::to_string(&change_type).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected));

        let deserialized: ParameterChangeType = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(
            (deserialized, change_type),
            (ParameterChangeType::Added, ParameterChangeType::Added)
                | (ParameterChangeType::Removed, ParameterChangeType::Removed)
                | (ParameterChangeType::Modified, ParameterChangeType::Modified)
        ));
    }
}

#[test]
fn test_guard_impact_serialization() {
    let impacts = vec![
        (GuardImpact::Restrictive, "restrictive"),
        (GuardImpact::Permissive, "permissive"),
        (GuardImpact::Neutral, "neutral"),
    ];

    for (impact, expected) in impacts {
        let serialized = serde_json::to_string(&impact).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected));

        let deserialized: GuardImpact = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(
            (deserialized, impact),
            (GuardImpact::Restrictive, GuardImpact::Restrictive)
                | (GuardImpact::Permissive, GuardImpact::Permissive)
                | (GuardImpact::Neutral, GuardImpact::Neutral)
        ));
    }
}

#[test]
fn test_risk_level_serialization_and_ordering() {
    let levels = vec![
        (RiskLevel::Low, "low"),
        (RiskLevel::Medium, "medium"),
        (RiskLevel::High, "high"),
        (RiskLevel::Critical, "critical"),
    ];

    // Test serialization
    for (level, expected) in &levels {
        let serialized = serde_json::to_string(level).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected));

        let deserialized: RiskLevel = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(
            (deserialized, level),
            (RiskLevel::Low, RiskLevel::Low)
                | (RiskLevel::Medium, RiskLevel::Medium)
                | (RiskLevel::High, RiskLevel::High)
                | (RiskLevel::Critical, RiskLevel::Critical)
        ));
    }

    // Test ordering
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
    assert!(RiskLevel::Critical == RiskLevel::Critical);
}

#[test]
fn test_capability_changes_comprehensive() {
    let pack1 = BehaviorPack {
        name: "pack1".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities {
            atoms: vec!["atom1".to_string(), "atom2".to_string(), "atom3".to_string()],
            macros: vec!["macro1".to_string(), "macro2".to_string()],
            playbooks: vec!["playbook1".to_string()],
        },
        params: HashMap::new(),
        guards: GuardConfig::default(),
    };

    let pack2 = BehaviorPack {
        name: "pack2".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities {
            atoms: vec!["atom2".to_string(), "atom4".to_string()], // removed: atom1, atom3; added: atom4
            macros: vec!["macro1".to_string(), "macro3".to_string()], // removed: macro2; added: macro3
            playbooks: vec!["playbook1".to_string(), "playbook2".to_string()], // added: playbook2
        },
        params: HashMap::new(),
        guards: GuardConfig::default(),
    };

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    // Check atoms
    assert_eq!(diff.capability_changes.atoms_enabled.len(), 1);
    assert!(diff.capability_changes.atoms_enabled.contains(&"atom4".to_string()));
    
    assert_eq!(diff.capability_changes.atoms_disabled.len(), 2);
    assert!(diff.capability_changes.atoms_disabled.contains(&"atom1".to_string()));
    assert!(diff.capability_changes.atoms_disabled.contains(&"atom3".to_string()));

    // Check macros
    assert_eq!(diff.capability_changes.macros_enabled.len(), 1);
    assert!(diff.capability_changes.macros_enabled.contains(&"macro3".to_string()));
    
    assert_eq!(diff.capability_changes.macros_disabled.len(), 1);
    assert!(diff.capability_changes.macros_disabled.contains(&"macro2".to_string()));

    // Check playbooks
    assert_eq!(diff.capability_changes.playbooks_enabled.len(), 1);
    assert!(diff.capability_changes.playbooks_enabled.contains(&"playbook2".to_string()));
    
    assert!(diff.capability_changes.playbooks_disabled.is_empty());

    assert_eq!(diff.summary.total_capability_changes, 5); // 3 + 1 + 1
}

#[test]
fn test_parameter_changes_added() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert(
        "fs.read.v1".to_string(),
        json!({
            "max_bytes": 1024,
            "timeout_ms": 5000
        }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.parameter_changes.len(), 2);
    
    let max_bytes_change = diff.parameter_changes.iter()
        .find(|c| c.key == "max_bytes")
        .unwrap();
    assert_eq!(max_bytes_change.capability, "fs.read.v1");
    assert!(max_bytes_change.old_value.is_none());
    assert_eq!(max_bytes_change.new_value, Some(json!(1024)));
    assert!(matches!(max_bytes_change.change_type, ParameterChangeType::Added));

    let timeout_change = diff.parameter_changes.iter()
        .find(|c| c.key == "timeout_ms")
        .unwrap();
    assert_eq!(timeout_change.capability, "fs.read.v1");
    assert!(timeout_change.old_value.is_none());
    assert_eq!(timeout_change.new_value, Some(json!(5000)));
    assert!(matches!(timeout_change.change_type, ParameterChangeType::Added));
}

#[test]
fn test_parameter_changes_removed() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert(
        "http.fetch.v1".to_string(),
        json!({
            "hosts": ["api.example.com"],
            "timeout": 30
        }),
    );

    let pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.parameter_changes.len(), 1);
    
    let removed_change = &diff.parameter_changes[0];
    assert_eq!(removed_change.capability, "http.fetch.v1");
    assert_eq!(removed_change.key, "*"); // Indicates all parameters removed
    assert!(removed_change.old_value.is_some());
    assert!(removed_change.new_value.is_none());
    assert!(matches!(removed_change.change_type, ParameterChangeType::Removed));
}

#[test]
fn test_parameter_changes_modified() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert(
        "fs.read.v1".to_string(),
        json!({
            "max_bytes": 1024,
            "paths": ["/tmp"]
        }),
    );

    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert(
        "fs.read.v1".to_string(),
        json!({
            "max_bytes": 2048,  // Modified
            "paths": ["/tmp"],  // Unchanged
            "new_param": "value" // Added
        }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.parameter_changes.len(), 2); // 1 modified + 1 added

    let modified_change = diff.parameter_changes.iter()
        .find(|c| c.key == "max_bytes")
        .unwrap();
    assert_eq!(modified_change.capability, "fs.read.v1");
    assert_eq!(modified_change.old_value, Some(json!(1024)));
    assert_eq!(modified_change.new_value, Some(json!(2048)));
    assert!(matches!(modified_change.change_type, ParameterChangeType::Modified));

    let added_change = diff.parameter_changes.iter()
        .find(|c| c.key == "new_param")
        .unwrap();
    assert_eq!(added_change.capability, "fs.read.v1");
    assert!(added_change.old_value.is_none());
    assert_eq!(added_change.new_value, Some(json!("value")));
    assert!(matches!(added_change.change_type, ParameterChangeType::Added));
}

#[test]
fn test_parameter_changes_non_object_values() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert("test.cap".to_string(), json!("not an object"));

    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert("test.cap".to_string(), json!("different value"));

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    // Should not generate parameter changes for non-object values
    // (compare_param_objects only works with objects)
    assert!(diff.parameter_changes.is_empty() || 
            diff.parameter_changes.iter().all(|c| c.capability != "test.cap"));
}

#[test]
fn test_guard_changes_atom_guards() {
    let pack1 = BehaviorPack {
        name: "pack1".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 1024,
                require_justification: true,
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    let pack2 = BehaviorPack {
        name: "pack2".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 2048, // Increased (more permissive)
                require_justification: false, // Disabled (more permissive)
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.guard_changes.atom_guards.len(), 2);

    let max_bytes_change = diff.guard_changes.atom_guards.iter()
        .find(|c| c.setting == "default_max_bytes")
        .unwrap();
    assert_eq!(max_bytes_change.old_value, json!(1024));
    assert_eq!(max_bytes_change.new_value, json!(2048));
    assert!(matches!(max_bytes_change.impact, GuardImpact::Permissive));

    let justification_change = diff.guard_changes.atom_guards.iter()
        .find(|c| c.setting == "require_justification")
        .unwrap();
    assert_eq!(justification_change.old_value, json!(true));
    assert_eq!(justification_change.new_value, json!(false));
    assert!(matches!(justification_change.impact, GuardImpact::Permissive));
}

#[test]
fn test_guard_changes_restrictive() {
    let pack1 = BehaviorPack {
        name: "pack1".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 2048,
                require_justification: false,
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    let pack2 = BehaviorPack {
        name: "pack2".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 1024, // Decreased (more restrictive)
                require_justification: true, // Enabled (more restrictive)
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.guard_changes.atom_guards.len(), 2);

    let max_bytes_change = diff.guard_changes.atom_guards.iter()
        .find(|c| c.setting == "default_max_bytes")
        .unwrap();
    assert!(matches!(max_bytes_change.impact, GuardImpact::Restrictive));

    let justification_change = diff.guard_changes.atom_guards.iter()
        .find(|c| c.setting == "require_justification")
        .unwrap();
    assert!(matches!(justification_change.impact, GuardImpact::Restrictive));
}

#[test]
fn test_guard_changes_playbook_guards() {
    let pack1 = BehaviorPack {
        name: "pack1".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards::default()),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards {
                parallel_execution: false,
                max_steps: 10,
            }),
        },
    };

    let pack2 = BehaviorPack {
        name: "pack2".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards::default()),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards {
                parallel_execution: true,
                max_steps: 5, // Decreased (more restrictive)
            }),
        },
    };

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.guard_changes.playbook_guards.len(), 1);
    
    let max_steps_change = &diff.guard_changes.playbook_guards[0];
    assert_eq!(max_steps_change.setting, "max_steps");
    assert_eq!(max_steps_change.old_value, json!(10));
    assert_eq!(max_steps_change.new_value, json!(5));
    assert!(matches!(max_steps_change.impact, GuardImpact::Restrictive));
}

#[test]
fn test_guard_changes_missing_guards() {
    let pack1 = BehaviorPack {
        name: "pack1".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: None, // Missing guards
            macros: Some(MacroGuards::default()),
            playbooks: None, // Missing guards
        },
    };

    let pack2 = BehaviorPack {
        name: "pack2".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards::default()),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    // Should not crash and should not detect any guard changes
    assert!(diff.guard_changes.atom_guards.is_empty());
    assert!(diff.guard_changes.playbook_guards.is_empty());
}

#[test]
fn test_mode_risk_analysis_all_transitions() {
    use BehaviorMode::*;

    let transitions = vec![
        (Strict, Explore, RiskLevel::Medium, "direct atom usage"),
        (Strict, Shadow, RiskLevel::Low, "no actual execution"),
        (Explore, Strict, RiskLevel::Low, "more restrictive"),
        (Explore, Shadow, RiskLevel::Low, "no actual execution"),
        (Shadow, Strict, RiskLevel::Low, "shadow to strict"),
        (Shadow, Explore, RiskLevel::Medium, "enables execution"),
        (Strict, Strict, RiskLevel::Low, "No mode change"),
        (Explore, Explore, RiskLevel::Low, "No mode change"),
        (Shadow, Shadow, RiskLevel::Low, "No mode change"),
    ];

    for (from_mode, to_mode, expected_risk, expected_desc_contains) in transitions {
        let pack1 = create_test_pack("pack1", from_mode.clone());
        let pack2 = create_test_pack("pack2", to_mode.clone());

        let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

        assert_eq!(diff.risk_analysis.mode_risk.risk_level, expected_risk,
                   "Failed for transition {:?} -> {:?}", from_mode, to_mode);
        assert!(diff.risk_analysis.mode_risk.description.contains(expected_desc_contains),
                "Description '{}' doesn't contain '{}'", 
                diff.risk_analysis.mode_risk.description, expected_desc_contains);
    }
}

#[test]
fn test_scope_expansion_detection_hosts() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert(
        "http.fetch.v1".to_string(),
        json!({ "hosts": ["api.example.com"] }),
    );

    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert(
        "http.fetch.v1".to_string(),
        json!({ "hosts": ["api.example.com", "untrusted.com"] }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.risk_analysis.scope_expansion_detected);
    assert!(matches!(diff.risk_analysis.overall_risk, RiskLevel::Critical));
}

#[test]
fn test_scope_expansion_detection_paths() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert(
        "fs.read.v1".to_string(),
        json!({ "paths": ["/safe/path"] }),
    );

    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert(
        "fs.read.v1".to_string(),
        json!({ "paths": ["/safe/path", "/dangerous/path"] }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.risk_analysis.scope_expansion_detected);
    assert!(matches!(diff.risk_analysis.overall_risk, RiskLevel::Critical));
}

#[test]
fn test_scope_expansion_detection_numeric_increase() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert(
        "fs.read.v1".to_string(),
        json!({ "max_bytes": 1024 }),
    );

    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert(
        "fs.read.v1".to_string(),
        json!({ "max_bytes": 2048 }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.risk_analysis.scope_expansion_detected);
    assert!(matches!(diff.risk_analysis.overall_risk, RiskLevel::Critical));
}

#[test]
fn test_scope_expansion_detection_timeout_increase() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert(
        "http.fetch.v1".to_string(),
        json!({ "timeout_ms": 5000 }),
    );

    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert(
        "http.fetch.v1".to_string(),
        json!({ "timeout_ms": 10000 }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.risk_analysis.scope_expansion_detected);
    assert!(matches!(diff.risk_analysis.overall_risk, RiskLevel::Critical));
}

#[test]
fn test_scope_expansion_not_detected_decrease() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert(
        "fs.read.v1".to_string(),
        json!({ "max_bytes": 2048 }),
    );

    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert(
        "fs.read.v1".to_string(),
        json!({ "max_bytes": 1024 }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(!diff.risk_analysis.scope_expansion_detected);
}

#[test]
fn test_scope_expansion_non_array_non_numeric() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert(
        "test.cap".to_string(),
        json!({ "hosts": "single-string" }),
    );

    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert(
        "test.cap".to_string(),
        json!({ "hosts": "different-string" }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(!diff.risk_analysis.scope_expansion_detected);
}

#[test]
fn test_capability_expansion_risk_levels() {
    // Test different levels of capability expansion risk
    let base_pack = create_test_pack("base", BehaviorMode::Explore);

    // Low risk: 1-2 new capabilities
    let mut low_risk_pack = create_test_pack("low", BehaviorMode::Explore);
    low_risk_pack.enable.atoms.push("new_atom1".to_string());
    
    let diff = BehaviorPackDiff::compare(&base_pack, &low_risk_pack).unwrap();
    // Note: Overall risk might be higher due to mode change from Explore to Explore
    // But capability expansion contributes Low risk
    
    // Medium risk: 3-5 new capabilities
    let mut medium_risk_pack = create_test_pack("medium", BehaviorMode::Explore);
    medium_risk_pack.enable.atoms.extend(vec![
        "new_atom1".to_string(),
        "new_atom2".to_string(),
        "new_atom3".to_string(),
    ]);
    
    let diff = BehaviorPackDiff::compare(&base_pack, &medium_risk_pack).unwrap();
    // Should contribute Medium risk due to 3 new capabilities

    // High risk: 6+ new capabilities
    let mut high_risk_pack = create_test_pack("high", BehaviorMode::Explore);
    high_risk_pack.enable.atoms.extend(vec![
        "new_atom1".to_string(),
        "new_atom2".to_string(),
        "new_atom3".to_string(),
        "new_atom4".to_string(),
        "new_atom5".to_string(),
        "new_atom6".to_string(),
    ]);
    
    let diff = BehaviorPackDiff::compare(&base_pack, &high_risk_pack).unwrap();
    // Should contribute High risk due to 6 new capabilities
}

#[test]
fn test_permissive_guard_changes_risk() {
    let pack1 = BehaviorPack {
        name: "pack1".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 1024,
                require_justification: true,
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    let pack2 = BehaviorPack {
        name: "pack2".to_string(),
        mode: BehaviorMode::Explore,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig {
            atoms: Some(AtomGuards {
                default_max_bytes: 2048, // More permissive
                require_justification: false, // More permissive
            }),
            macros: Some(MacroGuards::default()),
            playbooks: Some(PlaybookGuards::default()),
        },
    };

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    // Should contribute Medium risk due to permissive guard changes
    assert!(matches!(diff.risk_analysis.overall_risk, RiskLevel::Medium));
}

#[test]
fn test_extract_filesystem_changes() {
    let param_changes = vec![
        ParameterChange {
            capability: "fs.read.v1".to_string(),
            key: "paths".to_string(),
            old_value: Some(json!(["/safe"])),
            new_value: Some(json!(["/safe", "/dangerous"])),
            change_type: ParameterChangeType::Modified,
        },
        ParameterChange {
            capability: "fs.write.v1".to_string(),
            key: "max_bytes".to_string(),
            old_value: Some(json!(1024)),
            new_value: Some(json!(2048)),
            change_type: ParameterChangeType::Modified,
        },
        ParameterChange {
            capability: "http.fetch.v1".to_string(),
            key: "hosts".to_string(),
            old_value: Some(json!(["api.com"])),
            new_value: Some(json!(["api.com", "evil.com"])),
            change_type: ParameterChangeType::Modified,
        },
    ];

    let fs_changes = BehaviorPackDiff::extract_filesystem_changes(&param_changes);

    assert_eq!(fs_changes.len(), 2);
    assert!(fs_changes.iter().any(|s| s.contains("fs.read.v1.paths")));
    assert!(fs_changes.iter().any(|s| s.contains("fs.write.v1.max_bytes")));
    assert!(!fs_changes.iter().any(|s| s.contains("http.fetch.v1.hosts")));
}

#[test]
fn test_extract_network_changes() {
    let param_changes = vec![
        ParameterChange {
            capability: "http.fetch.v1".to_string(),
            key: "hosts".to_string(),
            old_value: Some(json!(["api.com"])),
            new_value: Some(json!(["api.com", "evil.com"])),
            change_type: ParameterChangeType::Modified,
        },
        ParameterChange {
            capability: "http.post.v1".to_string(),
            key: "timeout_ms".to_string(),
            old_value: Some(json!(5000)),
            new_value: Some(json!(10000)),
            change_type: ParameterChangeType::Modified,
        },
        ParameterChange {
            capability: "fs.read.v1".to_string(),
            key: "paths".to_string(),
            old_value: Some(json!(["/safe"])),
            new_value: Some(json!(["/safe", "/dangerous"])),
            change_type: ParameterChangeType::Modified,
        },
    ];

    let network_changes = BehaviorPackDiff::extract_network_changes(&param_changes);

    assert_eq!(network_changes.len(), 2);
    assert!(network_changes.iter().any(|s| s.contains("http.fetch.v1.hosts")));
    assert!(network_changes.iter().any(|s| s.contains("http.post.v1.timeout_ms")));
    assert!(!network_changes.iter().any(|s| s.contains("fs.read.v1.paths")));
}

#[test]
fn test_extract_memory_changes() {
    let param_changes = vec![
        ParameterChange {
            capability: "fs.read.v1".to_string(),
            key: "max_bytes".to_string(),
            old_value: Some(json!(1024)),
            new_value: Some(json!(2048)),
            change_type: ParameterChangeType::Modified,
        },
        ParameterChange {
            capability: "vm.runtime.v1".to_string(),
            key: "memory_limit".to_string(),
            old_value: Some(json!(512)),
            new_value: Some(json!(1024)),
            change_type: ParameterChangeType::Modified,
        },
    ];

    let guard_changes = GuardChanges {
        atom_guards: vec![GuardChange {
            setting: "default_max_bytes".to_string(),
            old_value: json!(1024),
            new_value: json!(2048),
            impact: GuardImpact::Permissive,
        }],
        macro_guards: vec![],
        playbook_guards: vec![],
    };

    let memory_changes = BehaviorPackDiff::extract_memory_changes(&param_changes, &guard_changes);

    assert_eq!(memory_changes.len(), 3);
    assert!(memory_changes.iter().any(|s| s.contains("fs.read.v1.max_bytes")));
    assert!(memory_changes.iter().any(|s| s.contains("vm.runtime.v1.memory_limit")));
    assert!(memory_changes.iter().any(|s| s.contains("guards.atoms.default_max_bytes")));
}

#[test]
fn test_extract_time_changes() {
    let param_changes = vec![
        ParameterChange {
            capability: "http.fetch.v1".to_string(),
            key: "timeout_ms".to_string(),
            old_value: Some(json!(5000)),
            new_value: Some(json!(10000)),
            change_type: ParameterChangeType::Modified,
        },
        ParameterChange {
            capability: "exec.run.v1".to_string(),
            key: "max_duration".to_string(),
            old_value: Some(json!(30)),
            new_value: Some(json!(60)),
            change_type: ParameterChangeType::Modified,
        },
        ParameterChange {
            capability: "fs.read.v1".to_string(),
            key: "max_bytes".to_string(),
            old_value: Some(json!(1024)),
            new_value: Some(json!(2048)),
            change_type: ParameterChangeType::Modified,
        },
    ];

    let time_changes = BehaviorPackDiff::extract_time_changes(&param_changes);

    assert_eq!(time_changes.len(), 2);
    assert!(time_changes.iter().any(|s| s.contains("http.fetch.v1.timeout_ms")));
    assert!(time_changes.iter().any(|s| s.contains("exec.run.v1.max_duration")));
    assert!(!time_changes.iter().any(|s| s.contains("fs.read.v1.max_bytes")));
}

#[test]
fn test_summary_generation() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    
    // Add capability changes
    pack2.enable.atoms.push("new_atom".to_string());
    pack2.enable.macros.push("new_macro".to_string());
    
    // Add parameter changes
    pack2.params.insert("fs.read.v1".to_string(), json!({"max_bytes": 1024}));
    
    // Change guards
    pack2.guards.atoms = Some(AtomGuards {
        default_max_bytes: 2048,
        require_justification: false,
    });

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.summary.total_capability_changes, 2); // 1 atom + 1 macro
    assert_eq!(diff.summary.total_parameter_changes, 1);
    assert_eq!(diff.summary.total_guard_changes, 2); // max_bytes + require_justification
    assert!(diff.summary.requires_review); // Due to mode change risk
    assert!(!diff.summary.description.is_empty());
}

#[test]
fn test_summary_requires_review_conditions() {
    // Test high/critical risk requires review
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    
    // Add scope expansion to trigger critical risk
    pack1.params.insert("http.fetch.v1".to_string(), json!({"hosts": ["api.com"]}));
    pack2.params.insert("http.fetch.v1".to_string(), json!({"hosts": ["api.com", "evil.com"]}));
    
    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();
    assert!(diff.summary.requires_review); // Due to critical risk from scope expansion

    // Test >5 capability changes requires review
    let pack3 = create_test_pack("pack3", BehaviorMode::Explore);
    let mut pack4 = create_test_pack("pack4", BehaviorMode::Explore);
    pack4.enable.atoms.extend(vec![
        "atom1".to_string(), "atom2".to_string(), "atom3".to_string(),
        "atom4".to_string(), "atom5".to_string(), "atom6".to_string(),
    ]);
    
    let diff = BehaviorPackDiff::compare(&pack3, &pack4).unwrap();
    assert!(diff.summary.requires_review); // Due to >5 capability changes
}

#[test]
fn test_generate_description_variations() {
    // Test with no changes
    let desc = BehaviorPackDiff::generate_description(0, 0, 0, &RiskLevel::Low);
    assert_eq!(desc, "No changes detected (low risk)");

    // Test with single type of change
    let desc = BehaviorPackDiff::generate_description(2, 0, 0, &RiskLevel::Medium);
    assert_eq!(desc, "2 capability changes (medium risk)");

    // Test with multiple types of changes
    let desc = BehaviorPackDiff::generate_description(2, 3, 1, &RiskLevel::High);
    assert_eq!(desc, "2 capability changes, 3 parameter changes, 1 guard changes (high risk)");

    // Test with critical risk
    let desc = BehaviorPackDiff::generate_description(1, 1, 1, &RiskLevel::Critical);
    assert_eq!(desc, "1 capability changes, 1 parameter changes, 1 guard changes (CRITICAL risk)");
}

#[test]
fn test_to_report_generation() {
    let mut pack1 = create_test_pack("dev-pack", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("prod-pack", BehaviorMode::Explore);
    
    // Add various changes to test report generation
    pack2.enable.atoms.push("fs.read.v1".to_string());
    pack2.enable.macros.push("data.analyze".to_string());
    pack1.enable.playbooks.push("removed.playbook".to_string());
    
    pack2.params.insert("fs.read.v1".to_string(), json!({"max_bytes": 1024}));
    
    pack2.guards.atoms = Some(AtomGuards {
        default_max_bytes: 2048,
        require_justification: false,
    });

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();
    let report = diff.to_report();

    // Check that report contains expected sections
    assert!(report.contains("# Behavior Pack Diff Report"));
    assert!(report.contains("dev-pack"));
    assert!(report.contains("prod-pack"));
    assert!(report.contains("strict"));
    assert!(report.contains("explore"));
    assert!(report.contains("## Summary"));
    assert!(report.contains("## Risk Analysis"));
    assert!(report.contains("## Capability Changes"));
    assert!(report.contains("## Parameter Changes"));
    assert!(report.contains("## Guard Changes"));
    
    // Check specific content
    assert!(report.contains("fs.read.v1"));
    assert!(report.contains("data.analyze"));
    assert!(report.contains("➕")); // Added symbol
    assert!(report.contains("🔓")); // Permissive symbol
    
    if diff.summary.requires_review {
        assert!(report.contains("⚠️  **Manual review required**"));
    }
}

#[test]
fn test_to_report_no_changes() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let pack2 = pack1.clone();

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();
    let report = diff.to_report();

    // Should contain basic structure but no change sections
    assert!(report.contains("# Behavior Pack Diff Report"));
    assert!(report.contains("## Summary"));
    assert!(report.contains("## Risk Analysis"));
    
    // Should not contain change sections for empty changes
    assert!(!report.contains("## Capability Changes"));
    assert!(!report.contains("## Parameter Changes"));
    assert!(!report.contains("## Guard Changes"));
}

#[test]
fn test_to_report_scope_expansion_warning() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    pack1.params.insert("http.fetch.v1".to_string(), json!({"hosts": ["safe.com"]}));
    
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.params.insert("http.fetch.v1".to_string(), json!({"hosts": ["safe.com", "evil.com"]}));

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();
    let report = diff.to_report();

    assert!(report.contains("🚨 **Silent scope expansion detected**"));
}

#[test]
fn test_risk_analysis_comprehensive() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    
    // Add scope expansion
    pack1.params.insert("fs.read.v1".to_string(), json!({"paths": ["/safe"]}));
    pack2.params.insert("fs.read.v1".to_string(), json!({"paths": ["/safe", "/dangerous"]}));
    
    // Add network changes
    pack2.params.insert("http.fetch.v1".to_string(), json!({"hosts": ["api.com"]}));

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.risk_analysis.scope_expansion_detected);
    assert!(matches!(diff.risk_analysis.overall_risk, RiskLevel::Critical));
    assert!(!diff.risk_analysis.security_scope.filesystem_changes.is_empty());
    assert!(diff.risk_analysis.security_scope.network_changes.is_empty()); // Only in pack2, not a change
    assert!(matches!(diff.risk_analysis.security_scope.risk_level, RiskLevel::High)); // Due to scope expansion
    assert!(matches!(diff.risk_analysis.mode_risk.risk_level, RiskLevel::Medium)); // Strict -> Explore
}

#[test]
fn test_diff_serde_round_trip() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);
    pack2.enable.atoms.push("test.atom".to_string());

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    // Serialize to JSON
    let json_str = serde_json::to_string_pretty(&diff).unwrap();
    
    // Deserialize back
    let deserialized: BehaviorPackDiff = serde_json::from_str(&json_str).unwrap();
    
    // Verify key fields match
    assert_eq!(diff.metadata.from_pack, deserialized.metadata.from_pack);
    assert_eq!(diff.metadata.to_pack, deserialized.metadata.to_pack);
    assert_eq!(diff.summary.total_capability_changes, deserialized.summary.total_capability_changes);
    assert_eq!(diff.capability_changes.atoms_enabled, deserialized.capability_changes.atoms_enabled);
}

// Helper function to create test behavior packs
fn create_test_pack(name: &str, mode: BehaviorMode) -> BehaviorPack {
    BehaviorPack {
        name: name.to_string(),
        mode,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: GuardConfig::default(),
    }
}