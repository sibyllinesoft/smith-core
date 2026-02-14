//! Comprehensive test coverage for behavior pack diff analysis
//!
//! NUCLEAR COVERAGE TARGET: 100% CODE OBLITERATION

use crate::behavior::{
    AtomGuards, BehaviorMode, BehaviorPack, EnabledCapabilities, MacroGuards, ValidationLevel,
};
use crate::diff::{BehaviorPackDiff, ParameterChangeType, RiskLevel};
use serde_json::json;
use std::collections::HashMap;

// Helper function to create a test behavior pack
fn create_test_pack(name: &str, mode: BehaviorMode) -> BehaviorPack {
    BehaviorPack {
        name: name.to_string(),
        mode,
        enable: EnabledCapabilities::default(),
        params: HashMap::new(),
        guards: crate::behavior::GuardConfig::default(),
    }
}

#[test]
fn test_diff_metadata_creation() {
    let pack1 = create_test_pack("old_pack", BehaviorMode::Strict);
    let pack2 = create_test_pack("new_pack", BehaviorMode::Explore);

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.metadata.from_pack, "old_pack");
    assert_eq!(diff.metadata.to_pack, "new_pack");
    assert_eq!(diff.metadata.from_mode, BehaviorMode::Strict);
    assert_eq!(diff.metadata.to_mode, BehaviorMode::Explore);
    assert!(!diff.metadata.timestamp.is_empty());
}

#[test]
fn test_basic_pack_comparison() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.metadata.from_pack, "pack1");
    assert_eq!(diff.metadata.to_pack, "pack2");
    assert_eq!(diff.metadata.from_mode, BehaviorMode::Strict);
    assert_eq!(diff.metadata.to_mode, BehaviorMode::Explore);
}

#[test]
fn test_capability_changes_detection() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Strict);

    // Add capabilities to pack2
    pack2.enable.atoms.push("fs.read.v1".to_string());
    pack2.enable.macros.push("data.process".to_string());
    pack2.enable.playbooks.push("deploy.sequence".to_string());

    // Add different capabilities to pack1
    pack1.enable.atoms.push("http.fetch.v1".to_string());

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    // Should detect additions and removals
    assert!(!diff.capability_changes.atoms_enabled.is_empty());
    assert!(!diff.capability_changes.atoms_disabled.is_empty());
    assert!(!diff.capability_changes.macros_enabled.is_empty());
    assert!(!diff.capability_changes.playbooks_enabled.is_empty());
}

#[test]
fn test_parameter_changes_detection() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Strict);

    // Add parameters
    pack1
        .params
        .insert("fs.read.v1".to_string(), json!({"max_bytes": 1024}));
    pack2
        .params
        .insert("fs.read.v1".to_string(), json!({"max_bytes": 2048}));
    pack2
        .params
        .insert("http.fetch.v1".to_string(), json!({"timeout_ms": 5000}));

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(!diff.parameter_changes.is_empty());

    // Should detect modified parameter
    let modified: Vec<_> = diff
        .parameter_changes
        .iter()
        .filter(|c| c.change_type == ParameterChangeType::Modified)
        .collect();
    assert!(!modified.is_empty());

    // Should detect added parameter
    let added: Vec<_> = diff
        .parameter_changes
        .iter()
        .filter(|c| c.change_type == ParameterChangeType::Added)
        .collect();
    assert!(!added.is_empty());
}

#[test]
fn test_guard_changes_detection() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Strict);

    // Modify guards
    pack2.guards.atoms = Some(AtomGuards {
        default_max_bytes: 2048,
        require_justification: false,
    });

    pack2.guards.macros = Some(MacroGuards {
        template_validation: ValidationLevel::Permissive,
    });

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    let total_guard_changes = diff.guard_changes.atom_guards.len()
        + diff.guard_changes.macro_guards.len()
        + diff.guard_changes.playbook_guards.len();
    assert!(total_guard_changes > 0);
}

#[test]
fn test_risk_analysis_low_risk() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Strict);

    // Small, safe change
    pack2.enable.atoms.push("fs.read.v1".to_string());

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.risk_analysis.overall_risk, RiskLevel::Low);
    assert!(!diff.risk_analysis.scope_expansion_detected);
}

#[test]
fn test_risk_analysis_medium_risk() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    // Mode change creates medium risk
    pack2
        .enable
        .atoms
        .extend(vec!["fs.read.v1".to_string(), "http.fetch.v1".to_string()]);

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(matches!(
        diff.risk_analysis.overall_risk,
        RiskLevel::Medium | RiskLevel::High
    ));
}

#[test]
fn test_scope_expansion_detection_hosts() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    // Silent scope expansion through host lists
    pack1.params.insert(
        "http.fetch.v1".to_string(),
        json!({"hosts": ["api.example.com"]}),
    );
    pack2.params.insert(
        "http.fetch.v1".to_string(),
        json!({"hosts": ["api.example.com", "malicious.com"]}),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.risk_analysis.scope_expansion_detected);
    assert!(matches!(
        diff.risk_analysis.overall_risk,
        RiskLevel::Critical
    ));
}

#[test]
fn test_scope_expansion_detection_paths() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    // Scope expansion through path changes
    pack1.params.insert(
        "fs.read.v1".to_string(),
        json!({"allowed_paths": ["/home/user/docs"]}),
    );
    pack2.params.insert(
        "fs.read.v1".to_string(),
        json!({"allowed_paths": ["/home/user/docs", "/etc"]}),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.risk_analysis.scope_expansion_detected);
    assert!(matches!(
        diff.risk_analysis.overall_risk,
        RiskLevel::Critical
    ));
}

#[test]
fn test_summary_generation() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    // Add capability changes
    pack2.enable.atoms.push("new_atom".to_string());
    pack2.enable.macros.push("new_macro".to_string());

    // Add parameter changes
    pack2
        .params
        .insert("fs.read.v1".to_string(), json!({"max_bytes": 1024}));

    // Change guards
    pack2.guards.atoms = Some(AtomGuards {
        default_max_bytes: 2048,
        require_justification: false,
    });

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.summary.total_capability_changes > 0);
    assert!(diff.summary.total_parameter_changes > 0);
    assert!(diff.summary.total_guard_changes > 0);
    assert!(!diff.summary.description.is_empty());
}

#[test]
fn test_review_requirements() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    // Add scope expansion to trigger critical risk
    pack1
        .params
        .insert("http.fetch.v1".to_string(), json!({"hosts": ["api.com"]}));
    pack2.params.insert(
        "http.fetch.v1".to_string(),
        json!({"hosts": ["api.com", "evil.com"]}),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();
    assert!(diff.summary.requires_review); // Due to critical risk from scope expansion

    // Test >5 capability changes requires review
    let pack3 = create_test_pack("pack3", BehaviorMode::Explore);
    let mut pack4 = create_test_pack("pack4", BehaviorMode::Explore);
    pack4.enable.atoms.extend(vec![
        "atom1".to_string(),
        "atom2".to_string(),
        "atom3".to_string(),
        "atom4".to_string(),
        "atom5".to_string(),
        "atom6".to_string(),
    ]);

    let diff = BehaviorPackDiff::compare(&pack3, &pack4).unwrap();
    assert!(diff.summary.requires_review); // Due to >5 capability changes
}

#[test]
fn test_to_report_generation() {
    let mut pack1 = create_test_pack("dev-pack", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("prod-pack", BehaviorMode::Explore);

    // Add various changes to test report generation
    pack2.enable.atoms.push("fs.read.v1".to_string());
    pack2.enable.macros.push("data.analyze".to_string());
    pack1.enable.playbooks.push("removed.playbook".to_string());

    pack2
        .params
        .insert("fs.read.v1".to_string(), json!({"max_bytes": 2048}));
    pack2.guards.atoms = Some(AtomGuards {
        default_max_bytes: 4096,
        require_justification: false,
    });

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();
    let report = diff.to_report();

    // Verify report contains essential sections
    assert!(report.contains("dev-pack"));
    assert!(report.contains("prod-pack"));
    assert!(report.contains("Risk Level:"));
    assert!(report.contains("Total Changes:"));

    // Should contain change details
    assert!(report.contains("Capability Changes") || report.contains("capabilities"));
    assert!(report.contains("Parameter Changes") || report.contains("parameters"));
    assert!(report.contains("Guard Changes") || report.contains("guards"));
}

#[test]
fn test_identical_packs_no_changes() {
    let pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let pack2 = create_test_pack("pack1", BehaviorMode::Strict); // Same as pack1

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert_eq!(diff.summary.total_capability_changes, 0);
    assert_eq!(diff.summary.total_parameter_changes, 0);
    assert_eq!(diff.summary.total_guard_changes, 0);
    assert_eq!(diff.risk_analysis.overall_risk, RiskLevel::Low);
    assert!(!diff.summary.requires_review);
}

#[test]
fn test_complex_parameter_nesting() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Explore);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    // Complex nested parameter changes
    pack1.params.insert(
        "complex.capability".to_string(),
        json!({
            "config": {
                "timeouts": {"read": 1000, "write": 2000},
                "limits": {"max_size": 1024}
            }
        }),
    );

    pack2.params.insert(
        "complex.capability".to_string(),
        json!({
            "config": {
                "timeouts": {"read": 1500, "write": 2000},
                "limits": {"max_size": 2048, "max_files": 100}
            }
        }),
    );

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(diff.summary.total_parameter_changes > 0);
    assert!(diff
        .parameter_changes
        .iter()
        .any(|c| c.capability == "complex.capability"));
}

#[test]
fn test_error_handling_invalid_comparison() {
    // Test with empty pack names
    let pack1 = create_test_pack("", BehaviorMode::Strict);
    let pack2 = create_test_pack("valid", BehaviorMode::Strict);

    // Should handle gracefully - empty names are still valid for comparison
    let result = BehaviorPackDiff::compare(&pack1, &pack2);
    assert!(result.is_ok());
}

#[test]
fn test_risk_factors_comprehensive() {
    let mut pack1 = create_test_pack("pack1", BehaviorMode::Strict);
    let mut pack2 = create_test_pack("pack2", BehaviorMode::Explore);

    // Add all types of risk factors
    pack2.enable.atoms.extend(vec![
        "fs.write.v1".to_string(),
        "exec.run.v1".to_string(),
        "network.access.v1".to_string(),
    ]);

    pack2
        .params
        .insert("exec.run.v1".to_string(), json!({"allow_sudo": true}));
    pack1.params.insert(
        "network.access.v1".to_string(),
        json!({"hosts": ["safe.com"]}),
    );
    pack2.params.insert(
        "network.access.v1".to_string(),
        json!({"hosts": ["safe.com", "unknown.com"]}),
    );

    pack2.guards.atoms = Some(AtomGuards {
        default_max_bytes: 1048576,
        require_justification: false,
    });

    let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

    assert!(matches!(
        diff.risk_analysis.overall_risk,
        RiskLevel::Critical
    ));
    assert!(diff.risk_analysis.scope_expansion_detected);
    assert!(diff.summary.requires_review);
}
