//! Behavior pack diff analysis engine
//!
//! This module provides human-readable analysis of changes between behavior packs,
//! including capability enablement/disablement, parameter changes, and risk deltas.

use crate::behavior::{BehaviorMode, BehaviorPack};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Diff analysis result for behavior pack changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPackDiff {
    /// Comparison metadata
    pub metadata: DiffMetadata,
    /// Changes to capability enablement
    pub capability_changes: CapabilityChanges,
    /// Parameter changes for capabilities
    pub parameter_changes: Vec<ParameterChange>,
    /// Guard configuration changes
    pub guard_changes: GuardChanges,
    /// Risk assessment of the changes
    pub risk_analysis: RiskAnalysis,
    /// Summary of the changes
    pub summary: DiffSummary,
}

/// Metadata about the diff comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffMetadata {
    /// Name of the original behavior pack
    pub from_pack: String,
    /// Name of the new behavior pack
    pub to_pack: String,
    /// Original execution mode
    pub from_mode: BehaviorMode,
    /// New execution mode
    pub to_mode: BehaviorMode,
    /// Timestamp of the comparison
    pub timestamp: String,
}

/// Changes to enabled capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityChanges {
    /// Newly enabled atoms
    pub atoms_enabled: Vec<String>,
    /// Newly disabled atoms
    pub atoms_disabled: Vec<String>,
    /// Newly enabled macros
    pub macros_enabled: Vec<String>,
    /// Newly disabled macros
    pub macros_disabled: Vec<String>,
    /// Newly enabled playbooks
    pub playbooks_enabled: Vec<String>,
    /// Newly disabled playbooks
    pub playbooks_disabled: Vec<String>,
}

/// A change to capability parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterChange {
    /// Name of the capability
    pub capability: String,
    /// Parameter key that changed
    pub key: String,
    /// Previous value (if any)
    pub old_value: Option<serde_json::Value>,
    /// New value (if any)
    pub new_value: Option<serde_json::Value>,
    /// Type of change
    pub change_type: ParameterChangeType,
}

/// Type of parameter change
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ParameterChangeType {
    /// Parameter was added
    Added,
    /// Parameter was removed
    Removed,
    /// Parameter value was modified
    Modified,
}

/// Changes to guard configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardChanges {
    /// Changes to atom guards
    pub atom_guards: Vec<GuardChange>,
    /// Changes to macro guards
    pub macro_guards: Vec<GuardChange>,
    /// Changes to playbook guards
    pub playbook_guards: Vec<GuardChange>,
}

/// A specific guard configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardChange {
    /// Name of the guard setting
    pub setting: String,
    /// Previous value
    pub old_value: serde_json::Value,
    /// New value
    pub new_value: serde_json::Value,
    /// Impact assessment
    pub impact: GuardImpact,
}

/// Impact level of a guard change
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardImpact {
    /// Change makes the system more secure/restrictive
    Restrictive,
    /// Change makes the system less secure/more permissive
    Permissive,
    /// Change has neutral security impact
    Neutral,
}

/// Risk analysis of the behavior pack changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAnalysis {
    /// Overall risk level
    pub overall_risk: RiskLevel,
    /// Security scope changes
    pub security_scope: ScopeRiskAnalysis,
    /// Resource limit changes
    pub resource_limits: ResourceRiskAnalysis,
    /// Mode transition risk
    pub mode_risk: ModeRiskAnalysis,
    /// Silent scope expansion detected
    pub scope_expansion_detected: bool,
}

/// Risk levels for changes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Security scope risk analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRiskAnalysis {
    /// File system scope changes
    pub filesystem_changes: Vec<String>,
    /// Network scope changes
    pub network_changes: Vec<String>,
    /// Risk level for scope changes
    pub risk_level: RiskLevel,
}

/// Resource limit risk analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRiskAnalysis {
    /// Memory limit changes
    pub memory_limit_changes: Vec<String>,
    /// Time limit changes
    pub time_limit_changes: Vec<String>,
    /// Risk level for resource changes
    pub risk_level: RiskLevel,
}

/// Mode transition risk analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeRiskAnalysis {
    /// Risk level of the mode change
    pub risk_level: RiskLevel,
    /// Description of the mode change impact
    pub description: String,
}

/// High-level summary of the diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Total number of capability changes
    pub total_capability_changes: usize,
    /// Total number of parameter changes
    pub total_parameter_changes: usize,
    /// Total number of guard changes
    pub total_guard_changes: usize,
    /// Whether manual review is recommended
    pub requires_review: bool,
    /// Human-readable summary description
    pub description: String,
}

impl BehaviorPackDiff {
    /// Compare two behavior packs and generate a diff analysis
    pub fn compare(from: &BehaviorPack, to: &BehaviorPack) -> Result<Self> {
        let metadata = DiffMetadata {
            from_pack: from.name.clone(),
            to_pack: to.name.clone(),
            from_mode: from.mode.clone(),
            to_mode: to.mode.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let capability_changes = Self::analyze_capability_changes(from, to);
        let parameter_changes = Self::analyze_parameter_changes(from, to);
        let guard_changes = Self::analyze_guard_changes(from, to);
        let risk_analysis = Self::analyze_risk(
            &capability_changes,
            &parameter_changes,
            &guard_changes,
            &metadata,
        );
        let summary = Self::generate_summary(
            &capability_changes,
            &parameter_changes,
            &guard_changes,
            &risk_analysis,
        );

        Ok(Self {
            metadata,
            capability_changes,
            parameter_changes,
            guard_changes,
            risk_analysis,
            summary,
        })
    }

    /// Analyze changes to capability enablement
    fn analyze_capability_changes(from: &BehaviorPack, to: &BehaviorPack) -> CapabilityChanges {
        let from_atoms: HashSet<_> = from.enable.atoms.iter().cloned().collect();
        let to_atoms: HashSet<_> = to.enable.atoms.iter().cloned().collect();

        let from_macros: HashSet<_> = from.enable.macros.iter().cloned().collect();
        let to_macros: HashSet<_> = to.enable.macros.iter().cloned().collect();

        let from_playbooks: HashSet<_> = from.enable.playbooks.iter().cloned().collect();
        let to_playbooks: HashSet<_> = to.enable.playbooks.iter().cloned().collect();

        CapabilityChanges {
            atoms_enabled: to_atoms.difference(&from_atoms).cloned().collect(),
            atoms_disabled: from_atoms.difference(&to_atoms).cloned().collect(),
            macros_enabled: to_macros.difference(&from_macros).cloned().collect(),
            macros_disabled: from_macros.difference(&to_macros).cloned().collect(),
            playbooks_enabled: to_playbooks.difference(&from_playbooks).cloned().collect(),
            playbooks_disabled: from_playbooks.difference(&to_playbooks).cloned().collect(),
        }
    }

    /// Analyze changes to capability parameters
    fn analyze_parameter_changes(from: &BehaviorPack, to: &BehaviorPack) -> Vec<ParameterChange> {
        let mut changes = Vec::new();

        // Find all capabilities that appear in either config
        let mut all_capabilities = HashSet::new();
        all_capabilities.extend(from.params.keys());
        all_capabilities.extend(to.params.keys());

        for capability in all_capabilities {
            let from_params = from.params.get(capability);
            let to_params = to.params.get(capability);

            match (from_params, to_params) {
                (None, Some(to_val)) => {
                    // Capability parameters added
                    if let Some(obj) = to_val.as_object() {
                        for (key, value) in obj {
                            changes.push(ParameterChange {
                                capability: capability.clone(),
                                key: key.clone(),
                                old_value: None,
                                new_value: Some(value.clone()),
                                change_type: ParameterChangeType::Added,
                            });
                        }
                    }
                }
                (Some(_from_val), None) => {
                    // Capability parameters removed
                    changes.push(ParameterChange {
                        capability: capability.clone(),
                        key: "*".to_string(), // Indicate all parameters removed
                        old_value: from_params.cloned(),
                        new_value: None,
                        change_type: ParameterChangeType::Removed,
                    });
                }
                (Some(from_val), Some(to_val)) => {
                    // Compare parameter objects
                    Self::compare_param_objects(capability, from_val, to_val, &mut changes);
                }
                (None, None) => {
                    // This shouldn't happen given our iteration logic
                }
            }
        }

        changes
    }

    /// Compare parameter objects for a specific capability
    fn compare_param_objects(
        capability: &str,
        from_val: &serde_json::Value,
        to_val: &serde_json::Value,
        changes: &mut Vec<ParameterChange>,
    ) {
        if let (Some(from_obj), Some(to_obj)) = (from_val.as_object(), to_val.as_object()) {
            let mut all_keys = HashSet::new();
            all_keys.extend(from_obj.keys());
            all_keys.extend(to_obj.keys());

            for key in all_keys {
                let from_key_val = from_obj.get(key);
                let to_key_val = to_obj.get(key);

                match (from_key_val, to_key_val) {
                    (None, Some(new_val)) => {
                        changes.push(ParameterChange {
                            capability: capability.to_string(),
                            key: key.clone(),
                            old_value: None,
                            new_value: Some(new_val.clone()),
                            change_type: ParameterChangeType::Added,
                        });
                    }
                    (Some(old_val), None) => {
                        changes.push(ParameterChange {
                            capability: capability.to_string(),
                            key: key.clone(),
                            old_value: Some(old_val.clone()),
                            new_value: None,
                            change_type: ParameterChangeType::Removed,
                        });
                    }
                    (Some(old_val), Some(new_val)) => {
                        if old_val != new_val {
                            changes.push(ParameterChange {
                                capability: capability.to_string(),
                                key: key.clone(),
                                old_value: Some(old_val.clone()),
                                new_value: Some(new_val.clone()),
                                change_type: ParameterChangeType::Modified,
                            });
                        }
                    }
                    (None, None) => {
                        // This shouldn't happen
                    }
                }
            }
        }
    }

    /// Analyze changes to guard configurations
    fn analyze_guard_changes(from: &BehaviorPack, to: &BehaviorPack) -> GuardChanges {
        let mut guard_changes = GuardChanges {
            atom_guards: Vec::new(),
            macro_guards: Vec::new(),
            playbook_guards: Vec::new(),
        };

        // Compare atom guards
        if let (Some(from_atom_guards), Some(to_atom_guards)) =
            (&from.guards.atoms, &to.guards.atoms)
        {
            if from_atom_guards.default_max_bytes != to_atom_guards.default_max_bytes {
                guard_changes.atom_guards.push(GuardChange {
                    setting: "default_max_bytes".to_string(),
                    old_value: serde_json::json!(from_atom_guards.default_max_bytes),
                    new_value: serde_json::json!(to_atom_guards.default_max_bytes),
                    impact: if to_atom_guards.default_max_bytes > from_atom_guards.default_max_bytes
                    {
                        GuardImpact::Permissive
                    } else {
                        GuardImpact::Restrictive
                    },
                });
            }

            if from_atom_guards.require_justification != to_atom_guards.require_justification {
                guard_changes.atom_guards.push(GuardChange {
                    setting: "require_justification".to_string(),
                    old_value: serde_json::json!(from_atom_guards.require_justification),
                    new_value: serde_json::json!(to_atom_guards.require_justification),
                    impact: if to_atom_guards.require_justification {
                        GuardImpact::Restrictive
                    } else {
                        GuardImpact::Permissive
                    },
                });
            }
        }

        // Compare playbook guards
        if let (Some(from_pb_guards), Some(to_pb_guards)) =
            (&from.guards.playbooks, &to.guards.playbooks)
        {
            if from_pb_guards.max_steps != to_pb_guards.max_steps {
                guard_changes.playbook_guards.push(GuardChange {
                    setting: "max_steps".to_string(),
                    old_value: serde_json::json!(from_pb_guards.max_steps),
                    new_value: serde_json::json!(to_pb_guards.max_steps),
                    impact: if to_pb_guards.max_steps > from_pb_guards.max_steps {
                        GuardImpact::Permissive
                    } else {
                        GuardImpact::Restrictive
                    },
                });
            }
        }

        guard_changes
    }

    /// Analyze risk implications of the changes
    fn analyze_risk(
        cap_changes: &CapabilityChanges,
        param_changes: &[ParameterChange],
        guard_changes: &GuardChanges,
        metadata: &DiffMetadata,
    ) -> RiskAnalysis {
        let mut risk_factors = Vec::new();

        // Mode change risk
        let mode_risk = Self::assess_mode_risk(&metadata.from_mode, &metadata.to_mode);
        risk_factors.push(mode_risk.risk_level.clone());

        // Capability expansion risk
        let total_new_capabilities = cap_changes.atoms_enabled.len()
            + cap_changes.macros_enabled.len()
            + cap_changes.playbooks_enabled.len();

        if total_new_capabilities > 0 {
            risk_factors.push(match total_new_capabilities {
                1..=2 => RiskLevel::Low,
                3..=5 => RiskLevel::Medium,
                _ => RiskLevel::High,
            });
        }

        // Silent scope expansion detection
        let scope_expansion_detected = Self::detect_silent_scope_expansion(param_changes);
        if scope_expansion_detected {
            risk_factors.push(RiskLevel::Critical);
        }

        // Guard permissiveness risk
        let permissive_guard_changes = guard_changes
            .atom_guards
            .iter()
            .chain(guard_changes.macro_guards.iter())
            .chain(guard_changes.playbook_guards.iter())
            .filter(|change| matches!(change.impact, GuardImpact::Permissive))
            .count();

        if permissive_guard_changes > 0 {
            risk_factors.push(RiskLevel::Medium);
        }

        // Determine overall risk
        let overall_risk = risk_factors.into_iter().max().unwrap_or(RiskLevel::Low);

        RiskAnalysis {
            overall_risk,
            security_scope: ScopeRiskAnalysis {
                filesystem_changes: Self::extract_filesystem_changes(param_changes),
                network_changes: Self::extract_network_changes(param_changes),
                risk_level: if scope_expansion_detected {
                    RiskLevel::High
                } else {
                    RiskLevel::Low
                },
            },
            resource_limits: ResourceRiskAnalysis {
                memory_limit_changes: Self::extract_memory_changes(param_changes, guard_changes),
                time_limit_changes: Self::extract_time_changes(param_changes),
                risk_level: RiskLevel::Low, // Conservative for now
            },
            mode_risk,
            scope_expansion_detected,
        }
    }

    /// Assess risk of mode changes
    fn assess_mode_risk(from_mode: &BehaviorMode, to_mode: &BehaviorMode) -> ModeRiskAnalysis {
        use BehaviorMode::*;

        match (from_mode, to_mode) {
            (Strict, Explore) => ModeRiskAnalysis {
                risk_level: RiskLevel::Medium,
                description: "Transition from strict to explore mode enables direct atom usage"
                    .to_string(),
            },
            (Strict, Shadow) => ModeRiskAnalysis {
                risk_level: RiskLevel::Low,
                description: "Transition to shadow mode - no actual execution".to_string(),
            },
            (Explore, Strict) => ModeRiskAnalysis {
                risk_level: RiskLevel::Low,
                description: "Transition to strict mode - more restrictive".to_string(),
            },
            (Explore, Shadow) => ModeRiskAnalysis {
                risk_level: RiskLevel::Low,
                description: "Transition to shadow mode - no actual execution".to_string(),
            },
            (Shadow, Strict) => ModeRiskAnalysis {
                risk_level: RiskLevel::Low,
                description: "Transition from shadow to strict mode".to_string(),
            },
            (Shadow, Explore) => ModeRiskAnalysis {
                risk_level: RiskLevel::Medium,
                description: "Transition from shadow to explore mode - enables execution"
                    .to_string(),
            },
            (Strict, Strict) | (Explore, Explore) | (Shadow, Shadow) => ModeRiskAnalysis {
                risk_level: RiskLevel::Low,
                description: "No mode change".to_string(),
            },
        }
    }

    /// Detect silent scope expansion in parameter changes
    fn detect_silent_scope_expansion(param_changes: &[ParameterChange]) -> bool {
        for change in param_changes {
            match &change.key as &str {
                "hosts" => {
                    if let (Some(old_val), Some(new_val)) = (&change.old_value, &change.new_value) {
                        if Self::array_expanded(old_val, new_val) {
                            return true;
                        }
                    }
                }
                "paths" | "allowed_paths" => {
                    if let (Some(old_val), Some(new_val)) = (&change.old_value, &change.new_value) {
                        if Self::array_expanded(old_val, new_val) {
                            return true;
                        }
                    }
                }
                "max_bytes" | "timeout_ms" => {
                    if let (Some(old_val), Some(new_val)) = (&change.old_value, &change.new_value) {
                        if Self::numeric_increased(old_val, new_val) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Check if an array parameter expanded
    fn array_expanded(old_val: &serde_json::Value, new_val: &serde_json::Value) -> bool {
        if let (Some(old_arr), Some(new_arr)) = (old_val.as_array(), new_val.as_array()) {
            new_arr.len() > old_arr.len()
        } else {
            false
        }
    }

    /// Check if a numeric parameter increased
    fn numeric_increased(old_val: &serde_json::Value, new_val: &serde_json::Value) -> bool {
        if let (Some(old_num), Some(new_num)) = (old_val.as_f64(), new_val.as_f64()) {
            new_num > old_num
        } else {
            false
        }
    }

    /// Extract filesystem-related changes from parameters
    fn extract_filesystem_changes(param_changes: &[ParameterChange]) -> Vec<String> {
        param_changes
            .iter()
            .filter(|change| matches!(change.key.as_str(), "paths" | "allowed_paths" | "max_bytes"))
            .map(|change| {
                format!(
                    "{}.{}: {:?} → {:?}",
                    change.capability, change.key, change.old_value, change.new_value
                )
            })
            .collect()
    }

    /// Extract network-related changes from parameters
    fn extract_network_changes(param_changes: &[ParameterChange]) -> Vec<String> {
        param_changes
            .iter()
            .filter(|change| matches!(change.key.as_str(), "hosts" | "timeout_ms"))
            .map(|change| {
                format!(
                    "{}.{}: {:?} → {:?}",
                    change.capability, change.key, change.old_value, change.new_value
                )
            })
            .collect()
    }

    /// Extract memory-related changes
    fn extract_memory_changes(
        param_changes: &[ParameterChange],
        guard_changes: &GuardChanges,
    ) -> Vec<String> {
        let mut changes = Vec::new();

        // From parameters
        for change in param_changes {
            if change.key.contains("memory") || change.key.contains("max_bytes") {
                changes.push(format!(
                    "{}.{}: {:?} → {:?}",
                    change.capability, change.key, change.old_value, change.new_value
                ));
            }
        }

        // From guards
        for guard_change in &guard_changes.atom_guards {
            if guard_change.setting == "default_max_bytes" {
                changes.push(format!(
                    "guards.atoms.{}: {:?} → {:?}",
                    guard_change.setting, guard_change.old_value, guard_change.new_value
                ));
            }
        }

        changes
    }

    /// Extract time-related changes
    fn extract_time_changes(param_changes: &[ParameterChange]) -> Vec<String> {
        param_changes
            .iter()
            .filter(|change| change.key.contains("timeout") || change.key.contains("duration"))
            .map(|change| {
                format!(
                    "{}.{}: {:?} → {:?}",
                    change.capability, change.key, change.old_value, change.new_value
                )
            })
            .collect()
    }

    /// Generate a high-level summary of the diff
    fn generate_summary(
        cap_changes: &CapabilityChanges,
        param_changes: &[ParameterChange],
        guard_changes: &GuardChanges,
        risk_analysis: &RiskAnalysis,
    ) -> DiffSummary {
        let total_capability_changes = cap_changes.atoms_enabled.len()
            + cap_changes.atoms_disabled.len()
            + cap_changes.macros_enabled.len()
            + cap_changes.macros_disabled.len()
            + cap_changes.playbooks_enabled.len()
            + cap_changes.playbooks_disabled.len();

        let total_guard_changes = guard_changes.atom_guards.len()
            + guard_changes.macro_guards.len()
            + guard_changes.playbook_guards.len();

        let requires_review = matches!(
            risk_analysis.overall_risk,
            RiskLevel::High | RiskLevel::Critical
        ) || risk_analysis.scope_expansion_detected
            || total_capability_changes > 5;

        let description = Self::generate_description(
            total_capability_changes,
            param_changes.len(),
            total_guard_changes,
            &risk_analysis.overall_risk,
        );

        DiffSummary {
            total_capability_changes,
            total_parameter_changes: param_changes.len(),
            total_guard_changes,
            requires_review,
            description,
        }
    }

    /// Generate human-readable description
    fn generate_description(
        cap_changes: usize,
        param_changes: usize,
        guard_changes: usize,
        risk_level: &RiskLevel,
    ) -> String {
        let mut parts = Vec::new();

        if cap_changes > 0 {
            parts.push(format!("{} capability changes", cap_changes));
        }

        if param_changes > 0 {
            parts.push(format!("{} parameter changes", param_changes));
        }

        if guard_changes > 0 {
            parts.push(format!("{} guard changes", guard_changes));
        }

        let changes_desc = if parts.is_empty() {
            "No changes detected".to_string()
        } else {
            parts.join(", ")
        };

        let risk_desc = match risk_level {
            RiskLevel::Low => "low risk",
            RiskLevel::Medium => "medium risk",
            RiskLevel::High => "high risk",
            RiskLevel::Critical => "CRITICAL risk",
        };

        format!("{} ({})", changes_desc, risk_desc)
    }

    /// Generate human-readable diff report
    pub fn to_report(&self) -> String {
        let mut report = String::new();

        report.push_str("# Behavior Pack Diff Report\n\n");
        report.push_str(&format!(
            "**From:** {} ({})\n",
            self.metadata.from_pack,
            format!("{:?}", self.metadata.from_mode).to_lowercase()
        ));
        report.push_str(&format!(
            "**To:** {} ({})\n",
            self.metadata.to_pack,
            format!("{:?}", self.metadata.to_mode).to_lowercase()
        ));
        report.push_str(&format!("**Timestamp:** {}\n\n", self.metadata.timestamp));

        // Summary
        report.push_str("## Summary\n\n");
        report.push_str(&format!("{}\n\n", self.summary.description));

        // Total changes summary
        report.push_str(&format!(
            "**Total Changes:** {} capabilities, {} parameters, {} guards\n\n",
            self.summary.total_capability_changes,
            self.summary.total_parameter_changes,
            self.summary.total_guard_changes
        ));

        if self.summary.requires_review {
            report.push_str("⚠️  **Manual review required**\n\n");
        }

        // Risk Analysis
        report.push_str("## Risk Analysis\n\n");
        report.push_str(&format!(
            "**Risk Level:** {:?}\n",
            self.risk_analysis.overall_risk
        ));

        if self.risk_analysis.scope_expansion_detected {
            report.push_str("🚨 **Silent scope expansion detected**\n");
        }

        report.push_str(&format!(
            "**Mode Change Risk:** {:?} - {}\n\n",
            self.risk_analysis.mode_risk.risk_level, self.risk_analysis.mode_risk.description
        ));

        // Capability Changes
        if self.summary.total_capability_changes > 0 {
            report.push_str("## Capability Changes\n\n");

            if !self.capability_changes.atoms_enabled.is_empty() {
                report.push_str(&format!(
                    "**Atoms Enabled:** {}\n",
                    self.capability_changes.atoms_enabled.join(", ")
                ));
            }
            if !self.capability_changes.atoms_disabled.is_empty() {
                report.push_str(&format!(
                    "**Atoms Disabled:** {}\n",
                    self.capability_changes.atoms_disabled.join(", ")
                ));
            }
            if !self.capability_changes.macros_enabled.is_empty() {
                report.push_str(&format!(
                    "**Macros Enabled:** {}\n",
                    self.capability_changes.macros_enabled.join(", ")
                ));
            }
            if !self.capability_changes.macros_disabled.is_empty() {
                report.push_str(&format!(
                    "**Macros Disabled:** {}\n",
                    self.capability_changes.macros_disabled.join(", ")
                ));
            }
            if !self.capability_changes.playbooks_enabled.is_empty() {
                report.push_str(&format!(
                    "**Playbooks Enabled:** {}\n",
                    self.capability_changes.playbooks_enabled.join(", ")
                ));
            }
            if !self.capability_changes.playbooks_disabled.is_empty() {
                report.push_str(&format!(
                    "**Playbooks Disabled:** {}\n",
                    self.capability_changes.playbooks_disabled.join(", ")
                ));
            }
            report.push('\n');
        }

        // Parameter Changes
        if !self.parameter_changes.is_empty() {
            report.push_str("## Parameter Changes\n\n");
            for change in &self.parameter_changes {
                let change_symbol = match change.change_type {
                    ParameterChangeType::Added => "➕",
                    ParameterChangeType::Removed => "➖",
                    ParameterChangeType::Modified => "🔄",
                };
                report.push_str(&format!(
                    "{} **{}.{}:** {:?} → {:?}\n",
                    change_symbol,
                    change.capability,
                    change.key,
                    change.old_value,
                    change.new_value
                ));
            }
            report.push('\n');
        }

        // Guard Changes
        if self.summary.total_guard_changes > 0 {
            report.push_str("## Guard Changes\n\n");
            for change in &self.guard_changes.atom_guards {
                let impact_symbol = match change.impact {
                    GuardImpact::Restrictive => "🔒",
                    GuardImpact::Permissive => "🔓",
                    GuardImpact::Neutral => "⚖️",
                };
                report.push_str(&format!(
                    "{} **atoms.{}:** {:?} → {:?}\n",
                    impact_symbol, change.setting, change.old_value, change.new_value
                ));
            }
            report.push('\n');
        }

        report
    }
}

// Add chrono dependency for timestamp generation
// This would need to be added to Cargo.toml:
// chrono = { version = "0.4", features = ["serde"] }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::{EnabledCapabilities, GuardConfig};
    use std::collections::HashMap;

    #[test]
    fn test_behavior_pack_diff_no_changes() {
        let pack1 = BehaviorPack {
            name: "test-pack".to_string(),
            mode: BehaviorMode::Strict,
            enable: EnabledCapabilities::default(),
            params: HashMap::new(),
            guards: GuardConfig::default(),
        };

        let pack2 = pack1.clone();

        let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();
        assert_eq!(diff.summary.total_capability_changes, 0);
        assert_eq!(diff.summary.total_parameter_changes, 0);
        assert!(matches!(diff.risk_analysis.overall_risk, RiskLevel::Low));
    }

    #[test]
    fn test_capability_changes_detection() {
        let pack1 = BehaviorPack {
            name: "pack1".to_string(),
            mode: BehaviorMode::Strict,
            enable: EnabledCapabilities {
                atoms: vec!["atom1".to_string()],
                macros: vec!["macro1".to_string()],
                playbooks: vec!["playbook1".to_string()],
            },
            params: HashMap::new(),
            guards: GuardConfig::default(),
        };

        let pack2 = BehaviorPack {
            name: "pack2".to_string(),
            mode: BehaviorMode::Strict,
            enable: EnabledCapabilities {
                atoms: vec!["atom1".to_string(), "atom2".to_string()],
                macros: vec!["macro2".to_string()],
                playbooks: vec!["playbook1".to_string()],
            },
            params: HashMap::new(),
            guards: GuardConfig::default(),
        };

        let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();

        assert_eq!(diff.capability_changes.atoms_enabled, vec!["atom2"]);
        assert_eq!(diff.capability_changes.macros_enabled, vec!["macro2"]);
        assert_eq!(diff.capability_changes.macros_disabled, vec!["macro1"]);
        assert!(diff.summary.total_capability_changes > 0);
    }

    #[test]
    fn test_scope_expansion_detection() {
        let mut params1 = HashMap::new();
        params1.insert(
            "http.fetch.v1".to_string(),
            serde_json::json!({
                "hosts": ["api.example.com"]
            }),
        );

        let mut params2 = HashMap::new();
        params2.insert(
            "http.fetch.v1".to_string(),
            serde_json::json!({
                "hosts": ["api.example.com", "untrusted.com"]
            }),
        );

        let pack1 = BehaviorPack {
            name: "pack1".to_string(),
            mode: BehaviorMode::Strict,
            enable: EnabledCapabilities::default(),
            params: params1,
            guards: GuardConfig::default(),
        };

        let pack2 = BehaviorPack {
            name: "pack2".to_string(),
            mode: BehaviorMode::Strict,
            enable: EnabledCapabilities::default(),
            params: params2,
            guards: GuardConfig::default(),
        };

        let diff = BehaviorPackDiff::compare(&pack1, &pack2).unwrap();
        assert!(diff.risk_analysis.scope_expansion_detected);
        assert!(matches!(
            diff.risk_analysis.overall_risk,
            RiskLevel::Critical
        ));
    }
}
