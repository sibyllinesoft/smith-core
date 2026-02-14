//! Guard engine for security and policy validation
//!
//! The Guard provides comprehensive security validation and policy enforcement
//! for all workflow actions before they are executed. It implements multiple
//! layers of security checks and provides detailed violation reporting.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

use super::schemas::{
    ActionModification, ActionType, GuardResult, RiskLevel, SecurityViolation, WorkflowAction,
};
use crate::runners::ExecContext;

/// Guard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    /// Security enforcement level
    pub enforcement_level: EnforcementLevel,

    /// Policy rules to enforce
    pub policy_rules: Vec<PolicyRule>,

    /// Allowed capabilities
    pub allowed_capabilities: HashSet<String>,

    /// Blocked patterns
    pub blocked_patterns: Vec<BlockedPattern>,

    /// Resource limits
    pub resource_limits: GuardResourceLimits,

    /// Security context requirements
    pub security_context: SecurityContext,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            enforcement_level: EnforcementLevel::Strict,
            policy_rules: Self::default_policy_rules(),
            allowed_capabilities: Self::default_capabilities(),
            blocked_patterns: Self::default_blocked_patterns(),
            resource_limits: GuardResourceLimits::default(),
            security_context: SecurityContext::default(),
        }
    }
}

impl GuardConfig {
    /// Get default policy rules
    fn default_policy_rules() -> Vec<PolicyRule> {
        vec![
            PolicyRule {
                name: "filesystem_access".to_string(),
                rule_type: PolicyRuleType::PathValidation,
                conditions: vec![PolicyCondition::PathAllowList(vec![
                    "/tmp/".to_string(),
                    "/workspace/".to_string(),
                    "/var/tmp/".to_string(),
                ])],
                severity: RiskLevel::High,
                action: PolicyAction::Block,
            },
            PolicyRule {
                name: "network_access".to_string(),
                rule_type: PolicyRuleType::NetworkValidation,
                conditions: vec![PolicyCondition::UrlPattern(
                    r"^https?://[a-zA-Z0-9.-]+\.(com|org|net|edu).*".to_string(),
                )],
                severity: RiskLevel::Medium,
                action: PolicyAction::Validate,
            },
            PolicyRule {
                name: "shell_command".to_string(),
                rule_type: PolicyRuleType::CommandValidation,
                conditions: vec![PolicyCondition::CommandBlockList(vec![
                    "rm -rf".to_string(),
                    "sudo".to_string(),
                    "chmod 777".to_string(),
                    "dd if=".to_string(),
                ])],
                severity: RiskLevel::Critical,
                action: PolicyAction::Block,
            },
            PolicyRule {
                name: "resource_limits".to_string(),
                rule_type: PolicyRuleType::ResourceValidation,
                conditions: vec![
                    PolicyCondition::MaxActions(100),
                    PolicyCondition::MaxDuration(3600), // 1 hour
                ],
                severity: RiskLevel::Medium,
                action: PolicyAction::Limit,
            },
        ]
    }

    /// Get default allowed capabilities
    fn default_capabilities() -> HashSet<String> {
        vec![
            "fs.read.v1".to_string(),
            "fs.write.v1".to_string(),
            "http.fetch.v1".to_string(),
            "planner.exec.v1".to_string(),
        ]
        .into_iter()
        .collect()
    }

    /// Get default blocked patterns
    fn default_blocked_patterns() -> Vec<BlockedPattern> {
        vec![
            BlockedPattern {
                pattern: r"/etc/passwd".to_string(),
                pattern_type: PatternType::Path,
                reason: "System password file access forbidden".to_string(),
            },
            BlockedPattern {
                pattern: r"/proc/.*".to_string(),
                pattern_type: PatternType::Path,
                reason: "Process filesystem access restricted".to_string(),
            },
            BlockedPattern {
                pattern: r".*\.exe$".to_string(),
                pattern_type: PatternType::Path,
                reason: "Executable file access restricted".to_string(),
            },
            BlockedPattern {
                pattern: r"password\s*=".to_string(),
                pattern_type: PatternType::Content,
                reason: "Potential credential exposure".to_string(),
            },
        ]
    }
}

/// Security enforcement levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    /// Block all violations
    Strict,
    /// Allow with warnings
    Permissive,
    /// Log only
    Monitor,
    /// No enforcement (testing only)
    Disabled,
}

/// Policy rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name/identifier
    pub name: String,

    /// Type of validation rule
    pub rule_type: PolicyRuleType,

    /// Conditions that trigger this rule
    pub conditions: Vec<PolicyCondition>,

    /// Severity of violations
    pub severity: RiskLevel,

    /// Action to take on violation
    pub action: PolicyAction,
}

/// Types of policy rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleType {
    PathValidation,
    NetworkValidation,
    CommandValidation,
    ResourceValidation,
    ContentValidation,
    CapabilityValidation,
}

/// Policy rule conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum PolicyCondition {
    PathAllowList(Vec<String>),
    PathBlockList(Vec<String>),
    UrlPattern(String),
    CommandBlockList(Vec<String>),
    MaxActions(u32),
    MaxDuration(u64),
    RequiredCapability(String),
    ContentPattern(String),
}

/// Actions to take when policy violations occur
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Block the action entirely
    Block,
    /// Allow but require validation
    Validate,
    /// Apply resource limits
    Limit,
    /// Transform the action
    Transform,
    /// Log and continue
    Log,
}

/// Blocked pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedPattern {
    /// Regular expression pattern
    pub pattern: String,

    /// Type of pattern
    pub pattern_type: PatternType,

    /// Reason for blocking
    pub reason: String,
}

/// Pattern types for validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    Path,
    Url,
    Command,
    Content,
    Parameter,
}

/// Resource limits enforced by the Guard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardResourceLimits {
    /// Maximum number of actions per workflow
    pub max_actions: u32,

    /// Maximum workflow duration in seconds
    pub max_duration_seconds: u64,

    /// Maximum memory usage per action in MB
    pub max_memory_mb: u64,

    /// Maximum file size for reads in MB
    pub max_file_size_mb: u64,

    /// Maximum network payload size in MB
    pub max_network_payload_mb: u64,
}

impl Default for GuardResourceLimits {
    fn default() -> Self {
        Self {
            max_actions: 100,
            max_duration_seconds: 3600, // 1 hour
            max_memory_mb: 512,
            max_file_size_mb: 100,
            max_network_payload_mb: 50,
        }
    }
}

/// Security context requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Required sandbox mode
    pub required_sandbox: bool,

    /// Required isolation features
    pub required_isolation: Vec<IsolationFeature>,

    /// Allowed network access
    pub network_allowed: bool,

    /// Allowed file system access
    pub filesystem_allowed: bool,

    /// Required audit level
    pub audit_level: AuditLevel,
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self {
            required_sandbox: true,
            required_isolation: vec![
                IsolationFeature::ProcessNamespace,
                IsolationFeature::NetworkNamespace,
                IsolationFeature::FileSystemRestrictions,
            ],
            network_allowed: true,
            filesystem_allowed: true,
            audit_level: AuditLevel::Full,
        }
    }
}

/// Isolation features
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IsolationFeature {
    ProcessNamespace,
    NetworkNamespace,
    FileSystemRestrictions,
    ResourceLimits,
    SeccompFiltering,
    LandlockRestrictions,
}

/// Audit level requirements
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    None,
    Basic,
    Standard,
    Full,
    Forensic,
}

/// Main Guard implementation
pub struct Guard {
    config: GuardConfig,
    execution_context: ExecContext,
    violation_count: u32,
    blocked_count: u32,
}

impl Guard {
    /// Create a new Guard instance
    pub fn new(exec_context: &ExecContext) -> Result<Self> {
        let config = GuardConfig::default();

        info!(
            enforcement_level = ?config.enforcement_level,
            policy_rules = config.policy_rules.len(),
            "Guard initialized"
        );

        Ok(Self {
            config,
            execution_context: exec_context.clone(),
            violation_count: 0,
            blocked_count: 0,
        })
    }

    /// Create Guard with custom configuration
    pub fn with_config(exec_context: &ExecContext, config: GuardConfig) -> Result<Self> {
        info!(
            enforcement_level = ?config.enforcement_level,
            policy_rules = config.policy_rules.len(),
            "Guard initialized with custom config"
        );

        Ok(Self {
            config,
            execution_context: exec_context.clone(),
            violation_count: 0,
            blocked_count: 0,
        })
    }

    /// Validate a workflow action
    pub async fn validate_action(&mut self, action: &WorkflowAction) -> Result<bool> {
        debug!(
            action_id = %action.id,
            action_type = ?action.action_type,
            "Validating action"
        );

        let result = self.perform_validation(action).await?;

        // Update statistics
        if !result.violations.is_empty() {
            self.violation_count += 1;
        }

        if !result.allowed {
            self.blocked_count += 1;
            warn!(
                action_id = %action.id,
                reason = %result.reason,
                violations = result.violations.len(),
                "Action blocked by guard"
            );
        } else {
            debug!(
                action_id = %action.id,
                violations = result.violations.len(),
                "Action allowed by guard"
            );
        }

        Ok(result.allowed)
    }

    /// Get detailed validation result
    pub async fn validate_action_detailed(
        &mut self,
        action: &WorkflowAction,
    ) -> Result<GuardResult> {
        debug!(
            action_id = %action.id,
            "Performing detailed validation"
        );

        let result = self.perform_validation(action).await?;

        // Update statistics
        if !result.violations.is_empty() {
            self.violation_count += 1;
        }

        if !result.allowed {
            self.blocked_count += 1;
        }

        Ok(result)
    }

    /// Perform the actual validation
    async fn perform_validation(&self, action: &WorkflowAction) -> Result<GuardResult> {
        let mut violations = Vec::new();
        let mut modifications = Vec::new();
        let mut allowed = true;
        let mut reason = "Action allowed".to_string();

        // Check if enforcement is disabled
        if self.config.enforcement_level == EnforcementLevel::Disabled {
            return Ok(GuardResult {
                allowed: true,
                reason: "Guard enforcement disabled".to_string(),
                violations,
                modifications,
            });
        }

        // 1. Capability validation
        self.validate_capability(action, &mut violations, &mut allowed, &mut reason)?;

        // 2. Policy rule validation
        self.validate_policy_rules(
            action,
            &mut violations,
            &mut modifications,
            &mut allowed,
            &mut reason,
        )
        .await?;

        // 3. Pattern validation
        self.validate_patterns(action, &mut violations, &mut allowed, &mut reason)?;

        // 4. Resource validation
        self.validate_resources(action, &mut violations, &mut allowed, &mut reason)?;

        // 5. Security context validation
        self.validate_security_context(action, &mut violations, &mut allowed, &mut reason)?;

        // Apply enforcement level
        match self.config.enforcement_level {
            EnforcementLevel::Strict => {
                // Already applied above
            }
            EnforcementLevel::Permissive => {
                // Allow with warnings
                if !allowed {
                    reason = format!(
                        "Permissive mode: {} (would be blocked in strict mode)",
                        reason
                    );
                    allowed = true;
                }
            }
            EnforcementLevel::Monitor => {
                // Log only
                allowed = true;
                if !violations.is_empty() {
                    reason = format!("Monitor mode: violations logged but action allowed");
                }
            }
            EnforcementLevel::Disabled => {
                // Already handled above
            }
        }

        Ok(GuardResult {
            allowed,
            reason,
            violations,
            modifications,
        })
    }

    /// Validate capability access
    fn validate_capability(
        &self,
        action: &WorkflowAction,
        violations: &mut Vec<SecurityViolation>,
        allowed: &mut bool,
        reason: &mut String,
    ) -> Result<()> {
        let capability = match &action.action_type {
            ActionType::FileSystem(cap) => cap,
            ActionType::Http(cap) => cap,
            ActionType::Shell(cap) => cap,
            ActionType::Research(cap) => cap,
            ActionType::Planning(cap) => cap,
            ActionType::Analysis(cap) => cap,
            ActionType::Custom(cap) => cap,
        };

        if !self.config.allowed_capabilities.contains(capability) {
            violations.push(SecurityViolation {
                violation_type: "CAPABILITY_NOT_ALLOWED".to_string(),
                severity: RiskLevel::High,
                description: format!("Capability '{}' is not in the allowed list", capability),
                remediation: "Use an allowed capability or request permission".to_string(),
            });

            *allowed = false;
            *reason = format!("Capability '{}' not allowed", capability);
        }

        Ok(())
    }

    /// Validate against policy rules
    async fn validate_policy_rules(
        &self,
        action: &WorkflowAction,
        violations: &mut Vec<SecurityViolation>,
        modifications: &mut Vec<ActionModification>,
        allowed: &mut bool,
        reason: &mut String,
    ) -> Result<()> {
        for rule in &self.config.policy_rules {
            let rule_violations = self.check_policy_rule(rule, action).await?;

            for violation in rule_violations {
                violations.push(violation.clone());

                match rule.action {
                    PolicyAction::Block => {
                        *allowed = false;
                        *reason = format!("Blocked by policy rule: {}", rule.name);
                    }
                    PolicyAction::Validate => {
                        // Additional validation required
                        debug!(rule = %rule.name, "Additional validation required");
                    }
                    PolicyAction::Limit => {
                        // Apply limits
                        modifications.push(ActionModification {
                            field: "resource_limits".to_string(),
                            suggested_value: serde_json::json!({
                                "max_memory_mb": self.config.resource_limits.max_memory_mb,
                                "max_duration_s": self.config.resource_limits.max_duration_seconds
                            }),
                            reason: format!("Applied limits due to rule: {}", rule.name),
                        });
                    }
                    PolicyAction::Transform => {
                        // Suggest transformations
                        modifications.push(ActionModification {
                            field: "parameters".to_string(),
                            suggested_value: serde_json::json!({}),
                            reason: format!("Transform required due to rule: {}", rule.name),
                        });
                    }
                    PolicyAction::Log => {
                        // Just log, don't block
                        info!(rule = %rule.name, "Policy violation logged");
                    }
                }
            }
        }

        Ok(())
    }

    /// Check a specific policy rule
    async fn check_policy_rule(
        &self,
        rule: &PolicyRule,
        action: &WorkflowAction,
    ) -> Result<Vec<SecurityViolation>> {
        let mut violations = Vec::new();

        for condition in &rule.conditions {
            match condition {
                PolicyCondition::PathAllowList(allowed_paths) => {
                    if let Some(path) = self.extract_path_parameter(action) {
                        if !allowed_paths
                            .iter()
                            .any(|allowed| path.starts_with(allowed))
                        {
                            violations.push(SecurityViolation {
                                violation_type: "PATH_NOT_ALLOWED".to_string(),
                                severity: rule.severity.clone(),
                                description: format!("Path '{}' not in allowed list", path),
                                remediation: "Use a path within the allowed directories"
                                    .to_string(),
                            });
                        }
                    }
                }

                PolicyCondition::PathBlockList(blocked_paths) => {
                    if let Some(path) = self.extract_path_parameter(action) {
                        if blocked_paths.iter().any(|blocked| path.contains(blocked)) {
                            violations.push(SecurityViolation {
                                violation_type: "PATH_BLOCKED".to_string(),
                                severity: rule.severity.clone(),
                                description: format!("Path '{}' contains blocked pattern", path),
                                remediation:
                                    "Use a different path that doesn't match blocked patterns"
                                        .to_string(),
                            });
                        }
                    }
                }

                PolicyCondition::UrlPattern(pattern) => {
                    if let Some(url) = self.extract_url_parameter(action) {
                        let regex =
                            regex::Regex::new(pattern).context("Invalid URL pattern regex")?;
                        if !regex.is_match(&url) {
                            violations.push(SecurityViolation {
                                violation_type: "URL_PATTERN_VIOLATION".to_string(),
                                severity: rule.severity.clone(),
                                description: format!(
                                    "URL '{}' doesn't match required pattern",
                                    url
                                ),
                                remediation: "Use a URL that matches the required pattern"
                                    .to_string(),
                            });
                        }
                    }
                }

                PolicyCondition::CommandBlockList(blocked_commands) => {
                    if let Some(command) = self.extract_command_parameter(action) {
                        if blocked_commands
                            .iter()
                            .any(|blocked| command.contains(blocked))
                        {
                            violations.push(SecurityViolation {
                                violation_type: "COMMAND_BLOCKED".to_string(),
                                severity: rule.severity.clone(),
                                description: format!(
                                    "Command '{}' contains blocked pattern",
                                    command
                                ),
                                remediation:
                                    "Use a different command that doesn't match blocked patterns"
                                        .to_string(),
                            });
                        }
                    }
                }

                PolicyCondition::MaxActions(max_actions) => {
                    // This would be checked at the workflow level
                    debug!(max_actions = max_actions, "Max actions condition checked");
                }

                PolicyCondition::MaxDuration(max_duration) => {
                    if let Some(timeout) = action.timeout_ms {
                        if timeout > (*max_duration * 1000) {
                            violations.push(SecurityViolation {
                                violation_type: "DURATION_EXCEEDED".to_string(),
                                severity: rule.severity.clone(),
                                description: format!(
                                    "Action timeout {}ms exceeds maximum {}s",
                                    timeout, max_duration
                                ),
                                remediation: format!(
                                    "Reduce timeout to maximum of {}s",
                                    max_duration
                                ),
                            });
                        }
                    }
                }

                PolicyCondition::RequiredCapability(required_cap) => {
                    let action_capability = match &action.action_type {
                        ActionType::FileSystem(cap) => cap,
                        ActionType::Http(cap) => cap,
                        ActionType::Shell(cap) => cap,
                        ActionType::Research(cap) => cap,
                        ActionType::Planning(cap) => cap,
                        ActionType::Analysis(cap) => cap,
                        ActionType::Custom(cap) => cap,
                    };

                    if action_capability != required_cap {
                        violations.push(SecurityViolation {
                            violation_type: "REQUIRED_CAPABILITY_MISSING".to_string(),
                            severity: rule.severity.clone(),
                            description: format!(
                                "Required capability '{}' not present",
                                required_cap
                            ),
                            remediation: format!("Use the required capability '{}'", required_cap),
                        });
                    }
                }

                PolicyCondition::ContentPattern(pattern) => {
                    let params_str = action.parameters.to_string();
                    let regex =
                        regex::Regex::new(pattern).context("Invalid content pattern regex")?;
                    if regex.is_match(&params_str) {
                        violations.push(SecurityViolation {
                            violation_type: "CONTENT_PATTERN_VIOLATION".to_string(),
                            severity: rule.severity.clone(),
                            description: "Action parameters contain prohibited content pattern"
                                .to_string(),
                            remediation: "Remove or modify prohibited content in parameters"
                                .to_string(),
                        });
                    }
                }
            }
        }

        Ok(violations)
    }

    /// Validate against blocked patterns
    fn validate_patterns(
        &self,
        action: &WorkflowAction,
        violations: &mut Vec<SecurityViolation>,
        allowed: &mut bool,
        reason: &mut String,
    ) -> Result<()> {
        let params_str = action.parameters.to_string();

        for pattern in &self.config.blocked_patterns {
            let regex =
                regex::Regex::new(&pattern.pattern).context("Invalid blocked pattern regex")?;

            let matches = match pattern.pattern_type {
                PatternType::Path => {
                    if let Some(path) = self.extract_path_parameter(action) {
                        regex.is_match(&path)
                    } else {
                        false
                    }
                }
                PatternType::Url => {
                    if let Some(url) = self.extract_url_parameter(action) {
                        regex.is_match(&url)
                    } else {
                        false
                    }
                }
                PatternType::Command => {
                    if let Some(command) = self.extract_command_parameter(action) {
                        regex.is_match(&command)
                    } else {
                        false
                    }
                }
                PatternType::Content | PatternType::Parameter => regex.is_match(&params_str),
            };

            if matches {
                violations.push(SecurityViolation {
                    violation_type: "BLOCKED_PATTERN".to_string(),
                    severity: RiskLevel::High,
                    description: format!("Content matches blocked pattern: {}", pattern.reason),
                    remediation: "Modify content to avoid blocked patterns".to_string(),
                });

                *allowed = false;
                *reason = format!("Blocked pattern detected: {}", pattern.reason);
            }
        }

        Ok(())
    }

    /// Validate resource requirements
    fn validate_resources(
        &self,
        action: &WorkflowAction,
        violations: &mut Vec<SecurityViolation>,
        allowed: &mut bool,
        reason: &mut String,
    ) -> Result<()> {
        // Check timeout limits
        if let Some(timeout_ms) = action.timeout_ms {
            let timeout_seconds = timeout_ms / 1000;
            if timeout_seconds > self.config.resource_limits.max_duration_seconds {
                violations.push(SecurityViolation {
                    violation_type: "TIMEOUT_EXCEEDED".to_string(),
                    severity: RiskLevel::Medium,
                    description: format!(
                        "Action timeout {}s exceeds maximum {}s",
                        timeout_seconds, self.config.resource_limits.max_duration_seconds
                    ),
                    remediation: format!(
                        "Reduce timeout to maximum of {}s",
                        self.config.resource_limits.max_duration_seconds
                    ),
                });

                *allowed = false;
                *reason = "Timeout exceeds resource limits".to_string();
            }
        }

        // Check file size limits (for file operations)
        if matches!(action.action_type, ActionType::FileSystem(_)) {
            if let Some(max_bytes) = action.parameters.get("max_bytes") {
                if let Some(max_bytes_val) = max_bytes.as_u64() {
                    let max_bytes_mb = max_bytes_val / (1024 * 1024);
                    if max_bytes_mb > self.config.resource_limits.max_file_size_mb {
                        violations.push(SecurityViolation {
                            violation_type: "FILE_SIZE_EXCEEDED".to_string(),
                            severity: RiskLevel::Medium,
                            description: format!(
                                "Requested file size {}MB exceeds maximum {}MB",
                                max_bytes_mb, self.config.resource_limits.max_file_size_mb
                            ),
                            remediation: format!(
                                "Reduce file size limit to maximum of {}MB",
                                self.config.resource_limits.max_file_size_mb
                            ),
                        });

                        *allowed = false;
                        *reason = "File size exceeds resource limits".to_string();
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate security context
    fn validate_security_context(
        &self,
        _action: &WorkflowAction,
        violations: &mut Vec<SecurityViolation>,
        allowed: &mut bool,
        reason: &mut String,
    ) -> Result<()> {
        // Check if sandbox is required but not available
        if self.config.security_context.required_sandbox {
            // In a real implementation, we'd check if the execution context has sandbox capabilities
            // For now, we'll assume sandbox is available if execution context is present
            debug!("Sandbox requirement validated");
        }

        // Check required isolation features
        for feature in &self.config.security_context.required_isolation {
            match feature {
                IsolationFeature::ProcessNamespace => {
                    // Check if process namespace isolation is available
                    debug!("Process namespace isolation required");
                }
                IsolationFeature::NetworkNamespace => {
                    if !self.config.security_context.network_allowed {
                        violations.push(SecurityViolation {
                            violation_type: "NETWORK_NOT_ALLOWED".to_string(),
                            severity: RiskLevel::High,
                            description: "Network access not allowed in current security context"
                                .to_string(),
                            remediation: "Remove network operations or request network permissions"
                                .to_string(),
                        });

                        *allowed = false;
                        *reason = "Network access not allowed".to_string();
                    }
                }
                IsolationFeature::FileSystemRestrictions => {
                    if !self.config.security_context.filesystem_allowed {
                        violations.push(SecurityViolation {
                            violation_type: "FILESYSTEM_NOT_ALLOWED".to_string(),
                            severity: RiskLevel::High,
                            description:
                                "Filesystem access not allowed in current security context"
                                    .to_string(),
                            remediation:
                                "Remove filesystem operations or request filesystem permissions"
                                    .to_string(),
                        });

                        *allowed = false;
                        *reason = "Filesystem access not allowed".to_string();
                    }
                }
                _ => {
                    debug!(feature = ?feature, "Isolation feature check");
                }
            }
        }

        Ok(())
    }

    /// Extract path parameter from action
    fn extract_path_parameter(&self, action: &WorkflowAction) -> Option<String> {
        action
            .parameters
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract URL parameter from action
    fn extract_url_parameter(&self, action: &WorkflowAction) -> Option<String> {
        action
            .parameters
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract command parameter from action
    fn extract_command_parameter(&self, action: &WorkflowAction) -> Option<String> {
        action
            .parameters
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Get Guard statistics
    pub fn get_statistics(&self) -> GuardStatistics {
        GuardStatistics {
            violation_count: self.violation_count,
            blocked_count: self.blocked_count,
            enforcement_level: self.config.enforcement_level.clone(),
            active_rules: self.config.policy_rules.len(),
            blocked_patterns: self.config.blocked_patterns.len(),
        }
    }

    /// Reset statistics
    pub fn reset_statistics(&mut self) {
        self.violation_count = 0;
        self.blocked_count = 0;
    }
}

/// Guard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardStatistics {
    /// Total violations detected
    pub violation_count: u32,

    /// Total actions blocked
    pub blocked_count: u32,

    /// Current enforcement level
    pub enforcement_level: EnforcementLevel,

    /// Number of active policy rules
    pub active_rules: usize,

    /// Number of blocked patterns
    pub blocked_patterns: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::{create_exec_context, Scope};
    use serde_json::json;
    use smith_protocol::ExecutionLimits;
    use tempfile::tempdir;

    fn create_test_context() -> ExecContext {
        let temp_dir = tempdir().unwrap();
        let limits = ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 100_000_000,
            io_bytes: 10_000_000,
            pids_max: 10,
            timeout_ms: 30_000,
        };
        let scope = Scope {
            paths: vec![temp_dir.path().to_string_lossy().to_string()],
            urls: vec![],
        };
        create_exec_context(temp_dir.path(), limits, scope, "test-trace-id".to_string())
    }

    #[tokio::test]
    async fn test_guard_creation() {
        let ctx = create_test_context();
        let guard = Guard::new(&ctx).unwrap();

        assert_eq!(guard.config.enforcement_level, EnforcementLevel::Strict);
        assert!(!guard.config.policy_rules.is_empty());
        assert!(!guard.config.allowed_capabilities.is_empty());
    }

    #[tokio::test]
    async fn test_capability_validation() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        // Test allowed capability
        let allowed_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/test.txt"}),
            "Read test file".to_string(),
        );

        let result = guard.validate_action(&allowed_action).await.unwrap();
        assert!(result);

        // Test disallowed capability
        let disallowed_action = WorkflowAction::new(
            ActionType::Custom("dangerous.capability.v1".to_string()),
            json!({}),
            "Dangerous action".to_string(),
        );

        let result = guard.validate_action(&disallowed_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_path_validation() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        // Test allowed path
        let allowed_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/allowed.txt"}),
            "Read allowed file".to_string(),
        );

        let result = guard.validate_action(&allowed_action).await.unwrap();
        assert!(result);

        // Test blocked path
        let blocked_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/etc/passwd"}),
            "Read password file".to_string(),
        );

        let result = guard.validate_action(&blocked_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_command_validation() {
        let ctx = create_test_context();

        // Create a custom config that allows shell commands
        let mut config = GuardConfig::default();
        config
            .allowed_capabilities
            .insert("shell.exec.v1".to_string());

        let mut guard = Guard::with_config(&ctx, config).unwrap();

        // Test safe command
        let safe_action = WorkflowAction::new(
            ActionType::Shell("shell.exec.v1".to_string()),
            json!({"command": "echo hello"}),
            "Safe echo command".to_string(),
        );

        let result = guard.validate_action(&safe_action).await.unwrap();
        assert!(result);

        // Test dangerous command
        let dangerous_action = WorkflowAction::new(
            ActionType::Shell("shell.exec.v1".to_string()),
            json!({"command": "rm -rf /"}),
            "Dangerous delete command".to_string(),
        );

        let result = guard.validate_action(&dangerous_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_detailed_validation() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/etc/passwd"}),
            "Read password file".to_string(),
        );

        let result = guard.validate_action_detailed(&action).await.unwrap();

        assert!(!result.allowed);
        assert!(!result.violations.is_empty());
        assert!(!result.reason.is_empty());
    }

    #[tokio::test]
    async fn test_enforcement_levels() {
        let ctx = create_test_context();

        // Test strict enforcement
        let mut strict_config = GuardConfig::default();
        strict_config.enforcement_level = EnforcementLevel::Strict;
        let mut strict_guard = Guard::with_config(&ctx, strict_config).unwrap();

        let blocked_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/etc/passwd"}),
            "Read password file".to_string(),
        );

        assert!(!strict_guard.validate_action(&blocked_action).await.unwrap());

        // Test permissive enforcement
        let mut permissive_config = GuardConfig::default();
        permissive_config.enforcement_level = EnforcementLevel::Permissive;
        let mut permissive_guard = Guard::with_config(&ctx, permissive_config).unwrap();

        assert!(permissive_guard
            .validate_action(&blocked_action)
            .await
            .unwrap());

        // Test disabled enforcement
        let mut disabled_config = GuardConfig::default();
        disabled_config.enforcement_level = EnforcementLevel::Disabled;
        let mut disabled_guard = Guard::with_config(&ctx, disabled_config).unwrap();

        assert!(disabled_guard
            .validate_action(&blocked_action)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_resource_limits() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        // Test action with excessive timeout
        let mut long_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/test.txt"}),
            "Long running read".to_string(),
        );
        long_action.timeout_ms = Some(7200000); // 2 hours

        let result = guard.validate_action(&long_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_statistics() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let stats = guard.get_statistics();
        assert_eq!(stats.violation_count, 0);
        assert_eq!(stats.blocked_count, 0);

        // Trigger some violations
        let blocked_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/etc/passwd"}),
            "Read password file".to_string(),
        );

        guard.validate_action(&blocked_action).await.unwrap();

        let updated_stats = guard.get_statistics();
        assert!(updated_stats.violation_count > 0);
        assert!(updated_stats.blocked_count > 0);

        // Test reset
        guard.reset_statistics();
        let reset_stats = guard.get_statistics();
        assert_eq!(reset_stats.violation_count, 0);
        assert_eq!(reset_stats.blocked_count, 0);
    }

    // === Serialization tests ===

    #[test]
    fn test_enforcement_level_serialization() {
        let levels = vec![
            (EnforcementLevel::Strict, "strict"),
            (EnforcementLevel::Permissive, "permissive"),
            (EnforcementLevel::Monitor, "monitor"),
            (EnforcementLevel::Disabled, "disabled"),
        ];

        for (level, expected) in levels {
            let json = serde_json::to_string(&level).unwrap();
            assert!(json.contains(expected));
            let parsed: EnforcementLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, level);
        }
    }

    #[test]
    fn test_policy_rule_type_serialization() {
        let types = vec![
            PolicyRuleType::PathValidation,
            PolicyRuleType::NetworkValidation,
            PolicyRuleType::CommandValidation,
            PolicyRuleType::ResourceValidation,
            PolicyRuleType::ContentValidation,
            PolicyRuleType::CapabilityValidation,
        ];

        for rule_type in types {
            let json = serde_json::to_string(&rule_type).unwrap();
            let parsed: PolicyRuleType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, rule_type);
        }
    }

    #[test]
    fn test_policy_action_serialization() {
        let actions = vec![
            PolicyAction::Block,
            PolicyAction::Validate,
            PolicyAction::Limit,
            PolicyAction::Transform,
            PolicyAction::Log,
        ];

        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: PolicyAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn test_pattern_type_serialization() {
        let types = vec![
            PatternType::Path,
            PatternType::Url,
            PatternType::Command,
            PatternType::Content,
            PatternType::Parameter,
        ];

        for pattern_type in types {
            let json = serde_json::to_string(&pattern_type).unwrap();
            let parsed: PatternType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, pattern_type);
        }
    }

    #[test]
    fn test_isolation_feature_serialization() {
        let features = vec![
            IsolationFeature::ProcessNamespace,
            IsolationFeature::NetworkNamespace,
            IsolationFeature::FileSystemRestrictions,
            IsolationFeature::ResourceLimits,
            IsolationFeature::SeccompFiltering,
            IsolationFeature::LandlockRestrictions,
        ];

        for feature in features {
            let json = serde_json::to_string(&feature).unwrap();
            let parsed: IsolationFeature = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, feature);
        }
    }

    #[test]
    fn test_audit_level_serialization() {
        let levels = vec![
            AuditLevel::None,
            AuditLevel::Basic,
            AuditLevel::Standard,
            AuditLevel::Full,
            AuditLevel::Forensic,
        ];

        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let parsed: AuditLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, level);
        }
    }

    #[test]
    fn test_guard_config_default() {
        let config = GuardConfig::default();
        assert_eq!(config.enforcement_level, EnforcementLevel::Strict);
        assert!(!config.policy_rules.is_empty());
        assert!(!config.allowed_capabilities.is_empty());
        assert!(!config.blocked_patterns.is_empty());
    }

    #[test]
    fn test_guard_resource_limits_default() {
        let limits = GuardResourceLimits::default();
        assert_eq!(limits.max_actions, 100);
        assert_eq!(limits.max_duration_seconds, 3600);
        assert_eq!(limits.max_memory_mb, 512);
        assert_eq!(limits.max_file_size_mb, 100);
        assert_eq!(limits.max_network_payload_mb, 50);
    }

    #[test]
    fn test_security_context_default() {
        let ctx = SecurityContext::default();
        assert!(ctx.required_sandbox);
        assert!(ctx.network_allowed);
        assert!(ctx.filesystem_allowed);
        assert_eq!(ctx.audit_level, AuditLevel::Full);
        assert!(!ctx.required_isolation.is_empty());
    }

    #[test]
    fn test_policy_condition_serialization_path_allow_list() {
        let condition = PolicyCondition::PathAllowList(vec!["/tmp/".to_string()]);
        let json = serde_json::to_string(&condition).unwrap();
        assert!(json.contains("PathAllowList"));
        let parsed: PolicyCondition = serde_json::from_str(&json).unwrap();
        if let PolicyCondition::PathAllowList(paths) = parsed {
            assert_eq!(paths.len(), 1);
        } else {
            panic!("Expected PathAllowList");
        }
    }

    #[test]
    fn test_policy_condition_serialization_path_block_list() {
        let condition = PolicyCondition::PathBlockList(vec!["/etc/".to_string()]);
        let json = serde_json::to_string(&condition).unwrap();
        let parsed: PolicyCondition = serde_json::from_str(&json).unwrap();
        if let PolicyCondition::PathBlockList(paths) = parsed {
            assert_eq!(paths.len(), 1);
        } else {
            panic!("Expected PathBlockList");
        }
    }

    #[test]
    fn test_policy_condition_serialization_url_pattern() {
        let condition = PolicyCondition::UrlPattern("https://.*".to_string());
        let json = serde_json::to_string(&condition).unwrap();
        let parsed: PolicyCondition = serde_json::from_str(&json).unwrap();
        if let PolicyCondition::UrlPattern(pattern) = parsed {
            assert_eq!(pattern, "https://.*");
        } else {
            panic!("Expected UrlPattern");
        }
    }

    #[test]
    fn test_policy_condition_serialization_command_block_list() {
        let condition = PolicyCondition::CommandBlockList(vec!["rm".to_string()]);
        let json = serde_json::to_string(&condition).unwrap();
        let parsed: PolicyCondition = serde_json::from_str(&json).unwrap();
        if let PolicyCondition::CommandBlockList(commands) = parsed {
            assert_eq!(commands.len(), 1);
        } else {
            panic!("Expected CommandBlockList");
        }
    }

    #[test]
    fn test_policy_condition_serialization_max_actions() {
        let condition = PolicyCondition::MaxActions(50);
        let json = serde_json::to_string(&condition).unwrap();
        let parsed: PolicyCondition = serde_json::from_str(&json).unwrap();
        if let PolicyCondition::MaxActions(max) = parsed {
            assert_eq!(max, 50);
        } else {
            panic!("Expected MaxActions");
        }
    }

    #[test]
    fn test_policy_condition_serialization_max_duration() {
        let condition = PolicyCondition::MaxDuration(1800);
        let json = serde_json::to_string(&condition).unwrap();
        let parsed: PolicyCondition = serde_json::from_str(&json).unwrap();
        if let PolicyCondition::MaxDuration(duration) = parsed {
            assert_eq!(duration, 1800);
        } else {
            panic!("Expected MaxDuration");
        }
    }

    #[test]
    fn test_policy_condition_serialization_required_capability() {
        let condition = PolicyCondition::RequiredCapability("fs.read.v1".to_string());
        let json = serde_json::to_string(&condition).unwrap();
        let parsed: PolicyCondition = serde_json::from_str(&json).unwrap();
        if let PolicyCondition::RequiredCapability(cap) = parsed {
            assert_eq!(cap, "fs.read.v1");
        } else {
            panic!("Expected RequiredCapability");
        }
    }

    #[test]
    fn test_policy_condition_serialization_content_pattern() {
        let condition = PolicyCondition::ContentPattern("password=.*".to_string());
        let json = serde_json::to_string(&condition).unwrap();
        let parsed: PolicyCondition = serde_json::from_str(&json).unwrap();
        if let PolicyCondition::ContentPattern(pattern) = parsed {
            assert_eq!(pattern, "password=.*");
        } else {
            panic!("Expected ContentPattern");
        }
    }

    #[test]
    fn test_policy_rule_serialization() {
        let rule = PolicyRule {
            name: "test_rule".to_string(),
            rule_type: PolicyRuleType::PathValidation,
            conditions: vec![PolicyCondition::PathAllowList(vec!["/tmp/".to_string()])],
            severity: RiskLevel::Medium,
            action: PolicyAction::Block,
        };

        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("test_rule"));
        let parsed: PolicyRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test_rule");
        assert_eq!(parsed.action, PolicyAction::Block);
    }

    #[test]
    fn test_blocked_pattern_serialization() {
        let pattern = BlockedPattern {
            pattern: "/etc/.*".to_string(),
            pattern_type: PatternType::Path,
            reason: "System files blocked".to_string(),
        };

        let json = serde_json::to_string(&pattern).unwrap();
        assert!(json.contains("System files blocked"));
        let parsed: BlockedPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pattern_type, PatternType::Path);
    }

    #[test]
    fn test_guard_resource_limits_serialization() {
        let limits = GuardResourceLimits {
            max_actions: 200,
            max_duration_seconds: 7200,
            max_memory_mb: 1024,
            max_file_size_mb: 200,
            max_network_payload_mb: 100,
        };

        let json = serde_json::to_string(&limits).unwrap();
        let parsed: GuardResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_actions, 200);
        assert_eq!(parsed.max_memory_mb, 1024);
    }

    #[test]
    fn test_security_context_serialization() {
        let ctx = SecurityContext {
            required_sandbox: false,
            required_isolation: vec![IsolationFeature::ProcessNamespace],
            network_allowed: false,
            filesystem_allowed: true,
            audit_level: AuditLevel::Forensic,
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: SecurityContext = serde_json::from_str(&json).unwrap();
        assert!(!parsed.required_sandbox);
        assert!(!parsed.network_allowed);
        assert_eq!(parsed.audit_level, AuditLevel::Forensic);
    }

    #[test]
    fn test_guard_statistics_serialization() {
        let stats = GuardStatistics {
            violation_count: 10,
            blocked_count: 5,
            enforcement_level: EnforcementLevel::Strict,
            active_rules: 4,
            blocked_patterns: 3,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: GuardStatistics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.violation_count, 10);
        assert_eq!(parsed.blocked_count, 5);
    }

    #[test]
    fn test_guard_config_serialization() {
        let config = GuardConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: GuardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enforcement_level, config.enforcement_level);
    }

    // === Additional edge case tests ===

    #[tokio::test]
    async fn test_monitor_enforcement_level() {
        let ctx = create_test_context();
        let mut monitor_config = GuardConfig::default();
        monitor_config.enforcement_level = EnforcementLevel::Monitor;
        let mut guard = Guard::with_config(&ctx, monitor_config).unwrap();

        let blocked_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/etc/passwd"}),
            "Read password file".to_string(),
        );

        // Monitor mode should allow the action but log violations
        let result = guard.validate_action(&blocked_action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_http_action_validation() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let http_action = WorkflowAction::new(
            ActionType::Http("http.fetch.v1".to_string()),
            json!({"url": "https://example.com/api"}),
            "Fetch API data".to_string(),
        );

        let result = guard.validate_action(&http_action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_research_action_validation() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config
            .allowed_capabilities
            .insert("research.v1".to_string());
        let mut guard = Guard::with_config(&ctx, config).unwrap();

        let research_action = WorkflowAction::new(
            ActionType::Research("research.v1".to_string()),
            json!({"query": "test research"}),
            "Research task".to_string(),
        );

        let result = guard.validate_action(&research_action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_planning_action_validation() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config
            .allowed_capabilities
            .insert("planning.v1".to_string());
        let mut guard = Guard::with_config(&ctx, config).unwrap();

        let planning_action = WorkflowAction::new(
            ActionType::Planning("planning.v1".to_string()),
            json!({"goal": "test planning"}),
            "Planning task".to_string(),
        );

        let result = guard.validate_action(&planning_action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_analysis_action_validation() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config
            .allowed_capabilities
            .insert("analysis.v1".to_string());
        let mut guard = Guard::with_config(&ctx, config).unwrap();

        let analysis_action = WorkflowAction::new(
            ActionType::Analysis("analysis.v1".to_string()),
            json!({"data": "test analysis"}),
            "Analysis task".to_string(),
        );

        let result = guard.validate_action(&analysis_action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_file_size_limit_validation() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let large_file_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/test.txt", "max_bytes": 200 * 1024 * 1024}), // 200MB
            "Read large file".to_string(),
        );

        let result = guard.validate_action(&large_file_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_proc_filesystem_blocked() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let proc_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/proc/1/status"}),
            "Read proc file".to_string(),
        );

        let result = guard.validate_action(&proc_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_exe_file_blocked() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let exe_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/malware.exe"}),
            "Read exe file".to_string(),
        );

        let result = guard.validate_action(&exe_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_workspace_path_allowed() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let workspace_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/workspace/project/file.txt"}),
            "Read workspace file".to_string(),
        );

        let result = guard.validate_action(&workspace_action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_var_tmp_path_allowed() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let var_tmp_action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/var/tmp/test.txt"}),
            "Read var/tmp file".to_string(),
        );

        let result = guard.validate_action(&var_tmp_action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_sudo_command_blocked() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config
            .allowed_capabilities
            .insert("shell.exec.v1".to_string());
        let mut guard = Guard::with_config(&ctx, config).unwrap();

        let sudo_action = WorkflowAction::new(
            ActionType::Shell("shell.exec.v1".to_string()),
            json!({"command": "sudo apt-get install something"}),
            "Sudo command".to_string(),
        );

        let result = guard.validate_action(&sudo_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_chmod_777_blocked() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config
            .allowed_capabilities
            .insert("shell.exec.v1".to_string());
        let mut guard = Guard::with_config(&ctx, config).unwrap();

        let chmod_action = WorkflowAction::new(
            ActionType::Shell("shell.exec.v1".to_string()),
            json!({"command": "chmod 777 /tmp/file.txt"}),
            "Chmod 777 command".to_string(),
        );

        let result = guard.validate_action(&chmod_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_dd_command_blocked() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config
            .allowed_capabilities
            .insert("shell.exec.v1".to_string());
        let mut guard = Guard::with_config(&ctx, config).unwrap();

        let dd_action = WorkflowAction::new(
            ActionType::Shell("shell.exec.v1".to_string()),
            json!({"command": "dd if=/dev/zero of=/tmp/file bs=1M count=100"}),
            "DD command".to_string(),
        );

        let result = guard.validate_action(&dd_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_content_pattern_credential_detection() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let cred_action = WorkflowAction::new(
            ActionType::FileSystem("fs.write.v1".to_string()),
            json!({"path": "/tmp/config.txt", "content": "password = secret123"}),
            "Write credential".to_string(),
        );

        let result = guard.validate_action(&cred_action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_action_with_no_path_parameter() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let action_no_path = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"other_param": "value"}),
            "Action without path".to_string(),
        );

        // Should still be allowed (no path means no path validation applies)
        let result = guard.validate_action(&action_no_path).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_action_without_timeout() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/test.txt"}),
            "Action without timeout".to_string(),
        );

        let result = guard.validate_action(&action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_multiple_violations() {
        let ctx = create_test_context();
        let mut guard = Guard::new(&ctx).unwrap();

        let multi_violation_action = WorkflowAction::new(
            ActionType::Custom("dangerous.capability.v1".to_string()),
            json!({"path": "/etc/passwd", "content": "password = test"}),
            "Multiple violations".to_string(),
        );

        let result = guard
            .validate_action_detailed(&multi_violation_action)
            .await
            .unwrap();
        assert!(!result.allowed);
        assert!(result.violations.len() > 1);
    }

    #[tokio::test]
    async fn test_custom_config_with_additional_capability() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config
            .allowed_capabilities
            .insert("custom.capability.v1".to_string());

        let mut guard = Guard::with_config(&ctx, config).unwrap();

        let custom_action = WorkflowAction::new(
            ActionType::Custom("custom.capability.v1".to_string()),
            json!({}),
            "Custom action".to_string(),
        );

        let result = guard.validate_action(&custom_action).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_security_context_network_not_allowed() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config.security_context.network_allowed = false;

        let mut guard = Guard::with_config(&ctx, config).unwrap();

        // Any action should fail due to network namespace check
        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/test.txt"}),
            "Read file".to_string(),
        );

        let result = guard.validate_action(&action).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_security_context_filesystem_not_allowed() {
        let ctx = create_test_context();
        let mut config = GuardConfig::default();
        config.security_context.filesystem_allowed = false;

        let mut guard = Guard::with_config(&ctx, config).unwrap();

        let action = WorkflowAction::new(
            ActionType::FileSystem("fs.read.v1".to_string()),
            json!({"path": "/tmp/test.txt"}),
            "Read file".to_string(),
        );

        let result = guard.validate_action(&action).await.unwrap();
        assert!(!result);
    }
}
