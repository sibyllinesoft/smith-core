/*!
# Guard Engine - Security & Policy Validation

The Guard Engine provides comprehensive security validation and policy enforcement for planner-executor workflows:

- **Policy Validation**: CUE-based policy enforcement with comprehensive rule checking
- **Security Analysis**: Threat modeling and vulnerability assessment for execution plans
- **Capability Mapping**: Fine-grained capability restrictions and resource limits
- **Risk Assessment**: Quantified risk scoring with mitigation recommendations

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                     Guard Engine                               │
├─────────────────────────────────────────────────────────────────┤
│  Policy Validation Engine                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │    CUE      │  │   Rule      │  │ Compliance  │           │
│  │  Policies   │  │ Validation  │  │   Check     │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Security Analysis Engine                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Threat    │  │ Vulnerability│  │   Attack    │           │
│  │  Modeling   │  │ Assessment  │  │  Surface    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Capability Mapping Engine                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ Permission  │  │  Resource   │  │ Capability  │           │
│  │   Matrix    │  │   Limits    │  │ Validation  │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Risk Assessment & Mitigation                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │    Risk     │  │  Mitigation │  │  Approval   │           │
│  │  Scoring    │  │ Strategies  │  │ Workflow    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Security Model

The Guard Engine implements a multi-layered security model:

1. **Policy Layer**: CUE-based declarative policies
2. **Capability Layer**: Fine-grained permission system
3. **Resource Layer**: Compute and network resource limits
4. **Monitoring Layer**: Continuous security monitoring

## Usage

```text
let guard = GuardEngine::new(&security_config).await?;

// Validate goal
let goal_result = guard.validate_goal(&goal).await?;
if !goal_result.approved {
    return Err(anyhow!("Goal rejected: {}", goal_result.reason));
}

// Validate execution plan
let plan_result = guard.validate_plan(&execution_plan).await?;
if plan_result.risk_score > 0.8 {
    println!("High risk plan - requires manual approval");
}
```
*/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::planner::oracle::ExecutionPlan;
use crate::planner::{Goal, SecurityConfig};

/// Guard engine for security validation
#[derive(Clone)]
pub struct GuardEngine {
    config: SecurityConfig,
    policy_validator: Arc<PolicyValidator>,
    security_analyzer: Arc<SecurityAnalyzer>,
    capability_mapper: Arc<CapabilityMapper>,
    validation_cache: Arc<RwLock<HashMap<String, GuardResult>>>,
    security_metrics: Arc<RwLock<SecurityMetrics>>,
}

/// Policy validation engine
#[derive(Clone)]
pub struct PolicyValidator {
    policies: Arc<RwLock<PolicySet>>,
    validation_rules: Arc<RwLock<Vec<ValidationRule>>>,
}

/// Security analysis engine
#[derive(Clone)]
pub struct SecurityAnalyzer {
    threat_models: Arc<RwLock<Vec<ThreatModel>>>,
    vulnerability_database: Arc<RwLock<VulnerabilityDatabase>>,
    attack_surface_analyzer: Arc<AttackSurfaceAnalyzer>,
}

/// Capability mapping engine
#[derive(Clone)]
pub struct CapabilityMapper {
    capability_matrix: Arc<RwLock<CapabilityMatrix>>,
    resource_limits: Arc<RwLock<ResourceLimitSet>>,
    permission_cache: Arc<RwLock<HashMap<String, PermissionSet>>>,
}

/// Guard validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardResult {
    pub validation_id: Uuid,
    pub approved: bool,
    pub reason: String,
    pub risk_score: f32,
    pub policy_violations: Vec<PolicyViolation>,
    pub security_issues: Vec<SecurityIssue>,
    pub capability_restrictions: Vec<CapabilityRestriction>,
    pub required_approvals: Vec<ApprovalRequirement>,
    pub mitigation_steps: Vec<MitigationStep>,
    pub confidence: f32,
    pub validated_at: chrono::DateTime<chrono::Utc>,
}

/// Policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub violation_id: Uuid,
    pub policy_name: String,
    pub rule_name: String,
    pub severity: ViolationSeverity,
    pub description: String,
    pub remediation: String,
    pub auto_fixable: bool,
}

/// Security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub issue_id: Uuid,
    pub issue_type: SecurityIssueType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub impact: String,
    pub mitigation: String,
    pub cve_references: Vec<String>,
}

/// Capability restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRestriction {
    pub restriction_id: Uuid,
    pub capability: String,
    pub restriction_type: RestrictionType,
    pub allowed_operations: Vec<String>,
    pub resource_limits: HashMap<String, serde_json::Value>,
    pub time_restrictions: Option<TimeRestriction>,
}

/// Approval requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    pub requirement_id: Uuid,
    pub approval_type: ApprovalType,
    pub required_role: String,
    pub reason: String,
    pub urgency: Urgency,
    pub auto_approve_conditions: Vec<String>,
}

/// Mitigation step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationStep {
    pub step_id: Uuid,
    pub step_type: MitigationType,
    pub description: String,
    pub implementation: String,
    pub priority: MitigationPriority,
    pub estimated_effort: String,
}

/// Policy set
#[derive(Debug, Clone, Default)]
struct PolicySet {
    capability_policies: HashMap<String, CapabilityPolicy>,
    resource_policies: HashMap<String, ResourcePolicy>,
    security_policies: HashMap<String, SecurityPolicy>,
    compliance_policies: HashMap<String, CompliancePolicy>,
}

/// Validation rule
#[derive(Debug, Clone)]
struct ValidationRule {
    rule_id: Uuid,
    name: String,
    rule_type: RuleType,
    condition: String,
    action: RuleAction,
    severity: ViolationSeverity,
}

/// Threat model
#[derive(Debug, Clone)]
struct ThreatModel {
    model_id: Uuid,
    name: String,
    description: String,
    threat_actors: Vec<ThreatActor>,
    attack_vectors: Vec<AttackVector>,
    assets: Vec<Asset>,
    mitigations: Vec<ThreatMitigation>,
}

/// Vulnerability database
#[derive(Debug, Clone, Default)]
struct VulnerabilityDatabase {
    vulnerabilities: HashMap<String, Vulnerability>,
    last_updated: chrono::DateTime<chrono::Utc>,
}

/// Attack surface analyzer
#[derive(Clone)]
struct AttackSurfaceAnalyzer {
    surface_map: Arc<RwLock<AttackSurfaceMap>>,
}

/// Capability matrix
#[derive(Debug, Clone, Default)]
struct CapabilityMatrix {
    permissions: HashMap<String, PermissionSet>,
    restrictions: HashMap<String, RestrictionSet>,
}

/// Resource limit set
#[derive(Debug, Clone, Default)]
struct ResourceLimitSet {
    cpu_limits: HashMap<String, f32>,
    memory_limits: HashMap<String, u64>,
    disk_limits: HashMap<String, u64>,
    network_limits: HashMap<String, f32>,
    time_limits: HashMap<String, u64>,
}

/// Permission set
#[derive(Debug, Clone, Default)]
struct PermissionSet {
    allowed_capabilities: Vec<String>,
    denied_capabilities: Vec<String>,
    conditional_capabilities: HashMap<String, Vec<String>>,
}

/// Security metrics
#[derive(Debug, Clone, Default)]
struct SecurityMetrics {
    total_validations: u64,
    approved_validations: u64,
    rejected_validations: u64,
    high_risk_validations: u64,
    policy_violations: u64,
    security_issues: u64,
    average_risk_score: f32,
}

// Enums
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityIssueType {
    AuthenticationBypass,
    AuthorizationEscalation,
    DataExfiltration,
    CodeInjection,
    ResourceExhaustion,
    ConfigurationError,
    CryptographicWeakness,
    NetworkSecurity,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestrictionType {
    Deny,
    Limit,
    Monitor,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalType {
    Manual,
    Automated,
    ConditionalManual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Urgency {
    Low,
    Medium,
    High,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationType {
    Prevention,
    Detection,
    Response,
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
enum RuleType {
    Capability,
    Resource,
    Security,
    Compliance,
}

#[derive(Debug, Clone)]
enum RuleAction {
    Allow,
    Deny,
    RequireApproval,
    ApplyRestrictions,
}

// Additional types for threat modeling
#[derive(Debug, Clone)]
struct ThreatActor {
    name: String,
    motivation: String,
    capabilities: Vec<String>,
    likelihood: f32,
}

#[derive(Debug, Clone)]
struct AttackVector {
    name: String,
    description: String,
    prerequisites: Vec<String>,
    impact: f32,
    likelihood: f32,
}

#[derive(Debug, Clone)]
struct Asset {
    name: String,
    value: f32,
    sensitivity: AssetSensitivity,
    dependencies: Vec<String>,
}

#[derive(Debug, Clone)]
enum AssetSensitivity {
    Public,
    Internal,
    Confidential,
    Secret,
}

#[derive(Debug, Clone)]
struct ThreatMitigation {
    name: String,
    description: String,
    effectiveness: f32,
    cost: f32,
}

#[derive(Debug, Clone)]
struct Vulnerability {
    cve_id: Option<String>,
    description: String,
    severity: SecuritySeverity,
    affected_components: Vec<String>,
    mitigation: String,
}

#[derive(Debug, Clone, Default)]
struct AttackSurfaceMap {
    entry_points: Vec<EntryPoint>,
    data_flows: Vec<DataFlow>,
    trust_boundaries: Vec<TrustBoundary>,
}

#[derive(Debug, Clone)]
struct EntryPoint {
    name: String,
    entry_type: EntryPointType,
    authentication_required: bool,
    authorization_required: bool,
    encryption_in_transit: bool,
}

#[derive(Debug, Clone)]
enum EntryPointType {
    Network,
    FileSystem,
    Process,
    Memory,
}

#[derive(Debug, Clone)]
struct DataFlow {
    source: String,
    destination: String,
    data_type: String,
    encryption_at_rest: bool,
    encryption_in_transit: bool,
}

#[derive(Debug, Clone)]
struct TrustBoundary {
    name: String,
    inside_components: Vec<String>,
    outside_components: Vec<String>,
    validation_required: bool,
}

#[derive(Debug, Clone)]
struct CapabilityPolicy {
    allowed_operations: Vec<String>,
    resource_limits: HashMap<String, serde_json::Value>,
    time_restrictions: Option<TimeRestriction>,
    approval_required: bool,
}

#[derive(Debug, Clone)]
struct ResourcePolicy {
    max_cpu_cores: f32,
    max_memory_mb: u64,
    max_disk_mb: u64,
    max_network_mbps: f32,
    max_duration_seconds: u64,
}

#[derive(Debug, Clone)]
struct SecurityPolicy {
    encryption_required: bool,
    authentication_required: bool,
    authorization_required: bool,
    audit_required: bool,
    allowed_protocols: Vec<String>,
    denied_protocols: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompliancePolicy {
    framework: String,
    requirements: Vec<String>,
    validation_rules: Vec<String>,
    reporting_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimeRestriction {
    allowed_hours: Vec<u8>,
    allowed_days: Vec<u8>,
    timezone: String,
    emergency_override: bool,
}

#[derive(Debug, Clone, Default)]
struct RestrictionSet {
    capability_restrictions: Vec<String>,
    resource_restrictions: HashMap<String, serde_json::Value>,
    time_restrictions: Option<TimeRestriction>,
}

impl GuardEngine {
    /// Create new guard engine
    pub async fn new(config: &SecurityConfig) -> Result<Self> {
        info!("Initializing Guard Engine");

        let policy_validator = Arc::new(PolicyValidator::new().await?);
        let security_analyzer = Arc::new(SecurityAnalyzer::new().await?);
        let capability_mapper = Arc::new(CapabilityMapper::new(config).await?);
        let validation_cache = Arc::new(RwLock::new(HashMap::new()));
        let security_metrics = Arc::new(RwLock::new(SecurityMetrics::default()));

        info!("Guard Engine initialized successfully");

        Ok(Self {
            config: config.clone(),
            policy_validator,
            security_analyzer,
            capability_mapper,
            validation_cache,
            security_metrics,
        })
    }

    /// Validate goal against security policies
    pub async fn validate_goal(&self, goal: &Goal) -> Result<GuardResult> {
        info!(goal_id = %goal.id, "Validating goal against security policies");

        let start_time = std::time::Instant::now();

        // Check cache first
        let cache_key = format!("goal_{}", goal.id);
        if let Some(cached_result) = self.validation_cache.read().await.get(&cache_key) {
            debug!(goal_id = %goal.id, "Using cached validation result");
            return Ok(cached_result.clone());
        }

        // Perform policy validation
        let policy_violations = self.policy_validator.validate_goal(goal).await?;

        // Perform security analysis
        let security_issues = self.security_analyzer.analyze_goal(goal).await?;

        // Check capability requirements
        let capability_restrictions = self.capability_mapper.map_goal_capabilities(goal).await?;

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&policy_violations, &security_issues);

        // Determine approval requirements
        let required_approvals = self
            .determine_approval_requirements(risk_score, &policy_violations)
            .await?;

        // Generate mitigation steps
        let mitigation_steps = self
            .generate_mitigation_steps(&policy_violations, &security_issues)
            .await?;

        // Determine overall approval
        let approved = policy_violations.is_empty()
            && security_issues
                .iter()
                .all(|i| matches!(i.severity, SecuritySeverity::Low | SecuritySeverity::Medium))
            && risk_score < 0.7;

        let reason = if approved {
            "Goal approved - no security concerns identified".to_string()
        } else {
            format!(
                "Goal requires attention: {} policy violations, {} security issues, risk score: {:.2}",
                policy_violations.len(),
                security_issues.len(),
                risk_score
            )
        };

        // Calculate confidence
        let confidence =
            self.calculate_validation_confidence(&policy_violations, &security_issues, risk_score);

        let result = GuardResult {
            validation_id: Uuid::new_v4(),
            approved,
            reason,
            risk_score,
            policy_violations,
            security_issues,
            capability_restrictions,
            required_approvals,
            mitigation_steps,
            confidence,
            validated_at: chrono::Utc::now(),
        };

        // Cache result
        self.validation_cache
            .write()
            .await
            .insert(cache_key, result.clone());

        // Update metrics
        self.update_security_metrics(&result).await;

        let elapsed = start_time.elapsed();
        info!(
            goal_id = %goal.id,
            approved = approved,
            risk_score = risk_score,
            validation_duration_ms = elapsed.as_millis(),
            "Goal validation completed"
        );

        Ok(result)
    }

    /// Validate execution plan
    pub async fn validate_plan(&self, plan: &ExecutionPlan) -> Result<GuardResult> {
        info!(plan_id = %plan.plan_id, "Validating execution plan");

        let start_time = std::time::Instant::now();

        // Check cache first
        let cache_key = format!("plan_{}", plan.plan_id);
        if let Some(cached_result) = self.validation_cache.read().await.get(&cache_key) {
            debug!(plan_id = %plan.plan_id, "Using cached validation result");
            return Ok(cached_result.clone());
        }

        // Validate each step in the plan
        let mut all_policy_violations = Vec::new();
        let mut all_security_issues = Vec::new();
        let mut all_capability_restrictions = Vec::new();

        for step in &plan.steps {
            let step_violations = self.policy_validator.validate_plan_step(step).await?;
            let step_security_issues = self.security_analyzer.analyze_plan_step(step).await?;
            let step_restrictions = self.capability_mapper.map_step_capabilities(step).await?;

            all_policy_violations.extend(step_violations);
            all_security_issues.extend(step_security_issues);
            all_capability_restrictions.extend(step_restrictions);
        }

        // Analyze plan-level security
        let plan_security_issues = self.security_analyzer.analyze_plan_security(plan).await?;
        all_security_issues.extend(plan_security_issues);

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&all_policy_violations, &all_security_issues);

        // Determine approval requirements
        let required_approvals = self
            .determine_approval_requirements(risk_score, &all_policy_violations)
            .await?;

        // Generate mitigation steps
        let mitigation_steps = self
            .generate_mitigation_steps(&all_policy_violations, &all_security_issues)
            .await?;

        // Determine overall approval
        let approved = all_policy_violations.is_empty()
            && all_security_issues
                .iter()
                .all(|i| matches!(i.severity, SecuritySeverity::Low | SecuritySeverity::Medium))
            && risk_score < 0.8; // Slightly higher threshold for plans

        let reason = if approved {
            "Execution plan approved - security validation passed".to_string()
        } else {
            format!(
                "Plan requires security review: {} violations, {} issues, risk: {:.2}",
                all_policy_violations.len(),
                all_security_issues.len(),
                risk_score
            )
        };

        let confidence = self.calculate_validation_confidence(
            &all_policy_violations,
            &all_security_issues,
            risk_score,
        );

        let result = GuardResult {
            validation_id: Uuid::new_v4(),
            approved,
            reason,
            risk_score,
            policy_violations: all_policy_violations,
            security_issues: all_security_issues,
            capability_restrictions: all_capability_restrictions,
            required_approvals,
            mitigation_steps,
            confidence,
            validated_at: chrono::Utc::now(),
        };

        // Cache result
        self.validation_cache
            .write()
            .await
            .insert(cache_key, result.clone());

        // Update metrics
        self.update_security_metrics(&result).await;

        let elapsed = start_time.elapsed();
        info!(
            plan_id = %plan.plan_id,
            approved = approved,
            risk_score = risk_score,
            validation_duration_ms = elapsed.as_millis(),
            "Plan validation completed"
        );

        Ok(result)
    }

    /// Calculate risk score based on violations and issues
    fn calculate_risk_score(
        &self,
        violations: &[PolicyViolation],
        issues: &[SecurityIssue],
    ) -> f32 {
        let violation_score = violations
            .iter()
            .map(|v| match v.severity {
                ViolationSeverity::Critical => 1.0,
                ViolationSeverity::High => 0.8,
                ViolationSeverity::Medium => 0.5,
                ViolationSeverity::Low => 0.2,
                ViolationSeverity::Info => 0.1,
            })
            .sum::<f32>();

        let issue_score = issues
            .iter()
            .map(|i| match i.severity {
                SecuritySeverity::Critical => 1.0,
                SecuritySeverity::High => 0.8,
                SecuritySeverity::Medium => 0.5,
                SecuritySeverity::Low => 0.2,
            })
            .sum::<f32>();

        ((violation_score + issue_score) / (violations.len() + issues.len()).max(1) as f32).min(1.0)
    }

    /// Determine required approvals
    async fn determine_approval_requirements(
        &self,
        risk_score: f32,
        violations: &[PolicyViolation],
    ) -> Result<Vec<ApprovalRequirement>> {
        let mut requirements = Vec::new();

        if risk_score > 0.8 {
            requirements.push(ApprovalRequirement {
                requirement_id: Uuid::new_v4(),
                approval_type: ApprovalType::Manual,
                required_role: "security_admin".to_string(),
                reason: "High risk score requires security admin approval".to_string(),
                urgency: Urgency::High,
                auto_approve_conditions: vec![],
            });
        }

        for violation in violations {
            if matches!(
                violation.severity,
                ViolationSeverity::Critical | ViolationSeverity::High
            ) {
                requirements.push(ApprovalRequirement {
                    requirement_id: Uuid::new_v4(),
                    approval_type: ApprovalType::Manual,
                    required_role: "policy_admin".to_string(),
                    reason: format!("Policy violation: {}", violation.description),
                    urgency: match violation.severity {
                        ViolationSeverity::Critical => Urgency::Emergency,
                        ViolationSeverity::High => Urgency::High,
                        _ => Urgency::Medium,
                    },
                    auto_approve_conditions: if violation.auto_fixable {
                        vec!["Auto-fix applied and verified".to_string()]
                    } else {
                        vec![]
                    },
                });
            }
        }

        Ok(requirements)
    }

    /// Generate mitigation steps
    async fn generate_mitigation_steps(
        &self,
        violations: &[PolicyViolation],
        issues: &[SecurityIssue],
    ) -> Result<Vec<MitigationStep>> {
        let mut steps = Vec::new();

        for violation in violations {
            steps.push(MitigationStep {
                step_id: Uuid::new_v4(),
                step_type: MitigationType::Prevention,
                description: format!("Address policy violation: {}", violation.description),
                implementation: violation.remediation.clone(),
                priority: match violation.severity {
                    ViolationSeverity::Critical => MitigationPriority::Critical,
                    ViolationSeverity::High => MitigationPriority::High,
                    ViolationSeverity::Medium => MitigationPriority::Medium,
                    _ => MitigationPriority::Low,
                },
                estimated_effort: if violation.auto_fixable {
                    "Automated".to_string()
                } else {
                    "Manual intervention required".to_string()
                },
            });
        }

        for issue in issues {
            steps.push(MitigationStep {
                step_id: Uuid::new_v4(),
                step_type: MitigationType::Prevention,
                description: format!("Address security issue: {}", issue.description),
                implementation: issue.mitigation.clone(),
                priority: match issue.severity {
                    SecuritySeverity::Critical => MitigationPriority::Critical,
                    SecuritySeverity::High => MitigationPriority::High,
                    SecuritySeverity::Medium => MitigationPriority::Medium,
                    SecuritySeverity::Low => MitigationPriority::Low,
                },
                estimated_effort: "Review and implement".to_string(),
            });
        }

        Ok(steps)
    }

    /// Calculate validation confidence
    fn calculate_validation_confidence(
        &self,
        violations: &[PolicyViolation],
        issues: &[SecurityIssue],
        risk_score: f32,
    ) -> f32 {
        // Base confidence starts high
        let mut confidence = 0.9;

        // Reduce confidence based on number of violations and issues
        confidence -= (violations.len() as f32 * 0.05).min(0.3);
        confidence -= (issues.len() as f32 * 0.05).min(0.3);

        // Reduce confidence based on risk score
        confidence -= risk_score * 0.2;

        confidence.max(0.1).min(1.0)
    }

    /// Update security metrics
    async fn update_security_metrics(&self, result: &GuardResult) {
        let mut metrics = self.security_metrics.write().await;

        metrics.total_validations += 1;

        if result.approved {
            metrics.approved_validations += 1;
        } else {
            metrics.rejected_validations += 1;
        }

        if result.risk_score > 0.7 {
            metrics.high_risk_validations += 1;
        }

        metrics.policy_violations += result.policy_violations.len() as u64;
        metrics.security_issues += result.security_issues.len() as u64;

        // Update average risk score
        metrics.average_risk_score = (metrics.average_risk_score
            * (metrics.total_validations - 1) as f32
            + result.risk_score)
            / metrics.total_validations as f32;
    }

    /// Export security metrics
    pub async fn export_metrics(&self) -> SecurityMetrics {
        self.security_metrics.read().await.clone()
    }

    /// Get validation history
    pub async fn get_validation_history(&self) -> Vec<GuardResult> {
        self.validation_cache
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Clear validation cache
    pub async fn clear_cache(&self) {
        self.validation_cache.write().await.clear();
        info!("Guard engine validation cache cleared");
    }
}

impl PolicyValidator {
    async fn new() -> Result<Self> {
        Ok(Self {
            policies: Arc::new(RwLock::new(PolicySet::default())),
            validation_rules: Arc::new(RwLock::new(Vec::new())),
        })
    }

    async fn validate_goal(&self, goal: &Goal) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        // Check goal description for security keywords
        if goal.description.to_lowercase().contains("admin")
            || goal.description.to_lowercase().contains("root")
            || goal.description.to_lowercase().contains("sudo")
        {
            violations.push(PolicyViolation {
                violation_id: Uuid::new_v4(),
                policy_name: "PrivilegeEscalation".to_string(),
                rule_name: "NoAdminOperations".to_string(),
                severity: ViolationSeverity::High,
                description: "Goal requests administrative privileges".to_string(),
                remediation: "Request specific capabilities instead of admin access".to_string(),
                auto_fixable: false,
            });
        }

        // Check constraints for security concerns
        for constraint in &goal.constraints {
            if constraint.to_lowercase().contains("unrestricted") {
                violations.push(PolicyViolation {
                    violation_id: Uuid::new_v4(),
                    policy_name: "ResourceLimits".to_string(),
                    rule_name: "NoUnrestrictedAccess".to_string(),
                    severity: ViolationSeverity::Medium,
                    description: "Goal requests unrestricted access".to_string(),
                    remediation: "Specify exact resource requirements".to_string(),
                    auto_fixable: true,
                });
            }
        }

        Ok(violations)
    }

    async fn validate_plan_step(
        &self,
        step: &crate::planner::oracle::PlanStep,
    ) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        // Check capability against policy
        if !self.is_capability_allowed(&step.capability).await {
            violations.push(PolicyViolation {
                violation_id: Uuid::new_v4(),
                policy_name: "CapabilityRestrictions".to_string(),
                rule_name: "AllowedCapabilities".to_string(),
                severity: ViolationSeverity::High,
                description: format!("Capability '{}' is not allowed", step.capability),
                remediation: "Use an approved capability from the allowlist".to_string(),
                auto_fixable: false,
            });
        }

        // Check execution time
        if step.expected_duration_minutes > 120 {
            violations.push(PolicyViolation {
                violation_id: Uuid::new_v4(),
                policy_name: "ResourceLimits".to_string(),
                rule_name: "MaxExecutionTime".to_string(),
                severity: ViolationSeverity::Medium,
                description: "Step execution time exceeds policy limit".to_string(),
                remediation: "Break down long-running operations into smaller steps".to_string(),
                auto_fixable: true,
            });
        }

        Ok(violations)
    }

    async fn is_capability_allowed(&self, capability: &str) -> bool {
        // Simple allowlist check
        let allowed_capabilities = vec![
            "fs.read.v1",
            "fs.write.v1",
            "http.fetch.v1",
            "process.run.v1",
            "analysis.system.v1",
            "implementation.execute.v1",
            "validation.test.v1",
            "validation.extended.v1",
            "rollback.restore.v1",
            "alternative.execute.v1",
        ];

        allowed_capabilities.contains(&capability)
    }
}

impl SecurityAnalyzer {
    async fn new() -> Result<Self> {
        Ok(Self {
            threat_models: Arc::new(RwLock::new(Vec::new())),
            vulnerability_database: Arc::new(RwLock::new(VulnerabilityDatabase::default())),
            attack_surface_analyzer: Arc::new(AttackSurfaceAnalyzer {
                surface_map: Arc::new(RwLock::new(AttackSurfaceMap::default())),
            }),
        })
    }

    async fn analyze_goal(&self, goal: &Goal) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();

        // Check for data access patterns
        if goal.description.to_lowercase().contains("database")
            || goal.description.to_lowercase().contains("sql")
        {
            issues.push(SecurityIssue {
                issue_id: Uuid::new_v4(),
                issue_type: SecurityIssueType::DataExfiltration,
                severity: SecuritySeverity::Medium,
                description: "Goal involves database access - review for data protection"
                    .to_string(),
                impact: "Potential unauthorized data access".to_string(),
                mitigation: "Implement proper access controls and audit logging".to_string(),
                cve_references: vec![],
            });
        }

        // Check for network operations
        if goal.description.to_lowercase().contains("network")
            || goal.description.to_lowercase().contains("internet")
            || goal.description.to_lowercase().contains("external")
        {
            issues.push(SecurityIssue {
                issue_id: Uuid::new_v4(),
                issue_type: SecurityIssueType::NetworkSecurity,
                severity: SecuritySeverity::Medium,
                description: "Goal involves network operations - review for security".to_string(),
                impact: "Potential network-based attacks".to_string(),
                mitigation: "Use encrypted connections and validate all external data".to_string(),
                cve_references: vec![],
            });
        }

        Ok(issues)
    }

    async fn analyze_plan_step(
        &self,
        step: &crate::planner::oracle::PlanStep,
    ) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();

        // Check for risky capabilities
        if step.capability.contains("process.run") {
            issues.push(SecurityIssue {
                issue_id: Uuid::new_v4(),
                issue_type: SecurityIssueType::CodeInjection,
                severity: SecuritySeverity::High,
                description: "Process execution capability poses code injection risk".to_string(),
                impact: "Arbitrary code execution possible".to_string(),
                mitigation: "Validate and sanitize all process arguments".to_string(),
                cve_references: vec![],
            });
        }

        // Check parameters for injection risks
        for (key, value) in &step.parameters {
            if key.contains("command") || key.contains("script") {
                if let Some(str_value) = value.as_str() {
                    if str_value.contains(";")
                        || str_value.contains("|")
                        || str_value.contains("&&")
                    {
                        issues.push(SecurityIssue {
                            issue_id: Uuid::new_v4(),
                            issue_type: SecurityIssueType::CodeInjection,
                            severity: SecuritySeverity::High,
                            description: "Parameter contains command injection patterns"
                                .to_string(),
                            impact: "Command injection possible".to_string(),
                            mitigation:
                                "Sanitize command parameters and use parameterized execution"
                                    .to_string(),
                            cve_references: vec![],
                        });
                    }
                }
            }
        }

        Ok(issues)
    }

    async fn analyze_plan_security(&self, plan: &ExecutionPlan) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();

        // Check for parallel execution security
        let parallel_groups: std::collections::HashSet<_> = plan
            .steps
            .iter()
            .filter_map(|s| s.parallel_group.as_ref())
            .collect();

        if parallel_groups.len() > 1 {
            issues.push(SecurityIssue {
                issue_id: Uuid::new_v4(),
                issue_type: SecurityIssueType::Other("ConcurrencyRisk".to_string()),
                severity: SecuritySeverity::Medium,
                description: "Multiple parallel execution groups may cause race conditions"
                    .to_string(),
                impact: "Data corruption or security bypasses possible".to_string(),
                mitigation: "Implement proper synchronization and isolation".to_string(),
                cve_references: vec![],
            });
        }

        // Check resource requirements
        if plan.resource_requirements.memory_mb > 2048 {
            issues.push(SecurityIssue {
                issue_id: Uuid::new_v4(),
                issue_type: SecurityIssueType::ResourceExhaustion,
                severity: SecuritySeverity::Low,
                description: "High memory usage may lead to resource exhaustion".to_string(),
                impact: "System instability or denial of service".to_string(),
                mitigation: "Implement memory limits and monitoring".to_string(),
                cve_references: vec![],
            });
        }

        Ok(issues)
    }
}

impl CapabilityMapper {
    async fn new(config: &SecurityConfig) -> Result<Self> {
        let mut capability_matrix = CapabilityMatrix::default();

        // Initialize permissions based on config
        for capability in &config.allowed_capabilities {
            capability_matrix.permissions.insert(
                capability.clone(),
                PermissionSet {
                    allowed_capabilities: vec![capability.clone()],
                    denied_capabilities: vec![],
                    conditional_capabilities: HashMap::new(),
                },
            );
        }

        Ok(Self {
            capability_matrix: Arc::new(RwLock::new(capability_matrix)),
            resource_limits: Arc::new(RwLock::new(ResourceLimitSet::default())),
            permission_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn map_goal_capabilities(&self, goal: &Goal) -> Result<Vec<CapabilityRestriction>> {
        let mut restrictions = Vec::new();

        // Analyze goal for capability requirements
        if goal.description.to_lowercase().contains("file")
            || goal.description.to_lowercase().contains("read")
        {
            restrictions.push(CapabilityRestriction {
                restriction_id: Uuid::new_v4(),
                capability: "fs.read.v1".to_string(),
                restriction_type: RestrictionType::Limit,
                allowed_operations: vec!["read".to_string()],
                resource_limits: {
                    let mut limits = HashMap::new();
                    limits.insert(
                        "max_files".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(100)),
                    );
                    limits
                },
                time_restrictions: None,
            });
        }

        Ok(restrictions)
    }

    async fn map_step_capabilities(
        &self,
        step: &crate::planner::oracle::PlanStep,
    ) -> Result<Vec<CapabilityRestriction>> {
        let mut restrictions = Vec::new();

        // Map capability to restrictions
        let restriction = CapabilityRestriction {
            restriction_id: Uuid::new_v4(),
            capability: step.capability.clone(),
            restriction_type: RestrictionType::Monitor,
            allowed_operations: vec!["execute".to_string()],
            resource_limits: {
                let mut limits = HashMap::new();
                limits.insert(
                    "max_duration_minutes".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(
                        step.expected_duration_minutes,
                    )),
                );
                limits
            },
            time_restrictions: None,
        };

        restrictions.push(restriction);
        Ok(restrictions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::{Goal, SecurityConfig};

    fn create_test_security_config() -> SecurityConfig {
        SecurityConfig {
            enable_policy_validation: true,
            enable_security_analysis: true,
            enable_capability_restrictions: true,
            max_execution_time_seconds: 3600,
            max_parallel_operations: 10,
            allowed_capabilities: vec!["fs.read.v1".to_string()],
        }
    }

    #[tokio::test]
    async fn test_guard_engine_creation() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await;
        assert!(guard.is_ok());
    }

    #[tokio::test]
    async fn test_goal_validation_approved() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();
        let goal = Goal::new("Read configuration file");

        let result = guard.validate_goal(&goal).await.unwrap();
        assert!(result.approved);
        assert!(result.risk_score < 0.5);
    }

    #[tokio::test]
    async fn test_goal_validation_rejected() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();
        let goal = Goal::new("Gain admin access to the system");

        let result = guard.validate_goal(&goal).await.unwrap();
        assert!(!result.approved);
        assert!(!result.policy_violations.is_empty());
    }

    #[tokio::test]
    async fn test_security_metrics() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();
        let goal = Goal::new("Test goal");

        let _result = guard.validate_goal(&goal).await.unwrap();
        let metrics = guard.export_metrics().await;

        assert_eq!(metrics.total_validations, 1);
    }

    // ViolationSeverity serialization tests
    #[test]
    fn test_violation_severity_serialization() {
        let severities = vec![
            ViolationSeverity::Info,
            ViolationSeverity::Low,
            ViolationSeverity::Medium,
            ViolationSeverity::High,
            ViolationSeverity::Critical,
        ];

        for severity in severities {
            let json = serde_json::to_string(&severity).unwrap();
            let parsed: ViolationSeverity = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // SecurityIssueType serialization tests
    #[test]
    fn test_security_issue_type_serialization() {
        let types = vec![
            SecurityIssueType::AuthenticationBypass,
            SecurityIssueType::AuthorizationEscalation,
            SecurityIssueType::DataExfiltration,
            SecurityIssueType::CodeInjection,
            SecurityIssueType::ResourceExhaustion,
            SecurityIssueType::ConfigurationError,
            SecurityIssueType::CryptographicWeakness,
            SecurityIssueType::NetworkSecurity,
            SecurityIssueType::Other("CustomType".to_string()),
        ];

        for issue_type in types {
            let json = serde_json::to_string(&issue_type).unwrap();
            let parsed: SecurityIssueType = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // SecuritySeverity serialization tests
    #[test]
    fn test_security_severity_serialization() {
        let severities = vec![
            SecuritySeverity::Low,
            SecuritySeverity::Medium,
            SecuritySeverity::High,
            SecuritySeverity::Critical,
        ];

        for severity in severities {
            let json = serde_json::to_string(&severity).unwrap();
            let parsed: SecuritySeverity = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // RestrictionType serialization tests
    #[test]
    fn test_restriction_type_serialization() {
        let types = vec![
            RestrictionType::Deny,
            RestrictionType::Limit,
            RestrictionType::Monitor,
            RestrictionType::RequireApproval,
        ];

        for restriction_type in types {
            let json = serde_json::to_string(&restriction_type).unwrap();
            let parsed: RestrictionType = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // ApprovalType serialization tests
    #[test]
    fn test_approval_type_serialization() {
        let types = vec![
            ApprovalType::Manual,
            ApprovalType::Automated,
            ApprovalType::ConditionalManual,
        ];

        for approval_type in types {
            let json = serde_json::to_string(&approval_type).unwrap();
            let parsed: ApprovalType = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // Urgency serialization tests
    #[test]
    fn test_urgency_serialization() {
        let urgencies = vec![
            Urgency::Low,
            Urgency::Medium,
            Urgency::High,
            Urgency::Emergency,
        ];

        for urgency in urgencies {
            let json = serde_json::to_string(&urgency).unwrap();
            let parsed: Urgency = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // MitigationType serialization tests
    #[test]
    fn test_mitigation_type_serialization() {
        let types = vec![
            MitigationType::Prevention,
            MitigationType::Detection,
            MitigationType::Response,
            MitigationType::Recovery,
        ];

        for mitigation_type in types {
            let json = serde_json::to_string(&mitigation_type).unwrap();
            let parsed: MitigationType = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // MitigationPriority serialization tests
    #[test]
    fn test_mitigation_priority_serialization() {
        let priorities = vec![
            MitigationPriority::Low,
            MitigationPriority::Medium,
            MitigationPriority::High,
            MitigationPriority::Critical,
        ];

        for priority in priorities {
            let json = serde_json::to_string(&priority).unwrap();
            let parsed: MitigationPriority = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // PolicyViolation serialization test
    #[test]
    fn test_policy_violation_serialization() {
        let violation = PolicyViolation {
            violation_id: Uuid::new_v4(),
            policy_name: "TestPolicy".to_string(),
            rule_name: "TestRule".to_string(),
            severity: ViolationSeverity::High,
            description: "Test violation".to_string(),
            remediation: "Fix it".to_string(),
            auto_fixable: true,
        };

        let json = serde_json::to_string(&violation).unwrap();
        let parsed: PolicyViolation = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.policy_name, "TestPolicy");
        assert_eq!(parsed.rule_name, "TestRule");
        assert!(parsed.auto_fixable);
    }

    // SecurityIssue serialization test
    #[test]
    fn test_security_issue_serialization() {
        let issue = SecurityIssue {
            issue_id: Uuid::new_v4(),
            issue_type: SecurityIssueType::CodeInjection,
            severity: SecuritySeverity::Critical,
            description: "SQL injection vulnerability".to_string(),
            impact: "Data breach possible".to_string(),
            mitigation: "Use parameterized queries".to_string(),
            cve_references: vec!["CVE-2024-0001".to_string()],
        };

        let json = serde_json::to_string(&issue).unwrap();
        let parsed: SecurityIssue = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.description, "SQL injection vulnerability");
        assert_eq!(parsed.cve_references.len(), 1);
    }

    // CapabilityRestriction serialization test
    #[test]
    fn test_capability_restriction_serialization() {
        let restriction = CapabilityRestriction {
            restriction_id: Uuid::new_v4(),
            capability: "fs.read.v1".to_string(),
            restriction_type: RestrictionType::Limit,
            allowed_operations: vec!["read".to_string()],
            resource_limits: HashMap::from([("max_files".to_string(), serde_json::json!(100))]),
            time_restrictions: None,
        };

        let json = serde_json::to_string(&restriction).unwrap();
        let parsed: CapabilityRestriction = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.capability, "fs.read.v1");
        assert_eq!(parsed.allowed_operations.len(), 1);
    }

    // ApprovalRequirement serialization test
    #[test]
    fn test_approval_requirement_serialization() {
        let requirement = ApprovalRequirement {
            requirement_id: Uuid::new_v4(),
            approval_type: ApprovalType::Manual,
            required_role: "security_admin".to_string(),
            reason: "High risk operation".to_string(),
            urgency: Urgency::High,
            auto_approve_conditions: vec!["Override approved".to_string()],
        };

        let json = serde_json::to_string(&requirement).unwrap();
        let parsed: ApprovalRequirement = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.required_role, "security_admin");
        assert!(matches!(parsed.urgency, Urgency::High));
    }

    // MitigationStep serialization test
    #[test]
    fn test_mitigation_step_serialization() {
        let step = MitigationStep {
            step_id: Uuid::new_v4(),
            step_type: MitigationType::Prevention,
            description: "Implement input validation".to_string(),
            implementation: "Add validation middleware".to_string(),
            priority: MitigationPriority::High,
            estimated_effort: "4 hours".to_string(),
        };

        let json = serde_json::to_string(&step).unwrap();
        let parsed: MitigationStep = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.description, "Implement input validation");
        assert_eq!(parsed.estimated_effort, "4 hours");
    }

    // GuardResult serialization test
    #[test]
    fn test_guard_result_serialization() {
        let result = GuardResult {
            validation_id: Uuid::new_v4(),
            approved: true,
            reason: "All checks passed".to_string(),
            risk_score: 0.3,
            policy_violations: vec![],
            security_issues: vec![],
            capability_restrictions: vec![],
            required_approvals: vec![],
            mitigation_steps: vec![],
            confidence: 0.95,
            validated_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: GuardResult = serde_json::from_str(&json).unwrap();

        assert!(parsed.approved);
        assert_eq!(parsed.risk_score, 0.3);
        assert_eq!(parsed.confidence, 0.95);
    }

    // calculate_risk_score tests
    #[tokio::test]
    async fn test_calculate_risk_score_no_issues() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        let risk_score = guard.calculate_risk_score(&[], &[]);
        assert_eq!(risk_score, 0.0);
    }

    #[tokio::test]
    async fn test_calculate_risk_score_critical_violation() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        let violations = vec![PolicyViolation {
            violation_id: Uuid::new_v4(),
            policy_name: "Test".to_string(),
            rule_name: "Test".to_string(),
            severity: ViolationSeverity::Critical,
            description: "Critical violation".to_string(),
            remediation: "Fix".to_string(),
            auto_fixable: false,
        }];

        let risk_score = guard.calculate_risk_score(&violations, &[]);
        assert_eq!(risk_score, 1.0);
    }

    #[tokio::test]
    async fn test_calculate_risk_score_mixed_severities() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        let violations = vec![
            PolicyViolation {
                violation_id: Uuid::new_v4(),
                policy_name: "Test".to_string(),
                rule_name: "Test".to_string(),
                severity: ViolationSeverity::Low,
                description: "Low".to_string(),
                remediation: "Fix".to_string(),
                auto_fixable: true,
            },
            PolicyViolation {
                violation_id: Uuid::new_v4(),
                policy_name: "Test".to_string(),
                rule_name: "Test".to_string(),
                severity: ViolationSeverity::Medium,
                description: "Medium".to_string(),
                remediation: "Fix".to_string(),
                auto_fixable: true,
            },
        ];

        let risk_score = guard.calculate_risk_score(&violations, &[]);
        assert!(risk_score > 0.0 && risk_score < 1.0);
    }

    // calculate_validation_confidence tests
    #[tokio::test]
    async fn test_calculate_validation_confidence_clean() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        let confidence = guard.calculate_validation_confidence(&[], &[], 0.0);
        assert!(confidence > 0.8);
    }

    #[tokio::test]
    async fn test_calculate_validation_confidence_with_issues() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        let violations = vec![PolicyViolation {
            violation_id: Uuid::new_v4(),
            policy_name: "Test".to_string(),
            rule_name: "Test".to_string(),
            severity: ViolationSeverity::High,
            description: "Issue".to_string(),
            remediation: "Fix".to_string(),
            auto_fixable: false,
        }];

        let confidence = guard.calculate_validation_confidence(&violations, &[], 0.8);
        assert!(confidence < 0.9);
    }

    // Cache tests
    #[tokio::test]
    async fn test_clear_cache() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        // Validate goal to populate cache
        let goal = Goal::new("Test goal");
        let _result = guard.validate_goal(&goal).await.unwrap();

        // Clear cache
        guard.clear_cache().await;

        // Verify cache is empty
        let history = guard.get_validation_history().await;
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_validation_history() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        // Validate two goals
        let goal1 = Goal::new("First goal");
        let goal2 = Goal::new("Second goal");

        let _result1 = guard.validate_goal(&goal1).await.unwrap();
        let _result2 = guard.validate_goal(&goal2).await.unwrap();

        let history = guard.get_validation_history().await;
        assert_eq!(history.len(), 2);
    }

    // Goal with security keywords tests
    #[tokio::test]
    async fn test_goal_with_root_keyword() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();
        let goal = Goal::new("Run as root user");

        let result = guard.validate_goal(&goal).await.unwrap();
        assert!(!result.approved);
        assert!(!result.policy_violations.is_empty());
    }

    #[tokio::test]
    async fn test_goal_with_sudo_keyword() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();
        let goal = Goal::new("Execute sudo command");

        let result = guard.validate_goal(&goal).await.unwrap();
        assert!(!result.approved);
    }

    #[tokio::test]
    async fn test_goal_with_database_keyword() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();
        let goal = Goal::new("Query the database for user data");

        let result = guard.validate_goal(&goal).await.unwrap();
        // May still be approved, but should have security issues noted
        assert!(!result.security_issues.is_empty());
    }

    #[tokio::test]
    async fn test_goal_with_network_keyword() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();
        let goal = Goal::new("Connect to external network service");

        let result = guard.validate_goal(&goal).await.unwrap();
        // Should note network security considerations
        assert!(!result.security_issues.is_empty());
    }

    // Metrics update tests
    #[tokio::test]
    async fn test_metrics_approved_increment() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        let goal = Goal::new("Simple safe goal");
        let _result = guard.validate_goal(&goal).await.unwrap();

        let metrics = guard.export_metrics().await;
        assert!(metrics.approved_validations > 0 || metrics.rejected_validations > 0);
    }

    #[tokio::test]
    async fn test_metrics_high_risk_count() {
        let config = create_test_security_config();
        let guard = GuardEngine::new(&config).await.unwrap();

        // Validate something that should be high risk
        let goal = Goal::new("Get admin access with unrestricted permissions");
        let _result = guard.validate_goal(&goal).await.unwrap();

        let metrics = guard.export_metrics().await;
        assert!(metrics.high_risk_validations > 0 || metrics.policy_violations > 0);
    }

    // Clone tests
    #[test]
    fn test_violation_severity_clone() {
        let severity = ViolationSeverity::Critical;
        let cloned = severity.clone();
        assert!(matches!(cloned, ViolationSeverity::Critical));
    }

    #[test]
    fn test_security_severity_clone() {
        let severity = SecuritySeverity::High;
        let cloned = severity.clone();
        assert!(matches!(cloned, SecuritySeverity::High));
    }

    #[test]
    fn test_restriction_type_clone() {
        let rt = RestrictionType::RequireApproval;
        let cloned = rt.clone();
        assert!(matches!(cloned, RestrictionType::RequireApproval));
    }

    #[test]
    fn test_urgency_clone() {
        let urgency = Urgency::Emergency;
        let cloned = urgency.clone();
        assert!(matches!(cloned, Urgency::Emergency));
    }

    #[test]
    fn test_mitigation_type_clone() {
        let mt = MitigationType::Recovery;
        let cloned = mt.clone();
        assert!(matches!(cloned, MitigationType::Recovery));
    }
}
