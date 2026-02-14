/*!
# Oracle System - AI-Powered Planning

The Oracle system provides sophisticated AI-driven planning capabilities with:

- **Deep Research Assistant**: Systematic codebase investigation and analysis
- **Planning Committee**: Multi-agent consensus building for robust plans
- **Decision Confidence**: Quantified confidence metrics for plan quality
- **Context Management**: Isolated conversation contexts for complex reasoning

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                        Oracle System                           │
├─────────────────────────────────────────────────────────────────┤
│  Goal Analysis Engine                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Context    │  │ Constraint  │  │  Success    │           │
│  │ Extraction  │  │  Analysis   │  │  Criteria   │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Deep Research Assistant                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ Codebase    │  │  Pattern    │  │  Risk       │           │
│  │ Analysis    │  │ Detection   │  │ Assessment  │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  Planning Committee (Multi-Agent Consensus)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │Architecture │  │  Security   │  │Performance  │           │
│  │ Specialist  │  │ Specialist  │  │ Specialist  │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
│  ┌─────────────┐  ┌─────────────┐                            │
│  │    QA       │  │  Consensus  │                            │
│  │ Specialist  │  │   Builder   │                            │
│  └─────────────┘  └─────────────┘                            │
├─────────────────────────────────────────────────────────────────┤
│  Plan Generation & Validation                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │    Step     │  │ Capability  │  │  Resource   │           │
│  │ Sequencing  │  │   Mapping   │  │ Estimation  │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

```text
let oracle = Oracle::new(&ai_config).await?;
let goal = Goal::new("Optimize database performance");
let decision = oracle.plan_execution(&goal).await?;

match decision.confidence {
    c if c > 0.8 => println!("High confidence plan: {}", decision.plan.summary),
    c if c > 0.5 => println!("Medium confidence plan: {}", decision.plan.summary),
    _ => println!("Low confidence - consider manual intervention"),
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

use crate::planner::executor_adapter::ExecutionResult;
use crate::planner::{AiConfig, Goal};

/// Location (relative to the executor workdir) where transient plan artifacts are written.
/// Stored under `target/` so they stay ephemeral and out of version control.
const PLAN_OUTPUT_DIR: &str = "target/smith-plans";

/// Oracle system for AI-powered planning
#[derive(Clone)]
pub struct Oracle {
    config: AiConfig,
    research_assistant: Arc<DeepResearchAssistant>,
    planning_committee: Arc<PlanningCommittee>,
    conversation_cache: Arc<RwLock<HashMap<String, ConversationContext>>>,
    decision_history: Arc<RwLock<Vec<OracleDecision>>>,
}

/// Deep research assistant for systematic analysis
#[derive(Clone)]
pub struct DeepResearchAssistant {
    config: AiConfig,
    research_cache: Arc<RwLock<HashMap<String, ResearchResult>>>,
}

/// Planning committee for multi-agent consensus
#[derive(Clone)]
pub struct PlanningCommittee {
    config: AiConfig,
    specialists: Vec<SpecialistAgent>,
    consensus_threshold: f32,
}

/// Specialist agent types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpecialistType {
    Architecture,
    Security,
    Performance,
    QualityAssurance,
}

/// Specialist agent
#[derive(Debug, Clone)]
pub struct SpecialistAgent {
    pub agent_type: SpecialistType,
    pub expertise_areas: Vec<String>,
    pub conversation_context: Option<String>,
}

/// Oracle decision result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleDecision {
    pub decision_id: Uuid,
    pub goal_id: Uuid,
    pub plan: ExecutionPlan,
    pub confidence: f32,
    pub reasoning: String,
    pub research_findings: Option<ResearchResult>,
    pub committee_consensus: Option<PlanningConsensus>,
    pub alternative_plans: Vec<ExecutionPlan>,
    pub risk_assessment: RiskAssessment,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Execution plan structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub plan_id: Uuid,
    pub summary: String,
    pub steps: Vec<PlanStep>,
    pub estimated_duration_minutes: u32,
    pub resource_requirements: ResourceRequirements,
    pub dependencies: Vec<String>,
    pub rollback_plan: Option<RollbackPlan>,
}

/// Individual plan step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub step_id: Uuid,
    pub sequence: u32,
    pub description: String,
    pub capability: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub expected_duration_minutes: u32,
    pub success_criteria: Vec<String>,
    pub failure_recovery: Option<String>,
    pub parallel_group: Option<String>,
}

/// Resource requirements for plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub cpu_cores: f32,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_bandwidth_mbps: f32,
    pub external_services: Vec<String>,
}

/// Rollback plan for failure recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub steps: Vec<PlanStep>,
    pub trigger_conditions: Vec<String>,
    pub estimated_duration_minutes: u32,
}

/// Deep research result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchResult {
    pub research_id: Uuid,
    pub goal_analysis: GoalAnalysis,
    pub codebase_analysis: Option<CodebaseAnalysis>,
    pub pattern_analysis: PatternAnalysis,
    pub risk_findings: Vec<RiskFinding>,
    pub recommendations: Vec<String>,
    pub confidence: f32,
    pub research_duration_minutes: u32,
}

/// Goal analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalAnalysis {
    pub complexity_score: f32,
    pub feasibility_score: f32,
    pub clarity_score: f32,
    pub scope_estimate: ScopeEstimate,
    pub success_probability: f32,
}

/// Scope estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeEstimate {
    pub small: bool,
    pub medium: bool,
    pub large: bool,
    pub estimated_effort_hours: f32,
    pub confidence_interval: (f32, f32),
}

/// Codebase analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodebaseAnalysis {
    pub relevant_files: Vec<String>,
    pub architectural_patterns: Vec<String>,
    pub technology_stack: Vec<String>,
    pub complexity_metrics: ComplexityMetrics,
    pub test_coverage: Option<f32>,
}

/// Code complexity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityMetrics {
    pub cyclomatic_complexity: f32,
    pub cognitive_complexity: f32,
    pub technical_debt_ratio: f32,
    pub maintainability_index: f32,
}

/// Pattern analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternAnalysis {
    pub design_patterns: Vec<String>,
    pub antipatterns: Vec<String>,
    pub best_practices: Vec<String>,
    pub improvement_opportunities: Vec<String>,
}

/// Risk finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub risk_type: RiskType,
    pub severity: RiskSeverity,
    pub description: String,
    pub mitigation: String,
    pub probability: f32,
}

/// Risk types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskType {
    Security,
    Performance,
    Reliability,
    Maintainability,
    Compliance,
    Technical,
}

/// Risk severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Planning committee consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanningConsensus {
    pub consensus_id: Uuid,
    pub specialist_opinions: HashMap<SpecialistType, SpecialistOpinion>,
    pub overall_confidence: f32,
    pub consensus_reached: bool,
    pub conflicting_recommendations: Vec<String>,
    pub final_recommendation: String,
}

/// Individual specialist opinion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialistOpinion {
    pub specialist_type: SpecialistType,
    pub confidence: f32,
    pub recommendation: String,
    pub concerns: Vec<String>,
    pub approval: bool,
    pub suggested_modifications: Vec<String>,
}

/// Risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_risk_score: f32,
    pub risk_categories: HashMap<RiskType, f32>,
    pub mitigation_strategies: Vec<String>,
    pub acceptable_risk_level: bool,
}

/// Conversation context for AI interactions
#[derive(Debug, Clone)]
struct ConversationContext {
    messages: Vec<ConversationMessage>,
    context_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used: chrono::DateTime<chrono::Utc>,
}

/// Conversation message
#[derive(Debug, Clone)]
struct ConversationMessage {
    role: String,
    content: String,
    timestamp: chrono::DateTime<chrono::Utc>,
}

/// Result evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultEvaluation {
    pub success: bool,
    pub confidence: f32,
    pub summary: String,
    pub goal_achievement_score: f32,
    pub improvement_possible: bool,
    pub recommendations: Vec<String>,
}

impl Oracle {
    /// Create new oracle system
    pub async fn new(config: &AiConfig) -> Result<Self> {
        info!("Initializing Oracle system");

        let research_assistant = Arc::new(DeepResearchAssistant::new(config.clone()).await?);
        let planning_committee = Arc::new(PlanningCommittee::new(config.clone()).await?);
        let conversation_cache = Arc::new(RwLock::new(HashMap::new()));
        let decision_history = Arc::new(RwLock::new(Vec::new()));

        info!("Oracle system initialized successfully");

        Ok(Self {
            config: config.clone(),
            research_assistant,
            planning_committee,
            conversation_cache,
            decision_history,
        })
    }

    /// Plan execution for goal
    pub async fn plan_execution(&self, goal: &Goal) -> Result<OracleDecision> {
        info!(goal_id = %goal.id, "Starting execution planning for goal");

        let start_time = std::time::Instant::now();

        // Step 1: Conduct deep research
        let research_result = self.research_assistant.conduct_research(goal).await?;
        debug!(
            goal_id = %goal.id,
            confidence = research_result.confidence,
            "Research completed"
        );

        // Step 2: Generate initial plan based on research
        let initial_plan = self.generate_initial_plan(goal, &research_result).await?;

        // Step 3: Get planning committee consensus
        let consensus = self
            .planning_committee
            .build_consensus(&initial_plan, goal)
            .await?;
        debug!(
            goal_id = %goal.id,
            consensus_reached = consensus.consensus_reached,
            overall_confidence = consensus.overall_confidence,
            "Planning committee consensus completed"
        );

        // Step 4: Refine plan based on consensus
        let final_plan = self
            .refine_plan_with_consensus(&initial_plan, &consensus)
            .await?;

        // Step 5: Assess risks
        let risk_assessment = self
            .assess_plan_risks(&final_plan, &research_result)
            .await?;

        // Step 6: Calculate overall confidence
        let overall_confidence =
            self.calculate_decision_confidence(&research_result, &consensus, &risk_assessment);

        // Step 7: Generate alternative plans
        let alternative_plans = self
            .generate_alternative_plans(goal, &research_result, 2)
            .await?;

        // Create oracle decision
        let decision = OracleDecision {
            decision_id: Uuid::new_v4(),
            goal_id: goal.id,
            plan: final_plan,
            confidence: overall_confidence,
            reasoning: self
                .generate_decision_reasoning(&research_result, &consensus)
                .await?,
            research_findings: Some(research_result),
            committee_consensus: Some(consensus),
            alternative_plans,
            risk_assessment,
            created_at: chrono::Utc::now(),
        };

        // Store decision in history
        self.decision_history.write().await.push(decision.clone());

        let elapsed = start_time.elapsed();
        info!(
            goal_id = %goal.id,
            decision_id = %decision.decision_id,
            confidence = decision.confidence,
            planning_duration_ms = elapsed.as_millis(),
            "Execution planning completed"
        );

        Ok(decision)
    }

    /// Evaluate execution results
    pub async fn evaluate_results(
        &self,
        goal: &Goal,
        execution_results: &[ExecutionResult],
    ) -> Result<ResultEvaluation> {
        info!(goal_id = %goal.id, "Evaluating execution results");

        // Analyze results against success criteria
        let success_score = self
            .calculate_success_score(goal, execution_results)
            .await?;

        // Check if goal was achieved
        let goal_achieved = success_score >= 0.8; // 80% threshold

        // Determine if improvement is possible
        let improvement_possible = self
            .assess_improvement_potential(goal, execution_results)
            .await?;

        // Generate recommendations
        let recommendations = self
            .generate_improvement_recommendations(goal, execution_results)
            .await?;

        // Calculate confidence in evaluation
        let confidence = self.calculate_evaluation_confidence(execution_results);

        let evaluation = ResultEvaluation {
            success: goal_achieved,
            confidence,
            summary: self
                .generate_evaluation_summary(goal, execution_results, goal_achieved)
                .await?,
            goal_achievement_score: success_score,
            improvement_possible,
            recommendations,
        };

        info!(
            goal_id = %goal.id,
            success = goal_achieved,
            score = success_score,
            confidence = confidence,
            "Result evaluation completed"
        );

        Ok(evaluation)
    }

    /// Generate initial execution plan
    async fn generate_initial_plan(
        &self,
        goal: &Goal,
        research: &ResearchResult,
    ) -> Result<ExecutionPlan> {
        debug!(goal_id = %goal.id, "Generating initial execution plan");

        // For this implementation, we'll create a structured plan
        // In a real system, this would use AI to generate the plan
        let plan_steps = self.create_plan_steps(goal, research).await?;
        let resource_requirements = self.estimate_resources(&plan_steps).await?;
        let estimated_duration = plan_steps.iter().map(|s| s.expected_duration_minutes).sum();

        Ok(ExecutionPlan {
            plan_id: Uuid::new_v4(),
            summary: format!("Execution plan for: {}", goal.description),
            steps: plan_steps,
            estimated_duration_minutes: estimated_duration,
            resource_requirements,
            dependencies: research.recommendations.clone(),
            rollback_plan: self.create_rollback_plan().await?,
        })
    }

    /// Create plan steps based on goal and research
    async fn create_plan_steps(
        &self,
        goal: &Goal,
        research: &ResearchResult,
    ) -> Result<Vec<PlanStep>> {
        // This is a simplified implementation
        // In practice, this would use sophisticated AI planning
        let mut steps = Vec::new();

        // Determine candidate files to inspect
        let target_files: Vec<String> = goal
            .metadata
            .get("target_files")
            .map(|value| {
                value
                    .split(',')
                    .filter_map(|entry| {
                        let trimmed = entry.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.to_string())
                        }
                    })
                    .collect()
            })
            .filter(|list: &Vec<String>| !list.is_empty())
            .unwrap_or_else(|| vec!["README.md".to_string()]);

        let mut analysis_params = HashMap::new();
        analysis_params.insert("target_files".to_string(), serde_json::json!(target_files));

        // Analysis step executed by the new analysis runner
        steps.push(PlanStep {
            step_id: Uuid::new_v4(),
            sequence: 1,
            description: "Analyze current state and requirements".to_string(),
            capability: "analysis.system.v1".to_string(),
            parameters: analysis_params,
            expected_duration_minutes: 5,
            success_criteria: vec!["Analysis report generated".to_string()],
            failure_recovery: Some("Retry analysis with different approach".to_string()),
            parallel_group: None,
        });

        // Implementation step writes a structured plan document to disk
        let implementation_doc = format!(
            "# Execution Plan for {}\n\n## Recommended Actions\n{}\n\n## Research Highlights\nConfidence: {:.2}\nResearch Duration: {} minutes\n",
            goal.description,
            research
                .recommendations
                .iter()
                .map(|rec| format!("- {}", rec))
                .collect::<Vec<_>>()
                .join("\n"),
            research.confidence,
            research.research_duration_minutes
        );

        let mut implementation_params = HashMap::new();
        implementation_params.insert(
            "operations".to_string(),
            serde_json::json!([
                {
                    "path": format!(
                        "{}/{}_plan.md",
                        PLAN_OUTPUT_DIR,
                        goal.id
                    ),
                    "content": implementation_doc,
                    "mode": "overwrite"
                }
            ]),
        );
        implementation_params.insert(
            "instructions".to_string(),
            serde_json::json!(format!(
                "Apply the recommended solution for '{}', ensuring artifacts and documentation are up to date.",
                goal.description
            )),
        );

        steps.push(PlanStep {
            step_id: Uuid::new_v4(),
            sequence: 2,
            description: "Execute implementation plan".to_string(),
            capability: "implementation.execute.v1".to_string(),
            parameters: implementation_params,
            expected_duration_minutes: 15,
            success_criteria: vec!["Plan artifacts produced".to_string()],
            failure_recovery: Some(
                "Review implementation output and retry with adjustments".to_string(),
            ),
            parallel_group: None,
        });

        let mut validation_params = HashMap::new();
        validation_params.insert(
            "command".to_string(),
            serde_json::json!(["cargo", "check", "--workspace"]),
        );
        validation_params.insert("working_dir".to_string(), serde_json::json!("."));
        validation_params.insert("timeout_ms".to_string(), serde_json::json!(180_000));

        steps.push(PlanStep {
            step_id: Uuid::new_v4(),
            sequence: 3,
            description: "Validate implementation through automated checks".to_string(),
            capability: "validation.test.v1".to_string(),
            parameters: validation_params,
            expected_duration_minutes: 5,
            success_criteria: vec!["Validation command exits successfully".to_string()],
            failure_recovery: Some("Address failures and rerun validation".to_string()),
            parallel_group: None,
        });

        Ok(steps)
    }

    /// Estimate resource requirements
    async fn estimate_resources(&self, steps: &[PlanStep]) -> Result<ResourceRequirements> {
        // Simple resource estimation based on step complexity
        let total_duration: u32 = steps.iter().map(|s| s.expected_duration_minutes).sum();

        Ok(ResourceRequirements {
            cpu_cores: (total_duration as f32 / 30.0).max(1.0), // 1 core per 30 minutes
            memory_mb: 512 + (total_duration as u64 * 10),      // Base + duration factor
            disk_mb: 1024,                                      // Standard disk allocation
            network_bandwidth_mbps: 10.0,                       // Standard bandwidth
            external_services: vec!["smith-executor".to_string()],
        })
    }

    /// Create rollback plan
    async fn create_rollback_plan(&self) -> Result<Option<RollbackPlan>> {
        Ok(Some(RollbackPlan {
            steps: vec![PlanStep {
                step_id: Uuid::new_v4(),
                sequence: 1,
                description: "Restore previous state".to_string(),
                capability: "rollback.restore.v1".to_string(),
                parameters: HashMap::new(),
                expected_duration_minutes: 5,
                success_criteria: vec!["State restored".to_string()],
                failure_recovery: None,
                parallel_group: None,
            }],
            trigger_conditions: vec![
                "Implementation failure".to_string(),
                "Validation failure".to_string(),
                "Critical error detected".to_string(),
            ],
            estimated_duration_minutes: 5,
        }))
    }

    /// Refine plan based on committee consensus
    async fn refine_plan_with_consensus(
        &self,
        plan: &ExecutionPlan,
        consensus: &PlanningConsensus,
    ) -> Result<ExecutionPlan> {
        let mut refined_plan = plan.clone();

        // Apply consensus modifications
        for opinion in consensus.specialist_opinions.values() {
            for modification in &opinion.suggested_modifications {
                debug!(modification = %modification, "Applying consensus modification");
                // In practice, this would parse and apply specific modifications
                // For now, we'll add them as metadata
            }
        }

        // Adjust confidence-based parameters
        if consensus.overall_confidence < 0.5 {
            // Add extra validation steps for low confidence plans
            refined_plan.steps.push(PlanStep {
                step_id: Uuid::new_v4(),
                sequence: refined_plan.steps.len() as u32 + 1,
                description: "Additional validation due to low confidence".to_string(),
                capability: "validation.extended.v1".to_string(),
                parameters: HashMap::new(),
                expected_duration_minutes: 10,
                success_criteria: vec!["Extended validation passed".to_string()],
                failure_recovery: Some("Escalate to manual review".to_string()),
                parallel_group: None,
            });
        }

        Ok(refined_plan)
    }

    /// Assess plan risks
    async fn assess_plan_risks(
        &self,
        plan: &ExecutionPlan,
        research: &ResearchResult,
    ) -> Result<RiskAssessment> {
        let mut risk_categories = HashMap::new();

        // Calculate risk scores based on plan complexity and research findings
        let complexity_risk = research.goal_analysis.complexity_score * 0.6;
        let feasibility_risk = (1.0 - research.goal_analysis.feasibility_score) * 0.8;

        risk_categories.insert(RiskType::Technical, complexity_risk);
        risk_categories.insert(RiskType::Reliability, feasibility_risk);

        // Add risks from research findings
        for finding in &research.risk_findings {
            let current = risk_categories.get(&finding.risk_type).unwrap_or(&0.0);
            risk_categories.insert(
                finding.risk_type.clone(),
                (*current + finding.probability * 0.5).min(1.0),
            );
        }

        let overall_risk = risk_categories.values().sum::<f32>() / risk_categories.len() as f32;

        Ok(RiskAssessment {
            overall_risk_score: overall_risk,
            risk_categories,
            mitigation_strategies: vec![
                "Implement rollback procedures".to_string(),
                "Add monitoring and alerting".to_string(),
                "Use incremental deployment".to_string(),
            ],
            acceptable_risk_level: overall_risk < 0.7,
        })
    }

    /// Calculate decision confidence
    fn calculate_decision_confidence(
        &self,
        research: &ResearchResult,
        consensus: &PlanningConsensus,
        risk_assessment: &RiskAssessment,
    ) -> f32 {
        let research_weight = 0.4;
        let consensus_weight = 0.4;
        let risk_weight = 0.2;

        let risk_confidence = 1.0 - risk_assessment.overall_risk_score;

        (research.confidence * research_weight
            + consensus.overall_confidence * consensus_weight
            + risk_confidence * risk_weight)
            .min(1.0)
            .max(0.0)
    }

    /// Generate decision reasoning
    async fn generate_decision_reasoning(
        &self,
        research: &ResearchResult,
        consensus: &PlanningConsensus,
    ) -> Result<String> {
        let mut reasoning = String::new();

        reasoning.push_str(&format!(
            "Decision based on research (confidence: {:.2}) and committee consensus (confidence: {:.2}). ",
            research.confidence, consensus.overall_confidence
        ));

        if consensus.consensus_reached {
            reasoning.push_str("Planning committee reached consensus. ");
        } else {
            reasoning.push_str("Planning committee had conflicting views. ");
        }

        reasoning.push_str(&format!(
            "Goal feasibility score: {:.2}, complexity score: {:.2}.",
            research.goal_analysis.feasibility_score, research.goal_analysis.complexity_score
        ));

        Ok(reasoning)
    }

    /// Generate alternative plans
    async fn generate_alternative_plans(
        &self,
        goal: &Goal,
        research: &ResearchResult,
        count: usize,
    ) -> Result<Vec<ExecutionPlan>> {
        let mut alternatives = Vec::new();

        for i in 0..count {
            // Create simplified alternative
            let alternative = ExecutionPlan {
                plan_id: Uuid::new_v4(),
                summary: format!("Alternative plan {} for: {}", i + 1, goal.description),
                steps: vec![PlanStep {
                    step_id: Uuid::new_v4(),
                    sequence: 1,
                    description: format!("Alternative approach {}", i + 1),
                    capability: "alternative.execute.v1".to_string(),
                    parameters: HashMap::new(),
                    expected_duration_minutes: 20,
                    success_criteria: goal.success_criteria.clone(),
                    failure_recovery: None,
                    parallel_group: None,
                }],
                estimated_duration_minutes: 20,
                resource_requirements: ResourceRequirements {
                    cpu_cores: 1.0,
                    memory_mb: 256,
                    disk_mb: 512,
                    network_bandwidth_mbps: 5.0,
                    external_services: vec![],
                },
                dependencies: vec![],
                rollback_plan: None,
            };
            alternatives.push(alternative);
        }

        Ok(alternatives)
    }

    /// Calculate success score
    async fn calculate_success_score(
        &self,
        goal: &Goal,
        results: &[ExecutionResult],
    ) -> Result<f32> {
        if results.is_empty() {
            return Ok(0.0);
        }

        let success_count = results.iter().filter(|r| r.success).count();
        let total_count = results.len();

        Ok(success_count as f32 / total_count as f32)
    }

    /// Assess improvement potential
    async fn assess_improvement_potential(
        &self,
        _goal: &Goal,
        results: &[ExecutionResult],
    ) -> Result<bool> {
        // Check if there are any failed results that could be retried
        Ok(results.iter().any(|r| !r.success && r.retryable))
    }

    /// Generate improvement recommendations
    async fn generate_improvement_recommendations(
        &self,
        _goal: &Goal,
        results: &[ExecutionResult],
    ) -> Result<Vec<String>> {
        let mut recommendations = Vec::new();

        // Analyze failed results
        for result in results.iter().filter(|r| !r.success) {
            recommendations.push(format!("Address failure: {}", result.error_message));
        }

        // General recommendations
        if results.iter().any(|r| r.execution_time_ms > 60000) {
            recommendations
                .push("Consider optimizing performance for long-running operations".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("No specific improvements identified".to_string());
        }

        Ok(recommendations)
    }

    /// Calculate evaluation confidence
    fn calculate_evaluation_confidence(&self, results: &[ExecutionResult]) -> f32 {
        if results.is_empty() {
            return 0.0;
        }

        // Confidence based on result completeness and clarity
        let complete_results = results.iter().filter(|r| !r.output.is_empty()).count();
        complete_results as f32 / results.len() as f32
    }

    /// Generate evaluation summary
    async fn generate_evaluation_summary(
        &self,
        goal: &Goal,
        results: &[ExecutionResult],
        success: bool,
    ) -> Result<String> {
        let total_results = results.len();
        let successful_results = results.iter().filter(|r| r.success).count();

        if success {
            Ok(format!(
                "Goal '{}' achieved successfully. {} of {} operations completed successfully.",
                goal.description, successful_results, total_results
            ))
        } else {
            Ok(format!(
                "Goal '{}' not fully achieved. {} of {} operations completed successfully. Review failed operations for improvement opportunities.",
                goal.description, successful_results, total_results
            ))
        }
    }

    /// Get decision history
    pub async fn get_decision_history(&self) -> Vec<OracleDecision> {
        self.decision_history.read().await.clone()
    }

    /// Export oracle metrics
    pub async fn export_metrics(&self) -> OracleMetrics {
        let history = self.decision_history.read().await;

        let total_decisions = history.len();
        let high_confidence = history.iter().filter(|d| d.confidence > 0.8).count();
        let medium_confidence = history
            .iter()
            .filter(|d| d.confidence > 0.5 && d.confidence <= 0.8)
            .count();
        let low_confidence = history.iter().filter(|d| d.confidence <= 0.5).count();

        let avg_confidence = if total_decisions > 0 {
            history.iter().map(|d| d.confidence).sum::<f32>() / total_decisions as f32
        } else {
            0.0
        };

        OracleMetrics {
            total_decisions,
            high_confidence_decisions: high_confidence,
            medium_confidence_decisions: medium_confidence,
            low_confidence_decisions: low_confidence,
            average_confidence: avg_confidence,
            research_cache_size: self.research_assistant.get_cache_size().await,
        }
    }
}

/// Oracle metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleMetrics {
    pub total_decisions: usize,
    pub high_confidence_decisions: usize,
    pub medium_confidence_decisions: usize,
    pub low_confidence_decisions: usize,
    pub average_confidence: f32,
    pub research_cache_size: usize,
}

impl DeepResearchAssistant {
    /// Create new research assistant
    pub async fn new(config: AiConfig) -> Result<Self> {
        Ok(Self {
            config,
            research_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Conduct research for goal
    pub async fn conduct_research(&self, goal: &Goal) -> Result<ResearchResult> {
        info!(goal_id = %goal.id, "Conducting deep research");

        let start_time = std::time::Instant::now();

        // Analyze goal
        let goal_analysis = self.analyze_goal(goal).await?;

        // Analyze codebase (if applicable)
        let codebase_analysis = self.analyze_codebase(goal).await?;

        // Detect patterns
        let pattern_analysis = self.analyze_patterns(goal).await?;

        // Assess risks
        let risk_findings = self.assess_risks(goal, &goal_analysis).await?;

        // Generate recommendations
        let recommendations = self.generate_recommendations(goal, &goal_analysis).await?;

        // Calculate confidence
        let confidence = self.calculate_research_confidence(&goal_analysis, &risk_findings);

        let duration = start_time.elapsed();

        let result = ResearchResult {
            research_id: Uuid::new_v4(),
            goal_analysis,
            codebase_analysis,
            pattern_analysis,
            risk_findings,
            recommendations,
            confidence,
            research_duration_minutes: duration.as_secs() as u32 / 60,
        };

        // Cache result
        let cache_key = format!("goal_{}", goal.id);
        self.research_cache
            .write()
            .await
            .insert(cache_key, result.clone());

        info!(
            goal_id = %goal.id,
            confidence = confidence,
            duration_ms = duration.as_millis(),
            "Research completed"
        );

        Ok(result)
    }

    /// Analyze goal complexity and feasibility
    async fn analyze_goal(&self, goal: &Goal) -> Result<GoalAnalysis> {
        // Simplified goal analysis
        let description_length = goal.description.len();
        let constraint_count = goal.constraints.len();
        let success_criteria_count = goal.success_criteria.len();

        let complexity_score =
            ((description_length as f32 / 100.0) + (constraint_count as f32 * 0.2)).min(1.0);

        let clarity_score = if success_criteria_count > 0 { 0.8 } else { 0.4 };
        let feasibility_score = 1.0 - (complexity_score * 0.5);

        Ok(GoalAnalysis {
            complexity_score,
            feasibility_score,
            clarity_score,
            scope_estimate: ScopeEstimate {
                small: complexity_score < 0.3,
                medium: complexity_score >= 0.3 && complexity_score < 0.7,
                large: complexity_score >= 0.7,
                estimated_effort_hours: complexity_score * 8.0, // Max 8 hours
                confidence_interval: (complexity_score * 0.8, complexity_score * 1.2),
            },
            success_probability: feasibility_score * clarity_score,
        })
    }

    /// Analyze codebase (simplified implementation)
    async fn analyze_codebase(&self, _goal: &Goal) -> Result<Option<CodebaseAnalysis>> {
        // In a real implementation, this would analyze actual codebase
        Ok(Some(CodebaseAnalysis {
            relevant_files: vec!["src/main.rs".to_string(), "src/lib.rs".to_string()],
            architectural_patterns: vec!["MVC".to_string(), "Repository".to_string()],
            technology_stack: vec!["Rust".to_string(), "Tokio".to_string()],
            complexity_metrics: ComplexityMetrics {
                cyclomatic_complexity: 5.2,
                cognitive_complexity: 8.1,
                technical_debt_ratio: 0.15,
                maintainability_index: 75.0,
            },
            test_coverage: Some(85.0),
        }))
    }

    /// Analyze patterns
    async fn analyze_patterns(&self, _goal: &Goal) -> Result<PatternAnalysis> {
        Ok(PatternAnalysis {
            design_patterns: vec!["Factory".to_string(), "Observer".to_string()],
            antipatterns: vec!["God Object".to_string()],
            best_practices: vec!["Error handling".to_string(), "Documentation".to_string()],
            improvement_opportunities: vec!["Performance optimization".to_string()],
        })
    }

    /// Assess risks
    async fn assess_risks(
        &self,
        _goal: &Goal,
        analysis: &GoalAnalysis,
    ) -> Result<Vec<RiskFinding>> {
        let mut risks = Vec::new();

        if analysis.complexity_score > 0.7 {
            risks.push(RiskFinding {
                risk_type: RiskType::Technical,
                severity: RiskSeverity::High,
                description: "High complexity goal may lead to implementation challenges"
                    .to_string(),
                mitigation: "Break down into smaller tasks".to_string(),
                probability: analysis.complexity_score,
            });
        }

        if analysis.feasibility_score < 0.5 {
            risks.push(RiskFinding {
                risk_type: RiskType::Reliability,
                severity: RiskSeverity::Medium,
                description: "Low feasibility may lead to incomplete implementation".to_string(),
                mitigation: "Conduct additional research and planning".to_string(),
                probability: 1.0 - analysis.feasibility_score,
            });
        }

        Ok(risks)
    }

    /// Generate recommendations
    async fn generate_recommendations(
        &self,
        _goal: &Goal,
        analysis: &GoalAnalysis,
    ) -> Result<Vec<String>> {
        let mut recommendations = Vec::new();

        if analysis.complexity_score > 0.5 {
            recommendations
                .push("Consider breaking down the goal into smaller, manageable tasks".to_string());
        }

        if analysis.clarity_score < 0.6 {
            recommendations.push("Define clearer success criteria".to_string());
        }

        recommendations.push("Implement comprehensive testing".to_string());
        recommendations.push("Add monitoring and observability".to_string());

        Ok(recommendations)
    }

    /// Calculate research confidence
    fn calculate_research_confidence(&self, analysis: &GoalAnalysis, risks: &[RiskFinding]) -> f32 {
        let clarity_weight = 0.4;
        let feasibility_weight = 0.4;
        let risk_weight = 0.2;

        let risk_factor = if risks.is_empty() {
            1.0
        } else {
            1.0 - (risks.iter().map(|r| r.probability).sum::<f32>() / risks.len() as f32)
        };

        (analysis.clarity_score * clarity_weight
            + analysis.feasibility_score * feasibility_weight
            + risk_factor * risk_weight)
            .min(1.0)
            .max(0.0)
    }

    /// Get cache size
    pub async fn get_cache_size(&self) -> usize {
        self.research_cache.read().await.len()
    }
}

impl PlanningCommittee {
    /// Create new planning committee
    pub async fn new(config: AiConfig) -> Result<Self> {
        let specialists = vec![
            SpecialistAgent {
                agent_type: SpecialistType::Architecture,
                expertise_areas: vec!["System design".to_string(), "Scalability".to_string()],
                conversation_context: None,
            },
            SpecialistAgent {
                agent_type: SpecialistType::Security,
                expertise_areas: vec!["Security analysis".to_string(), "Compliance".to_string()],
                conversation_context: None,
            },
            SpecialistAgent {
                agent_type: SpecialistType::Performance,
                expertise_areas: vec!["Optimization".to_string(), "Benchmarking".to_string()],
                conversation_context: None,
            },
            SpecialistAgent {
                agent_type: SpecialistType::QualityAssurance,
                expertise_areas: vec!["Testing".to_string(), "Quality metrics".to_string()],
                conversation_context: None,
            },
        ];

        Ok(Self {
            config,
            specialists,
            consensus_threshold: 0.7,
        })
    }

    /// Build consensus on execution plan
    pub async fn build_consensus(
        &self,
        plan: &ExecutionPlan,
        goal: &Goal,
    ) -> Result<PlanningConsensus> {
        info!(plan_id = %plan.plan_id, "Building planning committee consensus");

        let mut specialist_opinions = HashMap::new();

        // Get opinion from each specialist
        for specialist in &self.specialists {
            let opinion = self.get_specialist_opinion(specialist, plan, goal).await?;
            specialist_opinions.insert(specialist.agent_type.clone(), opinion);
        }

        // Calculate overall confidence
        let total_confidence: f32 = specialist_opinions.values().map(|o| o.confidence).sum();
        let overall_confidence = total_confidence / specialist_opinions.len() as f32;

        // Check if consensus reached
        let approval_count = specialist_opinions.values().filter(|o| o.approval).count();
        let consensus_reached =
            approval_count as f32 / specialist_opinions.len() as f32 >= self.consensus_threshold;

        // Collect conflicting recommendations
        let mut conflicting_recommendations = Vec::new();
        if !consensus_reached {
            for opinion in specialist_opinions.values() {
                if !opinion.approval {
                    conflicting_recommendations.extend(opinion.concerns.clone());
                }
            }
        }

        // Generate final recommendation
        let final_recommendation = if consensus_reached {
            "Plan approved by committee consensus".to_string()
        } else {
            "Plan requires modifications based on specialist concerns".to_string()
        };

        Ok(PlanningConsensus {
            consensus_id: Uuid::new_v4(),
            specialist_opinions,
            overall_confidence,
            consensus_reached,
            conflicting_recommendations,
            final_recommendation,
        })
    }

    /// Get specialist opinion on plan
    async fn get_specialist_opinion(
        &self,
        specialist: &SpecialistAgent,
        plan: &ExecutionPlan,
        _goal: &Goal,
    ) -> Result<SpecialistOpinion> {
        // Simplified specialist analysis
        let base_confidence = 0.8;
        let mut concerns = Vec::new();
        let mut suggested_modifications = Vec::new();

        match specialist.agent_type {
            SpecialistType::Architecture => {
                if plan.steps.len() > 5 {
                    concerns.push("Plan has many steps, consider consolidation".to_string());
                    suggested_modifications.push("Combine related steps".to_string());
                }
            }
            SpecialistType::Security => {
                if plan.resource_requirements.external_services.is_empty() {
                    // Good - no external dependencies
                } else {
                    concerns
                        .push("External service dependencies increase security risk".to_string());
                }
            }
            SpecialistType::Performance => {
                if plan.estimated_duration_minutes > 60 {
                    concerns.push("Long execution time may impact performance".to_string());
                    suggested_modifications
                        .push("Parallelize operations where possible".to_string());
                }
            }
            SpecialistType::QualityAssurance => {
                let has_validation = plan
                    .steps
                    .iter()
                    .any(|s| s.capability.contains("validation"));
                if !has_validation {
                    concerns.push("Plan lacks validation steps".to_string());
                    suggested_modifications.push("Add validation and testing steps".to_string());
                }
            }
        }

        let confidence = if concerns.is_empty() {
            base_confidence
        } else {
            base_confidence * 0.7
        };
        let approval = concerns.is_empty();

        Ok(SpecialistOpinion {
            specialist_type: specialist.agent_type.clone(),
            confidence,
            recommendation: if approval {
                "Approved".to_string()
            } else {
                "Requires modifications".to_string()
            },
            concerns,
            approval,
            suggested_modifications,
        })
    }
}

// Implement serialization for SpecialistType
impl Serialize for SpecialistType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SpecialistType::Architecture => serializer.serialize_str("Architecture"),
            SpecialistType::Security => serializer.serialize_str("Security"),
            SpecialistType::Performance => serializer.serialize_str("Performance"),
            SpecialistType::QualityAssurance => serializer.serialize_str("QualityAssurance"),
        }
    }
}

impl<'de> Deserialize<'de> for SpecialistType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "Architecture" => Ok(SpecialistType::Architecture),
            "Security" => Ok(SpecialistType::Security),
            "Performance" => Ok(SpecialistType::Performance),
            "QualityAssurance" => Ok(SpecialistType::QualityAssurance),
            _ => Err(serde::de::Error::custom("Invalid specialist type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::AiConfig;

    fn create_test_config() -> AiConfig {
        AiConfig {
            provider: "mock".to_string(),
            model: "test".to_string(),
            max_tokens: 1000,
            temperature: 0.1,
            timeout_seconds: 30,
            retry_attempts: 1,
            rate_limit_per_minute: 10,
        }
    }

    #[tokio::test]
    async fn test_oracle_creation() {
        let config = create_test_config();
        let oracle = Oracle::new(&config).await;
        assert!(oracle.is_ok());
    }

    #[tokio::test]
    async fn test_research_assistant() {
        let config = create_test_config();
        let assistant = DeepResearchAssistant::new(config).await.unwrap();
        let goal = Goal::new("Test goal");
        let result = assistant.conduct_research(&goal).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_planning_committee() {
        let config = create_test_config();
        let committee = PlanningCommittee::new(config).await.unwrap();
        assert_eq!(committee.specialists.len(), 4);
    }

    // Specialist type serialization tests
    #[test]
    fn test_specialist_type_serialization() {
        let types = vec![
            SpecialistType::Architecture,
            SpecialistType::Security,
            SpecialistType::Performance,
            SpecialistType::QualityAssurance,
        ];

        for specialist_type in types {
            let json = serde_json::to_string(&specialist_type).unwrap();
            let parsed: SpecialistType = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_specialist_type_invalid_deserialization() {
        let result: Result<SpecialistType, _> = serde_json::from_str("\"InvalidType\"");
        assert!(result.is_err());
    }

    // RiskType serialization tests
    #[test]
    fn test_risk_type_serialization() {
        let types = vec![
            RiskType::Security,
            RiskType::Performance,
            RiskType::Reliability,
            RiskType::Maintainability,
            RiskType::Compliance,
            RiskType::Technical,
        ];

        for risk_type in types {
            let json = serde_json::to_string(&risk_type).unwrap();
            let parsed: RiskType = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // RiskSeverity serialization tests
    #[test]
    fn test_risk_severity_serialization() {
        let severities = vec![
            RiskSeverity::Low,
            RiskSeverity::Medium,
            RiskSeverity::High,
            RiskSeverity::Critical,
        ];

        for severity in severities {
            let json = serde_json::to_string(&severity).unwrap();
            let parsed: RiskSeverity = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    // ExecutionPlan serialization test
    #[test]
    fn test_execution_plan_serialization() {
        let plan = ExecutionPlan {
            plan_id: Uuid::new_v4(),
            summary: "Test plan".to_string(),
            steps: vec![],
            estimated_duration_minutes: 30,
            resource_requirements: ResourceRequirements {
                cpu_cores: 2.0,
                memory_mb: 1024,
                disk_mb: 2048,
                network_bandwidth_mbps: 10.0,
                external_services: vec!["api".to_string()],
            },
            dependencies: vec!["dep1".to_string()],
            rollback_plan: None,
        };

        let json = serde_json::to_string(&plan).unwrap();
        let parsed: ExecutionPlan = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.summary, "Test plan");
        assert_eq!(parsed.estimated_duration_minutes, 30);
    }

    // PlanStep serialization test
    #[test]
    fn test_plan_step_serialization() {
        let step = PlanStep {
            step_id: Uuid::new_v4(),
            sequence: 1,
            description: "Test step".to_string(),
            capability: "test.cap.v1".to_string(),
            parameters: HashMap::from([("key".to_string(), serde_json::json!("value"))]),
            expected_duration_minutes: 5,
            success_criteria: vec!["criterion".to_string()],
            failure_recovery: Some("retry".to_string()),
            parallel_group: Some("group1".to_string()),
        };

        let json = serde_json::to_string(&step).unwrap();
        let parsed: PlanStep = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.description, "Test step");
        assert_eq!(parsed.sequence, 1);
        assert_eq!(parsed.parallel_group, Some("group1".to_string()));
    }

    // ResourceRequirements serialization test
    #[test]
    fn test_resource_requirements_serialization() {
        let requirements = ResourceRequirements {
            cpu_cores: 4.0,
            memory_mb: 8192,
            disk_mb: 10240,
            network_bandwidth_mbps: 100.0,
            external_services: vec!["db".to_string(), "cache".to_string()],
        };

        let json = serde_json::to_string(&requirements).unwrap();
        let parsed: ResourceRequirements = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.cpu_cores, 4.0);
        assert_eq!(parsed.memory_mb, 8192);
        assert_eq!(parsed.external_services.len(), 2);
    }

    // RollbackPlan serialization test
    #[test]
    fn test_rollback_plan_serialization() {
        let plan = RollbackPlan {
            steps: vec![PlanStep {
                step_id: Uuid::new_v4(),
                sequence: 1,
                description: "Rollback step".to_string(),
                capability: "rollback.v1".to_string(),
                parameters: HashMap::new(),
                expected_duration_minutes: 2,
                success_criteria: vec!["restored".to_string()],
                failure_recovery: None,
                parallel_group: None,
            }],
            trigger_conditions: vec!["failure".to_string()],
            estimated_duration_minutes: 5,
        };

        let json = serde_json::to_string(&plan).unwrap();
        let parsed: RollbackPlan = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.steps.len(), 1);
        assert_eq!(parsed.estimated_duration_minutes, 5);
    }

    // ResearchResult serialization test
    #[test]
    fn test_research_result_serialization() {
        let result = ResearchResult {
            research_id: Uuid::new_v4(),
            goal_analysis: GoalAnalysis {
                complexity_score: 0.5,
                feasibility_score: 0.8,
                clarity_score: 0.9,
                scope_estimate: ScopeEstimate {
                    small: false,
                    medium: true,
                    large: false,
                    estimated_effort_hours: 4.0,
                    confidence_interval: (3.0, 5.0),
                },
                success_probability: 0.72,
            },
            codebase_analysis: None,
            pattern_analysis: PatternAnalysis {
                design_patterns: vec![],
                antipatterns: vec![],
                best_practices: vec![],
                improvement_opportunities: vec![],
            },
            risk_findings: vec![],
            recommendations: vec!["recommendation".to_string()],
            confidence: 0.85,
            research_duration_minutes: 5,
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: ResearchResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.confidence, 0.85);
        assert_eq!(parsed.research_duration_minutes, 5);
    }

    // GoalAnalysis serialization test
    #[test]
    fn test_goal_analysis_serialization() {
        let analysis = GoalAnalysis {
            complexity_score: 0.3,
            feasibility_score: 0.9,
            clarity_score: 0.85,
            scope_estimate: ScopeEstimate {
                small: true,
                medium: false,
                large: false,
                estimated_effort_hours: 2.0,
                confidence_interval: (1.5, 2.5),
            },
            success_probability: 0.765,
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let parsed: GoalAnalysis = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.complexity_score, 0.3);
        assert_eq!(parsed.scope_estimate.small, true);
    }

    // CodebaseAnalysis serialization test
    #[test]
    fn test_codebase_analysis_serialization() {
        let analysis = CodebaseAnalysis {
            relevant_files: vec!["main.rs".to_string(), "lib.rs".to_string()],
            architectural_patterns: vec!["MVC".to_string()],
            technology_stack: vec!["Rust".to_string()],
            complexity_metrics: ComplexityMetrics {
                cyclomatic_complexity: 5.0,
                cognitive_complexity: 8.0,
                technical_debt_ratio: 0.1,
                maintainability_index: 80.0,
            },
            test_coverage: Some(90.0),
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let parsed: CodebaseAnalysis = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.relevant_files.len(), 2);
        assert_eq!(parsed.test_coverage, Some(90.0));
    }

    // ComplexityMetrics serialization test
    #[test]
    fn test_complexity_metrics_serialization() {
        let metrics = ComplexityMetrics {
            cyclomatic_complexity: 10.5,
            cognitive_complexity: 15.2,
            technical_debt_ratio: 0.25,
            maintainability_index: 65.0,
        };

        let json = serde_json::to_string(&metrics).unwrap();
        let parsed: ComplexityMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.cyclomatic_complexity, 10.5);
        assert_eq!(parsed.maintainability_index, 65.0);
    }

    // PatternAnalysis serialization test
    #[test]
    fn test_pattern_analysis_serialization() {
        let analysis = PatternAnalysis {
            design_patterns: vec!["Singleton".to_string(), "Factory".to_string()],
            antipatterns: vec!["God Object".to_string()],
            best_practices: vec!["Documentation".to_string()],
            improvement_opportunities: vec!["Refactoring".to_string()],
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let parsed: PatternAnalysis = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.design_patterns.len(), 2);
        assert_eq!(parsed.antipatterns.len(), 1);
    }

    // RiskFinding serialization test
    #[test]
    fn test_risk_finding_serialization() {
        let finding = RiskFinding {
            risk_type: RiskType::Security,
            severity: RiskSeverity::High,
            description: "Security vulnerability".to_string(),
            mitigation: "Apply patch".to_string(),
            probability: 0.7,
        };

        let json = serde_json::to_string(&finding).unwrap();
        let parsed: RiskFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.description, "Security vulnerability");
        assert_eq!(parsed.probability, 0.7);
    }

    // PlanningConsensus serialization test
    #[test]
    fn test_planning_consensus_serialization() {
        let consensus = PlanningConsensus {
            consensus_id: Uuid::new_v4(),
            specialist_opinions: HashMap::new(),
            overall_confidence: 0.8,
            consensus_reached: true,
            conflicting_recommendations: vec![],
            final_recommendation: "Approved".to_string(),
        };

        let json = serde_json::to_string(&consensus).unwrap();
        let parsed: PlanningConsensus = serde_json::from_str(&json).unwrap();

        assert!(parsed.consensus_reached);
        assert_eq!(parsed.overall_confidence, 0.8);
    }

    // SpecialistOpinion serialization test
    #[test]
    fn test_specialist_opinion_serialization() {
        let opinion = SpecialistOpinion {
            specialist_type: SpecialistType::Architecture,
            confidence: 0.85,
            recommendation: "Approved".to_string(),
            concerns: vec!["Minor concern".to_string()],
            approval: true,
            suggested_modifications: vec![],
        };

        let json = serde_json::to_string(&opinion).unwrap();
        let parsed: SpecialistOpinion = serde_json::from_str(&json).unwrap();

        assert!(parsed.approval);
        assert_eq!(parsed.concerns.len(), 1);
    }

    // RiskAssessment serialization test
    #[test]
    fn test_risk_assessment_serialization() {
        let assessment = RiskAssessment {
            overall_risk_score: 0.3,
            risk_categories: HashMap::from([
                (RiskType::Security, 0.2),
                (RiskType::Performance, 0.4),
            ]),
            mitigation_strategies: vec!["Strategy 1".to_string()],
            acceptable_risk_level: true,
        };

        let json = serde_json::to_string(&assessment).unwrap();
        let parsed: RiskAssessment = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.overall_risk_score, 0.3);
        assert!(parsed.acceptable_risk_level);
    }

    // OracleDecision serialization test
    #[test]
    fn test_oracle_decision_serialization() {
        let decision = OracleDecision {
            decision_id: Uuid::new_v4(),
            goal_id: Uuid::new_v4(),
            plan: ExecutionPlan {
                plan_id: Uuid::new_v4(),
                summary: "Test".to_string(),
                steps: vec![],
                estimated_duration_minutes: 10,
                resource_requirements: ResourceRequirements {
                    cpu_cores: 1.0,
                    memory_mb: 256,
                    disk_mb: 512,
                    network_bandwidth_mbps: 5.0,
                    external_services: vec![],
                },
                dependencies: vec![],
                rollback_plan: None,
            },
            confidence: 0.9,
            reasoning: "Test reasoning".to_string(),
            research_findings: None,
            committee_consensus: None,
            alternative_plans: vec![],
            risk_assessment: RiskAssessment {
                overall_risk_score: 0.1,
                risk_categories: HashMap::new(),
                mitigation_strategies: vec![],
                acceptable_risk_level: true,
            },
            created_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&decision).unwrap();
        let parsed: OracleDecision = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.confidence, 0.9);
        assert_eq!(parsed.reasoning, "Test reasoning");
    }

    // OracleMetrics serialization test
    #[test]
    fn test_oracle_metrics_serialization() {
        let metrics = OracleMetrics {
            total_decisions: 100,
            high_confidence_decisions: 60,
            medium_confidence_decisions: 30,
            low_confidence_decisions: 10,
            average_confidence: 0.75,
            research_cache_size: 50,
        };

        let json = serde_json::to_string(&metrics).unwrap();
        let parsed: OracleMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total_decisions, 100);
        assert_eq!(parsed.average_confidence, 0.75);
    }

    // ResultEvaluation serialization test
    #[test]
    fn test_result_evaluation_serialization() {
        let evaluation = ResultEvaluation {
            success: true,
            confidence: 0.95,
            summary: "Goal achieved".to_string(),
            goal_achievement_score: 0.9,
            improvement_possible: false,
            recommendations: vec!["Continue monitoring".to_string()],
        };

        let json = serde_json::to_string(&evaluation).unwrap();
        let parsed: ResultEvaluation = serde_json::from_str(&json).unwrap();

        assert!(parsed.success);
        assert_eq!(parsed.goal_achievement_score, 0.9);
    }

    // ScopeEstimate serialization test
    #[test]
    fn test_scope_estimate_serialization() {
        let estimate = ScopeEstimate {
            small: false,
            medium: true,
            large: false,
            estimated_effort_hours: 16.0,
            confidence_interval: (12.0, 20.0),
        };

        let json = serde_json::to_string(&estimate).unwrap();
        let parsed: ScopeEstimate = serde_json::from_str(&json).unwrap();

        assert!(parsed.medium);
        assert_eq!(parsed.estimated_effort_hours, 16.0);
    }

    // Clone tests
    #[test]
    fn test_specialist_type_clone() {
        let st = SpecialistType::Security;
        let cloned = st.clone();
        assert_eq!(st, cloned);
    }

    #[test]
    fn test_risk_type_clone() {
        let rt = RiskType::Compliance;
        let cloned = rt.clone();
        assert_eq!(rt, cloned);
    }

    // Oracle decision confidence calculation test
    #[tokio::test]
    async fn test_decision_confidence_calculation() {
        let config = create_test_config();
        let oracle = Oracle::new(&config).await.unwrap();

        let research = ResearchResult {
            research_id: Uuid::new_v4(),
            goal_analysis: GoalAnalysis {
                complexity_score: 0.5,
                feasibility_score: 0.8,
                clarity_score: 0.9,
                scope_estimate: ScopeEstimate {
                    small: false,
                    medium: true,
                    large: false,
                    estimated_effort_hours: 4.0,
                    confidence_interval: (3.0, 5.0),
                },
                success_probability: 0.72,
            },
            codebase_analysis: None,
            pattern_analysis: PatternAnalysis {
                design_patterns: vec![],
                antipatterns: vec![],
                best_practices: vec![],
                improvement_opportunities: vec![],
            },
            risk_findings: vec![],
            recommendations: vec![],
            confidence: 0.9,
            research_duration_minutes: 5,
        };

        let consensus = PlanningConsensus {
            consensus_id: Uuid::new_v4(),
            specialist_opinions: HashMap::new(),
            overall_confidence: 0.8,
            consensus_reached: true,
            conflicting_recommendations: vec![],
            final_recommendation: "Approved".to_string(),
        };

        let risk_assessment = RiskAssessment {
            overall_risk_score: 0.2,
            risk_categories: HashMap::new(),
            mitigation_strategies: vec![],
            acceptable_risk_level: true,
        };

        let confidence =
            oracle.calculate_decision_confidence(&research, &consensus, &risk_assessment);

        // Expected: 0.9 * 0.4 + 0.8 * 0.4 + (1 - 0.2) * 0.2 = 0.36 + 0.32 + 0.16 = 0.84
        assert!((confidence - 0.84).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_evaluation_confidence_empty_results() {
        let config = create_test_config();
        let oracle = Oracle::new(&config).await.unwrap();

        let confidence = oracle.calculate_evaluation_confidence(&[]);
        assert_eq!(confidence, 0.0);
    }

    #[tokio::test]
    async fn test_get_decision_history_empty() {
        let config = create_test_config();
        let oracle = Oracle::new(&config).await.unwrap();

        let history = oracle.get_decision_history().await;
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_export_metrics_empty() {
        let config = create_test_config();
        let oracle = Oracle::new(&config).await.unwrap();

        let metrics = oracle.export_metrics().await;
        assert_eq!(metrics.total_decisions, 0);
        assert_eq!(metrics.average_confidence, 0.0);
    }

    #[tokio::test]
    async fn test_research_cache_size() {
        let config = create_test_config();
        let assistant = DeepResearchAssistant::new(config).await.unwrap();

        // Initially empty
        assert_eq!(assistant.get_cache_size().await, 0);

        // After research
        let goal = Goal::new("Cache test goal");
        let _ = assistant.conduct_research(&goal).await.unwrap();
        assert_eq!(assistant.get_cache_size().await, 1);
    }

    #[tokio::test]
    async fn test_calculate_research_confidence() {
        let config = create_test_config();
        let assistant = DeepResearchAssistant::new(config).await.unwrap();

        let analysis = GoalAnalysis {
            complexity_score: 0.5,
            feasibility_score: 0.8,
            clarity_score: 0.9,
            scope_estimate: ScopeEstimate {
                small: false,
                medium: true,
                large: false,
                estimated_effort_hours: 4.0,
                confidence_interval: (3.0, 5.0),
            },
            success_probability: 0.72,
        };

        // No risks
        let confidence_no_risks = assistant.calculate_research_confidence(&analysis, &[]);
        // Expected: 0.9 * 0.4 + 0.8 * 0.4 + 1.0 * 0.2 = 0.36 + 0.32 + 0.2 = 0.88
        assert!((confidence_no_risks - 0.88).abs() < 0.01);

        // With risks
        let risks = vec![RiskFinding {
            risk_type: RiskType::Technical,
            severity: RiskSeverity::Medium,
            description: "Test risk".to_string(),
            mitigation: "Mitigate".to_string(),
            probability: 0.5,
        }];

        let confidence_with_risks = assistant.calculate_research_confidence(&analysis, &risks);
        assert!(confidence_with_risks < confidence_no_risks);
    }

    // Specialist agent tests
    #[test]
    fn test_specialist_agent_creation() {
        let agent = SpecialistAgent {
            agent_type: SpecialistType::Performance,
            expertise_areas: vec!["Optimization".to_string()],
            conversation_context: Some("context".to_string()),
        };

        assert!(matches!(agent.agent_type, SpecialistType::Performance));
        assert_eq!(agent.expertise_areas.len(), 1);
        assert!(agent.conversation_context.is_some());
    }

    #[test]
    fn test_specialist_type_equality() {
        assert_eq!(SpecialistType::Architecture, SpecialistType::Architecture);
        assert_ne!(SpecialistType::Architecture, SpecialistType::Security);
    }

    #[test]
    fn test_specialist_type_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(SpecialistType::Architecture);
        set.insert(SpecialistType::Security);

        assert!(set.contains(&SpecialistType::Architecture));
        assert!(set.contains(&SpecialistType::Security));
        assert!(!set.contains(&SpecialistType::Performance));
    }
}
