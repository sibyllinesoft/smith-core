//! Oracle layer for AI-powered planning and research
//!
//! The Oracle provides sophisticated AI-driven analysis, planning, and research
//! capabilities for the Planner-Executor Controller. It consists of multiple
//! specialized sub-systems working together to provide comprehensive decision support.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::schemas::{
    ActionType, PlanningResult, ResearchFinding, ResearchResult, RiskAssessment, RiskLevel,
    WorkflowAction,
};
use super::state_machine::StateMachine;
use crate::runners::ExecContext;

/// Oracle configuration and capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleConfig {
    /// Maximum number of planning iterations
    pub max_planning_iterations: u32,

    /// Research depth level (1-5)
    pub research_depth: u32,

    /// Confidence threshold for recommendations
    pub confidence_threshold: f64,

    /// Available research capabilities
    pub research_capabilities: Vec<String>,

    /// Planning committee configuration
    pub planning_committee: PlanningCommitteeConfig,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            max_planning_iterations: 5,
            research_depth: 3,
            confidence_threshold: 0.7,
            research_capabilities: vec![
                "codebase_analysis".to_string(),
                "documentation_review".to_string(),
                "pattern_recognition".to_string(),
                "dependency_mapping".to_string(),
                "security_assessment".to_string(),
            ],
            planning_committee: PlanningCommitteeConfig::default(),
        }
    }
}

/// Configuration for the Planning Committee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanningCommitteeConfig {
    /// Available committee members
    pub members: Vec<CommitteeMember>,

    /// Consensus threshold (0.0 - 1.0)
    pub consensus_threshold: f64,

    /// Maximum deliberation rounds
    pub max_deliberation_rounds: u32,
}

impl Default for PlanningCommitteeConfig {
    fn default() -> Self {
        Self {
            members: vec![
                CommitteeMember {
                    name: "Strategic Planner".to_string(),
                    role: CommitteeRole::Strategic,
                    expertise: vec![
                        "goal_decomposition".to_string(),
                        "resource_planning".to_string(),
                    ],
                    weight: 1.0,
                },
                CommitteeMember {
                    name: "Security Specialist".to_string(),
                    role: CommitteeRole::Security,
                    expertise: vec![
                        "vulnerability_assessment".to_string(),
                        "compliance".to_string(),
                    ],
                    weight: 1.0,
                },
                CommitteeMember {
                    name: "Performance Analyst".to_string(),
                    role: CommitteeRole::Performance,
                    expertise: vec!["optimization".to_string(), "resource_usage".to_string()],
                    weight: 0.8,
                },
                CommitteeMember {
                    name: "Risk Manager".to_string(),
                    role: CommitteeRole::Risk,
                    expertise: vec![
                        "risk_assessment".to_string(),
                        "mitigation_planning".to_string(),
                    ],
                    weight: 1.0,
                },
            ],
            consensus_threshold: 0.75,
            max_deliberation_rounds: 3,
        }
    }
}

/// Individual committee member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeMember {
    /// Member name/identifier
    pub name: String,

    /// Committee role
    pub role: CommitteeRole,

    /// Areas of expertise
    pub expertise: Vec<String>,

    /// Voting weight in decisions
    pub weight: f64,
}

/// Committee member roles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Strategic,
    Security,
    Performance,
    Risk,
    Quality,
    User,
}

/// Main Oracle implementation
pub struct Oracle {
    config: OracleConfig,
    execution_context: ExecContext,
    deep_research: DeepResearch,
    planning_committee: PlanningCommittee,
}

impl Oracle {
    /// Create a new Oracle instance
    pub fn new(exec_context: &ExecContext) -> Result<Self> {
        let config = OracleConfig::default();
        let deep_research = DeepResearch::new(&config)?;
        let planning_committee = PlanningCommittee::new(&config.planning_committee)?;

        info!(
            "Oracle initialized with {} research capabilities",
            config.research_capabilities.len()
        );

        Ok(Self {
            config,
            execution_context: exec_context.clone(),
            deep_research,
            planning_committee,
        })
    }

    /// Perform initial planning for the given goal
    pub async fn initial_planning(&self, goal: &str) -> Result<PlanningResult> {
        info!(goal = %goal, "Starting initial planning");

        // Step 1: Goal analysis and decomposition
        let goal_analysis = self.analyze_goal(goal).await?;

        // Step 2: Generate initial action plan
        let initial_actions = self.generate_initial_actions(&goal_analysis).await?;

        // Step 3: Planning committee review
        let committee_result = self
            .planning_committee
            .review_plan(goal, &initial_actions, &goal_analysis)
            .await?;

        // Step 4: Risk assessment
        let risks = self.assess_risks(&initial_actions, &goal_analysis).await?;

        // Step 5: Define success criteria
        let success_criteria = self.define_success_criteria(goal, &goal_analysis).await?;

        let planning_result = PlanningResult {
            actions: committee_result.refined_actions,
            strategy: committee_result.strategy,
            risks,
            success_criteria,
            confidence: committee_result.confidence,
        };

        info!(
            actions_count = planning_result.actions.len(),
            confidence = planning_result.confidence,
            "Initial planning completed"
        );

        Ok(planning_result)
    }

    /// Perform deep research on the current workflow state
    pub async fn deep_research(&self, state_machine: &StateMachine) -> Result<ResearchResult> {
        info!(
            workflow_id = %state_machine.workflow_id,
            "Starting deep research"
        );

        let research_result = self
            .deep_research
            .conduct_research(
                &state_machine.params.goal,
                state_machine,
                &self.execution_context,
            )
            .await?;

        info!(
            findings_count = research_result.findings.len(),
            confidence = research_result.confidence,
            "Deep research completed"
        );

        Ok(research_result)
    }

    /// Analyze and decompose the goal
    async fn analyze_goal(&self, goal: &str) -> Result<GoalAnalysis> {
        debug!(goal = %goal, "Analyzing goal");

        // This is a simplified goal analysis
        // In a real implementation, this would use LLM APIs for sophisticated analysis
        let complexity = self.assess_goal_complexity(goal);
        let domains = self.identify_domains(goal);
        let dependencies = self.identify_dependencies(goal);
        let constraints = self.identify_constraints(goal);

        Ok(GoalAnalysis {
            original_goal: goal.to_string(),
            complexity,
            domains,
            sub_goals: self.decompose_goal(goal),
            dependencies,
            constraints,
            estimated_effort: self.estimate_effort(goal),
            required_capabilities: self.identify_required_capabilities(goal),
        })
    }

    /// Assess the complexity of the goal
    fn assess_goal_complexity(&self, goal: &str) -> GoalComplexity {
        // Simple heuristic-based complexity assessment
        let word_count = goal.split_whitespace().count();
        let has_complex_keywords = goal.to_lowercase().contains("analyze")
            || goal.to_lowercase().contains("optimize")
            || goal.to_lowercase().contains("research")
            || goal.to_lowercase().contains("complex");

        let has_very_complex_keywords = goal.to_lowercase().contains("interconnected")
            || goal.to_lowercase().contains("multiple")
            || (goal.to_lowercase().contains("complex") && goal.to_lowercase().contains("system"));

        match (word_count, has_complex_keywords, has_very_complex_keywords) {
            (0..=5, false, false) => GoalComplexity::Simple,
            (0..=5, true, false) => GoalComplexity::Medium,
            (6..=15, false, false) => GoalComplexity::Medium,
            (6..=15, true, false) => GoalComplexity::Complex,
            (_, _, true) => GoalComplexity::VeryComplex,
            (16..=30, _, _) => GoalComplexity::Complex,
            _ => GoalComplexity::VeryComplex,
        }
    }

    /// Identify relevant domains for the goal
    fn identify_domains(&self, goal: &str) -> Vec<String> {
        let mut domains = Vec::new();
        let goal_lower = goal.to_lowercase();

        if goal_lower.contains("file")
            || goal_lower.contains("read")
            || goal_lower.contains("write")
        {
            domains.push("filesystem".to_string());
        }
        if goal_lower.contains("http")
            || goal_lower.contains("api")
            || goal_lower.contains("request")
        {
            domains.push("network".to_string());
        }
        if goal_lower.contains("analyze") || goal_lower.contains("research") {
            domains.push("analysis".to_string());
        }
        if goal_lower.contains("security") || goal_lower.contains("secure") {
            domains.push("security".to_string());
        }
        if goal_lower.contains("performance") || goal_lower.contains("optimize") {
            domains.push("performance".to_string());
        }

        if domains.is_empty() {
            domains.push("general".to_string());
        }

        domains
    }

    /// Decompose goal into sub-goals
    fn decompose_goal(&self, goal: &str) -> Vec<String> {
        // Simplified goal decomposition
        // In a real implementation, this would use sophisticated NLP/LLM analysis
        vec![
            format!("Research requirements for: {}", goal),
            format!("Plan implementation approach for: {}", goal),
            format!("Execute implementation steps for: {}", goal),
            format!("Validate results for: {}", goal),
        ]
    }

    /// Identify dependencies
    fn identify_dependencies(&self, _goal: &str) -> Vec<String> {
        // Simplified dependency identification
        vec![
            "Execution environment access".to_string(),
            "Required capabilities available".to_string(),
            "Security permissions granted".to_string(),
        ]
    }

    /// Identify constraints
    fn identify_constraints(&self, _goal: &str) -> Vec<String> {
        vec![
            "Security policy compliance".to_string(),
            "Resource usage limits".to_string(),
            "Execution timeout limits".to_string(),
        ]
    }

    /// Estimate effort required
    fn estimate_effort(&self, goal: &str) -> EffortEstimate {
        let complexity = self.assess_goal_complexity(goal);

        match complexity {
            GoalComplexity::Simple => EffortEstimate {
                estimated_steps: 1..=3,
                estimated_time_minutes: 1..=5,
                estimated_resources: ResourceEstimate::Low,
            },
            GoalComplexity::Medium => EffortEstimate {
                estimated_steps: 3..=10,
                estimated_time_minutes: 5..=30,
                estimated_resources: ResourceEstimate::Medium,
            },
            GoalComplexity::Complex => EffortEstimate {
                estimated_steps: 10..=30,
                estimated_time_minutes: 30..=120,
                estimated_resources: ResourceEstimate::High,
            },
            GoalComplexity::VeryComplex => EffortEstimate {
                estimated_steps: 30..=100,
                estimated_time_minutes: 120..=600,
                estimated_resources: ResourceEstimate::VeryHigh,
            },
        }
    }

    /// Identify required capabilities
    fn identify_required_capabilities(&self, goal: &str) -> Vec<String> {
        let mut capabilities = Vec::new();
        let goal_lower = goal.to_lowercase();

        if goal_lower.contains("read") || goal_lower.contains("file") {
            capabilities.push("fs.read.v1".to_string());
        }
        if goal_lower.contains("write") {
            capabilities.push("fs.write.v1".to_string());
        }
        if goal_lower.contains("http") || goal_lower.contains("fetch") || goal_lower.contains("api")
        {
            capabilities.push("http.fetch.v1".to_string());
        }
        if goal_lower.contains("shell") || goal_lower.contains("command") {
            capabilities.push("shell.exec.v1".to_string());
        }

        capabilities
    }

    /// Generate initial actions based on goal analysis
    async fn generate_initial_actions(
        &self,
        analysis: &GoalAnalysis,
    ) -> Result<Vec<WorkflowAction>> {
        debug!("Generating initial actions for goal analysis");

        let mut actions = Vec::new();

        // Generate actions based on required capabilities
        for capability in &analysis.required_capabilities {
            let action = self.create_action_for_capability(capability, analysis)?;
            actions.push(action);
        }

        // If no specific capabilities identified, create research action
        if actions.is_empty() {
            let research_action = WorkflowAction::new(
                ActionType::Research("deep_analysis".to_string()),
                serde_json::json!({
                    "goal": analysis.original_goal,
                    "domains": analysis.domains
                }),
                "Conduct deep research on the goal".to_string(),
            );
            actions.push(research_action);
        }

        Ok(actions)
    }

    /// Create an action for a specific capability
    fn create_action_for_capability(
        &self,
        capability: &str,
        analysis: &GoalAnalysis,
    ) -> Result<WorkflowAction> {
        let (action_type, params, expected_outcome) = match capability {
            "fs.read.v1" => (
                ActionType::FileSystem(capability.to_string()),
                serde_json::json!({"path": "/tmp/workspace"}),
                "Read filesystem data".to_string(),
            ),
            "http.fetch.v1" => (
                ActionType::Http(capability.to_string()),
                serde_json::json!({"url": "http://example.com", "method": "GET"}),
                "Fetch data from HTTP endpoint".to_string(),
            ),
            "shell.exec.v1" => (
                ActionType::Shell(capability.to_string()),
                serde_json::json!({"command": "echo 'Hello World'"}),
                "Execute shell command".to_string(),
            ),
            _ => (
                ActionType::Custom(capability.to_string()),
                serde_json::json!({"goal": analysis.original_goal}),
                format!("Execute {} capability", capability),
            ),
        };

        Ok(WorkflowAction::new(action_type, params, expected_outcome))
    }

    /// Assess risks for the planned actions
    async fn assess_risks(
        &self,
        actions: &[WorkflowAction],
        _analysis: &GoalAnalysis,
    ) -> Result<Vec<RiskAssessment>> {
        debug!("Assessing risks for {} actions", actions.len());

        let mut risks = Vec::new();

        // Check for common risk patterns
        for action in actions {
            // Filesystem risks
            if matches!(action.action_type, ActionType::FileSystem(_)) {
                risks.push(RiskAssessment {
                    description: "Filesystem access may encounter permission issues".to_string(),
                    level: RiskLevel::Medium,
                    mitigation: "Validate file permissions before access".to_string(),
                    impact: "Action may fail or provide incomplete results".to_string(),
                });
            }

            // Network risks
            if matches!(action.action_type, ActionType::Http(_)) {
                risks.push(RiskAssessment {
                    description: "Network requests may fail or timeout".to_string(),
                    level: RiskLevel::Medium,
                    mitigation: "Implement retry logic and timeout handling".to_string(),
                    impact: "External data may not be available".to_string(),
                });
            }

            // Shell execution risks
            if matches!(action.action_type, ActionType::Shell(_)) {
                risks.push(RiskAssessment {
                    description: "Shell execution poses security risks".to_string(),
                    level: RiskLevel::High,
                    mitigation: "Strict input validation and sandboxing".to_string(),
                    impact: "Potential security violations or system damage".to_string(),
                });
            }
        }

        // Add general workflow risks
        if actions.len() > 20 {
            risks.push(RiskAssessment {
                description: "Large number of actions may exceed resource limits".to_string(),
                level: RiskLevel::Medium,
                mitigation: "Monitor resource usage and implement backpressure".to_string(),
                impact: "Workflow may be terminated due to resource exhaustion".to_string(),
            });
        }

        Ok(risks)
    }

    /// Define success criteria
    async fn define_success_criteria(
        &self,
        goal: &str,
        analysis: &GoalAnalysis,
    ) -> Result<Vec<String>> {
        debug!("Defining success criteria for goal");

        let mut criteria = vec![
            "All planned actions completed successfully".to_string(),
            "No critical errors encountered".to_string(),
            "Resource usage within acceptable limits".to_string(),
        ];

        // Add goal-specific criteria
        if analysis.original_goal.to_lowercase().contains("analyze") {
            criteria.push("Analysis results provide actionable insights".to_string());
        }

        if analysis.original_goal.to_lowercase().contains("read") {
            criteria.push("Required data successfully retrieved".to_string());
        }

        if analysis.original_goal.to_lowercase().contains("secure") {
            criteria.push("Security requirements validated and met".to_string());
        }

        Ok(criteria)
    }
}

/// Goal analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalAnalysis {
    pub original_goal: String,
    pub complexity: GoalComplexity,
    pub domains: Vec<String>,
    pub sub_goals: Vec<String>,
    pub dependencies: Vec<String>,
    pub constraints: Vec<String>,
    pub estimated_effort: EffortEstimate,
    pub required_capabilities: Vec<String>,
}

/// Goal complexity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[serde(rename_all = "snake_case")]
pub enum GoalComplexity {
    Simple,
    Medium,
    Complex,
    VeryComplex,
}

/// Effort estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffortEstimate {
    pub estimated_steps: std::ops::RangeInclusive<usize>,
    pub estimated_time_minutes: std::ops::RangeInclusive<u32>,
    pub estimated_resources: ResourceEstimate,
}

/// Resource requirement estimates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceEstimate {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Deep Research sub-system
pub struct DeepResearch {
    config: OracleConfig,
}

impl DeepResearch {
    pub fn new(config: &OracleConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    pub async fn conduct_research(
        &self,
        goal: &str,
        state_machine: &StateMachine,
        _exec_context: &ExecContext,
    ) -> Result<ResearchResult> {
        debug!(goal = %goal, "Conducting deep research");

        let findings = self.gather_findings(goal, state_machine).await?;
        let recommendations = self
            .generate_recommendations(&findings, state_machine)
            .await?;
        let confidence = self.calculate_confidence(&findings);
        let sources = self.identify_sources();

        Ok(ResearchResult {
            findings,
            recommendations,
            confidence,
            sources,
        })
    }

    async fn gather_findings(
        &self,
        goal: &str,
        state_machine: &StateMachine,
    ) -> Result<Vec<ResearchFinding>> {
        let mut findings = Vec::new();

        // Analyze current state
        let state_finding = ResearchFinding {
            title: "Current Workflow State".to_string(),
            description: format!(
                "Workflow is in {:?} state with {} completed actions and {} actions in queue",
                state_machine.current_state(),
                state_machine.completed_actions.len(),
                state_machine.action_queue.len()
            ),
            evidence: vec![
                format!("State: {:?}", state_machine.current_state()),
                format!("Progress: {:.1}%", state_machine.get_progress() * 100.0),
            ],
            relevance: 1.0,
        };
        findings.push(state_finding);

        // Analyze goal characteristics
        let goal_finding = ResearchFinding {
            title: "Goal Analysis".to_string(),
            description: format!("Analysis of the goal: {}", goal),
            evidence: vec![
                format!("Goal length: {} characters", goal.len()),
                format!(
                    "Contains keywords: {}",
                    self.extract_keywords(goal).join(", ")
                ),
            ],
            relevance: 0.9,
        };
        findings.push(goal_finding);

        // Resource usage analysis
        if !state_machine.completed_actions.is_empty() {
            let resource_finding = ResearchFinding {
                title: "Resource Usage Patterns".to_string(),
                description: "Analysis of resource consumption patterns".to_string(),
                evidence: vec![
                    format!(
                        "CPU usage: {} ms",
                        state_machine.total_resource_usage.cpu_ms
                    ),
                    format!(
                        "Memory usage: {} bytes",
                        state_machine.total_resource_usage.memory_bytes
                    ),
                    format!(
                        "FS operations: {}",
                        state_machine.total_resource_usage.fs_operations
                    ),
                ],
                relevance: 0.8,
            };
            findings.push(resource_finding);
        }

        Ok(findings)
    }

    async fn generate_recommendations(
        &self,
        findings: &[ResearchFinding],
        state_machine: &StateMachine,
    ) -> Result<Vec<String>> {
        let mut recommendations = Vec::new();

        // State-based recommendations
        match state_machine.current_state() {
            super::state_machine::WorkflowState::Executing => {
                recommendations.push("Continue monitoring action execution progress".to_string());

                if state_machine.action_queue.len() > 10 {
                    recommendations.push(
                        "Consider breaking down large action queue into smaller batches"
                            .to_string(),
                    );
                }
            }
            super::state_machine::WorkflowState::Planning => {
                recommendations
                    .push("Complete planning phase before proceeding to execution".to_string());
            }
            _ => {
                recommendations
                    .push("Assess current state and determine next appropriate action".to_string());
            }
        }

        // Resource-based recommendations
        if state_machine.total_resource_usage.cpu_ms > 10000 {
            recommendations.push("Monitor CPU usage to prevent resource exhaustion".to_string());
        }

        // Quality-based recommendations
        if !state_machine.failed_actions.is_empty() {
            recommendations.push(format!(
                "Address {} failed actions to improve success rate",
                state_machine.failed_actions.len()
            ));
        }

        // Progress-based recommendations
        let progress = state_machine.get_progress();
        if progress < 0.1 && state_machine.metadata.total_steps > 5 {
            recommendations
                .push("Consider reviewing workflow approach due to low progress".to_string());
        }

        Ok(recommendations)
    }

    fn calculate_confidence(&self, findings: &[ResearchFinding]) -> f64 {
        if findings.is_empty() {
            return 0.0;
        }

        let total_relevance: f64 = findings.iter().map(|f| f.relevance).sum();
        let avg_relevance = total_relevance / findings.len() as f64;

        // Adjust confidence based on number of findings
        let finding_factor = (findings.len() as f64 / 10.0).min(1.0);

        avg_relevance * finding_factor
    }

    fn identify_sources(&self) -> Vec<String> {
        vec![
            "Workflow state analysis".to_string(),
            "Resource usage monitoring".to_string(),
            "Action execution history".to_string(),
            "Built-in heuristics".to_string(),
        ]
    }

    fn extract_keywords(&self, text: &str) -> Vec<String> {
        let keywords = [
            "analyze", "read", "write", "fetch", "execute", "research", "optimize", "secure",
        ];
        let text_lower = text.to_lowercase();

        keywords
            .iter()
            .filter(|&keyword| text_lower.contains(keyword))
            .map(|&keyword| keyword.to_string())
            .collect()
    }
}

/// Planning Committee sub-system
pub struct PlanningCommittee {
    config: PlanningCommitteeConfig,
}

impl PlanningCommittee {
    pub fn new(config: &PlanningCommitteeConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    pub async fn review_plan(
        &self,
        goal: &str,
        actions: &[WorkflowAction],
        analysis: &GoalAnalysis,
    ) -> Result<CommitteeResult> {
        debug!(
            goal = %goal,
            actions_count = actions.len(),
            "Planning committee reviewing plan"
        );

        let mut member_reviews = Vec::new();

        // Get review from each committee member
        for member in &self.config.members {
            let review = self
                .get_member_review(member, goal, actions, analysis)
                .await?;
            member_reviews.push(review);
        }

        // Synthesize results
        let consensus_score = self.calculate_consensus(&member_reviews);
        let refined_actions = self.refine_actions(actions, &member_reviews)?;
        let strategy = self.synthesize_strategy(&member_reviews, analysis);
        let confidence = consensus_score * 0.9; // Slight discount for uncertainty

        Ok(CommitteeResult {
            refined_actions,
            strategy,
            confidence,
            member_reviews,
            consensus_score,
        })
    }

    async fn get_member_review(
        &self,
        member: &CommitteeMember,
        goal: &str,
        actions: &[WorkflowAction],
        analysis: &GoalAnalysis,
    ) -> Result<MemberReview> {
        debug!(member = %member.name, "Getting member review");

        let score = match member.role {
            CommitteeRole::Strategic => self.evaluate_strategic_aspects(goal, actions, analysis),
            CommitteeRole::Security => self.evaluate_security_aspects(actions),
            CommitteeRole::Performance => self.evaluate_performance_aspects(actions, analysis),
            CommitteeRole::Risk => self.evaluate_risk_aspects(actions, analysis),
            CommitteeRole::Quality => self.evaluate_quality_aspects(actions),
            CommitteeRole::User => self.evaluate_user_aspects(goal, actions),
        };

        let recommendations = self.generate_member_recommendations(member, actions, score);

        Ok(MemberReview {
            member_name: member.name.clone(),
            score,
            weight: member.weight,
            recommendations,
            concerns: self.identify_member_concerns(member, actions),
        })
    }

    fn evaluate_strategic_aspects(
        &self,
        goal: &str,
        actions: &[WorkflowAction],
        analysis: &GoalAnalysis,
    ) -> f64 {
        let mut score = 0.8; // Base strategic score

        // Check if actions align with goal
        let goal_keywords = goal.to_lowercase();
        let action_alignment = actions
            .iter()
            .map(|action| {
                let action_str =
                    format!("{:?} {}", action.action_type, action.expected_outcome).to_lowercase();
                if goal_keywords
                    .split_whitespace()
                    .any(|word| action_str.contains(word))
                {
                    1.0
                } else {
                    0.5
                }
            })
            .sum::<f64>()
            / actions.len() as f64;

        score *= action_alignment;

        // Complexity alignment
        match (analysis.complexity, actions.len()) {
            (GoalComplexity::Simple, 1..=3) => score *= 1.0,
            (GoalComplexity::Medium, 3..=10) => score *= 1.0,
            (GoalComplexity::Complex, 10..=30) => score *= 1.0,
            (GoalComplexity::VeryComplex, 30..=100) => score *= 1.0,
            _ => score *= 0.7, // Misaligned complexity
        }

        score.min(1.0)
    }

    fn evaluate_security_aspects(&self, actions: &[WorkflowAction]) -> f64 {
        let mut score = 1.0;

        for action in actions {
            match &action.action_type {
                ActionType::Shell(_) => score *= 0.6, // Shell execution is risky
                ActionType::FileSystem(_) => score *= 0.8, // File access has some risk
                ActionType::Http(_) => score *= 0.9,  // HTTP requests are generally safe
                _ => score *= 0.95,                   // Other actions are mostly safe
            }
        }

        score
    }

    fn evaluate_performance_aspects(
        &self,
        actions: &[WorkflowAction],
        analysis: &GoalAnalysis,
    ) -> f64 {
        let mut score: f64 = 0.9;

        // Check for performance anti-patterns
        if actions.len() > 50 {
            score *= 0.8; // Too many actions
        }

        // Check for parallel vs sequential opportunities
        let parallelizable_actions = actions
            .iter()
            .filter(|action| action.dependencies.is_empty())
            .count();

        if parallelizable_actions > actions.len() / 2 {
            score *= 1.1; // Good parallelization potential
        }

        // Resource estimate alignment
        match analysis.estimated_effort.estimated_resources {
            ResourceEstimate::VeryHigh if actions.len() > 20 => score *= 0.7,
            ResourceEstimate::Low if actions.len() < 3 => score *= 1.1,
            _ => {}
        }

        score.min(1.0)
    }

    fn evaluate_risk_aspects(&self, actions: &[WorkflowAction], analysis: &GoalAnalysis) -> f64 {
        let mut score = 0.9;

        // Check for high-risk action types
        let risky_actions = actions
            .iter()
            .filter(|action| matches!(action.action_type, ActionType::Shell(_)))
            .count();

        if risky_actions > 0 {
            score *= 0.8 - (risky_actions as f64 * 0.1);
        }

        // Check for dependency complexity
        let max_dependencies = actions
            .iter()
            .map(|action| action.dependencies.len())
            .max()
            .unwrap_or(0);

        if max_dependencies > 3 {
            score *= 0.9;
        }

        // Goal complexity risk
        match analysis.complexity {
            GoalComplexity::VeryComplex => score *= 0.8,
            GoalComplexity::Complex => score *= 0.9,
            _ => {}
        }

        score.max(0.1)
    }

    fn evaluate_quality_aspects(&self, actions: &[WorkflowAction]) -> f64 {
        let mut score = 0.9;

        // Check for well-defined expected outcomes
        let well_defined = actions
            .iter()
            .filter(|action| {
                !action.expected_outcome.is_empty() && action.expected_outcome.len() > 10
            })
            .count();

        score *= well_defined as f64 / actions.len() as f64;

        // Check for retry policies
        let has_retry_policies = actions
            .iter()
            .filter(|action| action.retry_policy.max_retries > 0)
            .count();

        if has_retry_policies == actions.len() {
            score *= 1.1;
        }

        score.min(1.0)
    }

    fn evaluate_user_aspects(&self, goal: &str, actions: &[WorkflowAction]) -> f64 {
        let mut score = 0.8;

        // Check for user-friendly action descriptions
        let clear_descriptions = actions
            .iter()
            .filter(|action| action.expected_outcome.split_whitespace().count() > 3)
            .count();

        score *= clear_descriptions as f64 / actions.len() as f64;

        // Check goal clarity
        if goal.len() > 20 && goal.split_whitespace().count() > 3 {
            score *= 1.1;
        }

        score.min(1.0)
    }

    fn generate_member_recommendations(
        &self,
        member: &CommitteeMember,
        _actions: &[WorkflowAction],
        score: f64,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        match member.role {
            CommitteeRole::Strategic => {
                if score < 0.7 {
                    recommendations.push(
                        "Consider revising action plan to better align with strategic goals"
                            .to_string(),
                    );
                }
                recommendations.push("Ensure clear success metrics are defined".to_string());
            }
            CommitteeRole::Security => {
                recommendations.push("Validate all external inputs and outputs".to_string());
                if score < 0.8 {
                    recommendations.push(
                        "Consider additional security measures for high-risk actions".to_string(),
                    );
                }
            }
            CommitteeRole::Performance => {
                recommendations.push("Monitor resource usage throughout execution".to_string());
                recommendations.push("Consider parallelizing independent actions".to_string());
            }
            CommitteeRole::Risk => {
                recommendations.push(
                    "Implement comprehensive error handling and rollback procedures".to_string(),
                );
                if score < 0.7 {
                    recommendations
                        .push("Consider reducing complexity or adding safeguards".to_string());
                }
            }
            CommitteeRole::Quality => {
                recommendations.push("Ensure all actions have clear success criteria".to_string());
                recommendations.push("Implement validation steps for critical outputs".to_string());
            }
            CommitteeRole::User => {
                recommendations
                    .push("Provide clear progress indicators and user feedback".to_string());
                recommendations.push("Ensure error messages are user-friendly".to_string());
            }
        }

        recommendations
    }

    fn identify_member_concerns(
        &self,
        member: &CommitteeMember,
        actions: &[WorkflowAction],
    ) -> Vec<String> {
        let mut concerns = Vec::new();

        match member.role {
            CommitteeRole::Security => {
                for action in actions {
                    if matches!(action.action_type, ActionType::Shell(_)) {
                        concerns.push("Shell execution poses security risks".to_string());
                    }
                }
            }
            CommitteeRole::Performance => {
                if actions.len() > 30 {
                    concerns.push("Large number of actions may impact performance".to_string());
                }
            }
            CommitteeRole::Risk => {
                let complex_dependencies =
                    actions.iter().any(|action| action.dependencies.len() > 2);
                if complex_dependencies {
                    concerns.push("Complex dependency chains increase failure risk".to_string());
                }
            }
            _ => {}
        }

        concerns
    }

    fn calculate_consensus(&self, reviews: &[MemberReview]) -> f64 {
        if reviews.is_empty() {
            return 0.0;
        }

        let weighted_scores: f64 = reviews
            .iter()
            .map(|review| review.score * review.weight)
            .sum();

        let total_weight: f64 = reviews.iter().map(|review| review.weight).sum();

        if total_weight > 0.0 {
            weighted_scores / total_weight
        } else {
            0.0
        }
    }

    fn refine_actions(
        &self,
        actions: &[WorkflowAction],
        reviews: &[MemberReview],
    ) -> Result<Vec<WorkflowAction>> {
        let mut refined_actions = actions.to_vec();

        // Apply committee recommendations
        for review in reviews {
            if review.score < 0.5 {
                warn!(member = %review.member_name, score = review.score, "Low member score, considering action refinements");
                // In a real implementation, this would apply specific refinements
                // based on the member's concerns and recommendations
            }
        }

        Ok(refined_actions)
    }

    fn synthesize_strategy(&self, reviews: &[MemberReview], analysis: &GoalAnalysis) -> String {
        let high_consensus = self.calculate_consensus(reviews) > self.config.consensus_threshold;

        if high_consensus {
            format!(
                "Execute {}-complexity workflow with {} actions, focusing on {} domains. Committee consensus: HIGH",
                format!("{:?}", analysis.complexity).to_lowercase(),
                analysis.estimated_effort.estimated_steps.end(),
                analysis.domains.join(", ")
            )
        } else {
            format!(
                "Proceed with caution on {}-complexity workflow. Address committee concerns before full execution. Domains: {}",
                format!("{:?}", analysis.complexity).to_lowercase(),
                analysis.domains.join(", ")
            )
        }
    }
}

/// Committee review result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeResult {
    pub refined_actions: Vec<WorkflowAction>,
    pub strategy: String,
    pub confidence: f64,
    pub member_reviews: Vec<MemberReview>,
    pub consensus_score: f64,
}

/// Individual member review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberReview {
    pub member_name: String,
    pub score: f64,
    pub weight: f64,
    pub recommendations: Vec<String>,
    pub concerns: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::planner_exec::schemas::{PlannerExecParams, WorkflowType};
    use crate::runners::{create_exec_context, Scope};
    use smith_protocol::ExecutionLimits;
    use std::collections::HashMap;
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
    async fn test_oracle_creation() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();
        assert!(oracle.config.max_planning_iterations > 0);
    }

    #[tokio::test]
    async fn test_goal_complexity_assessment() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        assert_eq!(
            oracle.assess_goal_complexity("read file"),
            GoalComplexity::Simple
        );
        assert_eq!(
            oracle.assess_goal_complexity("analyze the codebase and provide recommendations"),
            GoalComplexity::Complex
        );
        assert_eq!(
            oracle.assess_goal_complexity(
                "complex system optimization with multiple interconnected components"
            ),
            GoalComplexity::VeryComplex
        );
    }

    #[tokio::test]
    async fn test_domain_identification() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let domains = oracle.identify_domains("read file and make http request");
        assert!(domains.contains(&"filesystem".to_string()));
        assert!(domains.contains(&"network".to_string()));

        let security_domains =
            oracle.identify_domains("secure analysis of security vulnerabilities");
        assert!(security_domains.contains(&"security".to_string()));
    }

    #[tokio::test]
    async fn test_planning_committee() {
        let config = PlanningCommitteeConfig::default();
        let committee = PlanningCommittee::new(&config).unwrap();

        assert_eq!(committee.config.members.len(), 4);
        assert!(committee.config.consensus_threshold > 0.0);
    }

    #[tokio::test]
    async fn test_deep_research() {
        let config = OracleConfig::default();
        let research = DeepResearch::new(&config).unwrap();

        let params = PlannerExecParams {
            workflow_id: "test-workflow-789".to_string(),
            goal: "Test research".to_string(),
            workflow_type: WorkflowType::Simple,
            max_steps: 5,
            timeout_ms: Some(30000),
            context: HashMap::new(),
            allowed_capabilities: vec![],
            resource_limits: super::super::schemas::ResourceLimits::default(),
            preferences: super::super::schemas::ExecutionPreferences::default(),
        };

        let state_machine = StateMachine::new("test".to_string(), params).unwrap();
        let ctx = create_test_context();

        let result = research
            .conduct_research("test goal", &state_machine, &ctx)
            .await
            .unwrap();

        assert!(!result.findings.is_empty());
        assert!(!result.recommendations.is_empty());
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
    }

    #[tokio::test]
    async fn test_initial_planning() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let result = oracle
            .initial_planning("read a file and analyze its contents")
            .await
            .unwrap();

        assert!(!result.actions.is_empty());
        assert!(!result.strategy.is_empty());
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
        assert!(!result.success_criteria.is_empty());
    }

    // === Serialization tests ===

    #[test]
    fn test_committee_role_serialization() {
        let roles = vec![
            (CommitteeRole::Strategic, "strategic"),
            (CommitteeRole::Security, "security"),
            (CommitteeRole::Performance, "performance"),
            (CommitteeRole::Risk, "risk"),
            (CommitteeRole::Quality, "quality"),
            (CommitteeRole::User, "user"),
        ];

        for (role, expected) in roles {
            let json = serde_json::to_string(&role).unwrap();
            assert!(json.contains(expected));
            let parsed: CommitteeRole = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn test_goal_complexity_serialization() {
        let complexities = vec![
            GoalComplexity::Simple,
            GoalComplexity::Medium,
            GoalComplexity::Complex,
            GoalComplexity::VeryComplex,
        ];

        for complexity in complexities {
            let json = serde_json::to_string(&complexity).unwrap();
            let parsed: GoalComplexity = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, complexity);
        }
    }

    #[test]
    fn test_resource_estimate_serialization() {
        let estimates = vec![
            ResourceEstimate::Low,
            ResourceEstimate::Medium,
            ResourceEstimate::High,
            ResourceEstimate::VeryHigh,
        ];

        for estimate in estimates {
            let json = serde_json::to_string(&estimate).unwrap();
            let parsed: ResourceEstimate = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, estimate);
        }
    }

    #[test]
    fn test_oracle_config_default() {
        let config = OracleConfig::default();
        assert_eq!(config.max_planning_iterations, 5);
        assert_eq!(config.research_depth, 3);
        assert!((config.confidence_threshold - 0.7).abs() < 0.01);
        assert!(!config.research_capabilities.is_empty());
    }

    #[test]
    fn test_oracle_config_serialization() {
        let config = OracleConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("max_planning_iterations"));
        let parsed: OracleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.max_planning_iterations,
            config.max_planning_iterations
        );
    }

    #[test]
    fn test_planning_committee_config_default() {
        let config = PlanningCommitteeConfig::default();
        assert_eq!(config.members.len(), 4);
        assert!((config.consensus_threshold - 0.75).abs() < 0.01);
        assert_eq!(config.max_deliberation_rounds, 3);
    }

    #[test]
    fn test_planning_committee_config_serialization() {
        let config = PlanningCommitteeConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PlanningCommitteeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.members.len(), config.members.len());
    }

    #[test]
    fn test_committee_member_serialization() {
        let member = CommitteeMember {
            name: "Test Member".to_string(),
            role: CommitteeRole::Security,
            expertise: vec!["penetration_testing".to_string()],
            weight: 1.5,
        };

        let json = serde_json::to_string(&member).unwrap();
        assert!(json.contains("Test Member"));
        let parsed: CommitteeMember = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Test Member");
        assert_eq!(parsed.weight, 1.5);
    }

    #[test]
    fn test_goal_analysis_serialization() {
        let analysis = GoalAnalysis {
            original_goal: "Test goal".to_string(),
            complexity: GoalComplexity::Medium,
            domains: vec!["security".to_string()],
            sub_goals: vec!["Sub goal 1".to_string()],
            dependencies: vec!["Dep 1".to_string()],
            constraints: vec!["Constraint 1".to_string()],
            estimated_effort: EffortEstimate {
                estimated_steps: 1..=5,
                estimated_time_minutes: 5..=15,
                estimated_resources: ResourceEstimate::Medium,
            },
            required_capabilities: vec!["fs.read.v1".to_string()],
        };

        let json = serde_json::to_string(&analysis).unwrap();
        assert!(json.contains("Test goal"));
        let parsed: GoalAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.original_goal, "Test goal");
    }

    #[test]
    fn test_committee_result_serialization() {
        let result = CommitteeResult {
            refined_actions: vec![],
            strategy: "Test strategy".to_string(),
            confidence: 0.85,
            member_reviews: vec![],
            consensus_score: 0.9,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Test strategy"));
        let parsed: CommitteeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.strategy, "Test strategy");
        assert_eq!(parsed.confidence, 0.85);
    }

    #[test]
    fn test_member_review_serialization() {
        let review = MemberReview {
            member_name: "Security Expert".to_string(),
            score: 0.8,
            weight: 1.0,
            recommendations: vec!["Use encryption".to_string()],
            concerns: vec!["Data exposure risk".to_string()],
        };

        let json = serde_json::to_string(&review).unwrap();
        assert!(json.contains("Security Expert"));
        let parsed: MemberReview = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.member_name, "Security Expert");
        assert_eq!(parsed.score, 0.8);
    }

    // === Edge case tests ===

    #[tokio::test]
    async fn test_goal_complexity_simple() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        assert_eq!(oracle.assess_goal_complexity("hi"), GoalComplexity::Simple);
        assert_eq!(oracle.assess_goal_complexity("x"), GoalComplexity::Simple);
        assert_eq!(
            oracle.assess_goal_complexity("read"),
            GoalComplexity::Simple
        );
    }

    #[tokio::test]
    async fn test_goal_complexity_medium_with_keywords() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        assert_eq!(
            oracle.assess_goal_complexity("analyze"),
            GoalComplexity::Medium
        );
        assert_eq!(
            oracle.assess_goal_complexity("optimize"),
            GoalComplexity::Medium
        );
        assert_eq!(
            oracle.assess_goal_complexity("research"),
            GoalComplexity::Medium
        );
    }

    #[tokio::test]
    async fn test_goal_complexity_very_long() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let very_long_goal = "This is a very long goal with many many many words that should indicate a complex task with lots of steps and requirements and dependencies and things to do over a long period of time";
        assert_eq!(
            oracle.assess_goal_complexity(very_long_goal),
            GoalComplexity::VeryComplex
        );
    }

    #[tokio::test]
    async fn test_identify_domains_general() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let domains = oracle.identify_domains("do something random");
        assert!(domains.contains(&"general".to_string()));
    }

    #[tokio::test]
    async fn test_identify_domains_all_types() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let domains = oracle.identify_domains(
            "read file, http api request, analyze research, security secure, performance optimize",
        );
        assert!(domains.contains(&"filesystem".to_string()));
        assert!(domains.contains(&"network".to_string()));
        assert!(domains.contains(&"analysis".to_string()));
        assert!(domains.contains(&"security".to_string()));
        assert!(domains.contains(&"performance".to_string()));
    }

    #[tokio::test]
    async fn test_identify_required_capabilities() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let caps = oracle.identify_required_capabilities("read file and write output");
        assert!(caps.contains(&"fs.read.v1".to_string()));
        assert!(caps.contains(&"fs.write.v1".to_string()));

        let http_caps = oracle.identify_required_capabilities("fetch from http api");
        assert!(http_caps.contains(&"http.fetch.v1".to_string()));

        let shell_caps = oracle.identify_required_capabilities("run shell command");
        assert!(shell_caps.contains(&"shell.exec.v1".to_string()));
    }

    #[tokio::test]
    async fn test_decompose_goal() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let sub_goals = oracle.decompose_goal("test goal");
        assert_eq!(sub_goals.len(), 4);
        assert!(sub_goals[0].contains("Research"));
        assert!(sub_goals[1].contains("Plan"));
        assert!(sub_goals[2].contains("Execute"));
        assert!(sub_goals[3].contains("Validate"));
    }

    #[tokio::test]
    async fn test_identify_dependencies() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let deps = oracle.identify_dependencies("any goal");
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.contains("Execution")));
        assert!(deps.iter().any(|d| d.contains("capabilities")));
        assert!(deps.iter().any(|d| d.contains("Security")));
    }

    #[tokio::test]
    async fn test_identify_constraints() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let constraints = oracle.identify_constraints("any goal");
        assert_eq!(constraints.len(), 3);
        assert!(constraints.iter().any(|c| c.contains("policy")));
        assert!(constraints.iter().any(|c| c.contains("Resource")));
        assert!(constraints.iter().any(|c| c.contains("timeout")));
    }

    #[tokio::test]
    async fn test_effort_estimate_simple() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let estimate = oracle.estimate_effort("read");
        assert!(*estimate.estimated_steps.start() <= 3);
        assert_eq!(estimate.estimated_resources, ResourceEstimate::Low);
    }

    #[tokio::test]
    async fn test_effort_estimate_complex() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let estimate = oracle.estimate_effort("analyze the entire codebase and provide comprehensive recommendations for all components");
        assert!(
            estimate.estimated_resources == ResourceEstimate::High
                || estimate.estimated_resources == ResourceEstimate::VeryHigh
        );
    }

    #[tokio::test]
    async fn test_deep_research_extract_keywords() {
        let config = OracleConfig::default();
        let research = DeepResearch::new(&config).unwrap();

        let keywords =
            research.extract_keywords("analyze and read the file, then optimize performance");
        assert!(keywords.contains(&"analyze".to_string()));
        assert!(keywords.contains(&"read".to_string()));
        assert!(keywords.contains(&"optimize".to_string()));
    }

    #[test]
    fn test_deep_research_calculate_confidence() {
        let config = OracleConfig::default();
        let research = DeepResearch::new(&config).unwrap();

        // Empty findings should return 0
        let empty_confidence = research.calculate_confidence(&[]);
        assert_eq!(empty_confidence, 0.0);

        // Single high relevance finding
        let single_finding = vec![ResearchFinding {
            title: "Test".to_string(),
            description: "Test".to_string(),
            evidence: vec![],
            relevance: 1.0,
        }];
        let single_confidence = research.calculate_confidence(&single_finding);
        assert!(single_confidence > 0.0 && single_confidence <= 1.0);

        // Multiple findings
        let multiple_findings = vec![
            ResearchFinding {
                title: "Test1".to_string(),
                description: "Test".to_string(),
                evidence: vec![],
                relevance: 0.9,
            },
            ResearchFinding {
                title: "Test2".to_string(),
                description: "Test".to_string(),
                evidence: vec![],
                relevance: 0.8,
            },
            ResearchFinding {
                title: "Test3".to_string(),
                description: "Test".to_string(),
                evidence: vec![],
                relevance: 0.7,
            },
        ];
        let multi_confidence = research.calculate_confidence(&multiple_findings);
        assert!(multi_confidence > single_confidence);
    }

    #[test]
    fn test_deep_research_identify_sources() {
        let config = OracleConfig::default();
        let research = DeepResearch::new(&config).unwrap();

        let sources = research.identify_sources();
        assert!(!sources.is_empty());
        assert!(sources.iter().any(|s| s.contains("state")));
    }

    #[tokio::test]
    async fn test_committee_calculate_consensus_empty() {
        let config = PlanningCommitteeConfig::default();
        let committee = PlanningCommittee::new(&config).unwrap();

        let consensus = committee.calculate_consensus(&[]);
        assert_eq!(consensus, 0.0);
    }

    #[tokio::test]
    async fn test_committee_calculate_consensus_single() {
        let config = PlanningCommitteeConfig::default();
        let committee = PlanningCommittee::new(&config).unwrap();

        let reviews = vec![MemberReview {
            member_name: "Test".to_string(),
            score: 0.8,
            weight: 1.0,
            recommendations: vec![],
            concerns: vec![],
        }];

        let consensus = committee.calculate_consensus(&reviews);
        assert_eq!(consensus, 0.8);
    }

    #[tokio::test]
    async fn test_committee_calculate_consensus_weighted() {
        let config = PlanningCommitteeConfig::default();
        let committee = PlanningCommittee::new(&config).unwrap();

        let reviews = vec![
            MemberReview {
                member_name: "A".to_string(),
                score: 1.0,
                weight: 2.0,
                recommendations: vec![],
                concerns: vec![],
            },
            MemberReview {
                member_name: "B".to_string(),
                score: 0.5,
                weight: 1.0,
                recommendations: vec![],
                concerns: vec![],
            },
        ];

        let consensus = committee.calculate_consensus(&reviews);
        // (1.0 * 2.0 + 0.5 * 1.0) / (2.0 + 1.0) = 2.5 / 3.0 = 0.833...
        assert!((consensus - 0.833).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_committee_evaluate_security_aspects() {
        let config = PlanningCommitteeConfig::default();
        let committee = PlanningCommittee::new(&config).unwrap();

        // All research actions should have high security score
        let safe_actions = vec![WorkflowAction::new(
            ActionType::Research("research.v1".to_string()),
            serde_json::json!({}),
            "Research".to_string(),
        )];
        let safe_score = committee.evaluate_security_aspects(&safe_actions);
        assert!(safe_score > 0.9);

        // Shell actions should have lower security score
        let risky_actions = vec![WorkflowAction::new(
            ActionType::Shell("shell.exec.v1".to_string()),
            serde_json::json!({}),
            "Shell".to_string(),
        )];
        let risky_score = committee.evaluate_security_aspects(&risky_actions);
        assert!(risky_score < safe_score);
    }

    #[tokio::test]
    async fn test_committee_identify_member_concerns_security() {
        let config = PlanningCommitteeConfig::default();
        let committee = PlanningCommittee::new(&config).unwrap();

        let security_member = CommitteeMember {
            name: "Security".to_string(),
            role: CommitteeRole::Security,
            expertise: vec![],
            weight: 1.0,
        };

        let shell_actions = vec![WorkflowAction::new(
            ActionType::Shell("shell.exec.v1".to_string()),
            serde_json::json!({}),
            "Shell".to_string(),
        )];

        let concerns = committee.identify_member_concerns(&security_member, &shell_actions);
        assert!(!concerns.is_empty());
        assert!(concerns[0].contains("security"));
    }

    #[tokio::test]
    async fn test_committee_identify_member_concerns_performance() {
        let config = PlanningCommitteeConfig::default();
        let committee = PlanningCommittee::new(&config).unwrap();

        let perf_member = CommitteeMember {
            name: "Performance".to_string(),
            role: CommitteeRole::Performance,
            expertise: vec![],
            weight: 1.0,
        };

        let many_actions: Vec<_> = (0..35)
            .map(|i| {
                WorkflowAction::new(
                    ActionType::Research(format!("research.{}", i)),
                    serde_json::json!({}),
                    "Action".to_string(),
                )
            })
            .collect();

        let concerns = committee.identify_member_concerns(&perf_member, &many_actions);
        assert!(!concerns.is_empty());
        assert!(concerns[0].contains("performance") || concerns[0].contains("actions"));
    }

    #[tokio::test]
    async fn test_committee_identify_member_concerns_risk() {
        let config = PlanningCommitteeConfig::default();
        let committee = PlanningCommittee::new(&config).unwrap();

        let risk_member = CommitteeMember {
            name: "Risk".to_string(),
            role: CommitteeRole::Risk,
            expertise: vec![],
            weight: 1.0,
        };

        let mut action_with_deps = WorkflowAction::new(
            ActionType::Research("research.v1".to_string()),
            serde_json::json!({}),
            "Action".to_string(),
        );
        action_with_deps.dependencies = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        let concerns = committee.identify_member_concerns(&risk_member, &[action_with_deps]);
        assert!(!concerns.is_empty());
        assert!(concerns[0].contains("dependency"));
    }

    #[tokio::test]
    async fn test_initial_planning_with_http_goal() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let result = oracle
            .initial_planning("fetch data from http api endpoint")
            .await
            .unwrap();

        assert!(!result.actions.is_empty());
        assert!(result
            .actions
            .iter()
            .any(|a| matches!(a.action_type, ActionType::Http(_))));
    }

    #[tokio::test]
    async fn test_initial_planning_with_shell_goal() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let result = oracle
            .initial_planning("run shell command to list files")
            .await
            .unwrap();

        assert!(!result.actions.is_empty());
        // Should have shell action and higher risk assessment
        assert!(!result.risks.is_empty());
        assert!(result.risks.iter().any(|r| r.level == RiskLevel::High));
    }

    #[tokio::test]
    async fn test_initial_planning_with_no_specific_capability() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let result = oracle
            .initial_planning("do something general")
            .await
            .unwrap();

        // Should have at least a research action
        assert!(!result.actions.is_empty());
    }

    #[tokio::test]
    async fn test_risk_assessment_many_actions() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let many_actions: Vec<_> = (0..25)
            .map(|i| {
                WorkflowAction::new(
                    ActionType::Research(format!("research.{}", i)),
                    serde_json::json!({}),
                    "Action".to_string(),
                )
            })
            .collect();

        let analysis = GoalAnalysis {
            original_goal: "test".to_string(),
            complexity: GoalComplexity::Complex,
            domains: vec![],
            sub_goals: vec![],
            dependencies: vec![],
            constraints: vec![],
            estimated_effort: EffortEstimate {
                estimated_steps: 1..=5,
                estimated_time_minutes: 5..=15,
                estimated_resources: ResourceEstimate::Medium,
            },
            required_capabilities: vec![],
        };

        let risks = oracle.assess_risks(&many_actions, &analysis).await.unwrap();
        // Should have risk about large number of actions
        assert!(risks.iter().any(|r| r.description.contains("Large number")));
    }

    #[tokio::test]
    async fn test_success_criteria_with_analyze() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let analysis = GoalAnalysis {
            original_goal: "analyze data".to_string(),
            complexity: GoalComplexity::Medium,
            domains: vec!["analysis".to_string()],
            sub_goals: vec![],
            dependencies: vec![],
            constraints: vec![],
            estimated_effort: EffortEstimate {
                estimated_steps: 1..=5,
                estimated_time_minutes: 5..=15,
                estimated_resources: ResourceEstimate::Medium,
            },
            required_capabilities: vec![],
        };

        let criteria = oracle
            .define_success_criteria("analyze data", &analysis)
            .await
            .unwrap();
        assert!(criteria.iter().any(|c| c.contains("actionable")));
    }

    #[tokio::test]
    async fn test_success_criteria_with_read() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let analysis = GoalAnalysis {
            original_goal: "read file".to_string(),
            complexity: GoalComplexity::Simple,
            domains: vec!["filesystem".to_string()],
            sub_goals: vec![],
            dependencies: vec![],
            constraints: vec![],
            estimated_effort: EffortEstimate {
                estimated_steps: 1..=5,
                estimated_time_minutes: 5..=15,
                estimated_resources: ResourceEstimate::Low,
            },
            required_capabilities: vec![],
        };

        let criteria = oracle
            .define_success_criteria("read file", &analysis)
            .await
            .unwrap();
        assert!(criteria.iter().any(|c| c.contains("retrieved")));
    }

    #[tokio::test]
    async fn test_success_criteria_with_secure() {
        let ctx = create_test_context();
        let oracle = Oracle::new(&ctx).unwrap();

        let analysis = GoalAnalysis {
            original_goal: "secure endpoint".to_string(),
            complexity: GoalComplexity::Medium,
            domains: vec!["security".to_string()],
            sub_goals: vec![],
            dependencies: vec![],
            constraints: vec![],
            estimated_effort: EffortEstimate {
                estimated_steps: 1..=5,
                estimated_time_minutes: 5..=15,
                estimated_resources: ResourceEstimate::Medium,
            },
            required_capabilities: vec![],
        };

        let criteria = oracle
            .define_success_criteria("secure endpoint", &analysis)
            .await
            .unwrap();
        assert!(criteria.iter().any(|c| c.contains("Security")));
    }

    #[tokio::test]
    async fn test_deep_research_with_failed_actions() {
        let config = OracleConfig::default();
        let research = DeepResearch::new(&config).unwrap();

        let params = PlannerExecParams {
            workflow_id: "test-workflow-failed".to_string(),
            goal: "Test with failures".to_string(),
            workflow_type: WorkflowType::Simple,
            max_steps: 5,
            timeout_ms: Some(30000),
            context: HashMap::new(),
            allowed_capabilities: vec![],
            resource_limits: super::super::schemas::ResourceLimits::default(),
            preferences: super::super::schemas::ExecutionPreferences::default(),
        };

        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();
        // Simulate failed actions
        let failed_result = super::super::schemas::ActionResult {
            action_id: "failed-1".to_string(),
            status: super::super::schemas::ActionStatus::Failed,
            output: None,
            error: Some(super::super::schemas::ActionError {
                code: "TEST_ERROR".to_string(),
                message: "Test failure".to_string(),
                details: None,
                retryable: false,
            }),
            metadata: super::super::schemas::ActionMetadata {
                retry_count: 0,
                resource_usage: super::super::schemas::ResourceUsage::default(),
                environment: super::super::schemas::ExecutionEnvironment {
                    executor_id: "test".to_string(),
                    sandbox_mode: "none".to_string(),
                    security_context: HashMap::new(),
                },
            },
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };
        state_machine.failed_actions.push(failed_result);

        let ctx = create_test_context();
        let result = research
            .conduct_research("test goal", &state_machine, &ctx)
            .await
            .unwrap();

        // Should have recommendation about failed actions
        assert!(result.recommendations.iter().any(|r| r.contains("failed")));
    }

    #[tokio::test]
    async fn test_deep_research_with_high_cpu() {
        let config = OracleConfig::default();
        let research = DeepResearch::new(&config).unwrap();

        let params = PlannerExecParams {
            workflow_id: "test-workflow-cpu".to_string(),
            goal: "Test high CPU".to_string(),
            workflow_type: WorkflowType::Simple,
            max_steps: 5,
            timeout_ms: Some(30000),
            context: HashMap::new(),
            allowed_capabilities: vec![],
            resource_limits: super::super::schemas::ResourceLimits::default(),
            preferences: super::super::schemas::ExecutionPreferences::default(),
        };

        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();
        state_machine.total_resource_usage.cpu_ms = 15000; // High CPU

        let ctx = create_test_context();
        let result = research
            .conduct_research("test goal", &state_machine, &ctx)
            .await
            .unwrap();

        // Should have recommendation about CPU
        assert!(result.recommendations.iter().any(|r| r.contains("CPU")));
    }

    #[tokio::test]
    async fn test_deep_research_with_large_queue() {
        let config = OracleConfig::default();
        let research = DeepResearch::new(&config).unwrap();

        let params = PlannerExecParams {
            workflow_id: "test-workflow-queue".to_string(),
            goal: "Test large queue".to_string(),
            workflow_type: WorkflowType::Simple,
            max_steps: 50,
            timeout_ms: Some(30000),
            context: HashMap::new(),
            allowed_capabilities: vec![],
            resource_limits: super::super::schemas::ResourceLimits::default(),
            preferences: super::super::schemas::ExecutionPreferences::default(),
        };

        let mut state_machine = StateMachine::new("test".to_string(), params).unwrap();
        // Transition through valid state sequence: Initializing -> Planning -> Executing
        state_machine
            .transition_to(crate::runners::planner_exec::state_machine::WorkflowState::Planning)
            .unwrap();
        state_machine
            .transition_to(crate::runners::planner_exec::state_machine::WorkflowState::Executing)
            .unwrap();

        // Add many actions to queue
        for i in 0..15 {
            let action = WorkflowAction::new(
                ActionType::Research(format!("research.{}", i)),
                serde_json::json!({}),
                "Test action".to_string(),
            );
            state_machine.action_queue.push_back(action);
        }

        let ctx = create_test_context();
        let result = research
            .conduct_research("test goal", &state_machine, &ctx)
            .await
            .unwrap();

        // Should have recommendation about breaking down queue
        assert!(result
            .recommendations
            .iter()
            .any(|r| r.contains("batch") || r.contains("breaking")));
    }
}
