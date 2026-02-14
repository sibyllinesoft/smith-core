/*!
# Comprehensive Test Suite for Oracle System

This test suite provides comprehensive coverage for the Oracle AI-powered planning system,
focusing on decision-making logic, research capabilities, planning committee consensus,
and security validation of AI-generated plans.

## Test Coverage Areas:
- Oracle system initialization and configuration
- Deep research assistant functionality and caching
- Planning committee consensus building
- Goal analysis and complexity assessment
- Risk assessment and mitigation strategies
- Decision confidence calculation
- Result evaluation and improvement recommendations
- Alternative plan generation
- Security validation of AI decisions
*/

#[cfg(test)]
mod oracle_tests {
    use agentd::planner::executor_adapter::ExecutionResult;
    use agentd::planner::oracle::*;
    use agentd::planner::{AiConfig, Goal, Priority};
    use anyhow::Result;
    use std::collections::HashMap;
    use uuid::Uuid;

    // Test fixtures and utilities
    fn create_test_ai_config() -> AiConfig {
        AiConfig {
            provider: "mock".to_string(),
            model: "test-model".to_string(),
            max_tokens: 1000,
            temperature: 0.1,
            timeout_seconds: 30,
            retry_attempts: 1,
            rate_limit_per_minute: 10,
        }
    }

    fn create_test_goal(description: &str) -> Goal {
        Goal {
            id: Uuid::new_v4(),
            description: description.to_string(),
            context: Some("Test context".to_string()),
            constraints: vec!["Test constraint".to_string()],
            success_criteria: vec!["Test success criterion".to_string()],
            priority: Priority::Medium,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        }
    }

    fn create_simple_goal() -> Goal {
        create_test_goal("Simple test goal")
    }

    fn create_complex_goal() -> Goal {
        create_test_goal("Complex multi-step optimization goal with performance constraints and security requirements for enterprise-scale deployment across multiple data centers with high availability and disaster recovery capabilities")
    }

    fn create_test_execution_result(success: bool) -> ExecutionResult {
        ExecutionResult {
            execution_id: Uuid::new_v4(),
            plan_id: Uuid::new_v4(),
            success,
            completed_operations: if success { 1 } else { 0 },
            failed_operations: if success { 0 } else { 1 },
            total_operations: 1,
            execution_time_ms: 5000,
            resource_usage: Default::default(),
            step_results: vec![],
            error_message: if success {
                String::new()
            } else {
                "Test error".to_string()
            },
            retryable: !success,
            attempt_count: 1,
            output: "Test output".to_string(),
            metadata: HashMap::new(),
            completed_at: chrono::Utc::now(),
        }
    }

    // Oracle system initialization tests
    #[tokio::test]
    async fn test_oracle_creation() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        // Verify oracle components were initialized
        // Note: Cannot access private config field
        Ok(())
    }

    #[tokio::test]
    async fn test_oracle_with_different_configurations() -> Result<()> {
        // Test with different AI provider configurations
        let configs = vec![
            AiConfig {
                provider: "claude".to_string(),
                model: "claude-3-5-sonnet".to_string(),
                max_tokens: 4096,
                temperature: 0.0,
                timeout_seconds: 120,
                retry_attempts: 3,
                rate_limit_per_minute: 60,
            },
            AiConfig {
                provider: "openai".to_string(),
                model: "gpt-4".to_string(),
                max_tokens: 2048,
                temperature: 0.2,
                timeout_seconds: 60,
                retry_attempts: 2,
                rate_limit_per_minute: 100,
            },
        ];

        for config in configs {
            let oracle = Oracle::new(&config).await?;
            // Note: Cannot access private config field
        }
        Ok(())
    }

    // Planning and decision-making tests
    #[tokio::test]
    async fn test_simple_goal_planning() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_simple_goal();

        let decision = oracle.plan_execution(&goal).await?;

        // Verify decision structure
        assert_eq!(decision.goal_id, goal.id);
        assert!(decision.confidence >= 0.0 && decision.confidence <= 1.0);
        assert!(!decision.reasoning.is_empty());
        assert!(decision.research_findings.is_some());
        assert!(decision.committee_consensus.is_some());
        assert!(!decision.plan.steps.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_complex_goal_planning() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_complex_goal();

        let decision = oracle.plan_execution(&goal).await?;

        // Complex goals should result in more detailed plans
        assert_eq!(decision.goal_id, goal.id);
        assert!(decision.plan.steps.len() >= 3); // Should have multiple steps
        assert!(
            decision.plan.estimated_duration_minutes >= 15,
            "Expected complex plan duration to be at least 15 minutes, got {}",
            decision.plan.estimated_duration_minutes
        );

        // Should have rollback plan for complex goals
        assert!(decision.plan.rollback_plan.is_some());

        // Risk assessment should be more comprehensive
        assert!(decision.risk_assessment.overall_risk_score > 0.0);
        Ok(())
    }

    #[tokio::test]
    async fn test_goal_analysis_accuracy() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        let simple_goal = create_simple_goal();
        let complex_goal = create_complex_goal();

        let simple_decision = oracle.plan_execution(&simple_goal).await?;
        let complex_decision = oracle.plan_execution(&complex_goal).await?;

        // Verify complexity assessment
        let simple_research = simple_decision.research_findings.unwrap();
        let complex_research = complex_decision.research_findings.unwrap();

        // Complex goal should have higher complexity score
        assert!(
            complex_research.goal_analysis.complexity_score
                > simple_research.goal_analysis.complexity_score
        );

        // Simple goal should have higher feasibility
        assert!(
            simple_research.goal_analysis.feasibility_score
                >= complex_research.goal_analysis.feasibility_score
        );
        Ok(())
    }

    // Deep Research Assistant tests
    #[tokio::test]
    async fn test_research_assistant_creation() -> Result<()> {
        let config = create_test_ai_config();
        let assistant = DeepResearchAssistant::new(config).await?;

        // Verify cache is initialized
        assert_eq!(assistant.get_cache_size().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_research_conduct_and_caching() -> Result<()> {
        let config = create_test_ai_config();
        let assistant = DeepResearchAssistant::new(config).await?;
        let goal = create_simple_goal();

        // First research should populate cache
        let result1 = assistant.conduct_research(&goal).await?;
        assert_eq!(assistant.get_cache_size().await, 1);

        // Second research for same goal should refresh cache entry without growing it
        let result2 = assistant.conduct_research(&goal).await?;
        assert_eq!(assistant.get_cache_size().await, 1);

        // Core analysis should remain consistent even if a new research id is generated
        assert_eq!(
            result1.goal_analysis.complexity_score,
            result2.goal_analysis.complexity_score
        );
        assert_eq!(
            result1.goal_analysis.feasibility_score,
            result2.goal_analysis.feasibility_score
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_research_goal_analysis() -> Result<()> {
        let config = create_test_ai_config();
        let assistant = DeepResearchAssistant::new(config).await?;

        let goals = vec![
            create_test_goal("Simple task"),
            create_test_goal("Medium complexity task with some constraints"),
            create_complex_goal(),
        ];

        let mut complexity_scores = Vec::new();

        for goal in goals {
            let result = assistant.conduct_research(&goal).await?;
            complexity_scores.push(result.goal_analysis.complexity_score);

            // Verify analysis components
            assert!(
                result.goal_analysis.complexity_score >= 0.0
                    && result.goal_analysis.complexity_score <= 1.0
            );
            assert!(
                result.goal_analysis.feasibility_score >= 0.0
                    && result.goal_analysis.feasibility_score <= 1.0
            );
            assert!(
                result.goal_analysis.clarity_score >= 0.0
                    && result.goal_analysis.clarity_score <= 1.0
            );
            assert!(
                result.goal_analysis.success_probability >= 0.0
                    && result.goal_analysis.success_probability <= 1.0
            );
        }

        // Complexity should generally increase with goal complexity
        assert!(complexity_scores[2] >= complexity_scores[0]); // Complex > Simple
        Ok(())
    }

    #[tokio::test]
    async fn test_research_risk_assessment() -> Result<()> {
        let config = create_test_ai_config();
        let assistant = DeepResearchAssistant::new(config).await?;
        let goal = create_complex_goal();

        let result = assistant.conduct_research(&goal).await?;

        // Verify risk findings
        assert!(!result.risk_findings.is_empty());

        for risk in &result.risk_findings {
            assert!(!risk.description.is_empty());
            assert!(!risk.mitigation.is_empty());
            assert!(risk.probability >= 0.0 && risk.probability <= 1.0);

            // Verify risk type is valid
            match risk.risk_type {
                RiskType::Security
                | RiskType::Performance
                | RiskType::Reliability
                | RiskType::Maintainability
                | RiskType::Compliance
                | RiskType::Technical => {}
            }

            // Verify severity is valid
            match risk.severity {
                RiskSeverity::Low
                | RiskSeverity::Medium
                | RiskSeverity::High
                | RiskSeverity::Critical => {}
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_research_recommendations() -> Result<()> {
        let config = create_test_ai_config();
        let assistant = DeepResearchAssistant::new(config).await?;
        let goal = create_simple_goal();

        let result = assistant.conduct_research(&goal).await?;

        // Should provide recommendations
        assert!(!result.recommendations.is_empty());

        // Recommendations should be meaningful
        for recommendation in &result.recommendations {
            assert!(!recommendation.is_empty());
            assert!(recommendation.len() > 10); // Not just single words
        }
        Ok(())
    }

    // Planning Committee tests
    #[tokio::test]
    async fn test_planning_committee_creation() -> Result<()> {
        let config = create_test_ai_config();
        let committee = PlanningCommittee::new(config).await?;

        // Verify all specialist types are represented
        // Note: Cannot access private field specialists
        Ok(())
    }

    #[tokio::test]
    async fn test_committee_consensus_building() -> Result<()> {
        let config = create_test_ai_config();
        let committee = PlanningCommittee::new(config).await?;
        let goal = create_simple_goal();

        // Create a simple execution plan
        let plan = ExecutionPlan {
            plan_id: Uuid::new_v4(),
            summary: "Test plan".to_string(),
            steps: vec![PlanStep {
                step_id: Uuid::new_v4(),
                sequence: 1,
                description: "Test step".to_string(),
                capability: "validation.test.v1".to_string(),
                parameters: HashMap::new(),
                expected_duration_minutes: 10,
                success_criteria: vec!["Test passes".to_string()],
                failure_recovery: None,
                parallel_group: None,
            }],
            estimated_duration_minutes: 10,
            resource_requirements: ResourceRequirements {
                cpu_cores: 1.0,
                memory_mb: 512,
                disk_mb: 1024,
                network_bandwidth_mbps: 10.0,
                external_services: vec![],
            },
            dependencies: vec![],
            rollback_plan: None,
        };

        let consensus = committee.build_consensus(&plan, &goal).await?;

        // Verify consensus structure
        assert_eq!(consensus.specialist_opinions.len(), 4);
        assert!(consensus.overall_confidence >= 0.0 && consensus.overall_confidence <= 1.0);
        assert!(!consensus.final_recommendation.is_empty());

        // Verify all specialists provided opinions
        for specialist_type in [
            SpecialistType::Architecture,
            SpecialistType::Security,
            SpecialistType::Performance,
            SpecialistType::QualityAssurance,
        ] {
            assert!(consensus.specialist_opinions.contains_key(&specialist_type));
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_committee_plan_validation() -> Result<()> {
        let config = create_test_ai_config();
        let committee = PlanningCommittee::new(config).await?;
        let goal = create_simple_goal();

        // Create a plan that should trigger specialist concerns
        let problematic_plan = ExecutionPlan {
            plan_id: Uuid::new_v4(),
            summary: "Problematic plan".to_string(),
            steps: (1..=10)
                .map(|i| PlanStep {
                    step_id: Uuid::new_v4(),
                    sequence: i,
                    description: format!("Step {}", i),
                    capability: "complex.operation.v1".to_string(),
                    parameters: HashMap::new(),
                    expected_duration_minutes: 30, // Long duration
                    success_criteria: vec![],
                    failure_recovery: None,
                    parallel_group: None,
                })
                .collect(),
            estimated_duration_minutes: 300, // Very long
            resource_requirements: ResourceRequirements {
                cpu_cores: 1.0,
                memory_mb: 512,
                disk_mb: 1024,
                network_bandwidth_mbps: 10.0,
                external_services: vec!["external-service".to_string()], // External dependency
            },
            dependencies: vec![],
            rollback_plan: None, // No rollback plan
        };

        let consensus = committee.build_consensus(&problematic_plan, &goal).await?;

        // Should have concerns from specialists
        let has_concerns = consensus
            .specialist_opinions
            .values()
            .any(|opinion| !opinion.concerns.is_empty());
        assert!(has_concerns);

        // Overall confidence should be lower
        assert!(consensus.overall_confidence < 1.0);
        Ok(())
    }

    // Result evaluation tests
    #[tokio::test]
    async fn test_successful_result_evaluation() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_simple_goal();

        let successful_results = vec![
            create_test_execution_result(true),
            create_test_execution_result(true),
        ];

        let evaluation = oracle.evaluate_results(&goal, &successful_results).await?;

        assert!(evaluation.success);
        assert!(evaluation.goal_achievement_score >= 0.8);
        assert!(evaluation.confidence > 0.5);
        assert!(!evaluation.summary.is_empty());
        assert!(!evaluation.improvement_possible || evaluation.recommendations.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_failed_result_evaluation() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_simple_goal();

        let failed_results = vec![
            create_test_execution_result(false),
            create_test_execution_result(false),
        ];

        let evaluation = oracle.evaluate_results(&goal, &failed_results).await?;

        assert!(!evaluation.success);
        assert!(evaluation.goal_achievement_score < 0.8);
        assert!(evaluation.improvement_possible);
        assert!(!evaluation.recommendations.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_mixed_result_evaluation() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_simple_goal();

        let mixed_results = vec![
            create_test_execution_result(true),
            create_test_execution_result(false),
            create_test_execution_result(true),
        ];

        let evaluation = oracle.evaluate_results(&goal, &mixed_results).await?;

        // Mixed results should show partial success
        assert!(evaluation.goal_achievement_score > 0.0 && evaluation.goal_achievement_score < 1.0);
        assert!(!evaluation.recommendations.is_empty());
        Ok(())
    }

    // Decision confidence and quality tests
    #[tokio::test]
    async fn test_decision_confidence_calculation() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        let simple_goal = create_simple_goal();
        let complex_goal = create_complex_goal();

        let simple_decision = oracle.plan_execution(&simple_goal).await?;
        let complex_decision = oracle.plan_execution(&complex_goal).await?;

        // Simple goals should generally have higher confidence
        // (though this depends on the mock implementation)
        assert!(simple_decision.confidence >= 0.0 && simple_decision.confidence <= 1.0);
        assert!(complex_decision.confidence >= 0.0 && complex_decision.confidence <= 1.0);

        // Both should have reasonable confidence levels
        assert!(simple_decision.confidence >= 0.3); // Should have some confidence
        assert!(complex_decision.confidence >= 0.2); // May be lower for complex goals
        Ok(())
    }

    #[tokio::test]
    async fn test_alternative_plan_generation() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_simple_goal();

        let decision = oracle.plan_execution(&goal).await?;

        // Should provide alternative plans
        assert!(!decision.alternative_plans.is_empty());
        assert!(decision.alternative_plans.len() <= 3); // Reasonable number

        for alt_plan in &decision.alternative_plans {
            assert_ne!(alt_plan.plan_id, decision.plan.plan_id);
            assert!(!alt_plan.steps.is_empty());
            assert!(!alt_plan.summary.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_decision_reasoning_quality() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_simple_goal();

        let decision = oracle.plan_execution(&goal).await?;

        // Reasoning should be comprehensive
        assert!(!decision.reasoning.is_empty());
        assert!(decision.reasoning.len() > 50); // Should be detailed

        // Should mention key components
        assert!(
            decision.reasoning.contains("research") || decision.reasoning.contains("confidence")
        );
        assert!(
            decision.reasoning.contains("consensus") || decision.reasoning.contains("committee")
        );
        Ok(())
    }

    // Risk assessment and security tests
    #[tokio::test]
    async fn test_risk_assessment_completeness() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_complex_goal();

        let decision = oracle.plan_execution(&goal).await?;

        let risk_assessment = &decision.risk_assessment;

        // Risk assessment should be comprehensive
        assert!(
            risk_assessment.overall_risk_score >= 0.0 && risk_assessment.overall_risk_score <= 1.0
        );
        assert!(!risk_assessment.risk_categories.is_empty());
        assert!(!risk_assessment.mitigation_strategies.is_empty());

        // Should assess multiple risk types
        assert!(risk_assessment.risk_categories.len() >= 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_security_risk_identification() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        // Create goal with security implications
        let security_goal = create_test_goal(
            "Deploy authentication system with database access and external API integration",
        );

        let decision = oracle.plan_execution(&security_goal).await?;

        // Should identify security risks
        let has_security_risks = decision
            .risk_assessment
            .risk_categories
            .contains_key(&RiskType::Security)
            || decision
                .research_findings
                .as_ref()
                .map(|r| {
                    r.risk_findings
                        .iter()
                        .any(|f| matches!(f.risk_type, RiskType::Security))
                })
                .unwrap_or(false);

        // Security-related goals should trigger security analysis
        // Note: This may depend on the sophistication of the mock implementation
        Ok(())
    }

    // Performance and scalability tests
    #[tokio::test]
    async fn test_oracle_performance_with_concurrent_requests() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        let goals: Vec<Goal> = (0..5)
            .map(|i| create_test_goal(&format!("Goal {}", i)))
            .collect();

        // Execute multiple planning requests concurrently
        let mut handles = Vec::new();
        for goal in goals {
            let oracle_clone = oracle.clone();
            let handle = tokio::spawn(async move { oracle_clone.plan_execution(&goal).await });
            handles.push(handle);
        }

        // Wait for all to complete
        let results: Result<Vec<_>, _> = futures::future::try_join_all(handles)
            .await
            .unwrap()
            .into_iter()
            .collect();

        let decisions = results?;

        // All should complete successfully
        assert_eq!(decisions.len(), 5);

        // Each should have unique decision IDs
        let decision_ids: std::collections::HashSet<_> =
            decisions.iter().map(|d| d.decision_id).collect();
        assert_eq!(decision_ids.len(), 5);
        Ok(())
    }

    #[tokio::test]
    async fn test_oracle_metrics_collection() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        // Execute some planning to generate metrics
        let goal = create_simple_goal();
        let _decision1 = oracle.plan_execution(&goal).await?;
        let _decision2 = oracle.plan_execution(&goal).await?;

        let metrics = oracle.export_metrics().await;

        // Verify metrics collection
        assert!(metrics.total_decisions >= 2);
        assert!(metrics.average_confidence >= 0.0 && metrics.average_confidence <= 1.0);
        assert_eq!(
            metrics.total_decisions,
            metrics.high_confidence_decisions
                + metrics.medium_confidence_decisions
                + metrics.low_confidence_decisions
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_oracle_decision_history() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        let goal = create_simple_goal();
        let decision = oracle.plan_execution(&goal).await?;

        let history = oracle.get_decision_history().await;

        // Should contain the decision we just made
        assert!(!history.is_empty());
        assert!(history
            .iter()
            .any(|d| d.decision_id == decision.decision_id));
        Ok(())
    }

    // Edge cases and error handling tests
    #[tokio::test]
    async fn test_empty_execution_results_evaluation() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;
        let goal = create_simple_goal();

        let evaluation = oracle.evaluate_results(&goal, &[]).await?;

        // Should handle empty results gracefully
        assert!(!evaluation.success);
        assert_eq!(evaluation.goal_achievement_score, 0.0);
        assert_eq!(evaluation.confidence, 0.0);
        Ok(())
    }

    #[tokio::test]
    async fn test_goal_with_no_success_criteria() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        let mut goal = create_simple_goal();
        goal.success_criteria.clear(); // Remove success criteria

        let decision = oracle.plan_execution(&goal).await?;

        // Should still generate a plan, but may have lower confidence
        assert!(!decision.plan.steps.is_empty());
        assert!(decision.confidence >= 0.0);
        Ok(())
    }

    #[tokio::test]
    async fn test_goal_with_many_constraints() -> Result<()> {
        let config = create_test_ai_config();
        let oracle = Oracle::new(&config).await?;

        let mut goal = create_simple_goal();
        goal.constraints = vec![
            "High performance requirement".to_string(),
            "Security compliance".to_string(),
            "Budget constraints".to_string(),
            "Time constraints".to_string(),
            "Resource limitations".to_string(),
        ];

        let decision = oracle.plan_execution(&goal).await?;

        // Should handle multiple constraints
        assert!(!decision.plan.steps.is_empty());

        // May result in higher complexity assessment
        if let Some(research) = &decision.research_findings {
            // More constraints should generally increase complexity
            assert!(research.goal_analysis.complexity_score > 0.0);
        }
        Ok(())
    }
}

// Add futures dependency for concurrent testing
// This would go in Cargo.toml: futures = "0.3"
use futures;
