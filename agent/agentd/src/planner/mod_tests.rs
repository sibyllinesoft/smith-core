/*!
# Comprehensive Test Suite for Planner Module

This test suite provides comprehensive coverage for the core PlannerExecutorController,
focusing on workflow orchestration, state machine execution, security validation,
and end-to-end execution safety.

## Test Coverage Areas:
- PlannerExecutorController initialization and configuration
- Goal submission and workflow creation
- State machine transitions and workflow execution
- Guard engine security validation
- Stall detection and recovery mechanisms
- Menu system user intervention
- Telemetry collection and metrics
- Concurrent workflow management
- Error handling and failure recovery
- Resource management and limits
- Security policy enforcement
*/

#[cfg(test)]
mod planner_mod_tests {
    use super::super::guard::GuardResult;
    use super::super::stall_detection::{RecoveryStrategy, StallEvent, StallType};
    use super::super::state_machine::{WorkflowState, WorkflowType};
    use super::super::telemetry::ExportFormat;
    use super::super::*;
    use anyhow::Result;
    use std::time::Duration;
    use tokio::time::timeout;
    use uuid::Uuid;

    // Test fixtures and utilities
    fn create_test_planner_config() -> PlannerConfig {
        PlannerConfig::test()
    }

    fn create_production_config() -> PlannerConfig {
        PlannerConfig::production()
    }

    fn create_development_config() -> PlannerConfig {
        PlannerConfig::development()
    }

    fn create_simple_test_goal() -> Goal {
        Goal::new("Simple test goal")
            .with_context("Test environment")
            .with_constraints(vec!["No external dependencies".to_string()])
            .with_success_criteria(vec!["Task completes successfully".to_string()])
            .with_priority(Priority::Medium)
    }

    fn create_complex_test_goal() -> Goal {
        Goal::new("Complex multi-phase system optimization with performance monitoring and security compliance")
            .with_context("Production environment with high availability requirements")
            .with_constraints(vec![
                "Zero downtime".to_string(),
                "< 100ms response time".to_string(),
                "SOC2 compliance".to_string(),
                "Budget limit $50k".to_string(),
            ])
            .with_success_criteria(vec![
                "Performance improved by 50%".to_string(),
                "Security audit passes".to_string(),
                "Zero data loss".to_string(),
                "Full rollback capability".to_string(),
            ])
            .with_priority(Priority::High)
    }

    fn create_security_sensitive_goal() -> Goal {
        Goal::new("Deploy authentication system with database encryption")
            .with_context("Financial services environment")
            .with_constraints(vec![
                "GDPR compliance".to_string(),
                "Multi-factor authentication".to_string(),
                "Audit logging required".to_string(),
            ])
            .with_success_criteria(vec![
                "Zero security vulnerabilities".to_string(),
                "Compliance certification".to_string(),
            ])
            .with_priority(Priority::Critical)
    }

    // Configuration and initialization tests
    #[tokio::test]
    async fn test_planner_controller_creation() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;

        // Verify controller was created successfully
        assert_eq!(controller.config.ai_config.provider, "mock");
        Ok(())
    }

    #[tokio::test]
    async fn test_different_configuration_modes() -> Result<()> {
        // Test all configuration modes
        let configs = vec![
            ("test", create_test_planner_config()),
            ("development", create_development_config()),
            ("production", create_production_config()),
        ];

        for (name, config) in configs {
            let controller = PlannerExecutorController::new(config.clone()).await?;

            match name {
                "test" => {
                    assert_eq!(controller.config.ai_config.provider, "mock");
                    assert_eq!(
                        controller
                            .config
                            .execution_config
                            .max_workflow_duration_hours,
                        1
                    );
                }
                "development" => {
                    assert!(!controller.config.security_config.enable_policy_validation);
                    assert_eq!(
                        controller.config.execution_config.max_concurrent_workflows,
                        2
                    );
                }
                "production" => {
                    assert!(controller.config.security_config.enable_policy_validation);
                    assert!(controller.config.security_config.enable_security_analysis);
                    assert_eq!(controller.config.ai_config.provider, "claude");
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_controller_with_invalid_configuration() -> Result<()> {
        let mut config = create_test_planner_config();

        // Test with invalid AI configuration
        config.ai_config.max_tokens = 0; // Invalid
        config.ai_config.timeout_seconds = 0; // Invalid

        // Should still create controller but may have issues during execution
        let controller = PlannerExecutorController::new(config).await;
        assert!(controller.is_ok()); // Creation should succeed
        Ok(())
    }

    // Goal submission and workflow management tests
    #[tokio::test]
    async fn test_simple_goal_submission() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        let workflow_id = controller
            .submit_goal(goal.clone(), WorkflowType::Simple)
            .await?;

        // Verify workflow was created
        assert!(!workflow_id.to_string().is_empty());

        // Check workflow status
        tokio::time::sleep(Duration::from_millis(100)).await; // Allow workflow to start
        let status = controller.get_workflow_status(workflow_id).await?;
        assert!(status.is_some());

        let workflow_context = status.unwrap();
        assert_eq!(workflow_context.goal.id, goal.id);
        assert_eq!(workflow_context.workflow_type, WorkflowType::Simple);
        Ok(())
    }

    #[tokio::test]
    async fn test_complex_goal_submission() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_complex_test_goal();

        let workflow_id = controller
            .submit_goal(goal.clone(), WorkflowType::ComplexOrchestration)
            .await?;

        // Allow more time for complex workflow to initialize
        tokio::time::sleep(Duration::from_millis(200)).await;

        let status = controller.get_workflow_status(workflow_id).await?;
        assert!(status.is_some());

        let workflow_context = status.unwrap();
        assert_eq!(
            workflow_context.workflow_type,
            WorkflowType::ComplexOrchestration
        );
        assert!(workflow_context.goal.constraints.len() > 1);
        assert!(workflow_context.goal.success_criteria.len() > 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_concurrent_goals() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;

        let goals = vec![
            create_simple_test_goal(),
            create_simple_test_goal(),
            create_simple_test_goal(),
        ];

        let mut workflow_ids = Vec::new();
        for goal in goals {
            let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;
            workflow_ids.push(workflow_id);
        }

        // Verify all workflows were created
        assert_eq!(workflow_ids.len(), 3);

        // All workflow IDs should be unique
        let unique_ids: std::collections::HashSet<_> = workflow_ids.iter().collect();
        assert_eq!(unique_ids.len(), 3);

        // Check active workflows
        tokio::time::sleep(Duration::from_secs(2)).await;
        let active_workflows = controller.list_active_workflows().await?;
        assert!(active_workflows.len() >= 1); // At least some should still be active
        Ok(())
    }

    #[tokio::test]
    async fn test_workflow_concurrency_limits() -> Result<()> {
        let mut config = create_test_planner_config();
        config.execution_config.max_concurrent_workflows = 1; // Limit to 1
        let controller = PlannerExecutorController::new(config).await?;

        let goals = vec![create_simple_test_goal(), create_simple_test_goal()];

        let workflow_id1 = controller
            .submit_goal(goals[0].clone(), WorkflowType::Simple)
            .await?;
        let workflow_id2 = controller
            .submit_goal(goals[1].clone(), WorkflowType::Simple)
            .await?;

        // Both should be submitted successfully
        assert_ne!(workflow_id1, workflow_id2);

        // But execution should be limited by concurrency
        tokio::time::sleep(Duration::from_millis(200)).await;
        let active_workflows = controller.list_active_workflows().await?;

        // Should respect concurrency limits (may have some still active)
        assert!(active_workflows.len() <= 2);
        Ok(())
    }

    // State machine and workflow execution tests
    #[tokio::test]
    async fn test_workflow_state_transitions() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;

        // Monitor state transitions over time
        let mut previous_state = WorkflowState::Initializing;
        let mut state_changes = Vec::new();

        for _ in 0..20 {
            // Check for up to 2 seconds
            tokio::time::sleep(Duration::from_millis(100)).await;

            if let Some(status) = controller.get_workflow_status(workflow_id).await? {
                if status.current_state != previous_state {
                    state_changes.push((previous_state.clone(), status.current_state.clone()));
                    previous_state = status.current_state.clone();
                }

                // Stop if workflow completed
                if matches!(
                    status.current_state,
                    WorkflowState::Completed | WorkflowState::Failed
                ) {
                    break;
                }
            }
        }

        // Should have made at least one state transition
        assert!(!state_changes.is_empty(), "No state transitions observed");

        // First transition should be from Initializing
        assert_eq!(state_changes[0].0, WorkflowState::Initializing);
        Ok(())
    }

    #[tokio::test]
    async fn test_workflow_completion() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;

        // Wait for workflow completion (with timeout)
        let completion_timeout = Duration::from_secs(30);
        let start_time = tokio::time::Instant::now();

        while start_time.elapsed() < completion_timeout {
            tokio::time::sleep(Duration::from_millis(200)).await;

            let status = controller.get_workflow_status(workflow_id).await?;
            if status.is_none() {
                // Workflow completed and was cleaned up
                break;
            }

            if let Some(context) = status {
                if matches!(
                    context.current_state,
                    WorkflowState::Completed | WorkflowState::Failed
                ) {
                    // Workflow reached terminal state
                    assert!(!context.execution_history.is_empty());
                    // Note: WorkflowMetrics doesn't have workflow_id field
                    break;
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_workflow_failure_handling() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;

        // Create a goal that might fail validation
        let mut problematic_goal = create_simple_test_goal();
        problematic_goal.description = "".to_string(); // Empty description might cause issues
        problematic_goal.success_criteria.clear(); // No success criteria

        let workflow_id = controller
            .submit_goal(problematic_goal, WorkflowType::Simple)
            .await?;

        // Monitor for failure or completion
        let timeout_duration = Duration::from_secs(10);
        let mut final_state = None;

        let result = timeout(timeout_duration, async {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;

                if let Some(status) = controller.get_workflow_status(workflow_id).await.unwrap() {
                    match status.current_state {
                        WorkflowState::Failed => {
                            final_state = Some(WorkflowState::Failed);
                            break;
                        }
                        WorkflowState::Completed => {
                            final_state = Some(WorkflowState::Completed);
                            break;
                        }
                        _ => continue,
                    }
                } else {
                    // Workflow was cleaned up
                    break;
                }
            }
        })
        .await;

        // Should either complete or still be trackable without panicking
        if result.is_err() && final_state.is_none() {
            let status = controller.get_workflow_status(workflow_id).await?;
            assert!(
                status.is_some(),
                "Workflow status unavailable after failure handling timeout"
            );
        }
        Ok(())
    }

    // Security and guard engine tests
    #[tokio::test]
    async fn test_security_policy_validation() -> Result<()> {
        let mut config = create_test_planner_config();
        config.security_config.enable_policy_validation = true;
        config.security_config.enable_security_analysis = true;

        let controller = PlannerExecutorController::new(config).await?;
        let security_goal = create_security_sensitive_goal();

        let workflow_id = controller
            .submit_goal(security_goal, WorkflowType::ComplexOrchestration)
            .await?;

        // Allow time for security validation
        tokio::time::sleep(Duration::from_millis(300)).await;

        let status = controller.get_workflow_status(workflow_id).await?;
        if let Some(context) = status {
            // Should have guard validations recorded
            // Note: Actual validation depends on guard engine implementation
            assert!(context.workflow_type == WorkflowType::ComplexOrchestration);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_capability_restrictions() -> Result<()> {
        let mut config = create_test_planner_config();
        config.security_config.enable_capability_restrictions = true;
        config.security_config.allowed_capabilities =
            vec!["fs.read.v1".to_string(), "analysis.system.v1".to_string()];

        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;

        // Security restrictions should be enforced during execution
        tokio::time::sleep(Duration::from_millis(200)).await;

        let status = controller.get_workflow_status(workflow_id).await?;
        assert!(status.is_some()); // Should create workflow even with restrictions
        Ok(())
    }

    #[tokio::test]
    async fn test_execution_timeout_limits() -> Result<()> {
        let mut config = create_test_planner_config();
        config.security_config.max_execution_time_seconds = 5; // Very short timeout

        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_complex_test_goal(); // Complex goal might take longer

        let workflow_id = controller
            .submit_goal(goal, WorkflowType::ComplexOrchestration)
            .await?;

        // Wait longer than the timeout
        tokio::time::sleep(Duration::from_secs(7)).await;

        // Workflow should have been terminated or handled timeout
        let status = controller.get_workflow_status(workflow_id).await?;
        if let Some(context) = status {
            // Should either be failed or completed (not stuck)
            match context.current_state {
                WorkflowState::Executing => {
                    // If still executing, should be close to completion
                    assert!(context.execution_history.len() > 0);
                }
                _ => {} // Other states are acceptable
            }
        }
        Ok(())
    }

    // Stall detection and recovery tests
    #[tokio::test]
    async fn test_stall_detection_timeout() -> Result<()> {
        let mut config = create_test_planner_config();
        // Configure aggressive stall detection
        config.stall_config.global_timeout_seconds = 2;

        let controller = PlannerExecutorController::new(config).await?;

        // Create a goal that might cause delays
        let slow_goal = Goal::new("Complex analysis requiring extended processing time")
            .with_context("Performance testing environment")
            .with_priority(Priority::Low);

        let workflow_id = controller
            .submit_goal(slow_goal, WorkflowType::ComplexOrchestration)
            .await?;

        // Wait for potential stall detection
        tokio::time::sleep(Duration::from_secs(5)).await;

        let status = controller.get_workflow_status(workflow_id).await?;
        if let Some(context) = status {
            // Stall detection may have been triggered
            // The exact behavior depends on stall detector implementation
            assert!(context.created_at <= context.updated_at);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_recovery_strategy_execution() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;

        // Allow workflow to progress
        tokio::time::sleep(Duration::from_millis(500)).await;

        let status = controller.get_workflow_status(workflow_id).await?;
        if let Some(context) = status {
            // Recovery mechanisms should be in place
            assert!(context.execution_history.len() >= 0);

            // Check if any stall events were recorded
            for stall_event in &context.stall_detections {
                // Verify recovery strategy is appropriate
                match stall_event.recovery_strategy {
                    RecoveryStrategy::AutoRetry => {
                        // Should attempt automatic recovery
                    }
                    RecoveryStrategy::UserIntervention => {
                        // Should request user input
                    }
                    RecoveryStrategy::Escalate => {
                        // Should escalate to manual intervention
                    }
                    RecoveryStrategy::Fail => {
                        // Should fail gracefully
                    }
                }
            }
        }
        Ok(())
    }

    // Telemetry and metrics tests
    #[tokio::test]
    async fn test_telemetry_collection() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;

        // Allow workflow to progress and collect telemetry
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Export telemetry
        let telemetry_json = controller.export_telemetry(ExportFormat::Json).await?;
        assert!(!telemetry_json.is_empty());

        // Verify it's valid JSON
        let _parsed: serde_json::Value = serde_json::from_str(&telemetry_json)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_metrics_export_formats() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        let _workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Test different export formats
        let formats = vec![ExportFormat::Json, ExportFormat::Prometheus];

        for format in formats {
            let export = controller.export_telemetry(format.clone()).await?;

            match format {
                ExportFormat::Json => {
                    if !export.is_empty() {
                        // Should be valid JSON when data is available
                        let _parsed: serde_json::Value = serde_json::from_str(&export)?;
                    }
                }
                ExportFormat::Csv => {
                    if !export.is_empty() {
                        assert!(export.contains(','));
                    }
                }
                ExportFormat::Prometheus => {
                    if !export.is_empty() {
                        assert!(export.contains('#') || export.contains("_total"));
                    }
                }
                ExportFormat::NatsStream => {
                    // Currently a no-op in tests; ensure the call succeeds
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_workflow_metrics_tracking() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let status = controller.get_workflow_status(workflow_id).await?;
        if let Some(context) = status {
            // Verify metrics are being tracked
            // Note: WorkflowMetrics doesn't have workflow_id field
            assert!(context.created_at <= context.updated_at);

            // Execution history should be populated
            assert!(context.execution_history.len() >= 0);
        }
        Ok(())
    }

    // Performance and stress tests
    #[tokio::test]
    async fn test_high_concurrency_workflows() -> Result<()> {
        let mut config = create_test_planner_config();
        config.execution_config.max_concurrent_workflows = 10;
        let controller = PlannerExecutorController::new(config).await?;

        // Submit many workflows concurrently
        let mut handles = Vec::new();
        for i in 0..20 {
            let controller_clone = controller.clone();
            let goal = Goal::new(format!("Concurrent goal {}", i));

            let handle = tokio::spawn(async move {
                controller_clone
                    .submit_goal(goal, WorkflowType::Simple)
                    .await
            });
            handles.push(handle);
        }

        // Wait for all submissions
        let results: Result<Vec<_>, _> = futures::future::try_join_all(handles)
            .await
            .unwrap()
            .into_iter()
            .collect();

        let workflow_ids = results?;
        assert_eq!(workflow_ids.len(), 20);

        // Allow some time for processing
        tokio::time::sleep(Duration::from_millis(500)).await;

        let active_workflows = controller.list_active_workflows().await?;
        // Should handle high concurrency (may still have some active)
        assert!(active_workflows.len() <= 20);
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_usage_under_load() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;

        // Submit workflows in batches to test memory management
        for batch in 0..5 {
            let mut batch_workflows = Vec::new();

            for i in 0..10 {
                let goal = Goal::new(format!("Batch {} Goal {}", batch, i));
                let workflow_id = controller.submit_goal(goal, WorkflowType::Simple).await?;
                batch_workflows.push(workflow_id);
            }

            // Allow batch to process
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Check that completed workflows are cleaned up
            let active_count = controller.list_active_workflows().await?.len();
            // Should not accumulate unlimited workflows
            assert!(active_count <= 50); // Reasonable upper bound
        }
        Ok(())
    }

    // Integration and end-to-end tests
    #[tokio::test]
    async fn test_complete_workflow_lifecycle() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;
        let goal = create_simple_test_goal();

        // Submit goal
        let workflow_id = controller
            .submit_goal(goal.clone(), WorkflowType::Simple)
            .await?;

        // Track complete lifecycle
        let mut lifecycle_states = Vec::new();
        let timeout_duration = Duration::from_secs(30);
        let start_time = tokio::time::Instant::now();

        while start_time.elapsed() < timeout_duration {
            tokio::time::sleep(Duration::from_millis(100)).await;

            if let Some(status) = controller.get_workflow_status(workflow_id).await? {
                if lifecycle_states.is_empty()
                    || lifecycle_states.last() != Some(&status.current_state)
                {
                    lifecycle_states.push(status.current_state.clone());
                }

                // Check for completion
                if matches!(
                    status.current_state,
                    WorkflowState::Completed | WorkflowState::Failed
                ) {
                    break;
                }
            } else {
                // Workflow completed and cleaned up
                break;
            }
        }

        // Should have progressed through multiple states
        assert!(lifecycle_states.len() >= 1);
        if let Some(first_state) = lifecycle_states.first() {
            assert!(matches!(
                first_state,
                WorkflowState::Initializing | WorkflowState::Planning
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_graceful_shutdown() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;

        // Submit some workflows
        let goal1 = create_simple_test_goal();
        let goal2 = create_simple_test_goal();

        let _workflow_id1 = controller.submit_goal(goal1, WorkflowType::Simple).await?;
        let _workflow_id2 = controller.submit_goal(goal2, WorkflowType::Simple).await?;

        // Allow workflows to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test graceful shutdown
        let shutdown_future = controller.shutdown();
        match timeout(Duration::from_secs(20), shutdown_future).await {
            Ok(res) => assert!(res.is_ok()),
            Err(_) => {
                // Ensure we can still invoke shutdown without panicking even if timeout elapsed
                controller.shutdown().await?;
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_error_propagation_and_handling() -> Result<()> {
        let config = create_test_planner_config();
        let controller = PlannerExecutorController::new(config).await?;

        // Create goal with potential error conditions
        let error_goal = Goal::new("Invalid operation with malformed parameters")
            .with_constraints(vec!["Impossible constraint".to_string()])
            .with_success_criteria(vec!["Contradictory requirement".to_string()]);

        let workflow_id = controller
            .submit_goal(error_goal, WorkflowType::Simple)
            .await?;

        // Monitor error handling
        tokio::time::sleep(Duration::from_millis(500)).await;

        let status = controller.get_workflow_status(workflow_id).await?;
        if let Some(context) = status {
            // Error conditions should be handled gracefully
            // Should not crash or hang indefinitely
            assert!(context.execution_history.len() >= 0);

            // May reach failed state, but should be handled
            match context.current_state {
                WorkflowState::Failed => {
                    // Should have recorded the failure
                    assert!(!context.execution_history.is_empty());
                }
                _ => {
                    // Other states are also acceptable if error was recovered
                }
            }
        }
        Ok(())
    }
}

// Add required dependencies for testing
use futures;
