//! # Demo Scenarios for Planner-Executor Controller
//!
//! This module provides a comprehensive library of predefined demo scenarios
//! that showcase different workflow patterns and capabilities of the
//! Smith planner-executor controller.
//!
//! ## Scenario Categories
//!
//! - **Simple Linear**: Basic sequential task execution
//! - **Research & Planning**: Deep analysis with planning committee
//! - **Complex Orchestration**: Multi-step workflows with sub-tasks
//! - **Error Recovery**: Scenarios that test stall detection and recovery
//! - **User Intervention**: Interactive workflows requiring human input
//! - **Stress Testing**: High-load scenarios for performance validation

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Workflow execution pattern
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WorkflowPattern {
    /// Simple linear execution (1-10 steps)
    Simple,
    /// Research and analysis focused (5-30 steps)
    Research,
    /// Complex multi-step orchestration (10-100 steps)
    Complex,
    /// Error scenarios for testing recovery (variable steps)
    ErrorRecovery,
    /// Interactive scenarios requiring user input
    Interactive,
    /// Stress testing scenarios
    Stress,
}

impl fmt::Display for WorkflowPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkflowPattern::Simple => write!(f, "simple"),
            WorkflowPattern::Research => write!(f, "research_and_planning"),
            WorkflowPattern::Complex => write!(f, "complex_orchestration"),
            WorkflowPattern::ErrorRecovery => write!(f, "simple"),
            WorkflowPattern::Interactive => write!(f, "research_and_planning"),
            WorkflowPattern::Stress => write!(f, "complex_orchestration"),
        }
    }
}

/// Individual demo scenario definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoScenario {
    /// Scenario name
    pub name: String,
    
    /// Detailed description
    pub description: String,
    
    /// Goal to be executed
    pub goal: String,
    
    /// Workflow pattern/type
    pub pattern: WorkflowPattern,
    
    /// Workflow type string for the executor
    pub workflow_type: String,
    
    /// Maximum execution steps
    pub max_steps: usize,
    
    /// Timeout in seconds
    pub timeout_seconds: Option<u64>,
    
    /// Expected number of steps for progress tracking
    pub expected_steps: usize,
    
    /// Additional context and metadata
    pub context: HashMap<String, serde_json::Value>,
    
    /// Tags for categorization
    pub tags: Vec<String>,
    
    /// Complexity level (1-5)
    pub complexity: u8,
    
    /// Whether this scenario requires user interaction
    pub interactive: bool,
}

/// Library of all available demo scenarios
pub struct ScenarioLibrary {
    scenarios: Vec<DemoScenario>,
}

impl ScenarioLibrary {
    /// Create new scenario library with all predefined scenarios
    pub fn new() -> Self {
        let mut library = Self {
            scenarios: Vec::new(),
        };
        
        // Add all predefined scenarios
        library.add_simple_scenarios();
        library.add_research_scenarios();
        library.add_complex_scenarios();
        library.add_error_recovery_scenarios();
        library.add_interactive_scenarios();
        library.add_stress_scenarios();
        
        library
    }
    
    /// Get all scenarios
    pub fn get_all_scenarios(&self) -> Vec<DemoScenario> {
        self.scenarios.clone()
    }
    
    /// Get scenario by name
    pub fn get_scenario(&self, name: &str) -> Option<DemoScenario> {
        self.scenarios.iter()
            .find(|s| s.name == name)
            .cloned()
    }
    
    /// Get scenarios by pattern
    pub fn get_scenarios_by_pattern(&self, pattern: WorkflowPattern) -> Vec<DemoScenario> {
        self.scenarios.iter()
            .filter(|s| s.pattern == pattern)
            .cloned()
            .collect()
    }
    
    /// Get scenarios by tag
    pub fn get_scenarios_by_tag(&self, tag: &str) -> Vec<DemoScenario> {
        self.scenarios.iter()
            .filter(|s| s.tags.contains(&tag.to_string()))
            .cloned()
            .collect()
    }
    
    /// Get scenarios by complexity level
    pub fn get_scenarios_by_complexity(&self, min_complexity: u8, max_complexity: u8) -> Vec<DemoScenario> {
        self.scenarios.iter()
            .filter(|s| s.complexity >= min_complexity && s.complexity <= max_complexity)
            .cloned()
            .collect()
    }
    
    /// Add simple linear execution scenarios
    fn add_simple_scenarios(&mut self) {
        // File System Operations
        self.scenarios.push(DemoScenario {
            name: "simple-file-ops".to_string(),
            description: "Basic file system operations - read, analyze, and report".to_string(),
            goal: "Read the current directory contents, identify all Rust files, and create a summary report of the project structure".to_string(),
            pattern: WorkflowPattern::Simple,
            workflow_type: "simple".to_string(),
            max_steps: 5,
            timeout_seconds: Some(30),
            expected_steps: 4,
            context: HashMap::from([
                ("domain".into(), "filesystem".into()),
                ("risk_level".into(), "low".into()),
            ]),
            tags: vec!["filesystem".to_string(), "basic".to_string(), "quick".to_string()],
            complexity: 1,
            interactive: false,
        });
        
        // Simple Web Request
        self.scenarios.push(DemoScenario {
            name: "simple-web-request".to_string(),
            description: "Make a simple HTTP request and process the response".to_string(),
            goal: "Fetch the current time from worldtimeapi.org and format it in a user-friendly way".to_string(),
            pattern: WorkflowPattern::Simple,
            workflow_type: "simple".to_string(),
            max_steps: 3,
            timeout_seconds: Some(20),
            expected_steps: 3,
            context: HashMap::from([
                ("domain".into(), "network".into()),
                ("api_endpoint".into(), "http://worldtimeapi.org/api/timezone/UTC".into()),
            ]),
            tags: vec!["network".to_string(), "api".to_string(), "quick".to_string()],
            complexity: 1,
            interactive: false,
        });
        
        // Configuration Analysis
        self.scenarios.push(DemoScenario {
            name: "config-analysis".to_string(),
            description: "Analyze configuration files and validate settings".to_string(),
            goal: "Examine all TOML configuration files in the project, validate their syntax, and identify any missing or deprecated settings".to_string(),
            pattern: WorkflowPattern::Simple,
            workflow_type: "simple".to_string(),
            max_steps: 6,
            timeout_seconds: Some(45),
            expected_steps: 5,
            context: HashMap::from([
                ("domain".into(), "configuration".into()),
                ("file_types".into(), serde_json::json!(["toml", "yaml", "json"])),
            ]),
            tags: vec!["configuration".to_string(), "validation".to_string(), "analysis".to_string()],
            complexity: 2,
            interactive: false,
        });
        
        // Log Processing
        self.scenarios.push(DemoScenario {
            name: "log-processing".to_string(),
            description: "Process and analyze system logs for patterns".to_string(),
            goal: "Scan system logs for the past hour, identify error patterns, and create a summary of issues found".to_string(),
            pattern: WorkflowPattern::Simple,
            workflow_type: "simple".to_string(),
            max_steps: 7,
            timeout_seconds: Some(60),
            expected_steps: 6,
            context: HashMap::from([
                ("domain".into(), "logging".into()),
                ("time_range".into(), "1h".into()),
                ("severity_levels".into(), serde_json::json!(["error", "warn", "critical"])),
            ]),
            tags: vec!["logging".to_string(), "analysis".to_string(), "monitoring".to_string()],
            complexity: 2,
            interactive: false,
        });
    }
    
    /// Add research and planning scenarios
    fn add_research_scenarios(&mut self) {
        // Codebase Analysis
        self.scenarios.push(DemoScenario {
            name: "codebase-analysis".to_string(),
            description: "Comprehensive analysis of codebase architecture and quality".to_string(),
            goal: "Perform a thorough analysis of the Smith platform codebase, including architecture review, dependency analysis, code quality metrics, security assessment, and improvement recommendations".to_string(),
            pattern: WorkflowPattern::Research,
            workflow_type: "research_and_planning".to_string(),
            max_steps: 20,
            timeout_seconds: Some(300),
            expected_steps: 15,
            context: HashMap::from([
                ("domain".into(), "software_analysis".into()),
                ("scope".into(), "full_project".into()),
                ("analysis_types".into(), serde_json::json!([
                    "architecture", "dependencies", "quality", "security", "performance"
                ])),
            ]),
            tags: vec!["research".to_string(), "architecture".to_string(), "quality".to_string()],
            complexity: 4,
            interactive: false,
        });
        
        // Security Audit
        self.scenarios.push(DemoScenario {
            name: "security-audit".to_string(),
            description: "Deep security analysis with vulnerability assessment".to_string(),
            goal: "Conduct a comprehensive security audit of the planner-executor system, including dependency vulnerability scanning, code security analysis, configuration review, and threat modeling".to_string(),
            pattern: WorkflowPattern::Research,
            workflow_type: "research_and_planning".to_string(),
            max_steps: 25,
            timeout_seconds: Some(400),
            expected_steps: 18,
            context: HashMap::from([
                ("domain".into(), "security".into()),
                ("audit_scope".into(), "full_system".into()),
                ("compliance_frameworks".into(), serde_json::json!(["OWASP", "CWE", "NIST"])),
            ]),
            tags: vec!["security".to_string(), "audit".to_string(), "compliance".to_string()],
            complexity: 5,
            interactive: false,
        });
        
        // Performance Optimization Research
        self.scenarios.push(DemoScenario {
            name: "performance-research".to_string(),
            description: "Research-driven performance optimization strategy".to_string(),
            goal: "Research and plan performance optimization strategies for the Smith platform, including profiling analysis, bottleneck identification, optimization techniques research, and implementation roadmap".to_string(),
            pattern: WorkflowPattern::Research,
            workflow_type: "research_and_planning".to_string(),
            max_steps: 18,
            timeout_seconds: Some(250),
            expected_steps: 14,
            context: HashMap::from([
                ("domain".into(), "performance".into()),
                ("focus_areas".into(), serde_json::json!([
                    "cpu_optimization", "memory_usage", "network_io", "concurrency"
                ])),
            ]),
            tags: vec!["performance".to_string(), "optimization".to_string(), "research".to_string()],
            complexity: 4,
            interactive: false,
        });
        
        // Technology Stack Evaluation
        self.scenarios.push(DemoScenario {
            name: "tech-stack-evaluation".to_string(),
            description: "Comprehensive evaluation of alternative technology choices".to_string(),
            goal: "Evaluate alternative technology stacks for the Smith platform, comparing Rust vs other languages, NATS vs other message brokers, and different database options with detailed pros/cons analysis".to_string(),
            pattern: WorkflowPattern::Research,
            workflow_type: "research_and_planning".to_string(),
            max_steps: 22,
            timeout_seconds: Some(350),
            expected_steps: 16,
            context: HashMap::from([
                ("domain".into(), "technology_evaluation".into()),
                ("comparison_areas".into(), serde_json::json!([
                    "languages", "message_brokers", "databases", "frameworks"
                ])),
            ]),
            tags: vec!["research".to_string(), "technology".to_string(), "comparison".to_string()],
            complexity: 4,
            interactive: false,
        });
    }
    
    /// Add complex orchestration scenarios
    fn add_complex_scenarios(&mut self) {
        // Multi-Service Deployment
        self.scenarios.push(DemoScenario {
            name: "multi-service-deployment".to_string(),
            description: "Complex orchestration of multi-service deployment pipeline".to_string(),
            goal: "Orchestrate a complete deployment of the Smith platform including dependency checks, build validation, testing pipeline, service deployment, health checks, and rollback procedures".to_string(),
            pattern: WorkflowPattern::Complex,
            workflow_type: "complex_orchestration".to_string(),
            max_steps: 40,
            timeout_seconds: Some(600),
            expected_steps: 30,
            context: HashMap::from([
                ("domain".into(), "deployment".into()),
                ("services".into(), serde_json::json!([
                    "executor", "planner", "http_client", "tui_client"
                ])),
                ("environments".into(), serde_json::json!(["staging", "production"])),
            ]),
            tags: vec!["deployment".to_string(), "orchestration".to_string(), "complex".to_string()],
            complexity: 5,
            interactive: false,
        });
        
        // Data Migration Workflow
        self.scenarios.push(DemoScenario {
            name: "data-migration".to_string(),
            description: "Complex data migration with validation and rollback".to_string(),
            goal: "Plan and execute a complex data migration for the Smith platform including schema changes, data transformation, validation, migration execution, and rollback planning".to_string(),
            pattern: WorkflowPattern::Complex,
            workflow_type: "complex_orchestration".to_string(),
            max_steps: 35,
            timeout_seconds: Some(500),
            expected_steps: 25,
            context: HashMap::from([
                ("domain".into(), "data_migration".into()),
                ("migration_type".into(), "schema_and_data".into()),
                ("validation_required".into(), true.into()),
            ]),
            tags: vec!["data".to_string(), "migration".to_string(), "complex".to_string()],
            complexity: 5,
            interactive: false,
        });
        
        // Distributed System Health Check
        self.scenarios.push(DemoScenario {
            name: "distributed-health-check".to_string(),
            description: "Comprehensive health monitoring of distributed system".to_string(),
            goal: "Perform a comprehensive health check of the distributed Smith platform including service discovery, connectivity testing, performance monitoring, log analysis, and alerting setup".to_string(),
            pattern: WorkflowPattern::Complex,
            workflow_type: "complex_orchestration".to_string(),
            max_steps: 30,
            timeout_seconds: Some(400),
            expected_steps: 22,
            context: HashMap::from([
                ("domain".into(), "monitoring".into()),
                ("check_types".into(), serde_json::json!([
                    "connectivity", "performance", "resources", "dependencies"
                ])),
            ]),
            tags: vec!["monitoring".to_string(), "health".to_string(), "distributed".to_string()],
            complexity: 4,
            interactive: false,
        });
        
        // Automated Testing Pipeline
        self.scenarios.push(DemoScenario {
            name: "automated-testing-pipeline".to_string(),
            description: "Set up comprehensive automated testing pipeline".to_string(),
            goal: "Create and execute a comprehensive automated testing pipeline including unit tests, integration tests, performance tests, security tests, and quality gates".to_string(),
            pattern: WorkflowPattern::Complex,
            workflow_type: "complex_orchestration".to_string(),
            max_steps: 28,
            timeout_seconds: Some(450),
            expected_steps: 20,
            context: HashMap::from([
                ("domain".into(), "testing".into()),
                ("test_types".into(), serde_json::json!([
                    "unit", "integration", "performance", "security", "e2e"
                ])),
            ]),
            tags: vec!["testing".to_string(), "automation".to_string(), "quality".to_string()],
            complexity: 4,
            interactive: false,
        });
    }
    
    /// Add error recovery and stall detection scenarios
    fn add_error_recovery_scenarios(&mut self) {
        // Network Failure Recovery
        self.scenarios.push(DemoScenario {
            name: "network-failure-recovery".to_string(),
            description: "Test network failure detection and recovery mechanisms".to_string(),
            goal: "Simulate network failures and test the system's ability to detect stalls, implement retry logic, and recover gracefully from network connectivity issues".to_string(),
            pattern: WorkflowPattern::ErrorRecovery,
            workflow_type: "simple".to_string(),
            max_steps: 15,
            timeout_seconds: Some(120),
            expected_steps: 12,
            context: HashMap::from([
                ("domain".into(), "error_recovery".into()),
                ("failure_type".into(), "network".into()),
                ("recovery_strategies".into(), serde_json::json!(["retry", "failover", "circuit_breaker"])),
            ]),
            tags: vec!["error_recovery".to_string(), "network".to_string(), "resilience".to_string()],
            complexity: 3,
            interactive: false,
        });
        
        // Resource Exhaustion Handling
        self.scenarios.push(DemoScenario {
            name: "resource-exhaustion".to_string(),
            description: "Test behavior under resource constraints and exhaustion".to_string(),
            goal: "Test the system's behavior when approaching resource limits including memory, CPU, and file descriptors, and validate graceful degradation".to_string(),
            pattern: WorkflowPattern::ErrorRecovery,
            workflow_type: "simple".to_string(),
            max_steps: 12,
            timeout_seconds: Some(90),
            expected_steps: 10,
            context: HashMap::from([
                ("domain".into(), "resource_management".into()),
                ("resource_types".into(), serde_json::json!(["memory", "cpu", "file_descriptors"])),
            ]),
            tags: vec!["resources".to_string(), "limits".to_string(), "recovery".to_string()],
            complexity: 3,
            interactive: false,
        });
        
        // Invalid Input Handling
        self.scenarios.push(DemoScenario {
            name: "invalid-input-handling".to_string(),
            description: "Test handling of malformed and invalid inputs".to_string(),
            goal: "Test the system's robustness by providing various types of invalid inputs and verifying proper error handling and recovery".to_string(),
            pattern: WorkflowPattern::ErrorRecovery,
            workflow_type: "simple".to_string(),
            max_steps: 10,
            timeout_seconds: Some(60),
            expected_steps: 8,
            context: HashMap::from([
                ("domain".into(), "input_validation".into()),
                ("input_types".into(), serde_json::json!(["malformed_json", "sql_injection", "path_traversal"])),
            ]),
            tags: vec!["security".to_string(), "validation".to_string(), "robustness".to_string()],
            complexity: 2,
            interactive: false,
        });
    }
    
    /// Add interactive scenarios requiring user intervention
    fn add_interactive_scenarios(&mut self) {
        // User-Guided Troubleshooting
        self.scenarios.push(DemoScenario {
            name: "user-guided-troubleshooting".to_string(),
            description: "Interactive troubleshooting with user guidance and decision points".to_string(),
            goal: "Troubleshoot a system issue with user interaction at key decision points, including problem analysis, solution options, and user-guided resolution selection".to_string(),
            pattern: WorkflowPattern::Interactive,
            workflow_type: "research_and_planning".to_string(),
            max_steps: 20,
            timeout_seconds: Some(300),
            expected_steps: 15,
            context: HashMap::from([
                ("domain".into(), "troubleshooting".into()),
                ("interaction_points".into(), serde_json::json!([
                    "problem_confirmation", "solution_selection", "execution_approval"
                ])),
            ]),
            tags: vec!["interactive".to_string(), "troubleshooting".to_string(), "user_guidance".to_string()],
            complexity: 3,
            interactive: true,
        });
        
        // Configuration Wizard
        self.scenarios.push(DemoScenario {
            name: "configuration-wizard".to_string(),
            description: "Interactive configuration setup with user preferences".to_string(),
            goal: "Guide the user through setting up a complex configuration with interactive prompts for preferences, validation of inputs, and generation of final configuration files".to_string(),
            pattern: WorkflowPattern::Interactive,
            workflow_type: "research_and_planning".to_string(),
            max_steps: 25,
            timeout_seconds: Some(400),
            expected_steps: 18,
            context: HashMap::from([
                ("domain".into(), "configuration".into()),
                ("config_sections".into(), serde_json::json!([
                    "network", "security", "performance", "logging"
                ])),
            ]),
            tags: vec!["interactive".to_string(), "configuration".to_string(), "wizard".to_string()],
            complexity: 3,
            interactive: true,
        });
        
        // Code Review Assistant
        self.scenarios.push(DemoScenario {
            name: "code-review-assistant".to_string(),
            description: "Interactive code review with user feedback incorporation".to_string(),
            goal: "Perform an interactive code review session with the user, providing analysis, recommendations, and incorporating user feedback into the final review report".to_string(),
            pattern: WorkflowPattern::Interactive,
            workflow_type: "research_and_planning".to_string(),
            max_steps: 22,
            timeout_seconds: Some(350),
            expected_steps: 16,
            context: HashMap::from([
                ("domain".into(), "code_review".into()),
                ("review_aspects".into(), serde_json::json!([
                    "correctness", "performance", "security", "maintainability"
                ])),
            ]),
            tags: vec!["interactive".to_string(), "code_review".to_string(), "collaboration".to_string()],
            complexity: 4,
            interactive: true,
        });
    }
    
    /// Add stress testing scenarios
    fn add_stress_scenarios(&mut self) {
        // High Concurrency Stress Test
        self.scenarios.push(DemoScenario {
            name: "high-concurrency-stress".to_string(),
            description: "Stress test with high concurrency and throughput".to_string(),
            goal: "Execute a high-concurrency stress test simulating multiple concurrent workflow executions, measuring throughput, latency, and system stability under load".to_string(),
            pattern: WorkflowPattern::Stress,
            workflow_type: "complex_orchestration".to_string(),
            max_steps: 50,
            timeout_seconds: Some(600),
            expected_steps: 35,
            context: HashMap::from([
                ("domain".into(), "stress_testing".into()),
                ("concurrency_level".into(), 50.into()),
                ("duration_minutes".into(), 10.into()),
            ]),
            tags: vec!["stress".to_string(), "concurrency".to_string(), "performance".to_string()],
            complexity: 5,
            interactive: false,
        });
        
        // Memory Pressure Test
        self.scenarios.push(DemoScenario {
            name: "memory-pressure-stress".to_string(),
            description: "Stress test with high memory usage patterns".to_string(),
            goal: "Execute workflows designed to test memory allocation patterns, garbage collection behavior, and system stability under memory pressure".to_string(),
            pattern: WorkflowPattern::Stress,
            workflow_type: "complex_orchestration".to_string(),
            max_steps: 45,
            timeout_seconds: Some(500),
            expected_steps: 30,
            context: HashMap::from([
                ("domain".into(), "memory_testing".into()),
                ("memory_pattern".into(), "incremental_allocation".into()),
                ("gc_testing".into(), true.into()),
            ]),
            tags: vec!["stress".to_string(), "memory".to_string(), "gc".to_string()],
            complexity: 4,
            interactive: false,
        });
        
        // Long Duration Stability Test
        self.scenarios.push(DemoScenario {
            name: "long-duration-stability".to_string(),
            description: "Long-running stability test for memory leaks and degradation".to_string(),
            goal: "Execute a long-duration workflow to test system stability, memory leak detection, and performance degradation over extended periods".to_string(),
            pattern: WorkflowPattern::Stress,
            workflow_type: "complex_orchestration".to_string(),
            max_steps: 100,
            timeout_seconds: Some(1800), // 30 minutes
            expected_steps: 60,
            context: HashMap::from([
                ("domain".into(), "stability_testing".into()),
                ("duration_minutes".into(), 30.into()),
                ("monitoring_interval".into(), 60.into()), // 1 minute
            ]),
            tags: vec!["stress".to_string(), "stability".to_string(), "long_duration".to_string()],
            complexity: 5,
            interactive: false,
        });
    }
    
    /// Create a custom scenario
    pub fn create_custom_scenario(
        name: String,
        description: String,
        goal: String,
        pattern: WorkflowPattern,
        max_steps: usize,
        timeout_seconds: Option<u64>,
    ) -> DemoScenario {
        DemoScenario {
            name,
            description,
            goal,
            workflow_type: pattern.to_string(),
            pattern,
            max_steps,
            timeout_seconds,
            expected_steps: (max_steps as f32 * 0.8) as usize, // Estimate 80% completion
            context: HashMap::new(),
            tags: vec!["custom".to_string()],
            complexity: 3, // Default moderate complexity
            interactive: false,
        }
    }
    
    /// Get scenario statistics
    pub fn get_statistics(&self) -> ScenarioStatistics {
        let total = self.scenarios.len();
        let by_pattern = self.scenarios.iter()
            .fold(HashMap::new(), |mut acc, scenario| {
                *acc.entry(scenario.pattern.clone()).or_insert(0) += 1;
                acc
            });
        
        let by_complexity = self.scenarios.iter()
            .fold(HashMap::new(), |mut acc, scenario| {
                *acc.entry(scenario.complexity).or_insert(0) += 1;
                acc
            });
        
        let interactive_count = self.scenarios.iter()
            .filter(|s| s.interactive)
            .count();
        
        ScenarioStatistics {
            total,
            by_pattern,
            by_complexity,
            interactive_count,
        }
    }
}

/// Statistics about the scenario library
#[derive(Debug, Serialize, Deserialize)]
pub struct ScenarioStatistics {
    pub total: usize,
    pub by_pattern: HashMap<WorkflowPattern, usize>,
    pub by_complexity: HashMap<u8, usize>,
    pub interactive_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scenario_library_creation() {
        let library = ScenarioLibrary::new();
        let scenarios = library.get_all_scenarios();
        
        assert!(!scenarios.is_empty());
        assert!(scenarios.len() > 10); // Should have a good variety
    }
    
    #[test]
    fn test_scenario_filtering() {
        let library = ScenarioLibrary::new();
        
        // Test pattern filtering
        let simple_scenarios = library.get_scenarios_by_pattern(WorkflowPattern::Simple);
        assert!(!simple_scenarios.is_empty());
        assert!(simple_scenarios.iter().all(|s| s.pattern == WorkflowPattern::Simple));
        
        // Test complexity filtering
        let easy_scenarios = library.get_scenarios_by_complexity(1, 2);
        assert!(!easy_scenarios.is_empty());
        assert!(easy_scenarios.iter().all(|s| s.complexity >= 1 && s.complexity <= 2));
        
        // Test tag filtering
        let security_scenarios = library.get_scenarios_by_tag("security");
        assert!(!security_scenarios.is_empty());
        assert!(security_scenarios.iter().all(|s| s.tags.contains(&"security".to_string())));
    }
    
    #[test]
    fn test_scenario_retrieval() {
        let library = ScenarioLibrary::new();
        
        // Test getting specific scenario
        let scenario = library.get_scenario("simple-file-ops");
        assert!(scenario.is_some());
        
        let scenario = scenario.unwrap();
        assert_eq!(scenario.name, "simple-file-ops");
        assert_eq!(scenario.pattern, WorkflowPattern::Simple);
    }
    
    #[test]
    fn test_custom_scenario_creation() {
        let scenario = ScenarioLibrary::create_custom_scenario(
            "test-scenario".to_string(),
            "Test description".to_string(),
            "Test goal".to_string(),
            WorkflowPattern::Simple,
            5,
            Some(60),
        );
        
        assert_eq!(scenario.name, "test-scenario");
        assert_eq!(scenario.pattern, WorkflowPattern::Simple);
        assert_eq!(scenario.max_steps, 5);
        assert_eq!(scenario.timeout_seconds, Some(60));
        assert!(scenario.tags.contains(&"custom".to_string()));
    }
    
    #[test]
    fn test_scenario_statistics() {
        let library = ScenarioLibrary::new();
        let stats = library.get_statistics();
        
        assert!(stats.total > 0);
        assert!(!stats.by_pattern.is_empty());
        assert!(!stats.by_complexity.is_empty());
        
        // Verify counts add up
        let pattern_total: usize = stats.by_pattern.values().sum();
        assert_eq!(pattern_total, stats.total);
        
        let complexity_total: usize = stats.by_complexity.values().sum();
        assert_eq!(complexity_total, stats.total);
    }
    
    #[test]
    fn test_workflow_pattern_display() {
        assert_eq!(WorkflowPattern::Simple.to_string(), "simple");
        assert_eq!(WorkflowPattern::Research.to_string(), "research_and_planning");
        assert_eq!(WorkflowPattern::Complex.to_string(), "complex_orchestration");
    }
    
    #[test]
    fn test_scenario_validation() {
        let library = ScenarioLibrary::new();
        let scenarios = library.get_all_scenarios();
        
        for scenario in scenarios {
            // Basic validation
            assert!(!scenario.name.is_empty());
            assert!(!scenario.description.is_empty());
            assert!(!scenario.goal.is_empty());
            assert!(scenario.max_steps > 0);
            assert!(scenario.expected_steps <= scenario.max_steps);
            assert!(scenario.complexity >= 1 && scenario.complexity <= 5);
            
            // Validate timeout if set
            if let Some(timeout) = scenario.timeout_seconds {
                assert!(timeout > 0);
            }
            
            // Interactive scenarios should have appropriate patterns
            if scenario.interactive {
                assert!(matches!(scenario.pattern, 
                    WorkflowPattern::Interactive | 
                    WorkflowPattern::Research | 
                    WorkflowPattern::Complex
                ));
            }
        }
    }
}