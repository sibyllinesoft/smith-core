//! Benchmark event protocol for Smith agent optimization
//!
//! This module defines the complete event schema for collecting agent performance
//! data to optimize Smith's performance on coding benchmarks like SWE-bench.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// Core benchmark event with required tracking fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkEvent {
    // Required IDs for event correlation
    pub run_id: Uuid,
    pub task_id: String,
    pub step_id: Uuid,
    pub ts: DateTime<Utc>,
    pub policy_id: String,
    pub cfg_hash: String,
    pub env_hash: String,
    pub seed: u64,

    // Event payload
    pub event_type: BenchmarkEventType,
    pub data: serde_json::Value,
}

/// All benchmark event types for agent optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BenchmarkEventType {
    RunStart(RunConfig),
    RunStop(RunResult),
    Step(StepData),
    ToolCall(ToolPerformance),
    ContextDecision(PruningDecision),
    Failure(FailureAnalysis),
    OptimizerUpdate(ConfigSuggestion),
}

/// Configuration for a benchmark run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    // Agent behavior parameters
    pub max_iterations: usize,
    pub temperature: f32,
    pub context_window: usize,
    pub pruning_threshold: f32,
    pub planner_depth: usize,
    pub debate_rounds: usize,

    // Tool configuration
    pub available_tools: Vec<String>,
    pub tool_timeout_ms: u64,
    pub retry_policy: RetryPolicy,

    // Early stopping criteria
    pub execution_timeout: Duration,
    pub failing_tests_patience: usize,
    pub no_progress_timeout: Duration,

    // Environment settings
    pub docker_image: String,
    pub tools_commit: String,
    pub sandbox_limits: SandboxLimits,
}

/// Results from a completed benchmark run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    // Core success metrics (for reward function)
    pub success: bool,
    pub wall_time_ms: u64,
    pub total_tokens: u64,
    pub tool_errors: u32,
    pub stability_variance: f64,

    // Detailed results
    pub final_score: f64,
    pub failing_tests: Vec<String>,
    pub tests_passed: u32,
    pub tests_failed: u32,
    pub files_modified: u32,
    pub early_stopped: bool,
    pub early_stop_reason: Option<String>,
}

/// Individual reasoning/action step data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepData {
    pub step_type: StepType,
    pub content: String,
    pub tokens_in: u32,
    pub tokens_out: u32,
    pub wall_time_ms: u64,
    pub planned_step: bool,
    pub context_kb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepType {
    Reason,
    Act,
    Observe,
    Conclude,
    Plan,
    Debate,
}

/// Tool performance metrics for optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPerformance {
    pub tool_name: String,
    pub tool_args_hash: String,
    pub latency_ms: u64,
    pub retries: u32,
    pub exit_kind: ExitKind,
    pub evidence_footprint: EvidenceFootprint,
    pub user_feedback_score: Option<f32>,
    pub intent_accuracy: Option<f32>, // Did tool do what agent wanted?
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExitKind {
    Ok,
    Deterministic(String),
    Flake(String),
    Oom,
    Timeout,
    UserError(String),
    SystemError(String),
}

/// Evidence of tool's impact on the codebase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFootprint {
    pub files_read: Vec<String>,
    pub files_modified: Vec<String>,
    pub lines_changed: usize,
    pub tests_added: usize,
    pub tests_modified: usize,
    pub bytes_read: usize,
    pub bytes_written: usize,
}

/// Context pruning decisions for optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningDecision {
    pub segment_id: String,
    pub kept: bool,
    pub segment_kb: usize,
    pub segment_type: SegmentType,
    pub impact_probe_ev: Option<f64>, // Expected value from shadow replay
    pub pruning_algorithm: String,
    pub confidence_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SegmentType {
    FileContent,
    SearchResults,
    ConversationHistory,
    ToolOutput,
    ReasoningContext,
    Documentation,
    ErrorLogs,
}

/// Structured failure analysis for learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureAnalysis {
    pub first_failure_root: FailureRoot,
    pub recovery_attempts: Vec<RecoveryAttempt>,
    pub final_error_state: ErrorState,
    pub contributing_factors: Vec<String>,
    pub remediation_suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailureRoot {
    Build {
        error_type: String,
        command: String,
    },
    Import {
        missing_module: String,
        suggested_fix: String,
    },
    Path {
        invalid_path: String,
        expected_location: String,
    },
    Flake {
        flaky_test: String,
        failure_rate: f64,
    },
    Semantic {
        logic_error: String,
        context: String,
    },
    Planning {
        reasoning_error: String,
        step_number: usize,
    },
    Context {
        missing_info: String,
        pruning_error: bool,
    },
    Tool {
        tool_name: String,
        usage_error: String,
    },
}

/// Recovery attempt during failure handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAttempt {
    pub strategy: String,
    pub success: bool,
    pub time_spent_ms: u64,
    pub side_effects: Vec<String>,
}

/// Final error state classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorState {
    pub recoverable: bool,
    pub error_category: String,
    pub confidence: f64,
    pub similar_failures: u32,
}

/// Optimizer configuration suggestions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSuggestion {
    pub suggested_config: RunConfig,
    pub confidence: f64,
    pub expected_improvement: f64,
    pub exploration_vs_exploitation: f64,
    pub reasoning: String,
}

/// Task features for contextual optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskFeatures {
    pub repo_size_mb: f64,
    pub file_count: u32,
    pub language_mix: HashMap<String, f64>,
    pub dependency_count: u32,
    pub test_count: u32,
    pub complexity_score: f64,
    pub domain: String,
    pub historical_failure_rate: f64,
    pub avg_completion_time_ms: u64,
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff_ms: u64,
    pub exponential_backoff: bool,
    pub retry_on_flake: bool,
    pub retry_on_timeout: bool,
}

/// Sandbox resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxLimits {
    pub memory_mb: u32,
    pub cpu_cores: f32,
    pub disk_mb: u32,
    pub network_enabled: bool,
    pub execution_timeout_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_ms: 1000,
            exponential_backoff: true,
            retry_on_flake: true,
            retry_on_timeout: true,
        }
    }
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            memory_mb: 4096,
            cpu_cores: 2.0,
            disk_mb: 10240,
            network_enabled: true,
            execution_timeout_ms: 600000, // 10 minutes
        }
    }
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            temperature: 0.7,
            context_window: 8192,
            pruning_threshold: 0.8,
            planner_depth: 3,
            debate_rounds: 2,
            available_tools: vec![
                "bash".to_string(),
                "str_replace_editor".to_string(),
                "grep".to_string(),
            ],
            tool_timeout_ms: 30000,
            retry_policy: RetryPolicy::default(),
            execution_timeout: Duration::from_secs(600),
            failing_tests_patience: 3,
            no_progress_timeout: Duration::from_secs(300),
            docker_image: "smith:latest".to_string(),
            tools_commit: "main".to_string(),
            sandbox_limits: SandboxLimits::default(),
        }
    }
}

impl RunConfig {
    /// Generate deterministic hash for configuration reproducibility
    pub fn hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let serialized = serde_json::to_string(self).expect("Failed to serialize RunConfig");

        let mut hasher = DefaultHasher::new();
        serialized.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Generate environment hash for reproducibility
    pub fn env_hash(&self) -> String {
        let env_string = format!(
            "{}:{}:{:?}",
            self.docker_image, self.tools_commit, self.sandbox_limits
        );

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        env_string.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

impl BenchmarkEvent {
    /// Create a new benchmark event with automatic timestamp
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: Uuid,
        task_id: String,
        step_id: Uuid,
        policy_id: String,
        cfg_hash: String,
        env_hash: String,
        seed: u64,
        event_type: BenchmarkEventType,
    ) -> Self {
        Self {
            run_id,
            task_id,
            step_id,
            ts: Utc::now(),
            policy_id,
            cfg_hash,
            env_hash,
            seed,
            data: serde_json::to_value(&event_type).unwrap(),
            event_type,
        }
    }

    /// Get event as JSON for NATS streaming
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap()
    }

    /// Get string representation of event type for ClickHouse
    pub fn event_type_name(&self) -> &'static str {
        match self.event_type {
            BenchmarkEventType::RunStart(_) => "run_start",
            BenchmarkEventType::RunStop(_) => "run_stop",
            BenchmarkEventType::Step(_) => "step",
            BenchmarkEventType::ToolCall(_) => "tool_call",
            BenchmarkEventType::ContextDecision(_) => "context_decision",
            BenchmarkEventType::Failure(_) => "failure",
            BenchmarkEventType::OptimizerUpdate(_) => "optimizer_update",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_event_serialization() {
        let run_config = RunConfig {
            max_iterations: 10,
            temperature: 0.7,
            context_window: 8192,
            pruning_threshold: 0.8,
            planner_depth: 3,
            debate_rounds: 2,
            available_tools: vec!["ripgrep".to_string(), "file_edit".to_string()],
            tool_timeout_ms: 30000,
            retry_policy: RetryPolicy {
                max_retries: 3,
                backoff_ms: 1000,
                exponential_backoff: true,
                retry_on_flake: true,
                retry_on_timeout: false,
            },
            execution_timeout: Duration::from_secs(300),
            failing_tests_patience: 5,
            no_progress_timeout: Duration::from_secs(60),
            docker_image: "smith:latest".to_string(),
            tools_commit: "abc123".to_string(),
            sandbox_limits: SandboxLimits {
                memory_mb: 1024,
                cpu_cores: 2.0,
                disk_mb: 2048,
                network_enabled: false,
                execution_timeout_ms: 300000,
            },
        };

        let event = BenchmarkEvent::new(
            Uuid::new_v4(),
            "swe_bench_task_123".to_string(),
            Uuid::new_v4(),
            "policy_v1".to_string(),
            run_config.hash(),
            run_config.env_hash(),
            42,
            BenchmarkEventType::RunStart(run_config),
        );

        let json = event.to_json();
        assert!(json.is_object());
        assert!(json.get("run_id").is_some());
        assert!(json.get("event_type").is_some());
    }

    #[test]
    fn test_defaults() {
        let retry_policy = RetryPolicy::default();
        assert_eq!(retry_policy.max_retries, 3);
        assert_eq!(retry_policy.backoff_ms, 1000);
        assert!(retry_policy.exponential_backoff);
        assert!(retry_policy.retry_on_flake);
        assert!(retry_policy.retry_on_timeout);

        let sandbox_limits = SandboxLimits::default();
        assert_eq!(sandbox_limits.memory_mb, 4096);
        assert_eq!(sandbox_limits.cpu_cores, 2.0);
        assert_eq!(sandbox_limits.disk_mb, 10240);
        assert!(sandbox_limits.network_enabled);
        assert_eq!(sandbox_limits.execution_timeout_ms, 600000);

        let run_config = RunConfig::default();
        assert_eq!(run_config.max_iterations, 10);
        assert_eq!(run_config.temperature, 0.7);
        assert_eq!(run_config.context_window, 8192);
        assert_eq!(run_config.pruning_threshold, 0.8);
        assert_eq!(run_config.planner_depth, 3);
        assert_eq!(run_config.debate_rounds, 2);
        assert!(!run_config.available_tools.is_empty());
        assert_eq!(run_config.tool_timeout_ms, 30000);
        assert_eq!(run_config.failing_tests_patience, 3);
        assert_eq!(run_config.docker_image, "smith:latest");
        assert_eq!(run_config.tools_commit, "main");
    }

    #[test]
    fn test_event_type_name() {
        let run_config = RunConfig::default();
        let run_result = RunResult {
            success: true,
            wall_time_ms: 1000,
            total_tokens: 500,
            tool_errors: 0,
            stability_variance: 0.1,
            final_score: 95.0,
            failing_tests: vec![],
            tests_passed: 10,
            tests_failed: 0,
            files_modified: 2,
            early_stopped: false,
            early_stop_reason: None,
        };

        let step_data = StepData {
            step_type: StepType::Reason,
            content: "Analyzing the problem".to_string(),
            tokens_in: 100,
            tokens_out: 50,
            wall_time_ms: 500,
            planned_step: true,
            context_kb: 4,
        };

        let tool_performance = ToolPerformance {
            tool_name: "bash".to_string(),
            tool_args_hash: "abc123".to_string(),
            latency_ms: 200,
            retries: 0,
            exit_kind: ExitKind::Ok,
            evidence_footprint: EvidenceFootprint {
                files_read: vec!["/tmp/test.py".to_string()],
                files_modified: vec![],
                lines_changed: 0,
                tests_added: 0,
                tests_modified: 0,
                bytes_read: 1024,
                bytes_written: 0,
            },
            user_feedback_score: Some(4.5),
            intent_accuracy: Some(0.9),
        };

        let pruning_decision = PruningDecision {
            segment_id: "context_123".to_string(),
            kept: true,
            segment_kb: 10,
            segment_type: SegmentType::FileContent,
            impact_probe_ev: Some(0.8),
            pruning_algorithm: "threshold_based".to_string(),
            confidence_score: 0.95,
        };

        let failure_analysis = FailureAnalysis {
            first_failure_root: FailureRoot::Build {
                error_type: "compilation_error".to_string(),
                command: "make build".to_string(),
            },
            recovery_attempts: vec![RecoveryAttempt {
                strategy: "fix_imports".to_string(),
                success: false,
                time_spent_ms: 5000,
                side_effects: vec!["modified_file".to_string()],
            }],
            final_error_state: ErrorState {
                recoverable: true,
                error_category: "build".to_string(),
                confidence: 0.85,
                similar_failures: 3,
            },
            contributing_factors: vec!["missing_dependency".to_string()],
            remediation_suggestions: vec!["install_package".to_string()],
        };

        let config_suggestion = ConfigSuggestion {
            suggested_config: run_config.clone(),
            confidence: 0.9,
            expected_improvement: 0.15,
            exploration_vs_exploitation: 0.3,
            reasoning: "Based on successful patterns".to_string(),
        };

        // Test event type names
        let run_start_event = BenchmarkEvent::new(
            Uuid::new_v4(),
            "task".to_string(),
            Uuid::new_v4(),
            "policy".to_string(),
            "cfg".to_string(),
            "env".to_string(),
            0,
            BenchmarkEventType::RunStart(run_config),
        );
        assert_eq!(run_start_event.event_type_name(), "run_start");

        let run_stop_event = BenchmarkEvent::new(
            Uuid::new_v4(),
            "task".to_string(),
            Uuid::new_v4(),
            "policy".to_string(),
            "cfg".to_string(),
            "env".to_string(),
            0,
            BenchmarkEventType::RunStop(run_result),
        );
        assert_eq!(run_stop_event.event_type_name(), "run_stop");

        let step_event = BenchmarkEvent::new(
            Uuid::new_v4(),
            "task".to_string(),
            Uuid::new_v4(),
            "policy".to_string(),
            "cfg".to_string(),
            "env".to_string(),
            0,
            BenchmarkEventType::Step(step_data),
        );
        assert_eq!(step_event.event_type_name(), "step");

        let tool_call_event = BenchmarkEvent::new(
            Uuid::new_v4(),
            "task".to_string(),
            Uuid::new_v4(),
            "policy".to_string(),
            "cfg".to_string(),
            "env".to_string(),
            0,
            BenchmarkEventType::ToolCall(tool_performance),
        );
        assert_eq!(tool_call_event.event_type_name(), "tool_call");

        let context_decision_event = BenchmarkEvent::new(
            Uuid::new_v4(),
            "task".to_string(),
            Uuid::new_v4(),
            "policy".to_string(),
            "cfg".to_string(),
            "env".to_string(),
            0,
            BenchmarkEventType::ContextDecision(pruning_decision),
        );
        assert_eq!(context_decision_event.event_type_name(), "context_decision");

        let failure_event = BenchmarkEvent::new(
            Uuid::new_v4(),
            "task".to_string(),
            Uuid::new_v4(),
            "policy".to_string(),
            "cfg".to_string(),
            "env".to_string(),
            0,
            BenchmarkEventType::Failure(failure_analysis),
        );
        assert_eq!(failure_event.event_type_name(), "failure");

        let optimizer_event = BenchmarkEvent::new(
            Uuid::new_v4(),
            "task".to_string(),
            Uuid::new_v4(),
            "policy".to_string(),
            "cfg".to_string(),
            "env".to_string(),
            0,
            BenchmarkEventType::OptimizerUpdate(config_suggestion),
        );
        assert_eq!(optimizer_event.event_type_name(), "optimizer_update");
    }

    #[test]
    fn test_env_hash() {
        let config = RunConfig::default();
        let hash1 = config.env_hash();

        let mut config2 = config.clone();
        config2.docker_image = "smith:v2".to_string();
        let hash2 = config2.env_hash();

        assert_ne!(hash1, hash2);

        // Same config should produce same hash
        assert_eq!(hash1, config.env_hash());
    }

    #[test]
    fn test_complex_failure_roots() {
        let failure_roots = vec![
            FailureRoot::Import {
                missing_module: "numpy".to_string(),
                suggested_fix: "pip install numpy".to_string(),
            },
            FailureRoot::Path {
                invalid_path: "/invalid/path".to_string(),
                expected_location: "/correct/path".to_string(),
            },
            FailureRoot::Flake {
                flaky_test: "test_network".to_string(),
                failure_rate: 0.25,
            },
            FailureRoot::Semantic {
                logic_error: "Off-by-one error".to_string(),
                context: "Loop iteration".to_string(),
            },
            FailureRoot::Planning {
                reasoning_error: "Incorrect assumption".to_string(),
                step_number: 3,
            },
            FailureRoot::Context {
                missing_info: "API documentation".to_string(),
                pruning_error: true,
            },
            FailureRoot::Tool {
                tool_name: "grep".to_string(),
                usage_error: "Invalid regex".to_string(),
            },
        ];

        for failure_root in failure_roots {
            let failure_analysis = FailureAnalysis {
                first_failure_root: failure_root,
                recovery_attempts: vec![],
                final_error_state: ErrorState {
                    recoverable: false,
                    error_category: "test".to_string(),
                    confidence: 0.9,
                    similar_failures: 1,
                },
                contributing_factors: vec!["test_factor".to_string()],
                remediation_suggestions: vec!["test_suggestion".to_string()],
            };

            // Test serialization
            let json = serde_json::to_value(&failure_analysis).unwrap();
            let deserialized: FailureAnalysis = serde_json::from_value(json).unwrap();

            // Basic validation that we can round-trip serialize
            assert_eq!(
                deserialized.contributing_factors,
                failure_analysis.contributing_factors
            );
            assert_eq!(
                deserialized.remediation_suggestions,
                failure_analysis.remediation_suggestions
            );
        }
    }

    #[test]
    fn test_config_hashing() {
        let config1 = RunConfig {
            max_iterations: 10,
            temperature: 0.7,
            context_window: 8192,
            pruning_threshold: 0.8,
            planner_depth: 3,
            debate_rounds: 2,
            available_tools: vec!["ripgrep".to_string()],
            tool_timeout_ms: 30000,
            retry_policy: RetryPolicy {
                max_retries: 3,
                backoff_ms: 1000,
                exponential_backoff: true,
                retry_on_flake: true,
                retry_on_timeout: false,
            },
            execution_timeout: Duration::from_secs(300),
            failing_tests_patience: 5,
            no_progress_timeout: Duration::from_secs(60),
            docker_image: "smith:latest".to_string(),
            tools_commit: "abc123".to_string(),
            sandbox_limits: SandboxLimits {
                memory_mb: 1024,
                cpu_cores: 2.0,
                disk_mb: 2048,
                network_enabled: false,
                execution_timeout_ms: 300000,
            },
        };

        let config2 = config1.clone();

        assert_eq!(config1.hash(), config2.hash());

        // Different configs should have different hashes
        let mut config3 = config1.clone();
        config3.temperature = 0.8;
        assert_ne!(config1.hash(), config3.hash());
    }
}
