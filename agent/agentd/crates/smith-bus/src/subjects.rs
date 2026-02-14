//! Canonical NATS subject patterns and builders for Smith platform
//!
//! This module provides typed constants and builders for all NATS subjects
//! used across the Smith platform, eliminating bare string literals.

/// Canonical subject patterns for Smith platform
pub mod patterns {
    /// Root prefix for all Smith subjects
    pub const ROOT: &str = "smith";

    /// Intent subjects
    pub mod intents {
        /// Raw intents from agents (before admission control)
        pub const RAW: &str = "smith.intents.raw";

        /// Vetted intents after admission control
        pub const VETTED: &str = "smith.intents.vetted";

        /// Quarantined intents (rejected by admission control)
        pub const QUARANTINE: &str = "smith.intents.quarantine";

        /// All intents (wildcard)
        pub const ALL: &str = "smith.intents.>";

        /// File system read capability
        pub const FS_READ_V1: &str = "smith.intents.fs.read.v1";

        /// HTTP fetch capability
        pub const HTTP_FETCH_V1: &str = "smith.intents.http.fetch.v1";

        /// Shell execution capability
        pub const SHELL_EXEC_V1: &str = "smith.intents.shell.exec.v1";

        /// Raw playbook intents (prefix)
        pub const RAW_PLAYBOOK: &str = "smith.intents.raw.playbook";

        /// Raw playbook intents (wildcarded)
        pub const RAW_PLAYBOOK_ALL: &str = "smith.intents.raw.playbook.*";

        /// Raw macro intents (prefix)
        pub const RAW_MACRO: &str = "smith.intents.raw.macro";

        /// Raw macro intents (wildcarded)
        pub const RAW_MACRO_ALL: &str = "smith.intents.raw.macro.*";

        /// Raw atom use intents
        pub const RAW_ATOM_USE: &str = "smith.intents.raw.atom.use";
    }

    /// Result subjects
    pub mod results {
        /// All results (wildcard)
        pub const ALL: &str = "smith.results.>";

        /// Results prefix for specific intent IDs
        pub const PREFIX: &str = "smith.results";
    }

    /// System event subjects
    pub mod events {
        /// All system events (wildcard)
        pub const ALL: &str = "smith.events.>";

        /// Executor lifecycle events
        pub const EXECUTOR_LIFECYCLE: &str = "smith.events.executor.lifecycle";

        /// Health check events
        pub const HEALTH: &str = "smith.events.health";

        /// Metrics events
        pub const METRICS: &str = "smith.events.metrics";
    }

    /// Structured logging subjects
    pub mod logs {
        /// All log events (wildcard)
        pub const ALL: &str = "smith.logs.>";

        /// Core service logs
        pub const CORE: &str = "smith.logs.core";
        pub const CORE_ALL: &str = "smith.logs.core.*";

        /// Executor service logs
        pub const EXECUTOR: &str = "smith.logs.executor";
        pub const EXECUTOR_ALL: &str = "smith.logs.executor.*";

        /// Admission service logs
        pub const ADMISSION: &str = "smith.logs.admission";
        pub const ADMISSION_ALL: &str = "smith.logs.admission.*";

        /// HTTP service logs
        pub const HTTP: &str = "smith.logs.http";
        pub const HTTP_ALL: &str = "smith.logs.http.*";

        /// Error logs (all services, error level)
        pub const ERRORS: &str = "smith.logs.errors";
        pub const ERRORS_ALL: &str = "smith.logs.errors.*";

        /// Performance logs (all services, performance-related)
        pub const PERFORMANCE: &str = "smith.logs.performance";
        pub const PERFORMANCE_ALL: &str = "smith.logs.performance.*";

        /// Security-related logs
        pub const SECURITY: &str = "smith.logs.security";
        pub const SECURITY_ALL: &str = "smith.logs.security.*";
    }

    /// Audit log subjects
    pub mod audit {
        /// All audit events (wildcard)
        pub const ALL: &str = "smith.audit.>";

        /// Execution audit logs
        pub const EXECUTION: &str = "smith.audit.execution";

        /// Policy decisions
        pub const POLICY: &str = "smith.audit.policy";

        /// All policy decisions (wildcarded)
        pub const POLICY_ALL: &str = "smith.audit.policy.*";

        /// Security events
        pub const SECURITY: &str = "smith.audit.security";
    }

    /// AI/SDLC action subjects
    pub mod ai_sdlc {
        /// All AI/SDLC events (wildcard)
        pub const ALL: &str = "smith.ai.sdlc.>";

        /// Action requests from orchestrators
        pub const ACTION_REQUEST: &str = "smith.ai.sdlc.action.request";

        /// Action results from processors
        pub const ACTION_RESULT: &str = "smith.ai.sdlc.action.result";
    }

    /// GitLab integration subjects
    pub mod gitlab {
        /// All GitLab events (wildcard)
        pub const ALL: &str = "smith.gitlab.>";

        /// Merge request events
        pub const EVENT_MR: &str = "smith.gitlab.event.mr";

        /// Pipeline events
        pub const EVENT_PIPELINE: &str = "smith.gitlab.event.pipeline";

        /// Issue events
        pub const EVENT_ISSUE: &str = "smith.gitlab.event.issue";
    }

    /// Orchestrator subjects
    pub mod orchestrator {
        /// All orchestrator events (wildcard)
        pub const ALL: &str = "smith.orchestrator.>";

        /// Audit events from orchestrator
        pub const AUDIT: &str = "smith.orchestrator.audit";

        /// Status events
        pub const STATUS: &str = "smith.orchestrator.status";
    }

    /// Benchmark optimization subjects
    pub mod benchmark {
        /// All benchmark events (wildcard)
        pub const ALL: &str = "smith.benchmark.>";

        /// Benchmark run lifecycle (start/stop with config)
        pub const RUNS: &str = "smith.benchmark.runs";

        /// Agent reasoning/action steps
        pub const STEPS: &str = "smith.benchmark.steps";

        /// Tool performance and effectiveness metrics
        pub const TOOL_PERFORMANCE: &str = "smith.benchmark.tools";

        /// Context pruning decisions for optimization
        pub const CONTEXT_DECISIONS: &str = "smith.benchmark.context";

        /// Structured failure analysis for learning
        pub const FAILURE_ANALYSIS: &str = "smith.benchmark.failures";

        /// Optimizer configuration suggestions
        pub const OPTIMIZER_FEEDBACK: &str = "smith.benchmark.optimizer";

        /// Task features for contextual optimization
        pub const TASK_FEATURES: &str = "smith.benchmark.task_features";

        /// Early stopping events
        pub const EARLY_STOPPING: &str = "smith.benchmark.early_stop";

        /// A/B test policy assignments
        pub const POLICY_ASSIGNMENTS: &str = "smith.benchmark.policy_assignments";

        /// Performance regression alerts
        pub const REGRESSION_ALERTS: &str = "smith.benchmark.regressions";
    }
}

/// Subject builder for dynamic subject construction
pub struct SubjectBuilder {
    parts: Vec<String>,
}

impl SubjectBuilder {
    /// Create a new subject builder
    pub fn new() -> Self {
        Self {
            parts: vec!["smith".to_string()],
        }
    }

    /// Add a part to the subject
    pub fn part<S: AsRef<str>>(mut self, part: S) -> Self {
        self.parts.push(part.as_ref().to_string());
        self
    }

    /// Add capability and version (e.g., "fs.read.v1")
    pub fn capability<S: AsRef<str>>(mut self, capability: S) -> Self {
        let cap = capability.as_ref();
        if cap.contains('.') {
            // Already formatted capability
            self.parts.push(cap.to_string());
        } else {
            // Simple capability name, assume v1
            self.parts.push(format!("{}.v1", cap));
        }
        self
    }

    /// Add a domain for routing/sharding
    pub fn domain<S: AsRef<str>>(mut self, domain: S) -> Self {
        self.parts.push(domain.as_ref().to_string());
        self
    }

    /// Build the final subject string
    pub fn build(self) -> String {
        self.parts.join(".")
    }

    /// Build as a wildcard subject
    pub fn wildcard(mut self) -> String {
        self.parts.push(">".to_string());
        self.parts.join(".")
    }
}

impl Default for SubjectBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed subject builders for different categories
pub mod builders {
    use super::SubjectBuilder;

    /// Builder for intent subjects
    pub struct IntentSubject;

    impl IntentSubject {
        /// Raw intent subject (before admission)
        pub fn raw<S: AsRef<str>>(capability: S) -> String {
            SubjectBuilder::new()
                .part("intents")
                .part("raw")
                .capability(capability)
                .build()
        }

        /// Vetted intent subject (after admission)
        pub fn vetted<S: AsRef<str>>(capability: S) -> String {
            SubjectBuilder::new()
                .part("intents")
                .part("vetted")
                .capability(capability)
                .build()
        }

        /// Intent subject with domain
        pub fn with_domain<S: AsRef<str>>(capability: S, domain: S) -> String {
            SubjectBuilder::new()
                .part("intents")
                .capability(capability)
                .domain(domain)
                .build()
        }

        /// Quarantined intent subject
        pub fn quarantine() -> String {
            SubjectBuilder::new()
                .part("intents")
                .part("quarantine")
                .build()
        }
    }

    /// Builder for result subjects
    pub struct ResultSubject;

    impl ResultSubject {
        /// Result subject for specific intent ID
        pub fn for_intent<S: AsRef<str>>(intent_id: S) -> String {
            SubjectBuilder::new()
                .part("results")
                .part(intent_id.as_ref())
                .build()
        }

        /// All results wildcard
        pub fn all() -> String {
            SubjectBuilder::new().part("results").wildcard()
        }
    }

    /// Builder for event subjects
    pub struct EventSubject;

    impl EventSubject {
        /// Executor lifecycle event
        pub fn executor_lifecycle<S: AsRef<str>>(executor_id: S) -> String {
            SubjectBuilder::new()
                .part("events")
                .part("executor")
                .part("lifecycle")
                .part(executor_id.as_ref())
                .build()
        }

        /// Health check event
        pub fn health<S: AsRef<str>>(service: S) -> String {
            SubjectBuilder::new()
                .part("events")
                .part("health")
                .part(service.as_ref())
                .build()
        }

        /// Metrics event
        pub fn metrics<S: AsRef<str>>(service: S) -> String {
            SubjectBuilder::new()
                .part("events")
                .part("metrics")
                .part(service.as_ref())
                .build()
        }
    }

    /// Builder for audit subjects
    pub struct AuditSubject;

    impl AuditSubject {
        /// Execution audit log
        pub fn execution<S: AsRef<str>>(intent_id: S) -> String {
            SubjectBuilder::new()
                .part("audit")
                .part("execution")
                .part(intent_id.as_ref())
                .build()
        }

        /// Policy decision audit
        pub fn policy<S: AsRef<str>>(intent_id: S) -> String {
            SubjectBuilder::new()
                .part("audit")
                .part("policy")
                .part(intent_id.as_ref())
                .build()
        }

        /// Security audit event
        pub fn security<S: AsRef<str>>(event_type: S) -> String {
            SubjectBuilder::new()
                .part("audit")
                .part("security")
                .part(event_type.as_ref())
                .build()
        }
    }

    /// Builder for log subjects
    pub struct LogSubject;

    impl LogSubject {
        /// Core service log subject
        pub fn core<S: AsRef<str>>(level: S) -> String {
            SubjectBuilder::new()
                .part("logs")
                .part("core")
                .part(level.as_ref())
                .build()
        }

        /// Executor service log subject
        pub fn executor<S: AsRef<str>>(level: S) -> String {
            SubjectBuilder::new()
                .part("logs")
                .part("executor")
                .part(level.as_ref())
                .build()
        }

        /// Admission service log subject
        pub fn admission<S: AsRef<str>>(level: S) -> String {
            SubjectBuilder::new()
                .part("logs")
                .part("admission")
                .part(level.as_ref())
                .build()
        }

        /// HTTP service log subject
        pub fn http<S: AsRef<str>>(level: S) -> String {
            SubjectBuilder::new()
                .part("logs")
                .part("http")
                .part(level.as_ref())
                .build()
        }

        /// Generic service log subject
        pub fn service<S: AsRef<str>>(service: S, level: S) -> String {
            SubjectBuilder::new()
                .part("logs")
                .part(service.as_ref())
                .part(level.as_ref())
                .build()
        }

        /// Error log subject (cross-service)
        pub fn error<S: AsRef<str>>(service: S) -> String {
            SubjectBuilder::new()
                .part("logs")
                .part("errors")
                .part(service.as_ref())
                .build()
        }

        /// Performance log subject (cross-service)
        pub fn performance<S: AsRef<str>>(service: S) -> String {
            SubjectBuilder::new()
                .part("logs")
                .part("performance")
                .part(service.as_ref())
                .build()
        }

        /// Security log subject (cross-service)
        pub fn security<S: AsRef<str>>(service: S, event_type: S) -> String {
            SubjectBuilder::new()
                .part("logs")
                .part("security")
                .part(service.as_ref())
                .part(event_type.as_ref())
                .build()
        }

        /// All logs wildcard
        pub fn all() -> String {
            SubjectBuilder::new().part("logs").wildcard()
        }
    }

    /// Builder for benchmark subjects
    pub struct BenchmarkSubject;

    impl BenchmarkSubject {
        /// Benchmark run lifecycle event (start/stop)
        pub fn run<S: AsRef<str>>(run_id: S) -> String {
            SubjectBuilder::new()
                .part("benchmark")
                .part("runs")
                .part(run_id.as_ref())
                .build()
        }

        /// Agent reasoning/action step
        pub fn step<S: AsRef<str>>(run_id: S, step_id: S) -> String {
            SubjectBuilder::new()
                .part("benchmark")
                .part("steps")
                .part(run_id.as_ref())
                .part(step_id.as_ref())
                .build()
        }

        /// Tool performance metrics
        pub fn tool_performance<S: AsRef<str>>(run_id: S, tool_name: S) -> String {
            SubjectBuilder::new()
                .part("benchmark")
                .part("tools")
                .part(run_id.as_ref())
                .part(tool_name.as_ref())
                .build()
        }

        /// Context pruning decision
        pub fn context_decision<S: AsRef<str>>(run_id: S, segment_id: S) -> String {
            SubjectBuilder::new()
                .part("benchmark")
                .part("context")
                .part(run_id.as_ref())
                .part(segment_id.as_ref())
                .build()
        }

        /// Failure analysis event
        pub fn failure<S: AsRef<str>>(run_id: S, failure_type: S) -> String {
            SubjectBuilder::new()
                .part("benchmark")
                .part("failures")
                .part(run_id.as_ref())
                .part(failure_type.as_ref())
                .build()
        }

        /// Optimizer configuration suggestion
        pub fn optimizer_feedback<S: AsRef<str>>(task_type: S) -> String {
            SubjectBuilder::new()
                .part("benchmark")
                .part("optimizer")
                .part(task_type.as_ref())
                .build()
        }

        /// Task features for contextual optimization
        pub fn task_features<S: AsRef<str>>(task_id: S) -> String {
            SubjectBuilder::new()
                .part("benchmark")
                .part("task_features")
                .part(task_id.as_ref())
                .build()
        }

        /// Early stopping event
        pub fn early_stop<S: AsRef<str>>(run_id: S, reason: S) -> String {
            SubjectBuilder::new()
                .part("benchmark")
                .part("early_stop")
                .part(run_id.as_ref())
                .part(reason.as_ref())
                .build()
        }

        /// All benchmark events wildcard
        pub fn all() -> String {
            SubjectBuilder::new().part("benchmark").wildcard()
        }
    }
}

/// Convenience functions matching the pseudocode pattern from TODO.md
pub fn raw<S: AsRef<str>>(capability: S) -> String {
    builders::IntentSubject::raw(capability)
}

pub fn vetted<S: AsRef<str>>(capability: S) -> String {
    builders::IntentSubject::vetted(capability)
}

/// Stream name constants
pub mod streams {
    /// Intent streams
    pub const INTENTS: &str = "INTENTS";
    pub const INTENTS_RAW: &str = "INTENTS_RAW";
    pub const INTENTS_VETTED: &str = "INTENTS_VETTED";
    pub const INTENTS_QUARANTINE: &str = "INTENTS_QUARANTINE";

    /// Result streams
    pub const RESULTS: &str = "RESULTS";

    /// Event streams
    pub const EVENTS: &str = "EVENTS";
    pub const SYSTEM_EVENTS: &str = "SYSTEM_EVENTS";

    /// Audit streams
    pub const AUDIT_LOGS: &str = "AUDIT_LOGS";

    /// Benchmark streams
    pub const BENCHMARK_RUNS: &str = "BENCHMARK_RUNS";
    pub const BENCHMARK_STEPS: &str = "BENCHMARK_STEPS";
    pub const BENCHMARK_TOOLS: &str = "BENCHMARK_TOOLS";
    pub const BENCHMARK_CONTEXT: &str = "BENCHMARK_CONTEXT";
    pub const BENCHMARK_FAILURES: &str = "BENCHMARK_FAILURES";
    pub const BENCHMARK_OPTIMIZER: &str = "BENCHMARK_OPTIMIZER";
}

/// Consumer name constants
pub mod consumers {
    /// Executor consumers
    pub const EXECUTOR: &str = "executor";
    pub const EXECUTOR_FS_READ: &str = "executor-fs-read";
    pub const EXECUTOR_HTTP_FETCH: &str = "executor-http-fetch";

    /// HTTP service consumers
    pub const HTTP_RESULTS: &str = "http-results";
    pub const HTTP_EVENTS: &str = "http-events";

    /// Admission control consumers
    pub const ADMISSION_RAW: &str = "admission-raw";

    /// Audit consumers
    pub const AUDIT_COLLECTOR: &str = "audit-collector";

    /// Benchmark consumers
    pub const BENCHMARK_COLLECTOR: &str = "benchmark-collector";
    pub const BENCHMARK_ANALYTICS: &str = "benchmark-analytics";
    pub const BENCHMARK_OPTIMIZER: &str = "benchmark-optimizer";
    pub const BENCHMARK_DASHBOARD: &str = "benchmark-dashboard";
}

/// Subject ABI version management for centralized control
pub mod abi {
    /// Subject ABI version - increment when breaking changes are made
    pub const SUBJECT_ABI_VERSION: u32 = 1;

    /// Generate ABI hash for CI validation
    pub fn generate_subject_abi_hash() -> String {
        use sha2::{Digest, Sha256};

        // Create deterministic representation of all subject patterns
        let subjects = [
            super::patterns::intents::RAW,
            super::patterns::intents::VETTED,
            super::patterns::intents::QUARANTINE,
            super::patterns::intents::FS_READ_V1,
            super::patterns::intents::HTTP_FETCH_V1,
            super::patterns::results::PREFIX,
            super::patterns::events::HEALTH,
            super::patterns::audit::EXECUTION,
        ];

        let abi_repr = format!(
            "SUBJECT_ABI_V{}_SUBJECTS:{}",
            SUBJECT_ABI_VERSION,
            subjects.join(",")
        );

        let mut hasher = Sha256::new();
        hasher.update(abi_repr.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Validate subject ABI stability for CI
    pub fn validate_subject_abi_stability(old_hash: &str, new_hash: &str) -> Result<(), String> {
        if old_hash != new_hash {
            return Err(format!(
                "Subject ABI hash mismatch: expected {} but got {}. This indicates breaking changes to NATS subjects.",
                old_hash, new_hash
            ));
        }
        Ok(())
    }
}

/// Compile-time validation macros for preventing raw strings
#[macro_export]
macro_rules! validate_no_raw_subjects {
    ($code:expr) => {
        // This macro can be used by linters to detect raw subject strings
        // Usage: validate_no_raw_subjects!("smith.intents.raw.fs.read.v1");
        compile_error!("Raw subject strings are forbidden. Use smith_bus::subjects constants or builders instead.")
    };
}

/// Subject validation functions
pub mod validation {

    /// Check if a subject is a valid Smith subject
    pub fn is_valid_smith_subject(subject: &str) -> bool {
        subject.starts_with("smith.") && !subject.is_empty()
    }

    /// Detect raw subject string patterns (for CI validation)
    pub fn contains_raw_subject_patterns(code: &str) -> Vec<String> {
        let mut violations = Vec::new();

        // Patterns that indicate raw subject usage
        let raw_patterns = vec![
            r#""smith\.intents\."#,
            r#""smith\.results\."#,
            r#""smith\.events\."#,
            r#""smith\.audit\."#,
        ];

        for pattern in raw_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                for mat in regex.find_iter(code) {
                    violations.push(mat.as_str().to_string());
                }
            }
        }

        violations
    }

    /// Check if code uses centralized subjects properly
    pub fn validate_centralized_usage(code: &str) -> Result<(), String> {
        let violations = contains_raw_subject_patterns(code);
        if !violations.is_empty() {
            return Err(format!(
                "Found {} raw subject string(s): {}. Use smith_bus::subjects constants instead.",
                violations.len(),
                violations.join(", ")
            ));
        }
        Ok(())
    }

    /// Check if a subject is an intent subject
    pub fn is_intent_subject(subject: &str) -> bool {
        subject.starts_with("smith.intents.")
    }

    /// Check if a subject is a result subject
    pub fn is_result_subject(subject: &str) -> bool {
        subject.starts_with("smith.results.")
    }

    /// Extract capability from an intent subject
    pub fn extract_capability(subject: &str) -> Option<String> {
        if !is_intent_subject(subject) {
            return None;
        }

        let parts: Vec<&str> = subject.split('.').collect();
        if parts.len() >= 4 {
            // smith.intents.{capability}.{version}
            Some(format!("{}.{}", parts[2], parts[3]))
        } else {
            None
        }
    }

    /// Extract intent ID from a result subject
    pub fn extract_intent_id(subject: &str) -> Option<String> {
        if !is_result_subject(subject) {
            return None;
        }

        let parts: Vec<&str> = subject.split('.').collect();
        if parts.len() >= 3 {
            // smith.results.{intent_id}
            Some(parts[2].to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subject_builder() {
        let subject = SubjectBuilder::new()
            .part("intents")
            .capability("fs.read.v1")
            .domain("file-processor")
            .build();

        assert_eq!(subject, "smith.intents.fs.read.v1.file-processor");
    }

    #[test]
    fn test_intent_subject_builders() {
        assert_eq!(
            builders::IntentSubject::raw("fs.read.v1"),
            "smith.intents.raw.fs.read.v1"
        );

        assert_eq!(
            builders::IntentSubject::vetted("http.fetch.v1"),
            "smith.intents.vetted.http.fetch.v1"
        );

        assert_eq!(
            builders::IntentSubject::with_domain("fs.read.v1", "processor"),
            "smith.intents.fs.read.v1.processor"
        );
    }

    #[test]
    fn test_result_subject_builders() {
        let intent_id = "intent-123-456";
        assert_eq!(
            builders::ResultSubject::for_intent(intent_id),
            "smith.results.intent-123-456"
        );

        assert_eq!(builders::ResultSubject::all(), "smith.results.>");
    }

    #[test]
    fn test_convenience_functions() {
        assert_eq!(raw("fs.read.v1"), "smith.intents.raw.fs.read.v1");
        assert_eq!(
            vetted("http.fetch.v1"),
            "smith.intents.vetted.http.fetch.v1"
        );
    }

    #[test]
    fn test_subject_validation() {
        assert!(validation::is_valid_smith_subject(
            "smith.intents.fs.read.v1"
        ));
        assert!(!validation::is_valid_smith_subject(
            "nats.intents.fs.read.v1"
        ));

        assert!(validation::is_intent_subject("smith.intents.fs.read.v1"));
        assert!(!validation::is_intent_subject("smith.results.123"));

        assert!(validation::is_result_subject("smith.results.intent-123"));
        assert!(!validation::is_result_subject("smith.intents.fs.read.v1"));
    }

    #[test]
    fn test_capability_extraction() {
        assert_eq!(
            validation::extract_capability("smith.intents.fs.read.v1"),
            Some("fs.read".to_string())
        );

        assert_eq!(
            validation::extract_capability("smith.intents.http.fetch.v1"),
            Some("http.fetch".to_string())
        );

        assert_eq!(validation::extract_capability("smith.results.123"), None);
    }

    #[test]
    fn test_intent_id_extraction() {
        assert_eq!(
            validation::extract_intent_id("smith.results.intent-123-456"),
            Some("intent-123-456".to_string())
        );

        assert_eq!(
            validation::extract_intent_id("smith.intents.fs.read.v1"),
            None
        );
    }

    #[test]
    fn test_stream_constants() {
        assert_eq!(streams::INTENTS, "INTENTS");
        assert_eq!(streams::RESULTS, "RESULTS");
        assert_eq!(streams::AUDIT_LOGS, "AUDIT_LOGS");
    }

    #[test]
    fn test_consumer_constants() {
        assert_eq!(consumers::EXECUTOR, "executor");
        assert_eq!(consumers::HTTP_RESULTS, "http-results");
        assert_eq!(consumers::ADMISSION_RAW, "admission-raw");
    }

    /// Comprehensive test that enumerates all subjects and asserts prefix contracts
    /// This ensures all subjects conform to Smith platform naming conventions
    #[test]
    fn test_subject_prefix_contracts() {
        // Collect all subject patterns from constants and builders
        let mut all_subjects = vec![
            patterns::intents::RAW.to_string(),
            patterns::intents::VETTED.to_string(),
            patterns::intents::QUARANTINE.to_string(),
            patterns::intents::FS_READ_V1.to_string(),
            patterns::intents::HTTP_FETCH_V1.to_string(),
            patterns::results::PREFIX.to_string(),
            patterns::events::EXECUTOR_LIFECYCLE.to_string(),
            patterns::events::HEALTH.to_string(),
            patterns::events::METRICS.to_string(),
            patterns::audit::EXECUTION.to_string(),
            patterns::audit::POLICY.to_string(),
            patterns::audit::SECURITY.to_string(),
            patterns::ai_sdlc::ACTION_REQUEST.to_string(),
            patterns::ai_sdlc::ACTION_RESULT.to_string(),
            patterns::gitlab::EVENT_MR.to_string(),
            patterns::gitlab::EVENT_PIPELINE.to_string(),
            patterns::gitlab::EVENT_ISSUE.to_string(),
            patterns::orchestrator::AUDIT.to_string(),
            patterns::orchestrator::STATUS.to_string(),
        ];

        // Generated subjects from builders with sample data
        all_subjects.extend([
            builders::IntentSubject::raw("fs.read.v1"),
            builders::IntentSubject::vetted("http.fetch.v1"),
            builders::IntentSubject::with_domain("fs.read.v1", "test"),
            builders::IntentSubject::quarantine(),
            builders::ResultSubject::for_intent("test-intent"),
            builders::EventSubject::executor_lifecycle("test-executor"),
            builders::EventSubject::health("test-service"),
            builders::EventSubject::metrics("test-service"),
            builders::AuditSubject::execution("test-intent"),
            builders::AuditSubject::policy("test-intent"),
            builders::AuditSubject::security("test-event"),
            raw("fs.read.v1"),
            vetted("http.fetch.v1"),
        ]);

        // Assert all subjects start with "smith."
        for subject in &all_subjects {
            assert!(
                subject.starts_with("smith."),
                "Subject '{}' does not start with 'smith.' prefix",
                subject
            );

            // Assert no subject contains bare format strings or template patterns
            assert!(
                !subject.contains("{}") && !subject.contains("{") && !subject.contains("}"),
                "Subject '{}' contains template patterns - this indicates a bare string wasn't replaced",
                subject
            );
        }

        // Contract assertions for specific subject categories
        let intent_subjects: Vec<&String> = all_subjects
            .iter()
            .filter(|s| s.contains(".intents."))
            .collect();

        let result_subjects: Vec<&String> = all_subjects
            .iter()
            .filter(|s| s.contains(".results."))
            .collect();

        let event_subjects: Vec<&String> = all_subjects
            .iter()
            .filter(|s| s.contains(".events."))
            .collect();

        let audit_subjects: Vec<&String> = all_subjects
            .iter()
            .filter(|s| s.contains(".audit."))
            .collect();

        // Assert minimum subject counts per category
        assert!(
            intent_subjects.len() >= 6,
            "Should have at least 6 intent subjects"
        );
        assert!(
            !result_subjects.is_empty(),
            "Should have at least 1 result subject"
        );
        assert!(
            event_subjects.len() >= 3,
            "Should have at least 3 event subjects"
        );
        assert!(
            audit_subjects.len() >= 3,
            "Should have at least 3 audit subjects"
        );

        // Assert specific patterns are followed
        for intent_subject in &intent_subjects {
            let parts: Vec<&str> = intent_subject.split('.').collect();
            assert!(
                parts.len() >= 3 && parts[1] == "intents",
                "Intent subject '{}' doesn't follow smith.intents.* pattern",
                intent_subject
            );
        }

        for result_subject in &result_subjects {
            let parts: Vec<&str> = result_subject.split('.').collect();
            assert!(
                parts.len() >= 3 && parts[1] == "results",
                "Result subject '{}' doesn't follow smith.results.* pattern",
                result_subject
            );
        }

        println!(
            "✓ All {} subjects conform to Smith prefix contracts",
            all_subjects.len()
        );
        println!("✓ Intent subjects: {}", intent_subjects.len());
        println!("✓ Result subjects: {}", result_subjects.len());
        println!("✓ Event subjects: {}", event_subjects.len());
        println!("✓ Audit subjects: {}", audit_subjects.len());
    }

    #[test]
    fn test_subject_builder_comprehensive() {
        // Test SubjectBuilder with all methods
        let subject = SubjectBuilder::new()
            .part("test")
            .capability("custom.v1")
            .domain("service")
            .build();
        assert_eq!(subject, "smith.test.custom.v1.service");

        // Test wildcard functionality
        let wildcard = SubjectBuilder::new().part("intents").wildcard();
        assert_eq!(wildcard, "smith.intents.>");

        // Test empty builder
        let empty = SubjectBuilder::new().build();
        assert_eq!(empty, "smith");

        // Test chaining different parts
        let complex = SubjectBuilder::new()
            .part("complex")
            .part("nested")
            .capability("multi.level.v2")
            .domain("advanced-service")
            .build();
        assert_eq!(
            complex,
            "smith.complex.nested.multi.level.v2.advanced-service"
        );
    }

    #[test]
    fn test_log_subject_builders() {
        // Test LogSubject builders
        assert_eq!(builders::LogSubject::core("error"), "smith.logs.core.error");
        assert_eq!(
            builders::LogSubject::executor("debug"),
            "smith.logs.executor.debug"
        );
        assert_eq!(
            builders::LogSubject::admission("warn"),
            "smith.logs.admission.warn"
        );
        assert_eq!(builders::LogSubject::http("info"), "smith.logs.http.info");
        assert_eq!(
            builders::LogSubject::service("custom-service", "trace"),
            "smith.logs.custom-service.trace"
        );
        assert_eq!(
            builders::LogSubject::error("test-service"),
            "smith.logs.errors.test-service"
        );
        assert_eq!(
            builders::LogSubject::performance("perf-service"),
            "smith.logs.performance.perf-service"
        );
        assert_eq!(
            builders::LogSubject::security("auth-service", "login-attempt"),
            "smith.logs.security.auth-service.login-attempt"
        );
        assert_eq!(builders::LogSubject::all(), "smith.logs.>");
    }

    #[test]
    fn test_event_subject_builders_comprehensive() {
        // Test EventSubject builders
        assert_eq!(
            builders::EventSubject::executor_lifecycle("exec-001"),
            "smith.events.executor.lifecycle.exec-001"
        );
        assert_eq!(
            builders::EventSubject::health("admission-service"),
            "smith.events.health.admission-service"
        );
        assert_eq!(
            builders::EventSubject::metrics("core-service"),
            "smith.events.metrics.core-service"
        );
    }

    #[test]
    fn test_audit_subject_builders_comprehensive() {
        // Test AuditSubject builders
        assert_eq!(
            builders::AuditSubject::execution("intent-abc-123"),
            "smith.audit.execution.intent-abc-123"
        );
        assert_eq!(
            builders::AuditSubject::policy("intent-policy-456"),
            "smith.audit.policy.intent-policy-456"
        );
        assert_eq!(
            builders::AuditSubject::security("failed-login"),
            "smith.audit.security.failed-login"
        );
    }

    #[test]
    fn test_benchmark_subject_builders() {
        // Test BenchmarkSubject builders
        assert_eq!(
            builders::BenchmarkSubject::run("run-001"),
            "smith.benchmark.runs.run-001"
        );
        assert_eq!(
            builders::BenchmarkSubject::step("run-001", "step-001"),
            "smith.benchmark.steps.run-001.step-001"
        );
        assert_eq!(
            builders::BenchmarkSubject::tool_performance("run-001", "git"),
            "smith.benchmark.tools.run-001.git"
        );
        assert_eq!(
            builders::BenchmarkSubject::context_decision("run-001", "segment-001"),
            "smith.benchmark.context.run-001.segment-001"
        );
        assert_eq!(
            builders::BenchmarkSubject::failure("run-001", "timeout"),
            "smith.benchmark.failures.run-001.timeout"
        );
        assert_eq!(
            builders::BenchmarkSubject::optimizer_feedback("coding"),
            "smith.benchmark.optimizer.coding"
        );
        assert_eq!(
            builders::BenchmarkSubject::task_features("task-001"),
            "smith.benchmark.task_features.task-001"
        );
        assert_eq!(
            builders::BenchmarkSubject::early_stop("run-001", "resource-limit"),
            "smith.benchmark.early_stop.run-001.resource-limit"
        );
        assert_eq!(builders::BenchmarkSubject::all(), "smith.benchmark.>");
    }

    #[test]
    fn test_pattern_constants_comprehensive() {
        // Test intent patterns
        assert_eq!(patterns::intents::RAW, "smith.intents.raw");
        assert_eq!(patterns::intents::VETTED, "smith.intents.vetted");
        assert_eq!(patterns::intents::QUARANTINE, "smith.intents.quarantine");
        assert_eq!(patterns::intents::ALL, "smith.intents.>");
        assert_eq!(patterns::intents::FS_READ_V1, "smith.intents.fs.read.v1");
        assert_eq!(
            patterns::intents::HTTP_FETCH_V1,
            "smith.intents.http.fetch.v1"
        );
        assert_eq!(
            patterns::intents::SHELL_EXEC_V1,
            "smith.intents.shell.exec.v1"
        );
        assert_eq!(
            patterns::intents::RAW_PLAYBOOK,
            "smith.intents.raw.playbook"
        );
        assert_eq!(
            patterns::intents::RAW_PLAYBOOK_ALL,
            "smith.intents.raw.playbook.*"
        );
        assert_eq!(patterns::intents::RAW_MACRO, "smith.intents.raw.macro");
        assert_eq!(
            patterns::intents::RAW_MACRO_ALL,
            "smith.intents.raw.macro.*"
        );
        assert_eq!(
            patterns::intents::RAW_ATOM_USE,
            "smith.intents.raw.atom.use"
        );

        // Test result patterns
        assert_eq!(patterns::results::ALL, "smith.results.>");
        assert_eq!(patterns::results::PREFIX, "smith.results");

        // Test event patterns
        assert_eq!(patterns::events::ALL, "smith.events.>");
        assert_eq!(
            patterns::events::EXECUTOR_LIFECYCLE,
            "smith.events.executor.lifecycle"
        );
        assert_eq!(patterns::events::HEALTH, "smith.events.health");
        assert_eq!(patterns::events::METRICS, "smith.events.metrics");

        // Test audit patterns
        assert_eq!(patterns::audit::ALL, "smith.audit.>");
        assert_eq!(patterns::audit::EXECUTION, "smith.audit.execution");
        assert_eq!(patterns::audit::POLICY, "smith.audit.policy");
        assert_eq!(patterns::audit::POLICY_ALL, "smith.audit.policy.*");
        assert_eq!(patterns::audit::SECURITY, "smith.audit.security");

        // Test AI/SDLC patterns
        assert_eq!(patterns::ai_sdlc::ALL, "smith.ai.sdlc.>");
        assert_eq!(
            patterns::ai_sdlc::ACTION_REQUEST,
            "smith.ai.sdlc.action.request"
        );
        assert_eq!(
            patterns::ai_sdlc::ACTION_RESULT,
            "smith.ai.sdlc.action.result"
        );

        // Test GitLab patterns
        assert_eq!(patterns::gitlab::ALL, "smith.gitlab.>");
        assert_eq!(patterns::gitlab::EVENT_MR, "smith.gitlab.event.mr");
        assert_eq!(
            patterns::gitlab::EVENT_PIPELINE,
            "smith.gitlab.event.pipeline"
        );
    }

    #[test]
    fn test_validation_functions_comprehensive() {
        // Test raw subject pattern detection
        let code_with_violations = r#"
            let subject1 = "smith.intents.raw.fs.read.v1";
            let subject2 = "smith.results.intent-123";
            let subject3 = "smith.events.health.check";
            let subject4 = "smith.audit.execution.log";
        "#;

        let violations = validation::contains_raw_subject_patterns(code_with_violations);
        assert!(!violations.is_empty(), "Should detect raw subject patterns");

        // Test centralized usage validation
        assert!(validation::validate_centralized_usage("let x = 5;").is_ok());
        assert!(validation::validate_centralized_usage(code_with_violations).is_err());

        // Test edge cases for capability extraction
        assert_eq!(
            validation::extract_capability("smith.intents.shell.exec.v1"),
            Some("shell.exec".to_string())
        );
        assert_eq!(
            validation::extract_capability("smith.intents.complex.nested.multi.v2"),
            Some("complex.nested".to_string())
        );
        assert_eq!(validation::extract_capability("invalid.subject"), None);
        assert_eq!(validation::extract_capability("smith.results.123"), None);

        // Test edge cases for intent ID extraction
        assert_eq!(
            validation::extract_intent_id("smith.results.complex-intent-id-with-dashes"),
            Some("complex-intent-id-with-dashes".to_string())
        );
        assert_eq!(validation::extract_intent_id("invalid.subject"), None);
        assert_eq!(
            validation::extract_intent_id("smith.intents.fs.read.v1"),
            None
        );

        // Test subject type validation edge cases
        assert!(validation::is_valid_smith_subject("smith.custom.subject"));
        assert!(!validation::is_valid_smith_subject(""));
        assert!(!validation::is_valid_smith_subject("nats.subject"));
        assert!(!validation::is_valid_smith_subject("smith"));

        assert!(validation::is_intent_subject("smith.intents.custom.action"));
        assert!(!validation::is_intent_subject("smith.results.intent-123"));
        assert!(!validation::is_intent_subject(""));

        assert!(validation::is_result_subject("smith.results.any-id"));
        assert!(!validation::is_result_subject("smith.intents.fs.read.v1"));
        assert!(!validation::is_result_subject(""));
    }

    #[test]
    fn test_stream_and_consumer_constants() {
        // Test stream constants
        assert_eq!(streams::INTENTS, "INTENTS");
        assert_eq!(streams::RESULTS, "RESULTS");
        assert_eq!(streams::EVENTS, "EVENTS");
        assert_eq!(streams::AUDIT_LOGS, "AUDIT_LOGS");
        assert_eq!(streams::BENCHMARK_RUNS, "BENCHMARK_RUNS");
        assert_eq!(streams::BENCHMARK_STEPS, "BENCHMARK_STEPS");

        // Test consumer constants
        assert_eq!(consumers::EXECUTOR, "executor");
        assert_eq!(consumers::HTTP_EVENTS, "http-events");
        assert_eq!(consumers::HTTP_RESULTS, "http-results");
        assert_eq!(consumers::ADMISSION_RAW, "admission-raw");
        assert_eq!(consumers::AUDIT_COLLECTOR, "audit-collector");
        assert_eq!(consumers::BENCHMARK_COLLECTOR, "benchmark-collector");
        assert_eq!(consumers::BENCHMARK_ANALYTICS, "benchmark-analytics");
        assert_eq!(consumers::BENCHMARK_OPTIMIZER, "benchmark-optimizer");
        assert_eq!(consumers::BENCHMARK_DASHBOARD, "benchmark-dashboard");
    }

    #[test]
    fn test_abi_hash_generation() {
        // Test ABI hash generation
        let hash1 = abi::generate_subject_abi_hash();
        let hash2 = abi::generate_subject_abi_hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2, "ABI hash should be deterministic");
        assert!(!hash1.is_empty(), "ABI hash should not be empty");
        assert!(
            hash1.len() >= 32,
            "ABI hash should be at least 32 characters"
        );

        // Test ABI stability validation
        assert!(abi::validate_subject_abi_stability(&hash1, &hash1).is_ok());
        assert!(abi::validate_subject_abi_stability(&hash1, "different-hash").is_err());
    }

    #[test]
    fn test_special_pattern_constants() {
        // Test GitLab specific patterns
        assert_eq!(patterns::gitlab::EVENT_ISSUE, "smith.gitlab.event.issue");

        // Test orchestrator patterns
        assert_eq!(patterns::orchestrator::ALL, "smith.orchestrator.>");
        assert_eq!(patterns::orchestrator::AUDIT, "smith.orchestrator.audit");
        assert_eq!(patterns::orchestrator::STATUS, "smith.orchestrator.status");

        // Test benchmark patterns
        assert_eq!(patterns::benchmark::RUNS, "smith.benchmark.runs");
        assert_eq!(patterns::benchmark::STEPS, "smith.benchmark.steps");
        assert_eq!(
            patterns::benchmark::TOOL_PERFORMANCE,
            "smith.benchmark.tools"
        );
        assert_eq!(
            patterns::benchmark::CONTEXT_DECISIONS,
            "smith.benchmark.context"
        );
        assert_eq!(
            patterns::benchmark::FAILURE_ANALYSIS,
            "smith.benchmark.failures"
        );
        assert_eq!(
            patterns::benchmark::OPTIMIZER_FEEDBACK,
            "smith.benchmark.optimizer"
        );

        // Test log pattern constants
        assert_eq!(patterns::logs::ALL, "smith.logs.>");
        assert_eq!(patterns::logs::CORE, "smith.logs.core");
        assert_eq!(patterns::logs::CORE_ALL, "smith.logs.core.*");
        assert_eq!(patterns::logs::EXECUTOR, "smith.logs.executor");
        assert_eq!(patterns::logs::EXECUTOR_ALL, "smith.logs.executor.*");
        assert_eq!(patterns::logs::ADMISSION, "smith.logs.admission");
        assert_eq!(patterns::logs::ADMISSION_ALL, "smith.logs.admission.*");
        assert_eq!(patterns::logs::HTTP, "smith.logs.http");
        assert_eq!(patterns::logs::HTTP_ALL, "smith.logs.http.*");
        assert_eq!(patterns::logs::ERRORS, "smith.logs.errors");
        assert_eq!(patterns::logs::ERRORS_ALL, "smith.logs.errors.*");
        assert_eq!(patterns::logs::PERFORMANCE, "smith.logs.performance");
        assert_eq!(patterns::logs::PERFORMANCE_ALL, "smith.logs.performance.*");
        assert_eq!(patterns::logs::SECURITY, "smith.logs.security");
        assert_eq!(patterns::logs::SECURITY_ALL, "smith.logs.security.*");
    }

    #[test]
    fn test_subject_builder_capability_variants() {
        // Test capability method with simple name
        let simple_cap = SubjectBuilder::new().capability("fs").build();
        assert_eq!(simple_cap, "smith.fs.v1");

        // Test capability method with already formatted capability
        let formatted_cap = SubjectBuilder::new().capability("fs.read.v1").build();
        assert_eq!(formatted_cap, "smith.fs.read.v1");

        // Test capability with complex nested names
        let complex_cap = SubjectBuilder::new()
            .part("test")
            .capability("complex.nested.action")
            .build();
        assert_eq!(complex_cap, "smith.test.complex.nested.action");
    }

    #[test]
    fn test_validation_error_handling() {
        // Test validation with code that has no violations
        let clean_code = r#"
            let subject = builders::IntentSubject::raw("fs.read.v1");
            let result = builders::ResultSubject::for_intent("test");
        "#;

        let violations = validation::contains_raw_subject_patterns(clean_code);
        assert!(
            violations.is_empty(),
            "Clean code should have no violations"
        );

        let validation_result = validation::validate_centralized_usage(clean_code);
        assert!(
            validation_result.is_ok(),
            "Clean code should pass validation"
        );

        // Test empty code validation
        assert!(validation::validate_centralized_usage("").is_ok());
        assert!(validation::contains_raw_subject_patterns("").is_empty());
    }

    #[test]
    fn test_subject_extraction_edge_cases() {
        // Test capability extraction with short subjects
        assert_eq!(validation::extract_capability("smith.intents"), None);
        assert_eq!(validation::extract_capability("smith.intents.fs"), None);
        assert_eq!(validation::extract_capability("smith"), None);

        // Test intent ID extraction with short subjects
        assert_eq!(validation::extract_intent_id("smith.results"), None);
        assert_eq!(validation::extract_intent_id("smith"), None);

        // Test with subjects that don't match expected patterns
        assert_eq!(validation::extract_capability("other.system.intent"), None);
        assert_eq!(validation::extract_intent_id("other.system.result"), None);
    }

    #[test]
    fn test_additional_benchmark_patterns() {
        // Test remaining benchmark patterns that may not be covered
        assert_eq!(patterns::benchmark::ALL, "smith.benchmark.>");
        assert_eq!(
            patterns::benchmark::TASK_FEATURES,
            "smith.benchmark.task_features"
        );
        assert_eq!(
            patterns::benchmark::EARLY_STOPPING,
            "smith.benchmark.early_stop"
        );
        assert_eq!(
            patterns::benchmark::POLICY_ASSIGNMENTS,
            "smith.benchmark.policy_assignments"
        );
        assert_eq!(
            patterns::benchmark::REGRESSION_ALERTS,
            "smith.benchmark.regressions"
        );
    }

    #[test]
    fn test_root_pattern_constant() {
        // Test the root pattern constant
        assert_eq!(patterns::ROOT, "smith");

        // Verify it's used consistently in builders
        let builder_subject = SubjectBuilder::new().build();
        assert!(builder_subject.starts_with(patterns::ROOT));
        assert_eq!(builder_subject, patterns::ROOT);
    }

    #[test]
    fn test_abi_version_constant() {
        // Test that ABI version is defined and sensible
        assert_eq!(abi::SUBJECT_ABI_VERSION, 1);

        // Test that ABI hash includes version in its calculation
        let hash = abi::generate_subject_abi_hash();
        assert!(hash.len() == 64); // SHA256 hex output length
    }

    #[test]
    fn test_comprehensive_constant_coverage() {
        // This test ensures we exercise more of the constant definitions
        // that might not be hit by other tests

        // Test remaining benchmark constants
        let benchmark_patterns = vec![
            patterns::benchmark::ALL,
            patterns::benchmark::RUNS,
            patterns::benchmark::STEPS,
            patterns::benchmark::TOOL_PERFORMANCE,
            patterns::benchmark::CONTEXT_DECISIONS,
            patterns::benchmark::FAILURE_ANALYSIS,
            patterns::benchmark::OPTIMIZER_FEEDBACK,
            patterns::benchmark::TASK_FEATURES,
            patterns::benchmark::EARLY_STOPPING,
            patterns::benchmark::POLICY_ASSIGNMENTS,
            patterns::benchmark::REGRESSION_ALERTS,
        ];

        for pattern in benchmark_patterns {
            assert!(pattern.starts_with("smith.benchmark"));
            assert!(!pattern.is_empty());
        }

        // Test additional stream constants
        let stream_names = vec![
            streams::INTENTS_RAW,
            streams::INTENTS_VETTED,
            streams::INTENTS_QUARANTINE,
            streams::SYSTEM_EVENTS,
            streams::BENCHMARK_CONTEXT,
            streams::BENCHMARK_FAILURES,
            streams::BENCHMARK_OPTIMIZER,
        ];

        for stream_name in stream_names {
            assert!(!stream_name.is_empty());
            assert!(stream_name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_'));
        }

        // Test additional consumer constants
        let consumer_names = vec![consumers::EXECUTOR_FS_READ, consumers::EXECUTOR_HTTP_FETCH];

        for consumer_name in consumer_names {
            assert!(!consumer_name.is_empty());
            assert!(consumer_name.starts_with("executor"));
        }
    }
}
