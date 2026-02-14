/*!
# Test Configuration and Integration

This module provides centralized test configuration, fixtures, and integration utilities
for comprehensive executor testing. It supports different test environments and provides
utilities for security testing, isolation validation, and performance benchmarking.

## Test Environments:
- Unit tests: Fast, isolated component testing
- Integration tests: Cross-component interaction testing
- Security tests: Isolation and security boundary validation
- Performance tests: Resource usage and execution time validation
- End-to-end tests: Complete workflow testing
*/

use anyhow::Result;
use rand;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Once;
use tracing::Level;
use uuid::Uuid;

/// Test environment configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub test_mode: TestMode,
    pub security_level: SecurityLevel,
    pub resource_limits: TestResourceLimits,
    pub temp_dir: PathBuf,
    pub enable_network_tests: bool,
    pub enable_security_tests: bool,
    pub enable_performance_tests: bool,
    pub test_timeout_seconds: u64,
}

/// Test execution modes
#[derive(Debug, Clone, PartialEq)]
pub enum TestMode {
    /// Fast unit tests only
    Unit,
    /// Integration tests with mocked external dependencies
    Integration,
    /// Full security validation tests
    Security,
    /// Performance and benchmark tests
    Performance,
    /// Complete end-to-end testing
    EndToEnd,
}

/// Security testing levels
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityLevel {
    /// Basic parameter validation only
    Basic,
    /// Full isolation testing (requires Linux)
    FullIsolation,
    /// Security policy enforcement testing
    PolicyEnforcement,
    /// Complete security boundary testing
    Complete,
}

/// Test resource limits
#[derive(Debug, Clone)]
pub struct TestResourceLimits {
    pub max_memory_mb: u64,
    pub timeout_ms: u64,
    pub max_temp_files: u32,
    pub pids_max: u32,
}

static INIT: Once = Once::new();

/// Initialize test environment
pub fn init_test_env() {
    INIT.call_once(|| {
        // Initialize tracing for tests
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .without_time()
            .init();

        // Set test environment variables
        env::set_var("RUST_TEST_THREADS", "1"); // Ensure sequential test execution for security tests
        env::set_var("SMITH_TEST_MODE", "true");
    });
}

impl TestConfig {
    /// Create configuration for unit tests
    pub fn unit() -> Self {
        Self {
            test_mode: TestMode::Unit,
            security_level: SecurityLevel::Basic,
            resource_limits: TestResourceLimits {
                max_memory_mb: 100,
                timeout_ms: 5,
                max_temp_files: 10,
                pids_max: 0, // No network in unit tests
            },
            temp_dir: temp_dir("unit"),
            enable_network_tests: false,
            enable_security_tests: false,
            enable_performance_tests: false,
            test_timeout_seconds: 10,
        }
    }

    /// Create configuration for integration tests
    pub fn integration() -> Self {
        Self {
            test_mode: TestMode::Integration,
            security_level: SecurityLevel::Basic,
            resource_limits: TestResourceLimits {
                max_memory_mb: 200,
                timeout_ms: 30,
                max_temp_files: 50,
                pids_max: 10,
            },
            temp_dir: temp_dir("integration"),
            enable_network_tests: true,
            enable_security_tests: false,
            enable_performance_tests: false,
            test_timeout_seconds: 60,
        }
    }

    /// Create configuration for security tests
    pub fn security() -> Self {
        Self {
            test_mode: TestMode::Security,
            security_level: if is_linux() {
                SecurityLevel::FullIsolation
            } else {
                SecurityLevel::PolicyEnforcement
            },
            resource_limits: TestResourceLimits {
                max_memory_mb: 50, // Restrictive for security testing
                timeout_ms: 10,
                max_temp_files: 5,
                pids_max: 2,
            },
            temp_dir: temp_dir("security"),
            enable_network_tests: true,
            enable_security_tests: true,
            enable_performance_tests: false,
            test_timeout_seconds: 30,
        }
    }

    /// Create configuration for performance tests
    pub fn performance() -> Self {
        Self {
            test_mode: TestMode::Performance,
            security_level: SecurityLevel::Basic,
            resource_limits: TestResourceLimits {
                max_memory_mb: 500,
                timeout_ms: 60,
                max_temp_files: 100,
                pids_max: 20,
            },
            temp_dir: temp_dir("performance"),
            enable_network_tests: true,
            enable_security_tests: false,
            enable_performance_tests: true,
            test_timeout_seconds: 120,
        }
    }

    /// Create configuration for end-to-end tests
    pub fn end_to_end() -> Self {
        Self {
            test_mode: TestMode::EndToEnd,
            security_level: SecurityLevel::Complete,
            resource_limits: TestResourceLimits {
                max_memory_mb: 1000,
                timeout_ms: 300,
                max_temp_files: 200,
                pids_max: 50,
            },
            temp_dir: temp_dir("e2e"),
            enable_network_tests: true,
            enable_security_tests: true,
            enable_performance_tests: true,
            test_timeout_seconds: 600,
        }
    }

    /// Get configuration from environment
    pub fn from_env() -> Self {
        let test_mode = env::var("SMITH_TEST_MODE").unwrap_or_else(|_| "unit".to_string());

        match test_mode.as_str() {
            "unit" => Self::unit(),
            "integration" => Self::integration(),
            "security" => Self::security(),
            "performance" => Self::performance(),
            "e2e" | "end-to-end" => Self::end_to_end(),
            _ => Self::unit(), // Default to unit tests
        }
    }

    /// Check if current configuration supports isolation testing
    pub fn supports_isolation(&self) -> bool {
        matches!(
            self.security_level,
            SecurityLevel::FullIsolation | SecurityLevel::Complete
        ) && is_linux()
    }

    /// Check if current configuration supports network testing
    pub fn supports_network(&self) -> bool {
        self.enable_network_tests && !is_ci_environment()
    }

    /// Get test data directory
    pub fn test_data_dir(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
    }

    /// Get temp directory for test artifacts
    pub fn temp_dir(&self) -> &PathBuf {
        &self.temp_dir
    }

    /// Clean up test environment
    pub fn cleanup(&self) -> Result<()> {
        if self.temp_dir.exists() {
            std::fs::remove_dir_all(&self.temp_dir)?;
        }
        Ok(())
    }
}

/// Test fixtures and utilities
pub struct TestFixtures;

impl TestFixtures {
    /// Create a test intent with specified parameters  
    pub fn create_test_intent(
        capability: &str,
        params: serde_json::Value,
    ) -> smith_protocol::Intent {
        use std::collections::HashMap;

        // Map capability string to enum
        let capability_enum = match capability {
            "fs.read.v1" => smith_protocol::Capability::FsReadV1,
            "fs.write.v1" => smith_protocol::Capability::FsWriteV1,
            "http.fetch.v1" => smith_protocol::Capability::HttpFetchV1,
            "shell.exec.v1" => smith_protocol::Capability::ShellExec,
            _ => smith_protocol::Capability::FsReadV1, // Default fallback
        };

        smith_protocol::Intent {
            id: Uuid::new_v4().to_string(),
            capability: capability_enum,
            domain: params
                .get("path")
                .or(params.get("url"))
                .map(|v| v.as_str().unwrap_or(""))
                .unwrap_or("test")
                .to_string(),
            params,
            created_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            ttl_ms: 300000, // 5 minutes
            nonce: format!("{:032x}", rand::random::<u128>()),
            signer: "test-signer".to_string(),
            signature_b64: "test-signature".to_string(),
            metadata: HashMap::new(),
        }
    }

    /// Create a malicious test intent
    pub fn create_malicious_intent(
        capability: &str,
        params: serde_json::Value,
    ) -> smith_protocol::Intent {
        // For malicious intents, we'll use a different signature to indicate test type
        let mut intent = Self::create_test_intent(capability, params);
        intent.signature_b64 = "malicious-test-signature".to_string();
        intent
    }

    /// Create test execution context
    pub fn create_test_exec_context() -> agentd::ExecContext {
        let config = TestConfig::from_env();
        agentd::create_exec_context(
            &config.temp_dir,
            agentd::ExecutionLimits {
                timeout_ms: config.resource_limits.timeout_ms,
                mem_bytes: config.resource_limits.max_memory_mb * 1024 * 1024,
                cpu_ms_per_100ms: 50,
                io_bytes: 10 * 1024 * 1024,
                pids_max: config.resource_limits.pids_max,
            },
            agentd::Scope {
                paths: vec!["/tmp".to_string()],
                urls: vec![],
            },
            format!("test-{}", Uuid::new_v4()),
        )
    }

    /// Create test files in temp directory
    pub fn create_test_files(config: &TestConfig) -> Result<Vec<PathBuf>> {
        std::fs::create_dir_all(&config.temp_dir)?;

        let files = vec![
            config.temp_dir.join("test1.txt"),
            config.temp_dir.join("test2.json"),
            config.temp_dir.join("readonly.txt"),
        ];

        // Create test files with different content
        std::fs::write(&files[0], "Test content 1")?;
        std::fs::write(&files[1], r#"{"test": "data"}"#)?;
        std::fs::write(&files[2], "Read-only content")?;

        // Make one file read-only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&files[2])?.permissions();
            perms.set_mode(0o444); // Read-only
            std::fs::set_permissions(&files[2], perms)?;
        }

        Ok(files)
    }
}

/// Test environment utilities
pub struct TestEnvironment;

impl TestEnvironment {
    /// Check if running in CI environment
    pub fn is_ci() -> bool {
        is_ci_environment()
    }

    /// Check if running on Linux (required for full isolation testing)
    pub fn is_linux() -> bool {
        is_linux()
    }

    /// Check if running with elevated privileges
    pub fn has_elevated_privileges() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Check if security features are available
    pub fn security_features_available() -> SecurityFeatures {
        SecurityFeatures {
            landlock: check_landlock_support(),
            seccomp: check_seccomp_support(),
            cgroups_v2: check_cgroups_v2_support(),
            namespaces: check_namespace_support(),
        }
    }

    /// Skip test if requirements not met
    pub fn skip_if_requirements_not_met(requirements: &TestRequirements) {
        if requirements.requires_linux && !Self::is_linux() {
            panic!("Test requires Linux - skipping");
        }

        if requirements.requires_elevated_privileges && !Self::has_elevated_privileges() {
            panic!("Test requires elevated privileges - skipping");
        }

        if requirements.requires_network && Self::is_ci() {
            panic!("Test requires network access - skipping in CI");
        }

        let features = Self::security_features_available();
        if requirements.requires_landlock && !features.landlock {
            panic!("Test requires Landlock LSM support - skipping");
        }

        if requirements.requires_seccomp && !features.seccomp {
            panic!("Test requires seccomp-bpf support - skipping");
        }
    }
}

/// Test requirements specification
#[derive(Debug, Default)]
pub struct TestRequirements {
    pub requires_linux: bool,
    pub requires_elevated_privileges: bool,
    pub requires_network: bool,
    pub requires_landlock: bool,
    pub requires_seccomp: bool,
    pub requires_cgroups: bool,
}

/// Available security features
#[derive(Debug)]
pub struct SecurityFeatures {
    pub landlock: bool,
    pub seccomp: bool,
    pub cgroups_v2: bool,
    pub namespaces: bool,
}

/// Test result analysis utilities
pub struct TestAnalyzer;

impl TestAnalyzer {
    /// Analyze test coverage from test results
    pub fn analyze_coverage(results: &[TestResult]) -> CoverageReport {
        let total_tests = results.len();
        let passed_tests = results.iter().filter(|r| r.passed).count();
        let failed_tests = total_tests - passed_tests;

        let security_tests = results.iter().filter(|r| r.test_type == "security").count();
        let isolation_tests = results
            .iter()
            .filter(|r| r.test_type == "isolation")
            .count();
        let capability_tests = results
            .iter()
            .filter(|r| r.test_type == "capability")
            .count();

        CoverageReport {
            total_tests,
            passed_tests,
            failed_tests,
            security_tests,
            isolation_tests,
            capability_tests,
            coverage_percentage: (passed_tests as f64 / total_tests as f64) * 100.0,
        }
    }

    /// Generate test report
    pub fn generate_report(coverage: &CoverageReport) -> String {
        format!(
            r#"
# Executor Test Coverage Report

## Summary
- Total Tests: {}
- Passed: {}
- Failed: {}
- Coverage: {:.1}%

## Test Categories
- Security Tests: {}
- Isolation Tests: {}
- Capability Tests: {}

## Status
{}
"#,
            coverage.total_tests,
            coverage.passed_tests,
            coverage.failed_tests,
            coverage.coverage_percentage,
            coverage.security_tests,
            coverage.isolation_tests,
            coverage.capability_tests,
            if coverage.coverage_percentage >= 85.0 {
                "✅ Coverage target met (85%+)"
            } else {
                "❌ Coverage target not met (< 85%)"
            }
        )
    }
}

/// Test result structure
#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub test_type: String,
    pub duration_ms: u64,
    pub error_message: Option<String>,
}

/// Coverage report structure
#[derive(Debug)]
pub struct CoverageReport {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub security_tests: usize,
    pub isolation_tests: usize,
    pub capability_tests: usize,
    pub coverage_percentage: f64,
}

// Helper functions
fn temp_dir(suffix: &str) -> PathBuf {
    std::env::temp_dir()
        .join("smith-executor-tests")
        .join(format!("{}-{}", suffix, Uuid::new_v4()))
}

fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

fn is_ci_environment() -> bool {
    env::var("CI").is_ok()
        || env::var("GITHUB_ACTIONS").is_ok()
        || env::var("GITLAB_CI").is_ok()
        || env::var("BUILDKITE").is_ok()
}

fn check_landlock_support() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if Landlock is available (Linux 5.13+)
        std::fs::metadata("/sys/kernel/security/landlock").is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn check_seccomp_support() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if seccomp is available
        std::fs::metadata("/proc/sys/kernel/seccomp").is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn check_cgroups_v2_support() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if cgroups v2 is available
        std::fs::metadata("/sys/fs/cgroup/cgroup.controllers").is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn check_namespace_support() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if namespaces are supported
        std::fs::metadata("/proc/self/ns").is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_mode_equality() {
        assert_eq!(TestMode::Unit, TestMode::Unit);
        assert_eq!(TestMode::Integration, TestMode::Integration);
        assert_eq!(TestMode::Security, TestMode::Security);
        assert_eq!(TestMode::Performance, TestMode::Performance);
        assert_eq!(TestMode::EndToEnd, TestMode::EndToEnd);
        assert_ne!(TestMode::Unit, TestMode::Integration);
    }

    #[test]
    fn test_security_level_equality() {
        assert_eq!(SecurityLevel::Basic, SecurityLevel::Basic);
        assert_eq!(SecurityLevel::FullIsolation, SecurityLevel::FullIsolation);
        assert_eq!(
            SecurityLevel::PolicyEnforcement,
            SecurityLevel::PolicyEnforcement
        );
        assert_eq!(SecurityLevel::Complete, SecurityLevel::Complete);
        assert_ne!(SecurityLevel::Basic, SecurityLevel::Complete);
    }

    #[test]
    fn test_test_config_unit() {
        let config = TestConfig::unit();
        assert_eq!(config.test_mode, TestMode::Unit);
        assert_eq!(config.security_level, SecurityLevel::Basic);
        assert!(!config.enable_network_tests);
        assert!(!config.enable_security_tests);
        assert!(!config.enable_performance_tests);
        assert_eq!(config.test_timeout_seconds, 10);
        assert_eq!(config.resource_limits.max_memory_mb, 100);
    }

    #[test]
    fn test_test_config_integration() {
        let config = TestConfig::integration();
        assert_eq!(config.test_mode, TestMode::Integration);
        assert_eq!(config.security_level, SecurityLevel::Basic);
        assert!(config.enable_network_tests);
        assert!(!config.enable_security_tests);
        assert_eq!(config.test_timeout_seconds, 60);
        assert_eq!(config.resource_limits.max_memory_mb, 200);
    }

    #[test]
    fn test_test_config_security() {
        let config = TestConfig::security();
        assert_eq!(config.test_mode, TestMode::Security);
        // Security level depends on platform
        assert!(matches!(
            config.security_level,
            SecurityLevel::FullIsolation | SecurityLevel::PolicyEnforcement
        ));
        assert!(config.enable_security_tests);
        assert_eq!(config.test_timeout_seconds, 30);
        assert_eq!(config.resource_limits.max_memory_mb, 50);
    }

    #[test]
    fn test_test_config_performance() {
        let config = TestConfig::performance();
        assert_eq!(config.test_mode, TestMode::Performance);
        assert_eq!(config.security_level, SecurityLevel::Basic);
        assert!(config.enable_performance_tests);
        assert_eq!(config.test_timeout_seconds, 120);
        assert_eq!(config.resource_limits.max_memory_mb, 500);
    }

    #[test]
    fn test_test_config_end_to_end() {
        let config = TestConfig::end_to_end();
        assert_eq!(config.test_mode, TestMode::EndToEnd);
        assert_eq!(config.security_level, SecurityLevel::Complete);
        assert!(config.enable_network_tests);
        assert!(config.enable_security_tests);
        assert!(config.enable_performance_tests);
        assert_eq!(config.test_timeout_seconds, 600);
        assert_eq!(config.resource_limits.max_memory_mb, 1000);
    }

    #[test]
    fn test_test_config_from_env() {
        // With default environment, should return unit config
        let config = TestConfig::from_env();
        // from_env returns based on SMITH_TEST_MODE which is set in init_test_env
        // Without init, it defaults to unit
        assert!(matches!(
            config.test_mode,
            TestMode::Unit
                | TestMode::Security
                | TestMode::Integration
                | TestMode::Performance
                | TestMode::EndToEnd
        ));
    }

    #[test]
    fn test_test_config_supports_isolation() {
        let config = TestConfig::unit();
        // Basic security level doesn't support isolation
        assert!(!config.supports_isolation());

        let config = TestConfig::end_to_end();
        // Complete security level supports isolation on Linux
        #[cfg(target_os = "linux")]
        assert!(config.supports_isolation());
        #[cfg(not(target_os = "linux"))]
        assert!(!config.supports_isolation());
    }

    #[test]
    fn test_test_config_supports_network() {
        let config = TestConfig::unit();
        // Unit tests don't enable network
        assert!(!config.supports_network());

        // Integration enables network but not in CI
        let config = TestConfig::integration();
        // In CI, network is disabled
        if !is_ci_environment() {
            assert!(config.supports_network());
        }
    }

    #[test]
    fn test_test_config_test_data_dir() {
        let config = TestConfig::unit();
        let data_dir = config.test_data_dir();
        assert!(data_dir.ends_with("tests/data"));
    }

    #[test]
    fn test_test_config_temp_dir() {
        let config = TestConfig::unit();
        let temp_dir = config.temp_dir();
        assert!(temp_dir.to_string_lossy().contains("unit"));
    }

    #[test]
    fn test_test_config_cleanup() {
        let config = TestConfig::unit();
        // Cleanup should not error on non-existent directory
        let result = config.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn test_test_environment_is_ci() {
        // This test just verifies the function doesn't panic
        let _is_ci = TestEnvironment::is_ci();
    }

    #[test]
    fn test_test_environment_is_linux() {
        let is_linux = TestEnvironment::is_linux();
        #[cfg(target_os = "linux")]
        assert!(is_linux);
        #[cfg(not(target_os = "linux"))]
        assert!(!is_linux);
    }

    #[test]
    fn test_test_environment_has_elevated_privileges() {
        // Just verify it doesn't panic
        let _has_elevated = TestEnvironment::has_elevated_privileges();
    }

    #[test]
    fn test_test_environment_security_features_available() {
        let features = TestEnvironment::security_features_available();
        // On non-Linux, all features should be false
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!features.landlock);
            assert!(!features.seccomp);
            assert!(!features.cgroups_v2);
            assert!(!features.namespaces);
        }
    }

    #[test]
    fn test_test_requirements_default() {
        let requirements = TestRequirements::default();
        assert!(!requirements.requires_linux);
        assert!(!requirements.requires_elevated_privileges);
        assert!(!requirements.requires_network);
        assert!(!requirements.requires_landlock);
        assert!(!requirements.requires_seccomp);
        assert!(!requirements.requires_cgroups);
    }

    #[test]
    fn test_test_result_creation() {
        let result = TestResult {
            name: "test_example".to_string(),
            passed: true,
            test_type: "unit".to_string(),
            duration_ms: 100,
            error_message: None,
        };
        assert_eq!(result.name, "test_example");
        assert!(result.passed);
        assert_eq!(result.test_type, "unit");
        assert_eq!(result.duration_ms, 100);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_test_result_with_error() {
        let result = TestResult {
            name: "test_failing".to_string(),
            passed: false,
            test_type: "security".to_string(),
            duration_ms: 50,
            error_message: Some("Assertion failed".to_string()),
        };
        assert!(!result.passed);
        assert_eq!(result.error_message, Some("Assertion failed".to_string()));
    }

    #[test]
    fn test_coverage_report_creation() {
        let report = CoverageReport {
            total_tests: 100,
            passed_tests: 85,
            failed_tests: 15,
            security_tests: 20,
            isolation_tests: 10,
            capability_tests: 30,
            coverage_percentage: 85.0,
        };
        assert_eq!(report.total_tests, 100);
        assert_eq!(report.passed_tests, 85);
        assert_eq!(report.failed_tests, 15);
        assert_eq!(report.coverage_percentage, 85.0);
    }

    #[test]
    fn test_test_analyzer_analyze_coverage() {
        let results = vec![
            TestResult {
                name: "test1".to_string(),
                passed: true,
                test_type: "security".to_string(),
                duration_ms: 10,
                error_message: None,
            },
            TestResult {
                name: "test2".to_string(),
                passed: true,
                test_type: "isolation".to_string(),
                duration_ms: 20,
                error_message: None,
            },
            TestResult {
                name: "test3".to_string(),
                passed: false,
                test_type: "capability".to_string(),
                duration_ms: 30,
                error_message: Some("Failed".to_string()),
            },
        ];

        let coverage = TestAnalyzer::analyze_coverage(&results);
        assert_eq!(coverage.total_tests, 3);
        assert_eq!(coverage.passed_tests, 2);
        assert_eq!(coverage.failed_tests, 1);
        assert_eq!(coverage.security_tests, 1);
        assert_eq!(coverage.isolation_tests, 1);
        assert_eq!(coverage.capability_tests, 1);
        assert!((coverage.coverage_percentage - 66.66).abs() < 1.0);
    }

    #[test]
    fn test_test_analyzer_generate_report() {
        let coverage = CoverageReport {
            total_tests: 100,
            passed_tests: 90,
            failed_tests: 10,
            security_tests: 30,
            isolation_tests: 20,
            capability_tests: 50,
            coverage_percentage: 90.0,
        };

        let report = TestAnalyzer::generate_report(&coverage);
        assert!(report.contains("Total Tests: 100"));
        assert!(report.contains("Passed: 90"));
        assert!(report.contains("Failed: 10"));
        assert!(report.contains("Coverage: 90.0%"));
        assert!(report.contains("Coverage target met"));
    }

    #[test]
    fn test_test_analyzer_generate_report_below_target() {
        let coverage = CoverageReport {
            total_tests: 100,
            passed_tests: 50,
            failed_tests: 50,
            security_tests: 10,
            isolation_tests: 10,
            capability_tests: 30,
            coverage_percentage: 50.0,
        };

        let report = TestAnalyzer::generate_report(&coverage);
        assert!(report.contains("Coverage target not met"));
    }

    #[test]
    fn test_temp_dir_function() {
        let dir = temp_dir("test-suffix");
        assert!(dir.to_string_lossy().contains("smith-executor-tests"));
        assert!(dir.to_string_lossy().contains("test-suffix"));
    }

    #[test]
    fn test_is_linux_function() {
        let result = is_linux();
        #[cfg(target_os = "linux")]
        assert!(result);
        #[cfg(not(target_os = "linux"))]
        assert!(!result);
    }

    #[test]
    fn test_is_ci_environment_function() {
        // Just verify it doesn't panic and returns a bool
        let _result = is_ci_environment();
    }

    #[test]
    fn test_check_landlock_support_function() {
        let result = check_landlock_support();
        #[cfg(not(target_os = "linux"))]
        assert!(!result);
        // On Linux, result depends on kernel version
    }

    #[test]
    fn test_check_seccomp_support_function() {
        let result = check_seccomp_support();
        #[cfg(not(target_os = "linux"))]
        assert!(!result);
    }

    #[test]
    fn test_check_cgroups_v2_support_function() {
        let result = check_cgroups_v2_support();
        #[cfg(not(target_os = "linux"))]
        assert!(!result);
    }

    #[test]
    fn test_check_namespace_support_function() {
        let result = check_namespace_support();
        #[cfg(not(target_os = "linux"))]
        assert!(!result);
    }

    #[test]
    fn test_resource_limits_creation() {
        let limits = TestResourceLimits {
            max_memory_mb: 256,
            timeout_ms: 5000,
            max_temp_files: 50,
            pids_max: 10,
        };
        assert_eq!(limits.max_memory_mb, 256);
        assert_eq!(limits.timeout_ms, 5000);
        assert_eq!(limits.max_temp_files, 50);
        assert_eq!(limits.pids_max, 10);
    }

    #[test]
    fn test_security_features_creation() {
        let features = SecurityFeatures {
            landlock: true,
            seccomp: true,
            cgroups_v2: false,
            namespaces: true,
        };
        assert!(features.landlock);
        assert!(features.seccomp);
        assert!(!features.cgroups_v2);
        assert!(features.namespaces);
    }

    #[test]
    fn test_test_config_clone() {
        let config = TestConfig::unit();
        let cloned = config.clone();
        assert_eq!(cloned.test_mode, config.test_mode);
        assert_eq!(cloned.security_level, config.security_level);
        assert_eq!(cloned.test_timeout_seconds, config.test_timeout_seconds);
    }

    #[test]
    fn test_test_resource_limits_clone() {
        let limits = TestResourceLimits {
            max_memory_mb: 100,
            timeout_ms: 1000,
            max_temp_files: 10,
            pids_max: 5,
        };
        let cloned = limits.clone();
        assert_eq!(cloned.max_memory_mb, limits.max_memory_mb);
        assert_eq!(cloned.timeout_ms, limits.timeout_ms);
    }
}
