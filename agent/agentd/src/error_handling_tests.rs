//! Comprehensive error handling and edge case tests for the executor
//! 
//! This module contains tests for error scenarios, edge cases, and
//! recovery mechanisms throughout the executor system.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Write, Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};
use tracing::{debug, warn};
use uuid::Uuid;

/// Error handling test environment
pub struct ErrorHandlingTestEnvironment {
    pub workdir: TempDir,
    pub invalid_policy_path: PathBuf,
    pub corrupted_file_path: PathBuf,
    pub permission_denied_path: PathBuf,
    pub non_existent_path: PathBuf,
    pub circular_symlink_path: PathBuf,
    pub error_counters: Arc<Mutex<HashMap<String, u32>>>,
}

impl ErrorHandlingTestEnvironment {
    /// Create a comprehensive test environment for error handling testing
    pub fn new() -> Result<Self> {
        let workdir = tempdir()?;
        
        // Create invalid policy file
        let invalid_policy_path = workdir.path().join("invalid_policy.json");
        File::create(&invalid_policy_path)?.write_all(b"invalid json content {")?;
        
        // Create corrupted file
        let corrupted_file_path = workdir.path().join("corrupted.bin");
        let mut corrupted_file = File::create(&corrupted_file_path)?;
        corrupted_file.write_all(&[0xFF, 0xFE, 0xFD])?; // Invalid UTF-8
        
        // Create file with restricted permissions (if possible)
        let permission_denied_path = workdir.path().join("restricted.txt");
        File::create(&permission_denied_path)?.write_all(b"restricted content")?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&permission_denied_path)?.permissions();
            perms.set_mode(0o000); // No permissions
            fs::set_permissions(&permission_denied_path, perms)?;
        }
        
        // Non-existent path
        let non_existent_path = workdir.path().join("does_not_exist.txt");
        
        // Create circular symlink (if supported)
        let circular_symlink_path = workdir.path().join("circular_link");
        let _ = std::os::unix::fs::symlink(&circular_symlink_path, &circular_symlink_path);
        
        let error_counters = Arc::new(Mutex::new(HashMap::new()));
        
        Ok(Self {
            workdir,
            invalid_policy_path,
            corrupted_file_path,
            permission_denied_path,
            non_existent_path,
            circular_symlink_path,
            error_counters,
        })
    }
    
    /// Increment error counter for tracking
    pub fn increment_error(&self, error_type: &str) {
        let mut counters = self.error_counters.lock().unwrap();
        *counters.entry(error_type.to_string()).or_insert(0) += 1;
    }
    
    /// Get error count for a specific error type
    pub fn get_error_count(&self, error_type: &str) -> u32 {
        let counters = self.error_counters.lock().unwrap();
        counters.get(error_type).copied().unwrap_or(0)
    }
}

/// Error recovery strategy enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorRecoveryStrategy {
    Retry,
    Fallback,
    Fail,
    Skip,
    Quarantine,
}

/// Error severity levels
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Comprehensive error classification system
#[derive(Debug, Clone)]
pub struct ExecutorError {
    pub error_type: String,
    pub severity: ErrorSeverity,
    pub recoverable: bool,
    pub recovery_strategy: ErrorRecoveryStrategy,
    pub message: String,
    pub context: HashMap<String, String>,
}

impl ExecutorError {
    pub fn new(error_type: &str, severity: ErrorSeverity, message: &str) -> Self {
        let recoverable = matches!(severity, ErrorSeverity::Low | ErrorSeverity::Medium);
        let recovery_strategy = match severity {
            ErrorSeverity::Low => ErrorRecoveryStrategy::Retry,
            ErrorSeverity::Medium => ErrorRecoveryStrategy::Fallback,
            ErrorSeverity::High => ErrorRecoveryStrategy::Quarantine,
            ErrorSeverity::Critical => ErrorRecoveryStrategy::Fail,
        };
        
        Self {
            error_type: error_type.to_string(),
            severity,
            recoverable,
            recovery_strategy,
            message: message.to_string(),
            context: HashMap::new(),
        }
    }
    
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    
    #[test]
    fn test_error_environment_setup() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Verify error environment is properly set up
        assert!(env.workdir.path().exists());
        assert!(env.invalid_policy_path.exists());
        assert!(env.corrupted_file_path.exists());
        assert!(env.permission_denied_path.exists());
        assert!(!env.non_existent_path.exists());
    }
    
    #[test]
    fn test_file_system_error_handling() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Test non-existent file error
        let result = fs::read_to_string(&env.non_existent_path);
        assert!(result.is_err());
        match result.unwrap_err().kind() {
            ErrorKind::NotFound => {
                env.increment_error("file_not_found");
            }
            _ => panic!("Expected NotFound error"),
        }
        
        // Test permission denied error (may not work in all test environments)
        let result = fs::read_to_string(&env.permission_denied_path);
        if result.is_err() {
            match result.unwrap_err().kind() {
                ErrorKind::PermissionDenied => {
                    env.increment_error("permission_denied");
                }
                _ => {
                    debug!("Permission test skipped - may not work in this environment");
                }
            }
        }
        
        // Test corrupted file handling
        let result = fs::read_to_string(&env.corrupted_file_path);
        match result {
            Ok(content) => {
                // File read successfully, but content may be invalid UTF-8
                debug!("Corrupted file content: {:?}", content);
            }
            Err(e) => {
                debug!("Expected error reading corrupted file: {}", e);
                env.increment_error("corrupted_file");
            }
        }
        
        // Verify error counting works
        assert!(env.get_error_count("file_not_found") > 0);
    }
    
    #[test]
    fn test_json_parsing_error_handling() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Test invalid JSON parsing
        let invalid_json_cases = vec![
            "invalid json content {",
            "{\"key\": }",
            "{\"key\": \"value\",}",
            "null null null",
            "\"unclosed string",
            "{\"nested\": {\"deeply\": {\"malformed\": }}}",
        ];
        
        for (i, invalid_json) in invalid_json_cases.iter().enumerate() {
            let result: Result<Value, _> = serde_json::from_str(invalid_json);
            assert!(result.is_err(), "Case {}: Should fail to parse: {}", i, invalid_json);
            env.increment_error("json_parse_error");
        }
        
        // Test JSON with unexpected structure
        let unexpected_structures = vec![
            json!(123), // Number instead of object
            json!("string"), // String instead of object
            json!([1, 2, 3]), // Array instead of object
            json!(null), // Null instead of object
        ];
        
        for (i, unexpected) in unexpected_structures.iter().enumerate() {
            let result = validate_json_structure(unexpected);
            assert!(result.is_err(), "Case {}: Should fail structure validation", i);
            env.increment_error("json_structure_error");
        }
        
        assert!(env.get_error_count("json_parse_error") > 0);
        assert!(env.get_error_count("json_structure_error") > 0);
    }
    
    #[test]
    fn test_intent_validation_error_handling() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Test malformed intents
        let malformed_intents = vec![
            json!({}), // Empty object
            json!({"id": "invalid"}), // Missing capability
            json!({"capability": "fs.read.v1"}), // Missing ID
            json!({"id": 123, "capability": "fs.read.v1"}), // Wrong ID type
            json!({"id": Uuid::new_v4().to_string(), "capability": 123}), // Wrong capability type
            json!({"id": Uuid::new_v4().to_string(), "capability": "unknown.capability.v1"}), // Unknown capability
            json!({"id": Uuid::new_v4().to_string(), "capability": "fs.read.v1", "params": "not_object"}), // Wrong params type
        ];
        
        for (i, malformed_intent) in malformed_intents.iter().enumerate() {
            let result = validate_intent_structure(malformed_intent);
            assert!(result.is_err(), "Case {}: Should fail intent validation: {:?}", i, malformed_intent);
            env.increment_error("intent_validation_error");
        }
        
        // Test intents with invalid parameters
        let invalid_param_intents = vec![
            json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "fs.read.v1",
                "params": {"path": "", "max_size": 1024} // Empty path
            }),
            json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "fs.read.v1",
                "params": {"path": "/../../../etc/passwd", "max_size": 1024} // Path traversal
            }),
            json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "http.fetch.v1",
                "params": {"url": "not-a-url", "method": "GET"} // Invalid URL
            }),
            json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "http.fetch.v1",
                "params": {"url": "https://example.com", "method": "INVALID"} // Invalid method
            }),
        ];
        
        for (i, invalid_intent) in invalid_param_intents.iter().enumerate() {
            let result = validate_intent_parameters(invalid_intent);
            assert!(result.is_err(), "Case {}: Should fail parameter validation: {:?}", i, invalid_intent);
            env.increment_error("parameter_validation_error");
        }
        
        assert!(env.get_error_count("intent_validation_error") > 0);
        assert!(env.get_error_count("parameter_validation_error") > 0);
    }
    
    #[test]
    fn test_resource_exhaustion_handling() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Test memory exhaustion simulation
        let large_requests = vec![
            json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "fs.read.v1",
                "params": {"path": "/tmp/test.txt", "max_size": 1_000_000_000} // 1GB
            }),
            json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "http.fetch.v1",
                "params": {
                    "url": "https://example.com",
                    "body": "x".repeat(10_000_000) // 10MB body
                }
            }),
        ];
        
        for (i, large_request) in large_requests.iter().enumerate() {
            let result = validate_resource_limits(large_request);
            assert!(result.is_err(), "Case {}: Should fail resource limit check: {:?}", i, large_request);
            env.increment_error("resource_limit_exceeded");
        }
        
        // Test concurrent request handling
        let mut handles = vec![];
        
        for i in 0..10 {
            let env = env.error_counters.clone();
            let handle = thread::spawn(move || {
                let intent = json!({
                    "id": Uuid::new_v4().to_string(),
                    "capability": "fs.read.v1",
                    "params": {"path": format!("/tmp/test_{}.txt", i)}
                });
                
                if validate_intent_structure(&intent).is_ok() {
                    // Simulate processing
                    thread::sleep(Duration::from_millis(10));
                    "success"
                } else {
                    let mut counters = env.lock().unwrap();
                    *counters.entry("concurrent_validation_error".to_string()).or_insert(0) += 1;
                    "error"
                }
            });
            handles.push(handle);
        }
        
        let mut success_count = 0;
        for handle in handles {
            match handle.join().unwrap() {
                "success" => success_count += 1,
                "error" => {}
                _ => {}
            }
        }
        
        assert!(success_count > 0, "At least some concurrent requests should succeed");
        assert!(env.get_error_count("resource_limit_exceeded") > 0);
    }
    
    #[test]
    fn test_timeout_handling() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Test timeout scenarios
        let timeout_operations = vec![
            ("quick_operation", Duration::from_millis(10), Duration::from_millis(100), true),
            ("slow_operation", Duration::from_millis(200), Duration::from_millis(50), false),
            ("very_slow_operation", Duration::from_millis(1000), Duration::from_millis(100), false),
        ];
        
        for (name, operation_time, timeout, should_succeed) in timeout_operations {
            let start = Instant::now();
            let result = simulate_operation_with_timeout(operation_time, timeout);
            let elapsed = start.elapsed();
            
            if should_succeed {
                assert!(result.is_ok(), "Operation {} should succeed", name);
                assert!(elapsed >= operation_time, "Should take at least operation time");
            } else {
                assert!(result.is_err(), "Operation {} should timeout", name);
                assert!(elapsed <= timeout + Duration::from_millis(50), "Should timeout quickly");
                env.increment_error("timeout_error");
            }
        }
        
        assert!(env.get_error_count("timeout_error") > 0);
    }
    
    #[test]
    fn test_error_recovery_strategies() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Test different error types and their recovery strategies
        let error_scenarios = vec![
            ("network_timeout", ErrorSeverity::Medium, ErrorRecoveryStrategy::Retry),
            ("file_not_found", ErrorSeverity::High, ErrorRecoveryStrategy::Quarantine),
            ("memory_exhausted", ErrorSeverity::Critical, ErrorRecoveryStrategy::Fail),
            ("invalid_parameter", ErrorSeverity::Low, ErrorRecoveryStrategy::Retry),
            ("security_violation", ErrorSeverity::Critical, ErrorRecoveryStrategy::Fail),
        ];
        
        for (error_type, severity, expected_strategy) in error_scenarios {
            let error = ExecutorError::new(error_type, severity, "Test error")
                .with_context("test_id", "test_123")
                .with_context("capability", "fs.read.v1");
            
            assert_eq!(error.recovery_strategy, expected_strategy);
            assert_eq!(error.error_type, error_type);
            assert!(error.context.contains_key("test_id"));
            assert!(error.context.contains_key("capability"));
            
            env.increment_error(error_type);
        }
        
        // Verify all error types were tracked
        assert!(env.get_error_count("network_timeout") > 0);
        assert!(env.get_error_count("memory_exhausted") > 0);
        assert!(env.get_error_count("security_violation") > 0);
    }
    
    #[test]
    fn test_circular_dependency_detection() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Test circular symlink detection
        if env.circular_symlink_path.exists() {
            let result = detect_circular_reference(&env.circular_symlink_path, 10);
            assert!(result.is_err(), "Should detect circular symlink");
            env.increment_error("circular_reference");
        }
        
        // Test circular intent dependencies (simulated)
        let circular_intents = json!({
            "intent_a": {"depends_on": ["intent_b"]},
            "intent_b": {"depends_on": ["intent_c"]},
            "intent_c": {"depends_on": ["intent_a"]} // Circular dependency
        });
        
        let result = detect_intent_circular_dependencies(&circular_intents);
        assert!(result.is_err(), "Should detect circular intent dependencies");
        env.increment_error("circular_dependency");
        
        // Test valid dependency chain
        let valid_intents = json!({
            "intent_a": {"depends_on": ["intent_b"]},
            "intent_b": {"depends_on": ["intent_c"]},
            "intent_c": {"depends_on": []}
        });
        
        let result = detect_intent_circular_dependencies(&valid_intents);
        assert!(result.is_ok(), "Should allow valid dependency chain");
    }
    
    #[test]
    fn test_error_aggregation_and_reporting() {
        let env = ErrorHandlingTestEnvironment::new().unwrap();
        
        // Generate various errors
        for i in 0..5 {
            env.increment_error("validation_error");
            if i % 2 == 0 {
                env.increment_error("timeout_error");
            }
            if i % 3 == 0 {
                env.increment_error("permission_error");
            }
        }
        
        // Test error aggregation
        let error_summary = get_error_summary(&env);
        assert!(error_summary.contains_key("validation_error"));
        assert!(error_summary.contains_key("timeout_error"));
        assert!(error_summary.contains_key("permission_error"));
        
        assert_eq!(error_summary["validation_error"], 5);
        assert_eq!(error_summary["timeout_error"], 3); // 0, 2, 4
        assert_eq!(error_summary["permission_error"], 2); // 0, 3
        
        // Test error report generation
        let report = generate_error_report(&env);
        assert!(report.contains("validation_error"));
        assert!(report.contains("timeout_error"));
        assert!(report.contains("permission_error"));
        assert!(report.contains("Total errors"));
    }
}

/// Helper functions for testing
#[cfg(test)]
mod test_helpers {
    use super::*;
    
    pub fn validate_json_structure(value: &Value) -> Result<()> {
        // Expect object with specific structure
        let obj = value.as_object()
            .ok_or_else(|| anyhow::anyhow!("Expected JSON object"))?;
        
        if obj.is_empty() {
            return Err(anyhow::anyhow!("Object cannot be empty"));
        }
        
        Ok(())
    }
    
    pub fn validate_intent_structure(intent: &Value) -> Result<()> {
        let obj = intent.as_object()
            .ok_or_else(|| anyhow::anyhow!("Intent must be an object"))?;
        
        // Check required fields
        let id = obj.get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'id' field"))?;
        
        // Validate UUID format
        Uuid::parse_str(id)
            .map_err(|_| anyhow::anyhow!("Invalid UUID format in 'id' field"))?;
        
        let capability = obj.get("capability")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'capability' field"))?;
        
        // Validate capability format
        if !capability.contains('.') || !capability.ends_with(".v1") {
            return Err(anyhow::anyhow!("Invalid capability format"));
        }
        
        // Known capabilities
        let known_capabilities = vec![
            "fs.read.v1", "fs.write.v1", "http.fetch.v1", 
            "sqlite.query.v1", "archive.read.v1"
        ];
        
        if !known_capabilities.contains(&capability) {
            return Err(anyhow::anyhow!("Unknown capability: {}", capability));
        }
        
        Ok(())
    }
    
    pub fn validate_intent_parameters(intent: &Value) -> Result<()> {
        let capability = intent["capability"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing capability"))?;
        let params = intent.get("params")
            .ok_or_else(|| anyhow::anyhow!("Missing params"))?;
        
        match capability {
            "fs.read.v1" => validate_fs_read_params(params),
            "http.fetch.v1" => validate_http_fetch_params(params),
            "sqlite.query.v1" => validate_sqlite_params(params),
            _ => Ok(()), // Other capabilities not validated in this test
        }
    }
    
    fn validate_fs_read_params(params: &Value) -> Result<()> {
        let path = params["path"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing path parameter"))?;
        
        if path.is_empty() {
            return Err(anyhow::anyhow!("Path cannot be empty"));
        }
        
        if path.contains("..") {
            return Err(anyhow::anyhow!("Path traversal detected"));
        }
        
        if let Some(max_size) = params.get("max_size") {
            let size = max_size.as_u64()
                .ok_or_else(|| anyhow::anyhow!("Invalid max_size type"))?;
            
            if size > 100_000_000 { // 100MB limit
                return Err(anyhow::anyhow!("max_size too large"));
            }
        }
        
        Ok(())
    }
    
    fn validate_http_fetch_params(params: &Value) -> Result<()> {
        let url_str = params["url"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing URL parameter"))?;
        
        let url = url::Url::parse(url_str)
            .map_err(|_| anyhow::anyhow!("Invalid URL format"))?;
        
        if url.scheme() != "https" && url.scheme() != "http" {
            return Err(anyhow::anyhow!("Only HTTP(S) URLs allowed"));
        }
        
        if let Some(method) = params.get("method") {
            let method_str = method.as_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid method type"))?;
            
            let allowed_methods = vec!["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"];
            if !allowed_methods.contains(&method_str) {
                return Err(anyhow::anyhow!("Invalid HTTP method"));
            }
        }
        
        Ok(())
    }
    
    fn validate_sqlite_params(params: &Value) -> Result<()> {
        let query = params["query"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing query parameter"))?;
        
        let query_upper = query.to_uppercase();
        let dangerous_keywords = vec!["DROP", "DELETE", "ALTER", "CREATE"];
        
        for keyword in dangerous_keywords {
            if query_upper.contains(keyword) {
                return Err(anyhow::anyhow!("Dangerous SQL operation detected"));
            }
        }
        
        Ok(())
    }
    
    pub fn validate_resource_limits(intent: &Value) -> Result<()> {
        let capability = intent["capability"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing capability"))?;
        let params = intent["params"].as_object()
            .ok_or_else(|| anyhow::anyhow!("Missing params"))?;
        
        match capability {
            "fs.read.v1" => {
                if let Some(max_size) = params.get("max_size") {
                    let size = max_size.as_u64()
                        .ok_or_else(|| anyhow::anyhow!("Invalid max_size type"))?;
                    
                    if size > 10_000_000 { // 10MB limit
                        return Err(anyhow::anyhow!("File size limit exceeded"));
                    }
                }
            }
            "http.fetch.v1" => {
                if let Some(body) = params.get("body") {
                    let body_str = serde_json::to_string(body)?;
                    if body_str.len() > 1_000_000 { // 1MB limit
                        return Err(anyhow::anyhow!("Request body size limit exceeded"));
                    }
                }
            }
            _ => {}
        }
        
        Ok(())
    }
    
    pub fn simulate_operation_with_timeout(operation_time: Duration, timeout: Duration) -> Result<()> {
        use std::sync::mpsc;
        
        let (tx, rx) = mpsc::channel();
        
        thread::spawn(move || {
            thread::sleep(operation_time);
            let _ = tx.send(());
        });
        
        match rx.recv_timeout(timeout) {
            Ok(()) => Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!("Operation timed out")),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!("Operation failed")),
        }
    }
    
    pub fn detect_circular_reference(path: &Path, max_depth: usize) -> Result<()> {
        let mut visited = std::collections::HashSet::new();
        check_circular_reference_recursive(path, &mut visited, 0, max_depth)
    }
    
    fn check_circular_reference_recursive(
        path: &Path, 
        visited: &mut std::collections::HashSet<PathBuf>, 
        depth: usize, 
        max_depth: usize
    ) -> Result<()> {
        if depth > max_depth {
            return Err(anyhow::anyhow!("Maximum recursion depth exceeded"));
        }
        
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        
        if visited.contains(&canonical) {
            return Err(anyhow::anyhow!("Circular reference detected"));
        }
        
        visited.insert(canonical.clone());
        
        if canonical.is_symlink() {
            if let Ok(target) = fs::read_link(&canonical) {
                check_circular_reference_recursive(&target, visited, depth + 1, max_depth)?;
            }
        }
        
        visited.remove(&canonical);
        Ok(())
    }
    
    pub fn detect_intent_circular_dependencies(intents: &Value) -> Result<()> {
        let obj = intents.as_object()
            .ok_or_else(|| anyhow::anyhow!("Intents must be an object"))?;
        
        for (intent_id, intent_data) in obj {
            let mut visited = std::collections::HashSet::new();
            check_intent_dependencies(intent_id, intent_data, obj, &mut visited)?;
        }
        
        Ok(())
    }
    
    fn check_intent_dependencies(
        intent_id: &str,
        intent_data: &Value,
        all_intents: &serde_json::Map<String, Value>,
        visited: &mut std::collections::HashSet<String>
    ) -> Result<()> {
        if visited.contains(intent_id) {
            return Err(anyhow::anyhow!("Circular dependency detected at: {}", intent_id));
        }
        
        visited.insert(intent_id.to_string());
        
        if let Some(dependencies) = intent_data.get("depends_on") {
            if let Some(deps_array) = dependencies.as_array() {
                for dep in deps_array {
                    if let Some(dep_id) = dep.as_str() {
                        if let Some(dep_data) = all_intents.get(dep_id) {
                            check_intent_dependencies(dep_id, dep_data, all_intents, visited)?;
                        }
                    }
                }
            }
        }
        
        visited.remove(intent_id);
        Ok(())
    }
    
    pub fn get_error_summary(env: &ErrorHandlingTestEnvironment) -> HashMap<String, u32> {
        env.error_counters.lock().unwrap().clone()
    }
    
    pub fn generate_error_report(env: &ErrorHandlingTestEnvironment) -> String {
        let counters = env.error_counters.lock().unwrap();
        let mut report = String::new();
        
        report.push_str("=== ERROR HANDLING TEST REPORT ===\n\n");
        
        let total_errors: u32 = counters.values().sum();
        report.push_str(&format!("Total errors encountered: {}\n\n", total_errors));
        
        let mut sorted_errors: Vec<_> = counters.iter().collect();
        sorted_errors.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count, descending
        
        report.push_str("Error breakdown:\n");
        for (error_type, count) in sorted_errors {
            report.push_str(&format!("  {}: {} occurrences\n", error_type, count));
        }
        
        report.push_str("\n=== END REPORT ===\n");
        report
    }
}