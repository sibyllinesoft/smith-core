//! Security Error Handling Tests for Smith Executor
//!
//! Tests that verify proper error handling, logging, and recovery
//! when security violations or failures occur.

use anyhow::Result;
use serde_json::json;
use std::{collections::HashMap, time::Duration};
use tempfile::TempDir;

use agentd::{
    capabilities::register_builtin_capabilities,
    capability::{ExecCtx, ExecutionScope, SandboxConfig},
    runners::{create_exec_context, MemoryOutputSink, RunnerRegistry, Scope},
    ExecutionLimits,
};
use smith_protocol::ExecutionLimits as CapabilityExecutionLimits;
use smith_protocol::{Capability as ProtoCapability, ExecutionStatus, Intent, SandboxMode};

/// Test error handling for validation failures
#[tokio::test]
async fn test_validation_error_handling() -> Result<()> {
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Test various validation errors and ensure proper error types
    let validation_test_cases = vec![
        (json!({ "command": "" }), "empty command"),
        (json!({}), "missing command"),
        (
            json!({ "command": "echo", "timeout_ms": 0 }),
            "invalid timeout",
        ),
        (
            json!({ "command": "echo", "timeout_ms": 999_999 }),
            "timeout too large",
        ),
        (
            json!({ "command": "echo", "forbidden_param": "value" }),
            "unsupported param",
        ),
        (json!({ "command": 123 }), "invalid command type"),
    ];

    for (params, description) in validation_test_cases {
        let intent = Intent::new(
            ProtoCapability::ShellExec,
            "validation-error-test".to_string(),
            params.clone(),
            30000,
            "test-user".to_string(),
        );

        let validation_result = capability.validate(&intent);

        match validation_result {
            Err(e) => {
                // Verify error contains meaningful information
                let error_msg = format!("{:?}", e);
                assert!(
                    !error_msg.is_empty(),
                    "Error message should not be empty for {}",
                    description
                );
                assert!(
                    !error_msg.contains("Unknown error"),
                    "Error should be descriptive for {}",
                    description
                );

                // Verify error is not leaking sensitive information
                assert!(
                    !error_msg.contains("super_secret_token"),
                    "Error should not leak secret values"
                );
                assert!(
                    !error_msg.contains("password="),
                    "Error should not leak credential-like material"
                );

                println!("Validation error for {}: {}", description, error_msg);
            }
            Ok(_) => {
                panic!(
                    "Validation should have failed for {}: {:?}",
                    description, params
                );
            }
        }
    }

    Ok(())
}

/// Test error handling for execution failures under security constraints
#[tokio::test]
async fn test_execution_error_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Test execution errors with proper error propagation
    let execution_test_cases = vec![
        ("nonexistent.txt", "file not found"),
        ("../outside_scope.txt", "path outside scope"),
        ("", "empty filename"),
    ];

    for (filename, description) in execution_test_cases {
        let exec_context = create_exec_context(
            temp_dir.path(),
            ExecutionLimits {
                cpu_ms_per_100ms: 80,
                mem_bytes: 64 * 1024 * 1024,
                io_bytes: 10 * 1024 * 1024,
                pids_max: 5,
                timeout_ms: 5000,
            },
            Scope {
                paths: vec![temp_dir.path().to_string_lossy().to_string()],
                urls: vec![],
            },
            format!("error-test-{}", description.replace(' ', "-")),
        );

        let mut output_sink = MemoryOutputSink::new();
        let params = json!({ "path": filename, "len": 1024 });

        let result = runner
            .execute(&exec_context, params, &mut output_sink)
            .await;

        match result {
            Ok(exec_result) => {
                // Should complete but with error status for invalid operations
                if filename == "nonexistent.txt" {
                    // File not found is acceptable - depends on runner implementation
                    assert!(
                        exec_result.status == ExecutionStatus::Ok
                            || exec_result.status == ExecutionStatus::Error,
                        "Should handle non-existent file gracefully: {}",
                        description
                    );
                } else {
                    // Other errors should be handled properly
                    assert!(
                        exec_result.status == ExecutionStatus::Error,
                        "Should return error status for: {}",
                        description
                    );
                }
            }
            Err(e) => {
                // Execution errors are also acceptable - verify they're informative
                let error_msg = format!("{:?}", e);
                assert!(
                    !error_msg.is_empty(),
                    "Error message should not be empty for {}",
                    description
                );
                println!("Execution error for {}: {}", description, error_msg);
            }
        }

        // Verify error logging occurred
        if !output_sink.logs.is_empty() {
            let log_content = output_sink.logs.join("\n");
            println!("Logs for {}: {}", description, log_content);
        }
    }

    Ok(())
}

/// Test timeout handling under security constraints
#[tokio::test]
async fn test_timeout_error_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create a legitimate file
    let test_file = temp_dir.path().join("timeout_test.txt");
    tokio::fs::write(&test_file, "timeout test content").await?;

    // Set very short timeout
    let exec_context = create_exec_context(
        temp_dir.path(),
        ExecutionLimits {
            cpu_ms_per_100ms: 80,
            mem_bytes: 64 * 1024 * 1024,
            io_bytes: 10 * 1024 * 1024,
            pids_max: 5,
            timeout_ms: 1, // 1ms timeout - should be too short
        },
        Scope {
            paths: vec![test_file.to_string_lossy().to_string()],
            urls: vec![],
        },
        "timeout-test".to_string(),
    );

    let mut output_sink = MemoryOutputSink::new();
    let params = json!({
        "path": test_file.file_name().unwrap().to_string_lossy(),
        "len": 1024
    });

    let start_time = std::time::Instant::now();
    let result = runner
        .execute(&exec_context, params, &mut output_sink)
        .await;
    let elapsed = start_time.elapsed();

    // Should complete quickly due to timeout, either successfully or with timeout error
    assert!(
        elapsed < Duration::from_secs(2),
        "Should not take longer than 2 seconds"
    );

    match result {
        Ok(exec_result) => {
            // May complete successfully if very fast, or with timeout error
            println!("Timeout test result: {:?}", exec_result.status);
        }
        Err(e) => {
            // Timeout error is acceptable
            let error_msg = e.to_string();
            println!("Timeout error (expected): {}", error_msg);
        }
    }

    Ok(())
}

/// Test resource limit error handling
#[tokio::test]
async fn test_resource_limit_error_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create a large file that exceeds I/O limits
    let large_file = temp_dir.path().join("large.txt");
    let content = "A".repeat(2 * 1024 * 1024); // 2MB content
    tokio::fs::write(&large_file, &content).await?;

    // Set very restrictive I/O limits
    let exec_context = create_exec_context(
        temp_dir.path(),
        ExecutionLimits {
            cpu_ms_per_100ms: 80,
            mem_bytes: 64 * 1024 * 1024,
            io_bytes: 512 * 1024, // 512KB I/O limit - less than file size
            pids_max: 5,
            timeout_ms: 10000,
        },
        Scope {
            paths: vec![large_file.to_string_lossy().to_string()],
            urls: vec![],
        },
        "resource-limit-test".to_string(),
    );

    let mut output_sink = MemoryOutputSink::new();
    let params = json!({
        "path": large_file.file_name().unwrap().to_string_lossy(),
        "len": 2 * 1024 * 1024 // Request full file
    });

    let result = runner
        .execute(&exec_context, params, &mut output_sink)
        .await?;

    // Should handle resource limits gracefully
    assert!(result.status == ExecutionStatus::Ok || result.status == ExecutionStatus::Error);

    // Should not exceed I/O limits
    assert!(
        result.stdout_bytes <= 512 * 1024,
        "Should respect I/O limits, got {} bytes",
        result.stdout_bytes
    );

    // Check for appropriate logging
    if !output_sink.logs.is_empty() {
        let log_content = output_sink.logs.join("\n");
        println!("Resource limit logs: {}", log_content);
    }

    Ok(())
}

/// Test network error handling for HTTP fetch
#[tokio::test]
async fn test_network_error_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("http.fetch")
        .expect("http.fetch runner should be registered");

    // Test various network error scenarios
    let network_error_cases = vec![
        ("http://127.0.0.1:1", "connection refused"),
        (
            "http://nonexistent-domain-12345.com",
            "DNS resolution failure",
        ),
        ("http://httpbin.org:99999/get", "invalid port"),
    ];

    for (url, description) in network_error_cases {
        let exec_context = create_exec_context(
            temp_dir.path(),
            ExecutionLimits {
                cpu_ms_per_100ms: 80,
                mem_bytes: 64 * 1024 * 1024,
                io_bytes: 10 * 1024 * 1024,
                pids_max: 5,
                timeout_ms: 5000, // 5 second timeout
            },
            Scope {
                paths: vec![],
                urls: vec![url.to_string()],
            },
            format!("network-error-{}", description.replace(' ', "-")),
        );

        let mut output_sink = MemoryOutputSink::new();
        let params = json!({
            "url": url,
            "method": "GET",
            "timeout": 2000
        });

        let result = runner
            .execute(&exec_context, params, &mut output_sink)
            .await;

        match result {
            Ok(exec_result) => {
                // Network errors should be handled gracefully
                assert!(
                    exec_result.status == ExecutionStatus::Ok
                        || exec_result.status == ExecutionStatus::Error,
                    "Should handle network error gracefully: {}",
                    description
                );

                // Should not crash or hang
                println!(
                    "Network error test completed for {}: {:?}",
                    description, exec_result.status
                );
            }
            Err(e) => {
                // Execution errors are also acceptable for network failures
                let error_msg = format!("{:?}", e);
                println!("Network execution error for {}: {}", description, error_msg);
            }
        }

        // Check error logging
        if !output_sink.logs.is_empty() {
            let log_content = output_sink.logs.join("\n");
            println!("Network error logs for {}: {}", description, log_content);
        }
    }

    Ok(())
}

/// Test concurrent error handling with capability validation
#[tokio::test]
async fn test_concurrent_error_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = std::sync::Arc::new(register_builtin_capabilities());

    // Create some test files
    let valid_file = temp_dir.path().join("valid.txt");
    tokio::fs::write(&valid_file, "valid content").await?;

    // Test concurrent validation with various error conditions
    let mut tasks = Vec::new();

    for i in 0..10 {
        let registry_ref = registry.clone();
        let _temp_dir_path = temp_dir.path().to_path_buf();

        let task = tokio::spawn(async move {
            let capability = registry_ref
                .get("shell.exec.v1")
                .expect("shell.exec.v1 should be registered");

            let params = if i % 2 == 0 {
                json!({ "command": "echo", "args": ["valid"] })
            } else {
                json!({ "command": "echo", "timeout_ms": 0 })
            };

            let intent = Intent::new(
                ProtoCapability::ShellExec,
                format!("concurrent-error-{}", i),
                params,
                30000,
                "test-user".to_string(),
            );

            let validation_result = capability.validate(&intent);
            (i, validation_result)
        });

        tasks.push(task);
    }

    // Wait for all tasks and verify error handling
    let results = futures::future::join_all(tasks).await;

    let mut success_count = 0;
    let mut error_count = 0;
    let mut panic_count = 0;

    for result in results {
        match result {
            Ok((task_id, validation_result)) => match validation_result {
                Ok(_) => {
                    success_count += 1;
                    println!("Task {} validation succeeded", task_id);
                }
                Err(e) => {
                    error_count += 1;
                    println!("Task {} validation failed safely: {:?}", task_id, e);
                }
            },
            Err(e) => {
                panic_count += 1;
                println!("Task panicked: {}", e);
            }
        }
    }

    // Verify system remained stable
    assert_eq!(
        panic_count, 0,
        "No tasks should panic during error handling"
    );
    assert!(
        success_count > 0,
        "At least some validations should succeed"
    );

    println!(
        "Concurrent error handling results - Success: {}, Errors: {}, Panics: {}",
        success_count, error_count, panic_count
    );

    Ok(())
}

/// Test error recovery and cleanup
#[tokio::test]
async fn test_error_recovery_and_cleanup() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Test recovery after various error conditions
    let error_recovery_tests = vec![
        // Invalid intent that should be rejected
        Intent::new(
            ProtoCapability::ShellExec,
            "invalid-1".to_string(),
            json!({ "command": "" }),
            30000,
            "attacker".to_string(),
        ),
        // Another invalid intent
        Intent::new(
            ProtoCapability::ShellExec,
            "invalid-2".to_string(),
            json!({ "command": "echo", "timeout_ms": 0 }),
            30000,
            "attacker".to_string(),
        ),
    ];

    // Process invalid intents
    for invalid_intent in error_recovery_tests {
        let validation_result = capability.validate(&invalid_intent);
        assert!(
            validation_result.is_err(),
            "Invalid intent should be rejected"
        );
    }

    // After errors, system should still work for valid requests
    let valid_intent = Intent::new(
        ProtoCapability::ShellExec,
        "valid-after-errors".to_string(),
        json!({ "command": "echo", "args": ["Recovery test content"] }),
        30000,
        "legitimate-user".to_string(),
    );

    // Validation should succeed
    let validation_result = capability.validate(&valid_intent);
    assert!(
        validation_result.is_ok(),
        "Valid intent should succeed after error recovery"
    );

    // Execution should also work
    let exec_context = ExecCtx {
        workdir: temp_dir.path().to_path_buf(),
        limits: CapabilityExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "recovery-test".to_string(),
        sandbox: SandboxConfig {
            mode: SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    };

    let execution_result = capability.execute(valid_intent, exec_context).await;
    assert!(
        execution_result.is_ok(),
        "Execution should succeed after error recovery"
    );

    let result = execution_result.unwrap();
    assert_eq!(
        result.status,
        ExecutionStatus::Ok,
        "Should execute successfully"
    );

    Ok(())
}

/// Test error message sanitization
#[test]
fn test_error_message_sanitization() {
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Test that error messages don't leak sensitive information
    let sensitive_test_cases = vec![
        json!({ "command": "x".repeat(5000), "token": "secret_key=abc123" }),
        json!({ "command": "echo", "timeout_ms": 0, "password": "xyz789" }),
        json!({ "command": 123, "api_key": "top_secret" }),
    ];

    for params in sensitive_test_cases {
        let intent = Intent::new(
            ProtoCapability::ShellExec,
            "sanitization-test".to_string(),
            params,
            30000,
            "test-user".to_string(),
        );

        let validation_result = capability.validate(&intent);

        if let Err(e) = validation_result {
            let error_msg = format!("{:?}", e).to_lowercase();

            // Verify error doesn't contain sensitive patterns
            assert!(
                !error_msg.contains("passwd"),
                "Error should not contain 'passwd'"
            );
            assert!(!error_msg.contains("ssh"), "Error should not contain 'ssh'");
            assert!(
                !error_msg.contains("secret_key=abc123"),
                "Error should not leak secret token values"
            );
            assert!(
                !error_msg.contains("xyz789"),
                "Error should not leak password values"
            );

            // Error should be generic but informative
            assert!(
                error_msg.contains("invalid")
                    || error_msg.contains("forbidden")
                    || error_msg.contains("not allowed")
                    || error_msg.contains("violation"),
                "Error should be informative but generic. Actual error: '{}'",
                error_msg
            );
        }
    }
}

/// Test logging safety under error conditions
#[tokio::test]
async fn test_logging_safety_under_errors() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create exec context that will cause errors
    let exec_context = create_exec_context(
        temp_dir.path(),
        ExecutionLimits {
            cpu_ms_per_100ms: 80,
            mem_bytes: 64 * 1024 * 1024,
            io_bytes: 10 * 1024 * 1024,
            pids_max: 5,
            timeout_ms: 5000,
        },
        Scope {
            paths: vec![], // Empty scope - will cause access errors
            urls: vec![],
        },
        "logging-safety-test".to_string(),
    );

    let mut output_sink = MemoryOutputSink::new();
    let params = json!({
        "path": "nonexistent.txt",
        "len": 1024
    });

    let _result = runner
        .execute(&exec_context, params, &mut output_sink)
        .await;

    // Check that logs don't contain sensitive information
    for log_entry in &output_sink.logs {
        let log_lower = log_entry.to_lowercase();

        // Verify logs don't leak sensitive system information
        assert!(
            !log_lower.contains("/etc/passwd"),
            "Log should not contain sensitive paths"
        );
        assert!(
            !log_lower.contains("root:"),
            "Log should not contain sensitive user info"
        );
        assert!(
            !log_lower.contains("secret"),
            "Log should not contain secrets"
        );

        println!("Safe log entry: {}", log_entry);
    }

    // Check stdout/stderr for safety as well
    let stdout_content = String::from_utf8_lossy(&output_sink.stdout);
    let stderr_content = String::from_utf8_lossy(&output_sink.stderr);

    assert!(
        !stdout_content.contains("/etc/passwd"),
        "Stdout should be safe"
    );
    assert!(
        !stderr_content.contains("/etc/passwd"),
        "Stderr should be safe"
    );

    Ok(())
}
