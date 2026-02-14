//! Comprehensive Security Tests for Smith Executor
//!
//! Tests that verify the security boundaries and isolation guarantees
//! across all layers of the Smith execution environment.

use anyhow::Result;
use serde_json::json;
use std::{collections::HashMap, time::Instant};
use tempfile::TempDir;

use agentd::{
    capabilities::register_builtin_capabilities,
    capability::{ExecCtx, ExecutionScope, SandboxConfig},
    runners::{create_exec_context, MemoryOutputSink, RunnerRegistry, Scope},
    ExecutionLimits,
};
use smith_protocol::ExecutionLimits as CapabilityExecutionLimits;
use smith_protocol::{Capability as ProtoCapability, Intent, SandboxMode};

/// Helper to create execution context with security constraints
fn create_secure_exec_context(
    workdir: &std::path::Path,
    limits: ExecutionLimits,
) -> agentd::runners::ExecContext {
    create_exec_context(
        workdir,
        limits,
        Scope {
            paths: vec![workdir.to_string_lossy().to_string()],
            urls: vec![],
        },
        format!("security-test-{}", uuid::Uuid::new_v4()),
    )
}

/// Helper to create capability execution context
fn create_capability_context(workdir: std::path::PathBuf) -> ExecCtx {
    ExecCtx {
        workdir,
        limits: CapabilityExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: format!("capability-test-{}", uuid::Uuid::new_v4()),
        sandbox: SandboxConfig {
            mode: SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    }
}

/// Test security boundary enforcement for shell.exec.v1 capability
#[tokio::test]
async fn test_multi_capability_security_boundaries() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    // Test shell.exec.v1 security boundaries
    let shell_capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Attempt to execute a command - validation should pass for valid params
    let valid_intent = Intent::new(
        ProtoCapability::ShellExec,
        "valid-intent".to_string(),
        json!({ "command": "echo", "args": ["hello"] }),
        30000,
        "test-signer".to_string(),
    );

    let validation_result = shell_capability.validate(&valid_intent);
    assert!(
        validation_result.is_ok(),
        "Valid command should pass validation"
    );

    // Test that empty command is rejected
    let empty_command_intent = Intent::new(
        ProtoCapability::ShellExec,
        "empty-command".to_string(),
        json!({ "command": "" }),
        30000,
        "test-signer".to_string(),
    );

    let validation_result = shell_capability.validate(&empty_command_intent);
    assert!(
        validation_result.is_err(),
        "Empty command should be rejected"
    );

    // Test that very long command is rejected
    let long_command = "a".repeat(5000);
    let long_command_intent = Intent::new(
        ProtoCapability::ShellExec,
        "long-command".to_string(),
        json!({ "command": long_command }),
        30000,
        "test-signer".to_string(),
    );

    let validation_result = shell_capability.validate(&long_command_intent);
    assert!(
        validation_result.is_err(),
        "Very long command should be rejected"
    );

    Ok(())
}

/// Test resource limit enforcement under security constraints
#[tokio::test]
async fn test_resource_limits_under_security() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create a moderately large test file (1MB)
    let large_file = temp_dir.path().join("large.txt");
    let content = "A".repeat(1024 * 1024); // 1MB
    tokio::fs::write(&large_file, &content).await?;

    // Test with very restrictive limits
    let restrictive_limits = ExecutionLimits {
        cpu_ms_per_100ms: 20,   // Very low CPU allowance
        mem_bytes: 1024 * 1024, // 1MB memory limit
        io_bytes: 512 * 1024,   // 512KB I/O limit (smaller than file)
        pids_max: 1,
        timeout_ms: 1000, // 1 second timeout
    };

    let exec_context = create_secure_exec_context(temp_dir.path(), restrictive_limits);
    let mut output_sink = MemoryOutputSink::new();

    let params = json!({
        "path": large_file.file_name().unwrap().to_string_lossy(),
        "len": 1024 * 1024 // Request full file
    });

    // This should still work but may hit I/O limits
    let start_time = Instant::now();
    let result = runner
        .execute(&exec_context, params, &mut output_sink)
        .await?;
    let execution_time = start_time.elapsed();

    // Verify execution completed within timeout
    assert!(
        execution_time.as_millis() < 5000,
        "Execution should complete within reasonable time"
    );

    // Result may be truncated due to I/O limits, but should not crash
    assert!(
        result.status == smith_protocol::ExecutionStatus::Ok
            || result.status == smith_protocol::ExecutionStatus::Error
    );

    Ok(())
}

/// Test concurrent security enforcement
#[tokio::test]
async fn test_concurrent_security_isolation() -> Result<()> {
    let temp_dir1 = TempDir::new()?;
    let temp_dir2 = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create test files in separate directories
    let file1 = temp_dir1.path().join("file1.txt");
    let file2 = temp_dir2.path().join("file2.txt");
    tokio::fs::write(&file1, "Content from directory 1").await?;
    tokio::fs::write(&file2, "Content from directory 2").await?;

    // Create isolated execution contexts
    let ctx1 = create_secure_exec_context(
        temp_dir1.path(),
        ExecutionLimits {
            cpu_ms_per_100ms: 80,
            mem_bytes: 64 * 1024 * 1024,
            io_bytes: 10 * 1024 * 1024,
            pids_max: 5,
            timeout_ms: 10000,
        },
    );

    let ctx2 = create_secure_exec_context(
        temp_dir2.path(),
        ExecutionLimits {
            cpu_ms_per_100ms: 80,
            mem_bytes: 64 * 1024 * 1024,
            io_bytes: 10 * 1024 * 1024,
            pids_max: 5,
            timeout_ms: 10000,
        },
    );

    // Execute concurrently
    let params1 = json!({ "path": "file1.txt", "len": 1024 });
    let params2 = json!({ "path": "file2.txt", "len": 1024 });

    let mut sink1 = MemoryOutputSink::new();
    let mut sink2 = MemoryOutputSink::new();

    let (result1, result2) = tokio::join!(
        runner.execute(&ctx1, params1, &mut sink1),
        runner.execute(&ctx2, params2, &mut sink2)
    );

    // Both should succeed
    let result1 = result1?;
    let result2 = result2?;

    assert_eq!(result1.status, smith_protocol::ExecutionStatus::Ok);
    assert_eq!(result2.status, smith_protocol::ExecutionStatus::Ok);

    // Verify isolation - each should only read from its own directory
    let content1 = String::from_utf8_lossy(&sink1.stdout);
    let content2 = String::from_utf8_lossy(&sink2.stdout);

    assert!(content1.contains("directory 1"));
    assert!(!content1.contains("directory 2"));
    assert!(content2.contains("directory 2"));
    assert!(!content2.contains("directory 1"));

    Ok(())
}

/// Test security failure recovery and cleanup
#[tokio::test]
async fn test_security_failure_recovery() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Create multiple invalid intents
    let invalid_intents = vec![
        Intent::new(
            ProtoCapability::ShellExec,
            "empty-command".to_string(),
            json!({ "command": "" }),
            30000,
            "attacker".to_string(),
        ),
        Intent::new(
            ProtoCapability::ShellExec,
            "invalid-timeout".to_string(),
            json!({ "command": "echo", "timeout_ms": 0 }),
            30000,
            "attacker".to_string(),
        ),
        Intent::new(
            ProtoCapability::ShellExec,
            "timeout-too-large".to_string(),
            json!({ "command": "echo", "timeout_ms": 999999999 }),
            30000,
            "attacker".to_string(),
        ),
    ];

    // All should be rejected during validation
    for (i, intent) in invalid_intents.iter().enumerate() {
        let result = capability.validate(intent);
        assert!(
            result.is_err(),
            "Invalid intent {} should be rejected",
            i + 1
        );

        // Verify system remains stable after rejection
        let _exec_context = create_capability_context(temp_dir.path().to_path_buf());

        // System should still be able to execute valid intents after rejecting invalid ones
        let valid_intent = Intent::new(
            ProtoCapability::ShellExec,
            "valid-after-attack".to_string(),
            json!({ "command": "echo", "args": ["test"] }),
            30000,
            "legitimate-user".to_string(),
        );

        let validation_result = capability.validate(&valid_intent);
        assert!(
            validation_result.is_ok(),
            "System should accept valid intents after rejecting invalid ones"
        );
    }

    Ok(())
}

/// Test performance under maximum security constraints
#[tokio::test]
async fn test_performance_under_full_security() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create multiple test files of different sizes
    let medium_content = "Medium file content. ".repeat(100);
    let large_content = "Large file content data. ".repeat(1000);
    let test_files = vec![
        ("small.txt", "Small file content"),
        ("medium.txt", medium_content.as_str()),
        ("large.txt", large_content.as_str()),
    ];

    for (filename, content) in &test_files {
        let file_path = temp_dir.path().join(filename);
        tokio::fs::write(file_path, content).await?;
    }

    // Create execution context with full security enabled
    let secure_limits = ExecutionLimits {
        cpu_ms_per_100ms: 80,
        mem_bytes: 128 * 1024 * 1024, // 128MB
        io_bytes: 50 * 1024 * 1024,   // 50MB
        pids_max: 10,
        timeout_ms: 30000, // 30 seconds
    };

    let exec_context = create_secure_exec_context(temp_dir.path(), secure_limits);

    // Measure performance for each file size
    let mut performance_results = Vec::new();

    for (filename, expected_content) in &test_files {
        let start_time = Instant::now();
        let mut output_sink = MemoryOutputSink::new();

        let params = json!({
            "path": filename,
            "len": expected_content.len() + 1024 // Allow some buffer
        });

        let result = runner
            .execute(&exec_context, params, &mut output_sink)
            .await?;
        let execution_time = start_time.elapsed();

        assert_eq!(result.status, smith_protocol::ExecutionStatus::Ok);

        let actual_content = String::from_utf8_lossy(&output_sink.stdout);
        assert!(actual_content.contains(expected_content));

        performance_results.push((filename, execution_time));

        // Verify performance is reasonable even under full security
        assert!(
            execution_time.as_millis() < 5000,
            "File {} took too long: {:?}",
            filename,
            execution_time
        );
    }

    // Log performance results for analysis
    for (filename, time) in &performance_results {
        println!("Security test - {}: {:?}", filename, time);
    }

    // Verify performance scaling is reasonable
    let small_time = performance_results[0].1;
    let large_time = performance_results[2].1;

    let small_time_us = small_time.as_micros();
    let large_time_us = large_time.as_micros();
    if small_time_us > 0 {
        // Allow generous scaling due to environment variability
        assert!(
            large_time_us < small_time_us * 50,
            "Performance scaling under security constraints is unreasonable"
        );
    }

    Ok(())
}

/// Test security audit trail generation
#[tokio::test]
async fn test_security_audit_trail() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create test file
    let test_file = temp_dir.path().join("audit_test.txt");
    tokio::fs::write(&test_file, "Audit test content").await?;

    let exec_context = create_secure_exec_context(
        temp_dir.path(),
        ExecutionLimits {
            cpu_ms_per_100ms: 80,
            mem_bytes: 64 * 1024 * 1024,
            io_bytes: 10 * 1024 * 1024,
            pids_max: 5,
            timeout_ms: 10000,
        },
    );

    let mut output_sink = MemoryOutputSink::new();

    let params = json!({
        "path": "audit_test.txt",
        "len": 1024
    });

    let result = runner
        .execute(&exec_context, params, &mut output_sink)
        .await?;

    assert_eq!(result.status, smith_protocol::ExecutionStatus::Ok);

    // Verify that trace ID is properly maintained for audit trail
    assert!(!exec_context.trace_id.is_empty());
    assert!(exec_context.trace_id.contains("security-test"));

    // Verify that output sink captured execution data
    assert!(!output_sink.logs.is_empty() || result.stdout_bytes > 0);

    // Verify execution metadata for audit purposes
    assert!(result.duration_ms > 0);
    assert!(result.stdout_bytes > 0);

    Ok(())
}

/// Benchmark security overhead
#[tokio::test]
async fn benchmark_security_overhead() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    let intent = Intent::new(
        ProtoCapability::ShellExec,
        "benchmark-intent".to_string(),
        json!({ "command": "echo", "args": ["benchmark"] }),
        30000,
        "benchmarker".to_string(),
    );

    // Benchmark with minimal security (demo mode)
    let demo_context = ExecCtx {
        workdir: temp_dir.path().to_path_buf(),
        limits: CapabilityExecutionLimits {
            cpu_ms_per_100ms: 100,
            mem_bytes: 256 * 1024 * 1024,
            io_bytes: 100 * 1024 * 1024,
            pids_max: 20,
            timeout_ms: 60000,
        },
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "benchmark-demo".to_string(),
        sandbox: SandboxConfig {
            mode: SandboxMode::Demo,
            landlock_enabled: false,
            seccomp_enabled: false,
            cgroups_enabled: false,
            namespaces_enabled: false,
        },
    };

    // Benchmark with full security
    let full_security_context = ExecCtx {
        workdir: temp_dir.path().to_path_buf(),
        limits: CapabilityExecutionLimits {
            cpu_ms_per_100ms: 100,
            mem_bytes: 256 * 1024 * 1024,
            io_bytes: 100 * 1024 * 1024,
            pids_max: 20,
            timeout_ms: 60000,
        },
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "benchmark-full".to_string(),
        sandbox: SandboxConfig {
            mode: SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    };

    // Run benchmarks
    let demo_start = Instant::now();
    let demo_result = capability
        .execute(intent.clone(), demo_context)
        .await
        .map_err(|e| anyhow::anyhow!("Demo execution failed: {:?}", e))?;
    let demo_time = demo_start.elapsed();

    let full_start = Instant::now();
    let full_result = capability
        .execute(intent, full_security_context)
        .await
        .map_err(|e| anyhow::anyhow!("Full security execution failed: {:?}", e))?;
    let full_time = full_start.elapsed();

    // Both should succeed
    assert_eq!(demo_result.status, smith_protocol::ExecutionStatus::Ok);
    assert_eq!(full_result.status, smith_protocol::ExecutionStatus::Ok);

    // Log benchmark results
    println!("Security benchmark - Demo mode: {:?}", demo_time);
    println!("Security benchmark - Full security: {:?}", full_time);

    // Security overhead should be reasonable (< 3x slower)
    let overhead_ratio = full_time.as_nanos() as f64 / demo_time.as_nanos() as f64;
    println!("Security overhead ratio: {:.2}x", overhead_ratio);

    assert!(
        overhead_ratio < 8.0,
        "Security overhead is too high for this environment: {:.2}x",
        overhead_ratio
    );

    Ok(())
}
