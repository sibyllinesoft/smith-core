//! Security Penetration Tests for Smith Executor
//!
//! Advanced security tests that attempt to exploit the sandbox
//! and verify that all security layers hold under attack.

use anyhow::Result;
use serde_json::json;
use std::{collections::HashMap, path::PathBuf};
use tempfile::TempDir;

use agentd::{
    capabilities::register_builtin_capabilities,
    capability::{ExecCtx, ExecutionScope, SandboxConfig},
    runners::{create_exec_context, MemoryOutputSink, RunnerRegistry, Scope},
    ExecutionLimits,
};
use smith_protocol::ExecutionLimits as CapabilityExecutionLimits;
use smith_protocol::{Capability as ProtoCapability, Intent, SandboxMode};

/// Test filesystem isolation bypass attempts
#[tokio::test]
async fn test_filesystem_isolation_penetration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Create legitimate file in working directory
    let allowed_file = temp_dir.path().join("allowed.txt");
    tokio::fs::write(&allowed_file, "This file is allowed").await?;

    // Attempt various cwd traversal/escape attacks
    let traversal_attacks = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/shadow",
        "C:\\Windows\\System32\\config\\SAM",
        "allowed.txt/../../../etc/passwd",
        "allowed.txt/../../../../../../proc/version",
        "./../../../../etc/hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", // URL encoded
        "..%252f..%252f..%252fetc%252fpasswd",     // Double URL encoded
        "..%5c..%5c..%5cetc%5cpasswd",             // URL encoded backslash
        "allowed.txt\0../../../../etc/passwd",     // Null byte injection
    ];

    let exec_context = ExecCtx {
        workdir: temp_dir.path().to_path_buf(),
        limits: CapabilityExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "penetration-test".to_string(),
        sandbox: SandboxConfig {
            mode: SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    };

    for (i, attack_cwd) in traversal_attacks.iter().enumerate() {
        let intent = Intent::new(
            ProtoCapability::ShellExec,
            format!("attack-{}", i),
            json!({ "command": "echo", "args": ["attack"], "cwd": attack_cwd }),
            30000,
            "attacker".to_string(),
        );

        // Traversal attempts are enforced at execution time in full mode.
        let execution_result = capability.execute(intent, exec_context.clone()).await;
        assert!(
            execution_result.is_err(),
            "cwd traversal attack should be blocked: {}",
            attack_cwd
        );
    }

    // Verify legitimate execution still works
    let legitimate_intent = Intent::new(
        ProtoCapability::ShellExec,
        "legitimate".to_string(),
        json!({ "command": "echo", "args": ["allowed"], "cwd": "." }),
        30000,
        "user".to_string(),
    );

    assert!(
        capability
            .execute(legitimate_intent, exec_context)
            .await
            .is_ok(),
        "Legitimate command execution should still work"
    );

    Ok(())
}

/// Test HTTP fetch security bypass attempts
#[tokio::test]
async fn test_http_fetch_penetration() -> Result<()> {
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    let exec_context = ExecCtx {
        workdir: std::env::temp_dir(),
        limits: CapabilityExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "env-attack-test".to_string(),
        sandbox: SandboxConfig {
            mode: SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    };

    // Attempt various environment-based injection attacks blocked in full mode.
    let env_attacks = vec![
        ("LD_PRELOAD", "/tmp/pwn.so"),
        ("LD_LIBRARY_PATH", "/tmp/lib"),
        ("DYLD_INSERT_LIBRARIES", "/tmp/pwn.dylib"),
        ("DYLD_LIBRARY_PATH", "/tmp/lib"),
        ("BASH_ENV", "/tmp/bashrc"),
        ("ENV", "/tmp/envrc"),
    ];

    for (i, (key, value)) in env_attacks.iter().enumerate() {
        let intent = Intent::new(
            ProtoCapability::ShellExec,
            format!("env-attack-{}", i),
            json!({ "command": "echo", "args": ["test"], "env": { (*key): *value } }),
            30000,
            "attacker".to_string(),
        );

        let execution_result = capability.execute(intent, exec_context.clone()).await;
        assert!(
            execution_result.is_err(),
            "Environment injection should be blocked: {}",
            key
        );
    }

    // Legitimate env usage should still work.
    let legitimate_intent = Intent::new(
        ProtoCapability::ShellExec,
        "legitimate".to_string(),
        json!({ "command": "echo", "args": ["ok"], "env": { "SAFE_ENV": "1" } }),
        30000,
        "user".to_string(),
    );

    assert!(
        capability
            .execute(legitimate_intent, exec_context)
            .await
            .is_ok(),
        "Legitimate environment should be allowed"
    );

    Ok(())
}

/// Test resource exhaustion attacks
#[tokio::test]
async fn test_resource_exhaustion_protection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create a large file for exhaustion testing
    let large_file = temp_dir.path().join("large.txt");
    let content = "A".repeat(10 * 1024 * 1024); // 10MB
    tokio::fs::write(&large_file, &content).await?;

    // Test with very restrictive resource limits
    let restrictive_limits = ExecutionLimits {
        cpu_ms_per_100ms: 10,   // Very restrictive
        mem_bytes: 1024 * 1024, // 1MB only
        io_bytes: 512 * 1024,   // 512KB I/O limit
        pids_max: 1,
        timeout_ms: 2000, // 2 second timeout
    };

    let exec_context = create_exec_context(
        temp_dir.path(),
        restrictive_limits.clone(),
        Scope {
            paths: vec![large_file.to_string_lossy().to_string()],
            urls: vec![],
        },
        "exhaustion-test".to_string(),
    );

    let mut output_sink = MemoryOutputSink::new();

    // Attempt to read beyond I/O limits
    let params = json!({
        "path": large_file.file_name().unwrap().to_string_lossy(),
        "len": 20 * 1024 * 1024 // Try to read 20MB
    });

    let result = runner
        .execute(&exec_context, params, &mut output_sink)
        .await?;

    // Should complete without crashing, may be truncated due to limits
    assert!(
        result.status == smith_protocol::ExecutionStatus::Ok
            || result.status == smith_protocol::ExecutionStatus::Error
    );

    // Should not have read more than the I/O limit allows
    assert!(
        result.stdout_bytes <= restrictive_limits.io_bytes,
        "Should respect I/O limits"
    );

    // Memory usage should be constrained
    // Note: We can't directly measure memory here, but the process should complete

    Ok(())
}

/// Test symlink attack prevention
#[tokio::test]
async fn test_symlink_attack_prevention() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Create a legitimate file
    let target_file = temp_dir.path().join("target.txt");
    tokio::fs::write(&target_file, "Secret content").await?;

    // Create a symlink pointing outside the allowed area
    let symlink_path = temp_dir.path().join("symlink_attack");

    // Try to create symlink to /etc/passwd (will fail on systems without permission, but test the logic)
    let etc_passwd = PathBuf::from("/etc/passwd");
    if etc_passwd.exists() {
        let _ = std::os::unix::fs::symlink("/etc/passwd", &symlink_path);
    } else {
        // Create symlink to our target file for testing
        std::os::unix::fs::symlink(&target_file, &symlink_path)?;
    }

    // Attempt to execute using symlinked cwd that escapes workdir
    let symlink_intent = Intent::new(
        ProtoCapability::ShellExec,
        "symlink-attack".to_string(),
        json!({
            "command": "echo",
            "args": ["symlink"],
            "cwd": symlink_path.file_name().unwrap().to_string_lossy()
        }),
        30000,
        "attacker".to_string(),
    );

    let exec_context = ExecCtx {
        workdir: temp_dir.path().to_path_buf(),
        limits: CapabilityExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "symlink-test".to_string(),
        sandbox: SandboxConfig {
            mode: SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    };

    let execution_result = capability.execute(symlink_intent, exec_context).await;
    assert!(
        execution_result.is_err(),
        "Symlink cwd escape should be blocked in full mode"
    );

    Ok(())
}

/// Test race condition exploitation attempts
#[tokio::test]
async fn test_race_condition_protection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = std::sync::Arc::new(register_builtin_capabilities());

    // Create a file that we'll try to manipulate during execution
    let race_file = temp_dir.path().join("race.txt");
    tokio::fs::write(&race_file, "Original content").await?;

    // Test that validation is stable under concurrent access
    let intent = Intent::new(
        ProtoCapability::ShellExec,
        "race-test".to_string(),
        json!({ "command": "echo", "args": ["race.txt"] }),
        30000,
        "test-user".to_string(),
    );

    // Spawn multiple concurrent validations
    let mut tasks = Vec::new();

    for i in 0..10 {
        let registry_ref = registry.clone();
        let intent_clone = intent.clone();

        let task = tokio::spawn(async move {
            let capability = registry_ref
                .get("shell.exec.v1")
                .expect("shell.exec.v1 should be registered");
            // All validations should be consistent
            let result = capability.validate(&intent_clone);
            (i, result)
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    let results: Vec<_> = futures::future::join_all(tasks).await;

    // All validations should succeed and be consistent
    for result in results {
        match result {
            Ok((task_id, validation_result)) => {
                assert!(
                    validation_result.is_ok(),
                    "Task {} validation should succeed",
                    task_id
                );
            }
            Err(e) => {
                panic!("Task panicked: {}", e);
            }
        }
    }

    Ok(())
}

/// Test privilege escalation prevention
#[tokio::test]
async fn test_privilege_escalation_prevention() -> Result<()> {
    let _temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Attempt to use privileged absolute cwd paths (blocked in full mode).
    let privileged_paths = vec![
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh/id_rsa",
        "/proc/1/environ",                 // Init process environment
        "/sys/kernel/debug/tracing/trace", // Kernel tracing
        "/dev/mem",                        // Physical memory device
        "/dev/kmem",                       // Kernel memory device
    ];

    for path in privileged_paths {
        let intent = Intent::new(
            ProtoCapability::ShellExec,
            "privilege-escalation".to_string(),
            json!({ "command": "echo", "args": ["blocked"], "cwd": path }),
            30000,
            "attacker".to_string(),
        );

        let mut sandbox = SandboxConfig::default();
        sandbox.mode = SandboxMode::Full;
        let exec_ctx = ExecCtx {
            workdir: std::env::temp_dir(),
            limits: CapabilityExecutionLimits::default(),
            scope: ExecutionScope {
                paths: vec![],
                urls: vec![],
                env_vars: vec![],
                custom: HashMap::new(),
            },
            trace_id: "privilege-test".to_string(),
            sandbox,
        };
        let validation_result = capability.execute(intent, exec_ctx).await;
        assert!(
            validation_result.is_err(),
            "Privileged cwd should be blocked: {}",
            path
        );
    }

    Ok(())
}

/// Test container escape prevention
#[tokio::test]
async fn test_container_escape_prevention() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    // Attempt to access container runtime files that could enable escape
    let container_escape_paths = vec![
        "/proc/self/mountinfo",                        // Mount information
        "/proc/mounts",                                // Mount points
        "/proc/self/cgroup",                           // Control group info
        "/sys/fs/cgroup/memory/memory.limit_in_bytes", // Memory limits
        "/var/run/docker.sock",                        // Docker socket
        "/run/containerd/containerd.sock",             // Containerd socket
        "/../../../proc/1/root/etc/passwd",            // Escape to host root
    ];

    for path in container_escape_paths {
        let intent = Intent::new(
            ProtoCapability::ShellExec,
            "container-escape".to_string(),
            json!({ "command": "echo", "args": ["escape"], "cwd": path }),
            30000,
            "attacker".to_string(),
        );

        let exec_context = ExecCtx {
            workdir: temp_dir.path().to_path_buf(),
            limits: CapabilityExecutionLimits::default(),
            scope: ExecutionScope {
                paths: vec![],
                urls: vec![],
                env_vars: vec![],
                custom: HashMap::new(),
            },
            trace_id: "escape-test".to_string(),
            sandbox: SandboxConfig {
                mode: SandboxMode::Full,
                landlock_enabled: true,
                seccomp_enabled: true,
                cgroups_enabled: true,
                namespaces_enabled: true,
            },
        };

        let execution_result = capability.execute(intent, exec_context).await;
        assert!(
            execution_result.is_err(),
            "Container escape attempt should fail: {}",
            path
        );
    }

    Ok(())
}

/// Test malformed input handling
#[tokio::test]
async fn test_malformed_input_handling() -> Result<()> {
    let registry = register_builtin_capabilities();

    let shell_capability = registry
        .get("shell.exec.v1")
        .expect("shell.exec.v1 should be registered");

    let malformed_shell_inputs = vec![
        json!({}),                                                       // Missing required fields
        json!({"command": 123}),                                         // Wrong type
        json!({"command": null}),                                        // Null value
        json!({"command": ""}),                                          // Empty command
        json!({"command": "echo", "timeout_ms": 0}),                     // Invalid timeout
        json!({"command": "echo", "timeout_ms": 999999}),                // Timeout too large
        json!({"command": "a".repeat(5000)}),                            // Extremely long command
        json!({"command": "echo", "extra_field": "should_not_be_here"}), // Extra fields
        json!({"command": "echo", "args": "not-an-array"}),              // Invalid args type
    ];

    for (i, malformed_input) in malformed_shell_inputs.iter().enumerate() {
        let intent = Intent::new(
            ProtoCapability::ShellExec,
            format!("malformed-shell-{}", i),
            malformed_input.clone(),
            30000,
            "attacker".to_string(),
        );

        let validation_result = shell_capability.validate(&intent);
        assert!(
            validation_result.is_err(),
            "Malformed shell input should be rejected: {}",
            malformed_input
        );
    }

    Ok(())
}
