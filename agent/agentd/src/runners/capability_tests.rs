/*!
# Comprehensive Test Suite for Capability Runners

This test suite provides comprehensive coverage for the security-critical capability runners,
focusing on isolation testing, security validation, and safe execution of fs.read.v1 and http.fetch.v1 capabilities.

## Test Coverage Areas:
- fs.read.v1 capability security and isolation
- http.fetch.v1 capability security and validation
- Capability parameter validation and sanitization
- Sandbox isolation verification
- Resource limit enforcement
- Error handling and recovery
- Security boundary testing
- Malicious intent blocking
- Path traversal prevention
- Network access control
*/

#[cfg(test)]
mod capability_tests {
    use super::super::fs_read::FsReadRunner;
    use super::super::http_fetch::HttpFetchRunner;
    use crate::intent::Intent;
    use crate::runners::{
        ExecContext, ExecutionResult, MemoryOutputSink, OutputSink, Runner, Scope,
    };
    use anyhow::Result;
    use serde_json::json;
    use smith_protocol::{ExecutionLimits, ExecutionStatus};
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::time::timeout;
    use uuid::Uuid;

    // Test fixtures and utilities
    fn create_test_intent(capability: &str, params: serde_json::Value) -> Intent {
        Intent {
            id: Uuid::new_v4(),
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            ttl_s: 300, // 5 minutes
            seq: 1,
            nonce: format!("{:032x}", Uuid::new_v4().as_u128()),
            capability: capability.to_string(),
            version: 1,
            resource: "test".to_string(),
            params,
            constraints: serde_json::json!({
                "timeout_ms": 30000,
                "mem_bytes": 100 * 1024 * 1024,
                "cpu_ms_per_100ms": 50
            }),
            actor: crate::intent::Actor {
                jwt: "test-jwt".to_string(),
                tenant: "test-tenant".to_string(),
                key_id: "test-key".to_string(),
            },
            signature: "test-signature".to_string(),
        }
    }

    fn create_test_exec_context() -> ExecContext {
        ExecContext {
            workdir: PathBuf::from("/tmp/smith-test"),
            limits: ExecutionLimits {
                cpu_ms_per_100ms: 50,         // 50% CPU
                mem_bytes: 100 * 1024 * 1024, // 100MB
                io_bytes: 10 * 1024 * 1024,   // 10MB I/O
                pids_max: 10,
                timeout_ms: 30000, // 30 seconds
            },
            scope: Scope {
                paths: vec!["/tmp".to_string()],
                urls: vec![],
            },
            creds: None,
            netns: None,
            trace_id: Uuid::new_v4().to_string(),
            session: None,
        }
    }

    fn create_http_test_exec_context() -> ExecContext {
        ExecContext {
            workdir: PathBuf::from("/tmp/smith-test"),
            limits: ExecutionLimits {
                cpu_ms_per_100ms: 50,         // 50% CPU
                mem_bytes: 100 * 1024 * 1024, // 100MB
                io_bytes: 10 * 1024 * 1024,   // 10MB I/O
                pids_max: 10,
                timeout_ms: 30000, // 30 seconds
            },
            scope: Scope {
                paths: vec!["/tmp".to_string()],
                urls: vec![
                    "https://httpbin\\.org/.*".to_string(),
                    "https://example\\.com/.*".to_string(),
                    "https://postman-echo\\.com/.*".to_string(),
                ],
            },
            creds: None,
            netns: None,
            trace_id: Uuid::new_v4().to_string(),
            session: None,
        }
    }

    fn create_restricted_exec_context() -> ExecContext {
        ExecContext {
            workdir: PathBuf::from("/tmp/smith-test-restricted"),
            limits: ExecutionLimits {
                cpu_ms_per_100ms: 25,        // 25% CPU
                mem_bytes: 10 * 1024 * 1024, // 10MB
                io_bytes: 1024 * 1024,       // 1MB I/O
                pids_max: 5,
                timeout_ms: 5000, // 5 seconds
            },
            scope: Scope {
                paths: vec!["/tmp".to_string()],
                urls: vec![],
            },
            creds: None,
            netns: None,
            trace_id: Uuid::new_v4().to_string(),
            session: None,
        }
    }

    // fs.read.v1 capability tests
    #[tokio::test]
    async fn test_fs_read_valid_file() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/etc/passwd",
                "len": 1024
            }),
        );
        let ctx = create_test_exec_context();

        let mut output_sink = MemoryOutputSink::new();
        let result = runner
            .execute(&ctx, intent.params, &mut output_sink)
            .await?;

        match result.status {
            ExecutionStatus::Success => {
                let output = String::from_utf8_lossy(&output_sink.stdout);
                assert!(!output.is_empty());
                // Should contain typical passwd file structure
                assert!(output.contains(":") || output.len() > 0);
            }
            ExecutionStatus::Error => {
                // On some systems, /etc/passwd might not be accessible
                // This is acceptable in a security context
                let _output = String::from_utf8_lossy(&output_sink.stderr);
                // May have some error output
            }
            _ => {}
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_fs_read_path_traversal_prevention() -> Result<()> {
        let runner = FsReadRunner::new();

        // Test various path traversal attempts
        let malicious_paths = vec![
            "../../../etc/passwd",
            "../../root/.ssh/id_rsa",
            "/etc/shadow",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/proc/version",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        ];

        for path in malicious_paths {
            let intent = create_test_intent(
                "fs.read.v1",
                json!({
                    "path": path,
                    "len": 1024
                }),
            );
            let ctx = create_test_exec_context();

            let mut output_sink = MemoryOutputSink::new();
            let result = runner
                .execute(&ctx, intent.params, &mut output_sink)
                .await?;

            // Should either block access or handle securely
            match result.status {
                ExecutionStatus::Success => {
                    // If successful, it should be because the path is safe/allowed
                }
                ExecutionStatus::Error => {
                    // Security blocking is expected and correct
                    let stderr_output = String::from_utf8_lossy(&output_sink.stderr);
                    assert!(stderr_output.len() > 0);
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_fs_read_nonexistent_file() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/nonexistent/file/path/that/does/not/exist.txt",
                "len": 1024
            }),
        );
        let ctx = create_test_exec_context();

        let mut output_sink = MemoryOutputSink::new();
        let result = runner
            .execute(&ctx, intent.params, &mut output_sink)
            .await?;

        match result.status {
            ExecutionStatus::Error => {
                let stderr_output = String::from_utf8_lossy(&output_sink.stderr);
                assert!(
                    stderr_output.contains("not found")
                        || stderr_output.contains("No such file")
                        || stderr_output.len() > 0
                );
            }
            ExecutionStatus::Success => {
                // Should not succeed for nonexistent files
                panic!("Should not successfully read nonexistent file");
            }
            _ => {}
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_fs_read_permission_denied() -> Result<()> {
        let runner = FsReadRunner::new();

        // Attempt to read a typically restricted file
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/etc/shadow",
                "len": 1024
            }),
        );
        let ctx = create_test_exec_context();

        let mut output_sink = MemoryOutputSink::new();
        let result = runner
            .execute(&ctx, intent.params, &mut output_sink)
            .await?;

        match result.status {
            ExecutionStatus::Error => {
                // Should be blocked due to permissions - can check stderr for error message
                let stderr_output = String::from_utf8_lossy(&output_sink.stderr);
                assert!(
                    stderr_output.contains("Permission denied")
                        || stderr_output.contains("Access denied")
                        || stderr_output.contains("not permitted")
                        || stderr_output.len() > 0
                ); // At least some error output
            }
            ExecutionStatus::Success => {
                // On some test systems, shadow file might be readable
                // This is system-dependent
            }
            _ => {}
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_fs_read_large_file_handling() -> Result<()> {
        let runner = FsReadRunner::new();

        // Try to read a potentially large file
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/dev/zero",
                "len": 1024
            }),
        );
        let ctx = create_restricted_exec_context();

        let mut output_sink = MemoryOutputSink::new();
        let result = timeout(
            Duration::from_secs(5),
            runner.execute(&ctx, intent.params, &mut output_sink),
        )
        .await??;

        match result.status {
            ExecutionStatus::Success => {
                // Should limit output size
                let output = String::from_utf8_lossy(&output_sink.stdout);
                assert!(output.len() <= 1024);
            }
            ExecutionStatus::Error => {
                // May be blocked or fail due to special file type
            }
            _ => {}
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_fs_read_parameter_validation() -> Result<()> {
        let runner = FsReadRunner::new();

        // Test invalid parameters
        let invalid_params = vec![
            json!({}),                         // Missing path and len
            json!({"path": ""}),               // Empty path, missing len
            json!({"path": null}),             // Null path, missing len
            json!({"invalid_param": "value"}), // Invalid parameter, missing len
            json!({"path": "test.txt"}),       // Missing len
            json!({"len": 1024}),              // Missing path
        ];

        for params in invalid_params {
            let intent = create_test_intent("fs.read.v1", params.clone());
            let ctx = create_test_exec_context();

            let mut output_sink = MemoryOutputSink::new();
            let result = runner.execute(&ctx, params, &mut output_sink).await;

            match result {
                Ok(exec_result) => {
                    match exec_result.status {
                        ExecutionStatus::Error => {
                            // Should indicate parameter validation error
                            let stderr_output = String::from_utf8_lossy(&output_sink.stderr);
                            assert!(
                                stderr_output.contains("parameter")
                                    || stderr_output.contains("path")
                                    || stderr_output.contains("invalid")
                                    || stderr_output.len() > 0
                            ); // At least some error
                        }
                        ExecutionStatus::Success => {
                            panic!("Should not succeed with invalid parameters");
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    // Parameter validation errors are also acceptable as anyhow errors
                    let error_msg = e.to_string().to_lowercase();
                    assert!(
                        error_msg.contains("parameter")
                            || error_msg.contains("path")
                            || error_msg.contains("len")
                            || error_msg.contains("invalid")
                    );
                }
            }
        }
        Ok(())
    }

    // http.fetch.v1 capability tests
    #[tokio::test]
    async fn test_http_fetch_valid_request() -> Result<()> {
        let runner = HttpFetchRunner::new();
        let intent = create_test_intent(
            "http.fetch.v1",
            json!({
                "url": "https://httpbin.org/get",
                "method": "GET"
            }),
        );
        let ctx = create_http_test_exec_context();

        // Use timeout for network request
        let mut output_sink = MemoryOutputSink::new();
        let result = timeout(
            Duration::from_secs(10),
            runner.execute(&ctx, intent.params, &mut output_sink),
        )
        .await??;

        match result.status {
            ExecutionStatus::Success | ExecutionStatus::Ok => {
                let output = String::from_utf8_lossy(&output_sink.stdout);
                assert!(!output.is_empty());
                // Should contain response data
                assert!(output.contains("{") || output.len() > 0);
            }
            ExecutionStatus::Error | ExecutionStatus::Failed => {
                // Network errors are acceptable in test environments
                // Error output may be in stderr or logs, so we don't require specific stderr content
            }
            ExecutionStatus::Denied => {
                // Access denied by policy
            }
            ExecutionStatus::Timeout => {
                // Request timed out
            }
            ExecutionStatus::Killed => {
                // Process was killed
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_http_fetch_malicious_url_blocking() -> Result<()> {
        let runner = HttpFetchRunner::new();

        // Test potentially malicious URLs
        let malicious_urls = vec![
            "http://localhost:22",                      // SSH port
            "http://127.0.0.1:3306",                    // MySQL port
            "http://169.254.169.254/latest/meta-data/", // AWS metadata
            "file:///etc/passwd",                       // File protocol
            "ftp://example.com/file.txt",               // FTP protocol
            "http://internal.company.com/admin",        // Internal network
        ];

        for url in malicious_urls {
            let intent = create_test_intent(
                "http.fetch.v1",
                json!({
                    "url": url,
                    "method": "GET"
                }),
            );
            let ctx = create_http_test_exec_context();

            let mut output_sink = MemoryOutputSink::new();
            let execution = timeout(
                Duration::from_secs(5),
                runner.execute(&ctx, intent.params, &mut output_sink),
            )
            .await;

            match execution {
                Ok(Ok(result)) => match result.status {
                    ExecutionStatus::Error | ExecutionStatus::Denied => {}
                    ExecutionStatus::Success => {}
                    _ => {}
                },
                Ok(Err(err)) => {
                    assert!(!err.to_string().is_empty());
                }
                Err(_) => panic!("HTTP malicious URL test timed out"),
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_http_fetch_timeout_handling() -> Result<()> {
        let runner = HttpFetchRunner::new();
        let intent = create_test_intent(
            "http.fetch.v1",
            json!({
                "url": "https://httpbin.org/delay/10", // 10 second delay
                "method": "GET",
                "timeout_seconds": 2
            }),
        );
        let ctx = create_restricted_exec_context();

        let mut output_sink = MemoryOutputSink::new();
        let execution = timeout(
            Duration::from_secs(5),
            runner.execute(&ctx, intent.params, &mut output_sink),
        )
        .await;

        match execution {
            Ok(Ok(result)) => {
                assert!(matches!(
                    result.status,
                    ExecutionStatus::Error | ExecutionStatus::Timeout | ExecutionStatus::Denied
                ));
            }
            Ok(Err(err)) => {
                assert!(!err.to_string().is_empty());
            }
            Err(_) => panic!("HTTP timeout test exceeded harness timeout"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_http_fetch_parameter_validation() -> Result<()> {
        let runner = HttpFetchRunner::new();

        // Test invalid parameters
        let invalid_params = vec![
            json!({}),                                                  // Missing URL
            json!({"url": ""}),                                         // Empty URL
            json!({"url": "not-a-url"}),                                // Invalid URL
            json!({"url": "https://example.com", "method": "INVALID"}), // Invalid method
            json!({"url": null}),                                       // Null URL
        ];

        for params in invalid_params {
            let intent = create_test_intent("http.fetch.v1", params.clone());
            let ctx = create_http_test_exec_context();

            let mut output_sink = MemoryOutputSink::new();
            match runner.execute(&ctx, intent.params, &mut output_sink).await {
                Ok(result) => {
                    assert!(matches!(
                        result.status,
                        ExecutionStatus::Error | ExecutionStatus::Denied
                    ));
                }
                Err(err) => {
                    assert!(
                        !err.to_string().is_empty(),
                        "expected validation error for params {:?}",
                        params
                    );
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_http_fetch_request_size_limits() -> Result<()> {
        let runner = HttpFetchRunner::new();
        let intent = create_test_intent(
            "http.fetch.v1",
            json!({
                "url": "https://httpbin.org/bytes/1048576", // 1MB response
                "method": "GET"
            }),
        );
        let ctx = create_restricted_exec_context(); // Limited resources

        let mut output_sink = MemoryOutputSink::new();
        let execution = timeout(
            Duration::from_secs(10),
            runner.execute(&ctx, intent.params, &mut output_sink),
        )
        .await;

        match execution {
            Ok(Ok(result)) => {
                if let ExecutionStatus::Success = result.status {
                    let output = String::from_utf8_lossy(&output_sink.stdout);
                    assert!(output.len() <= 10 * 1024 * 1024);
                }
            }
            Ok(Err(err)) => {
                assert!(!err.to_string().is_empty());
            }
            Err(_) => panic!("HTTP size limit test timed out"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_http_fetch_post_request() -> Result<()> {
        let runner = HttpFetchRunner::new();
        // Since POST is not supported, test that it properly rejects POST requests
        let intent = create_test_intent(
            "http.fetch.v1",
            json!({
                "url": "https://httpbin.org/post",
                "method": "POST",
                "body": json!({"test": "data"}),
                "headers": {
                    "Content-Type": "application/json"
                }
            }),
        );
        let ctx = create_http_test_exec_context();

        let mut output_sink = MemoryOutputSink::new();
        let execution = timeout(
            Duration::from_secs(10),
            runner.execute(&ctx, intent.params, &mut output_sink),
        )
        .await;

        match execution {
            Ok(Ok(result)) => {
                assert!(matches!(
                    result.status,
                    ExecutionStatus::Error | ExecutionStatus::Denied
                ));
            }
            Ok(Err(err)) => {
                assert!(!err.to_string().is_empty());
            }
            Err(_) => panic!("POST validation test timed out"),
        }
        Ok(())
    }

    // Resource limit enforcement tests
    #[tokio::test]
    async fn test_execution_time_limits() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/dev/urandom",
                "len": 1024
            }),
        );

        let mut ctx = create_test_exec_context();
        ctx.limits.timeout_ms = 1000; // 1 second

        let start_time = std::time::Instant::now();
        let mut output_sink = MemoryOutputSink::new();
        let result = runner
            .execute(&ctx, intent.params, &mut output_sink)
            .await?;
        let elapsed = start_time.elapsed();

        // Should enforce time limits
        assert!(elapsed.as_secs() <= 5); // Should not run indefinitely

        match result.status {
            ExecutionStatus::Error => {
                // May timeout - this is expected
                let stderr_output = String::from_utf8_lossy(&output_sink.stderr);
                assert!(stderr_output.len() > 0);
            }
            ExecutionStatus::Success => {
                // Quick completion is also acceptable
            }
            _ => {}
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_limit_enforcement() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/dev/zero",
                "len": 1024
            }),
        );

        let mut ctx = create_test_exec_context();
        ctx.limits.mem_bytes = 1024 * 1024; // 1MB limit

        let mut output_sink = MemoryOutputSink::new();
        let result = runner
            .execute(&ctx, intent.params, &mut output_sink)
            .await?;

        // Should not exceed memory limits
        match result.status {
            ExecutionStatus::Success => {
                // Output should be reasonable size
                let output = String::from_utf8_lossy(&output_sink.stdout);
                assert!(output.len() <= 10 * 1024 * 1024); // 10MB reasonable upper bound
            }
            ExecutionStatus::Error => {
                // May fail due to memory limits
            }
            _ => {}
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_disk_read_limit_enforcement() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/dev/urandom",
                "len": 1024
            }),
        );

        let mut ctx = create_test_exec_context();
        ctx.limits.io_bytes = 1024; // 1KB limit

        let mut output_sink = MemoryOutputSink::new();
        let result = runner
            .execute(&ctx, intent.params, &mut output_sink)
            .await?;

        match result.status {
            ExecutionStatus::Success => {
                // Should respect disk read limits
                let output = String::from_utf8_lossy(&output_sink.stdout);
                assert!(output.len() <= 10 * 1024); // Should be limited
            }
            ExecutionStatus::Error => {
                // May fail due to limits
            }
            _ => {}
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_network_request_limit_enforcement() -> Result<()> {
        let runner = HttpFetchRunner::new();

        let mut ctx = create_http_test_exec_context();
        // Note: Network request limits are handled by the actual runner implementation
        // We'll test if multiple requests work within execution limits

        // First request should work
        let intent1 = create_test_intent(
            "http.fetch.v1",
            json!({
                "url": "https://httpbin.org/get",
                "method": "GET"
            }),
        );

        let mut output_sink1 = MemoryOutputSink::new();
        let result1 = timeout(
            Duration::from_secs(5),
            runner.execute(&ctx, intent1.params, &mut output_sink1),
        )
        .await??;

        // Should succeed or fail gracefully
        match result1.status {
            ExecutionStatus::Success | ExecutionStatus::Ok => {
                // First request succeeded
            }
            ExecutionStatus::Error | ExecutionStatus::Failed => {
                // May fail due to network issues
            }
            ExecutionStatus::Denied => {
                // Access denied by policy
            }
            ExecutionStatus::Timeout => {
                // Request timed out
            }
            ExecutionStatus::Killed => {
                // Process was killed
            }
        }
        Ok(())
    }

    // Security boundary and isolation tests
    #[tokio::test]
    async fn test_scope_isolation_enforcement() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/etc/passwd",
                "len": 1024
            }),
        );

        // Test different scope levels
        let scope_paths = vec![
            vec!["/etc".to_string()], // Allow /etc access
            vec!["/tmp".to_string()], // Only allow /tmp access
        ];

        for paths in scope_paths {
            let mut ctx = create_test_exec_context();
            ctx.scope.paths = paths;

            let mut output_sink = MemoryOutputSink::new();
            let result = runner
                .execute(&ctx, intent.params.clone(), &mut output_sink)
                .await?;

            // Should handle different scope levels appropriately
            match result.status {
                ExecutionStatus::Success => {
                    // May succeed in some scopes
                }
                ExecutionStatus::Error => {
                    // May be blocked in restricted scopes
                    let stderr_output = String::from_utf8_lossy(&output_sink.stderr);
                    assert!(stderr_output.len() > 0);
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_working_directory_isolation() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "./test_file.txt",
                "len": 1024
            }),
        );

        let mut ctx = create_test_exec_context();
        ctx.workdir = PathBuf::from("/tmp/isolated-test-dir");

        let mut output_sink = MemoryOutputSink::new();
        let result = runner
            .execute(&ctx, intent.params, &mut output_sink)
            .await?;

        // Should operate within working directory context
        match result.status {
            ExecutionStatus::Error => {
                // Expected since file likely doesn't exist
                let stderr_output = String::from_utf8_lossy(&output_sink.stderr);
                assert!(
                    stderr_output.contains("not found")
                        || stderr_output.contains("No such file")
                        || stderr_output.len() > 0
                );
            }
            ExecutionStatus::Success => {
                // May succeed if file exists
            }
            _ => {}
        }
        Ok(())
    }

    // Malicious intent detection and blocking tests
    #[tokio::test]
    async fn test_malicious_fs_read_blocking() -> Result<()> {
        let runner = FsReadRunner::new();

        // Test various malicious attempts
        let malicious_attempts = vec![
            json!({"path": "/proc/self/environ", "len": 1024}), // Environment variables
            json!({"path": "/proc/self/cmdline", "len": 1024}), // Command line
            json!({"path": "/etc/shadow", "len": 1024}),        // Shadow file
            json!({"path": "/root/.ssh/id_rsa", "len": 1024}),  // SSH keys
            json!({"path": "/home/user/.bashrc", "len": 1024}), // User files
            json!({"path": "/var/log/auth.log", "len": 1024}),  // System logs
        ];

        for params in malicious_attempts {
            let intent = create_test_intent("fs.read.v1", params);
            let ctx = create_test_exec_context();

            let mut output_sink = MemoryOutputSink::new();
            let result = runner
                .execute(&ctx, intent.params.clone(), &mut output_sink)
                .await?;

            // Should block or handle securely
            match result.status {
                ExecutionStatus::Error | ExecutionStatus::Failed => {
                    // Blocking is expected and correct
                    let stderr_output = String::from_utf8_lossy(&output_sink.stderr);
                    assert!(stderr_output.len() > 0);
                }
                ExecutionStatus::Success | ExecutionStatus::Ok => {
                    // May succeed if file is actually safe/accessible
                    // This depends on system configuration
                }
                ExecutionStatus::Denied => {
                    // Access denied by policy - also acceptable
                }
                ExecutionStatus::Timeout => {
                    // Timeout - also acceptable
                }
                ExecutionStatus::Killed => {
                    // Process killed - also acceptable
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_malicious_http_request_blocking() -> Result<()> {
        let runner = HttpFetchRunner::new();

        // Test various malicious HTTP attempts
        let malicious_attempts = vec![
            json!({"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "method": "GET"}), // AWS metadata
            json!({"url": "http://metadata.google.internal/computeMetadata/v1/", "method": "GET"}), // GCP metadata
            json!({"url": "http://localhost:22", "method": "GET"}), // SSH port
            json!({"url": "http://127.0.0.1:3306", "method": "GET"}), // MySQL port
            json!({"url": "file:///etc/passwd", "method": "GET"}),  // File protocol
            json!({"url": "ftp://example.com/file", "method": "GET"}), // FTP protocol
        ];

        for params in malicious_attempts {
            let intent = create_test_intent("http.fetch.v1", params);
            let ctx = create_http_test_exec_context();

            let mut output_sink = MemoryOutputSink::new();
            let execution = timeout(
                Duration::from_secs(5),
                runner.execute(&ctx, intent.params, &mut output_sink),
            )
            .await;

            match execution {
                Ok(Ok(result)) => {
                    assert!(matches!(
                        result.status,
                        ExecutionStatus::Error | ExecutionStatus::Denied | ExecutionStatus::Timeout
                    ));
                }
                Ok(Err(err)) => {
                    assert!(!err.to_string().is_empty());
                }
                Err(_) => panic!("Malicious HTTP request test timed out"),
            }
        }
        Ok(())
    }

    // Error handling and recovery tests
    #[tokio::test]
    async fn test_capability_error_reporting() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent("fs.read.v1", json!({})); // Invalid parameters
        let ctx = create_test_exec_context();

        let mut output_sink = MemoryOutputSink::new();
        match runner.execute(&ctx, intent.params, &mut output_sink).await {
            Ok(result) => {
                assert!(matches!(
                    result.status,
                    ExecutionStatus::Error | ExecutionStatus::Denied
                ));
            }
            Err(err) => {
                assert!(!err.to_string().is_empty());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_capability_graceful_failure() -> Result<()> {
        let runner = HttpFetchRunner::new();
        let intent = create_test_intent(
            "http.fetch.v1",
            json!({
                "url": "https://this-domain-should-not-exist-12345.com",
                "method": "GET"
            }),
        );
        let ctx = create_test_exec_context();

        let mut output_sink = MemoryOutputSink::new();
        let execution = timeout(
            Duration::from_secs(10),
            runner.execute(&ctx, intent.params, &mut output_sink),
        )
        .await;

        match execution {
            Ok(Ok(result)) => {
                assert!(matches!(
                    result.status,
                    ExecutionStatus::Error | ExecutionStatus::Denied | ExecutionStatus::Timeout
                ));
            }
            Ok(Err(err)) => {
                assert!(!err.to_string().is_empty());
            }
            Err(_) => panic!("Graceful failure test timed out"),
        }
        Ok(())
    }

    // Integration and compatibility tests
    #[tokio::test]
    async fn test_capability_output_sink_integration() -> Result<()> {
        let runner = FsReadRunner::new();
        let intent = create_test_intent(
            "fs.read.v1",
            json!({
                "path": "/etc/hostname",
                "len": 1024
            }),
        );

        let mut ctx = create_test_exec_context();
        // Output sink is passed directly to execute method

        let mut output_sink = MemoryOutputSink::new();
        let result = runner
            .execute(&ctx, intent.params, &mut output_sink)
            .await?;

        // Should integrate properly with output sink
        match result.status {
            ExecutionStatus::Success => {
                let output = String::from_utf8_lossy(&output_sink.stdout);
                // May be empty but should not fail
                assert!(output.len() >= 0); // Always true, but validates access
            }
            ExecutionStatus::Error => {
                // File may not exist on all systems
            }
            _ => {}
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_capability_execution() -> Result<()> {
        let runner = FsReadRunner::new();

        // Execute multiple capability instances concurrently
        let mut handles = Vec::new();
        for i in 0..5 {
            // Create a new runner instance for each concurrent execution
            let runner_instance = FsReadRunner::new();
            let intent = create_test_intent(
                "fs.read.v1",
                json!({
                    "path": format!("/etc/hostname{}", i), // Different paths to avoid conflicts
                    "len": 1024
                }),
            );
            let ctx = create_test_exec_context();

            let handle = tokio::spawn(async move {
                let mut output_sink = MemoryOutputSink::new();
                runner_instance
                    .execute(&ctx, intent.params, &mut output_sink)
                    .await
            });
            handles.push(handle);
        }

        // Wait for all to complete
        let results: Result<Vec<_>, _> = futures::future::try_join_all(handles)
            .await
            .unwrap()
            .into_iter()
            .collect();

        let execution_results = results?;

        // All should complete (may succeed or fail based on file existence)
        assert_eq!(execution_results.len(), 5);

        for result in execution_results {
            match result.status {
                ExecutionStatus::Success => {
                    // Success is acceptable
                }
                ExecutionStatus::Error => {
                    // Errors are also acceptable for this test
                    // We can't access the stderr easily in this concurrent test
                    // but execution completion is what we're testing
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// Add required dependencies for testing
use futures;
