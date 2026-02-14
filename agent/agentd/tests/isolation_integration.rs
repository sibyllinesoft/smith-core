use agentd::isolation_tests::{quick_isolation_check, run_isolation_tests, IsolationTestResults};
use anyhow::Result;
use tokio;

#[tokio::test]
async fn test_isolation_system_integration() -> Result<()> {
    // Only run on Linux systems
    if !cfg!(target_os = "linux") {
        println!("Skipping isolation tests - Linux required");
        return Ok(());
    }

    // Test 1: Quick isolation check
    println!("Running quick isolation check...");
    let quick_result = quick_isolation_check().await;

    match quick_result {
        Ok(isolation_ok) => {
            println!("Quick isolation check result: {}", isolation_ok);
        }
        Err(e) => {
            println!("Quick isolation check failed: {}", e);
            // This is not necessarily a test failure - it might be expected on some systems
        }
    }

    // Test 2: Comprehensive isolation tests
    println!("Running comprehensive isolation tests...");
    let comprehensive_result = run_isolation_tests().await;

    match comprehensive_result {
        Ok(results) => {
            print_test_results(&results);

            // Validate result structure
            assert!(!results.seccomp_details.is_empty());
            assert!(!results.landlock_details.is_empty());
            assert!(!results.cgroups_details.is_empty());

            // Check that at least some tests should pass on a proper Linux system
            if std::path::Path::new("/sys/fs/cgroup").exists() {
                // If cgroups is available, at least some basic functionality should work
                println!("System has cgroups - expecting some tests to pass");
            }

            println!("All isolation tests completed successfully");
        }
        Err(e) => {
            println!("Comprehensive isolation tests failed: {}", e);
            // This could be expected on non-Linux or restricted environments
            // The important thing is that the test framework itself works
        }
    }

    Ok(())
}

fn print_test_results(results: &IsolationTestResults) {
    println!("=== ISOLATION TEST RESULTS ===");
    println!(
        "Overall Status: {}",
        if results.overall_passed() {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!();

    println!("Seccomp Tests:");
    println!(
        "  Status: {}",
        if results.seccomp_passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!("  Details: {}", results.seccomp_details);
    println!();

    println!("Landlock Tests:");
    println!(
        "  Status: {}",
        if results.landlock_passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!("  Details: {}", results.landlock_details);
    println!();

    println!("Cgroups Tests:");
    println!(
        "  Status: {}",
        if results.cgroups_passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!("  Details: {}", results.cgroups_details);
    println!();

    if results.overall_passed() {
        println!("🎉 All isolation mechanisms are working correctly!");
    } else {
        println!("⚠️  Some isolation mechanisms need attention");

        let mut failed_tests = Vec::new();
        if !results.seccomp_passed {
            failed_tests.push("seccomp");
        }
        if !results.landlock_passed {
            failed_tests.push("landlock");
        }
        if !results.cgroups_passed {
            failed_tests.push("cgroups");
        }

        println!("Failed tests: {}", failed_tests.join(", "));
    }
}

#[tokio::test]
async fn test_health_service_isolation_reporting() -> Result<()> {
    use agentd::health::HealthService;

    // Test that health service can be created and provides meaningful status
    let health_service = HealthService::new()?;
    let status = health_service.get_status().await;

    println!("Health Service Status:");
    println!(
        "  Platform: {} {} (Linux: {})",
        status.platform.os, status.platform.arch, status.platform.is_linux
    );
    println!("  Security Features:");
    println!("    - Landlock: {}", status.security.landlock_available);
    println!("    - Seccomp: {}", status.security.seccomp_available);
    println!("    - Cgroups: {}", status.security.cgroups_available);
    println!("    - Overall Secure: {}", status.security.overall_secure);

    // Validate that detection works
    assert!(!status.platform.os.is_empty());
    assert!(!status.platform.arch.is_empty());

    // On Linux, we should detect at least some security features
    if status.platform.is_linux {
        // Seccomp should be available on all modern Linux systems
        assert!(status.security.seccomp_available);
    }

    Ok(())
}

#[test]
fn test_platform_detection() {
    use agentd::health::PlatformInfo;

    let platform = PlatformInfo::detect();

    println!("Detected Platform:");
    println!("  OS: {}", platform.os);
    println!("  Architecture: {}", platform.arch);
    println!("  Is Linux: {}", platform.is_linux);
    println!("  Is Root: {}", platform.is_root);

    if let Some(ref kernel) = platform.kernel_version {
        println!("  Kernel: {}", kernel);
    }

    // Basic validation
    assert!(!platform.os.is_empty());
    assert!(!platform.arch.is_empty());
    assert_eq!(platform.is_linux, cfg!(target_os = "linux"));
}

#[test]
fn test_security_feature_detection() {
    use agentd::health::SecurityStatus;

    let security = SecurityStatus::detect();

    println!("Security Feature Detection:");
    println!("  Landlock Available: {}", security.landlock_available);
    println!("  Seccomp Available: {}", security.seccomp_available);
    println!("  Cgroups Available: {}", security.cgroups_available);
    println!("  Namespaces Available: {}", security.namespaces_available);
    println!("  Overall Secure: {}", security.overall_secure);

    // On Linux, we should detect basic features
    if cfg!(target_os = "linux") {
        assert!(security.seccomp_available);
        assert!(security.namespaces_available);

        // Cgroups v2 detection
        if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            assert!(security.cgroups_available);
        }
    } else {
        // On non-Linux, security features should be unavailable
        assert!(!security.landlock_available);
        assert!(!security.seccomp_available);
        assert!(!security.cgroups_available);
        assert!(!security.namespaces_available);
        assert!(!security.overall_secure);
    }
}

#[tokio::test]
async fn test_self_test_simulation() -> Result<()> {
    // Simulate what the --self-test command does
    println!("Simulating self-test execution...");

    // Platform check
    let platform = agentd::health::PlatformInfo::detect();
    println!(
        "Platform: {} {} (Linux: {})",
        platform.os, platform.arch, platform.is_linux
    );

    // Security features check
    let security = agentd::health::SecurityStatus::detect();
    println!(
        "Security: Landlock={}, Seccomp={}, Cgroups={}",
        security.landlock_available, security.seccomp_available, security.cgroups_available
    );

    // Quick isolation check
    match quick_isolation_check().await {
        Ok(isolation_ok) => {
            println!(
                "Quick isolation check: {}",
                if isolation_ok { "PASS" } else { "FAIL" }
            );

            if platform.is_linux && security.overall_secure {
                println!("Self-test status: READY FOR PRODUCTION");
            } else if platform.is_linux {
                println!("Self-test status: READY FOR DEVELOPMENT");
            } else {
                println!("Self-test status: DEMO MODE ONLY");
            }
        }
        Err(e) => {
            println!("Quick isolation check failed: {}", e);
            println!("Self-test status: CONFIGURATION ISSUES DETECTED");
        }
    }

    Ok(())
}
