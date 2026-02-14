//! Demonstration of Smith Executor isolation testing capabilities
//!
//! This example shows how to use the isolation testing system to validate
//! that security mechanisms are working correctly.
//!
//! Run with: cargo run --example test_isolation_demo

use agentd::health::{HealthService, PlatformInfo, SecurityStatus};
use agentd::isolation_tests::{quick_isolation_check, run_isolation_tests};
use std::time::Instant;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🛡️  Smith Executor Isolation Testing Demo");
    println!("========================================");
    println!();

    // Step 1: Platform Detection
    println!("📋 Step 1: Platform Detection");
    let platform = PlatformInfo::detect();
    println!("  OS: {} {}", platform.os, platform.arch);
    println!(
        "  Linux: {}",
        if platform.is_linux {
            "✅ Yes"
        } else {
            "❌ No"
        }
    );
    println!(
        "  Root: {}",
        if platform.is_root {
            "⚠️  Yes (not recommended)"
        } else {
            "✅ No"
        }
    );

    if let Some(ref kernel) = platform.kernel_version {
        println!("  Kernel: {}", kernel.lines().next().unwrap_or("unknown"));
    }
    println!();

    // Step 2: Security Feature Detection
    println!("🔍 Step 2: Security Feature Detection");
    let security = SecurityStatus::detect();
    println!(
        "  Landlock: {}",
        if security.landlock_available {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );
    println!(
        "  Seccomp: {}",
        if security.seccomp_available {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );
    println!(
        "  Cgroups: {}",
        if security.cgroups_available {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );
    println!(
        "  Namespaces: {}",
        if security.namespaces_available {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );
    println!(
        "  Overall: {}",
        if security.overall_secure {
            "🔒 Secure"
        } else {
            "⚠️  Limited"
        }
    );
    println!();

    // Step 3: Health Service Demonstration
    println!("🏥 Step 3: Health Service");
    let health_service = HealthService::new()?;
    let health_status = health_service.get_status().await;
    println!("  Service Status: {}", health_status.status);
    println!("  Version: {}", health_status.version);
    println!(
        "  Isolation Effective: {}",
        health_status.isolation.isolation_effective
    );
    println!();

    // Step 4: Quick Isolation Check
    println!("⚡ Step 4: Quick Isolation Check");
    let quick_start = Instant::now();

    match quick_isolation_check().await {
        Ok(isolation_ok) => {
            let quick_duration = quick_start.elapsed();
            println!(
                "  Result: {}",
                if isolation_ok {
                    "✅ Passed"
                } else {
                    "⚠️  Issues detected"
                }
            );
            println!("  Duration: {:?}", quick_duration);
            println!("  Details: Basic isolation mechanisms appear functional");
        }
        Err(e) => {
            println!("  Result: ❌ Failed");
            println!("  Error: {}", e);
            println!("  Note: This may be expected on non-Linux systems");
        }
    }
    println!();

    // Step 5: Comprehensive Isolation Tests (only on Linux)
    if platform.is_linux {
        println!("🧪 Step 5: Comprehensive Isolation Tests");
        println!("  Running comprehensive isolation validation...");
        println!("  This may take 10-30 seconds...");

        let comprehensive_start = Instant::now();

        match run_isolation_tests().await {
            Ok(results) => {
                let comprehensive_duration = comprehensive_start.elapsed();
                println!("  Duration: {:?}", comprehensive_duration);
                println!();

                // Print detailed results
                print_comprehensive_results(&results);

                // Overall assessment
                if results.overall_passed() {
                    println!("🎉 SECURITY VALIDATION: ALL TESTS PASSED");
                    println!("   The Smith Executor is ready for secure code execution");
                    println!("   All isolation mechanisms are functioning correctly");
                } else {
                    println!("⚠️  SECURITY VALIDATION: SOME TESTS FAILED");
                    println!("   Review the failed tests above");
                    println!("   Consider running in --demo mode for development");
                    println!("   Production use requires all isolation tests to pass");
                }
            }
            Err(e) => {
                println!("  Result: ❌ Test execution failed");
                println!("  Error: {}", e);
                println!("  This may indicate system configuration issues");
            }
        }
    } else {
        println!("🧪 Step 5: Comprehensive Isolation Tests");
        println!("  Skipped: Linux required for isolation testing");
        println!("  On this platform, executor will run in demo mode only");
    }

    println!();
    println!("✨ Demo Complete!");
    println!();
    println!("Next Steps:");
    println!("  1. Run 'smith-executor self-test --comprehensive' for CLI testing");
    println!("  2. Start health server and test HTTP endpoints");
    println!("  3. Review ISOLATION_TESTING.md for detailed documentation");

    Ok(())
}

fn print_comprehensive_results(results: &agentd::isolation_tests::IsolationTestResults) {
    println!("  📊 Test Results Summary:");

    // Seccomp results
    print!("    Seccomp: ");
    if results.seccomp_passed {
        println!("✅ PASS");
        println!("      {}", results.seccomp_details);
    } else {
        println!("❌ FAIL");
        println!("      {}", results.seccomp_details);
    }

    // Landlock results
    print!("    Landlock: ");
    if results.landlock_passed {
        println!("✅ PASS");
        println!("      {}", results.landlock_details);
    } else {
        println!("❌ FAIL");
        println!("      {}", results.landlock_details);
    }

    // Cgroups results
    print!("    Cgroups: ");
    if results.cgroups_passed {
        println!("✅ PASS");
        println!("      {}", results.cgroups_details);
    } else {
        println!("❌ FAIL");
        println!("      {}", results.cgroups_details);
    }

    println!();

    // Security implications
    println!("  🔒 Security Implications:");
    if results.seccomp_passed {
        println!("    ✅ Dangerous syscalls are properly blocked");
    } else {
        println!("    ⚠️  Processes may execute dangerous system calls");
    }

    if results.landlock_passed {
        println!("    ✅ Filesystem access is properly restricted");
    } else {
        println!("    ⚠️  Processes may access unauthorized files");
    }

    if results.cgroups_passed {
        println!("    ✅ Resource usage is properly limited");
    } else {
        println!("    ⚠️  Processes may consume unlimited resources");
    }

    println!();
}
