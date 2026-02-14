/*!
 * Self-test command implementation
 *
 * Extracted from main.rs to reduce complexity and improve maintainability.
 * Handles comprehensive system and security validation tests.
 */

use anyhow::Result;
use std::path::PathBuf;

use crate::bootstrap::validate_security_capabilities;
use crate::commands::check_config::{check_directories, check_nats_connectivity};
use crate::config::{self, Config};
use crate::{health, isolation_tests};

/// Handles the self-test command
pub struct SelfTestCommand;

impl SelfTestCommand {
    pub async fn execute(config_path: PathBuf, comprehensive: bool) -> Result<()> {
        println!("🧪 Smith Executor Self-Test");
        println!("===========================");

        // Load configuration
        let config = match config::load_config(&config_path) {
            Ok(config) => {
                println!("✅ Configuration loaded successfully");
                config
            }
            Err(e) => {
                println!("❌ Configuration failed to load: {}", e);
                std::process::exit(1);
            }
        };

        let mut all_tests_passed = true;

        // Platform check
        all_tests_passed &= Self::run_platform_check().await;

        // Security features check
        all_tests_passed &= Self::run_security_check().await;

        // Isolation tests
        all_tests_passed &= Self::run_isolation_tests(comprehensive).await;

        // Directory validation
        all_tests_passed &= Self::run_directory_validation(&config).await;

        // Configuration validation
        all_tests_passed &= Self::run_configuration_validation(&config).await;

        // NATS connectivity test
        Self::run_nats_connectivity_test(&config).await;

        // Final result
        Self::print_final_results(all_tests_passed).await;

        if !all_tests_passed {
            Self::print_troubleshooting_tips();
            std::process::exit(1);
        }

        println!("\n✨ Self-test completed successfully!");

        if !comprehensive {
            println!("💡 For comprehensive isolation testing, run:");
            println!("   smith-executor self-test --comprehensive");
        }

        Ok(())
    }

    async fn run_platform_check() -> bool {
        let platform = health::PlatformInfo::detect();
        println!("\n🖥️  Platform Information:");
        println!("├─ OS: {} {}", platform.os, platform.arch);
        println!(
            "├─ Linux: {}",
            if platform.is_linux {
                "✅ Yes"
            } else {
                "❌ No"
            }
        );
        println!(
            "└─ Root: {}",
            if platform.is_root {
                "⚠️  Yes"
            } else {
                "✅ No"
            }
        );

        true // Platform check is always informational
    }

    async fn run_security_check() -> bool {
        let security = health::SecurityStatus::detect();
        println!("\n🔒 Security Features:");
        println!(
            "├─ Landlock: {}",
            if security.landlock_available {
                "✅ Available"
            } else {
                "❌ Not Available"
            }
        );
        println!(
            "├─ Seccomp: {}",
            if security.seccomp_available {
                "✅ Available"
            } else {
                "❌ Not Available"
            }
        );
        println!(
            "├─ Cgroups: {}",
            if security.cgroups_available {
                "✅ Available"
            } else {
                "❌ Not Available"
            }
        );
        println!(
            "└─ Namespaces: {}",
            if security.namespaces_available {
                "✅ Available"
            } else {
                "❌ Not Available"
            }
        );

        true // Security check is always informational
    }

    async fn run_isolation_tests(comprehensive: bool) -> bool {
        let mut tests_passed = true;

        // Quick isolation check (always run)
        println!("\n🛡️  Quick Isolation Check:");
        match isolation_tests::quick_isolation_check().await {
            Ok(isolation_ok) => {
                if isolation_ok {
                    println!("├─ Result: ✅ Isolation mechanisms appear functional");
                } else {
                    println!("├─ Result: ⚠️  Some isolation mechanisms may not be working");
                    tests_passed = false;
                }
            }
            Err(e) => {
                println!("├─ Result: ❌ Isolation check failed: {}", e);
                tests_passed = false;
            }
        }

        // Comprehensive isolation tests (if requested)
        if comprehensive {
            println!("\n🧪 Comprehensive Isolation Tests:");
            match isolation_tests::run_isolation_tests().await {
                Ok(results) => {
                    isolation_tests::print_isolation_report(&results);
                    if !results.overall_passed() {
                        tests_passed = false;
                    }
                }
                Err(e) => {
                    println!("❌ Comprehensive isolation tests failed: {}", e);
                    tests_passed = false;
                }
            }
        } else {
            println!("└─ Tip: Use --comprehensive for detailed isolation testing");
        }

        tests_passed
    }

    async fn run_directory_validation(config: &Config) -> bool {
        println!("\n📁 Directory Validation:");
        let dir_status = check_directories(config);
        println!(
            "├─ Work Root: {}",
            if dir_status.work_root {
                "✅ OK"
            } else {
                "❌ Inaccessible"
            }
        );
        println!(
            "├─ State Dir: {}",
            if dir_status.state_dir {
                "✅ OK"
            } else {
                "❌ Inaccessible"
            }
        );
        println!(
            "└─ Audit Dir: {}",
            if dir_status.audit_dir {
                "✅ OK"
            } else {
                "❌ Inaccessible"
            }
        );

        dir_status.all_valid
    }

    async fn run_configuration_validation(config: &Config) -> bool {
        println!("\n⚙️  Configuration Validation:");
        match validate_security_capabilities(config, false) {
            Ok(_) => {
                println!("└─ Security Configuration: ✅ Valid");
                true
            }
            Err(e) => {
                println!("└─ Security Configuration: ❌ Invalid: {}", e);
                false
            }
        }
    }

    async fn run_nats_connectivity_test(config: &Config) {
        println!("\n🔌 NATS Connectivity Test:");
        let nats_status = check_nats_connectivity(config).await;
        if nats_status.connected {
            println!("├─ Connection: ✅ Connected");
            println!(
                "└─ JetStream: {}",
                if nats_status.jetstream_available {
                    "✅ Available"
                } else {
                    "❌ Not Available"
                }
            );
        } else {
            println!("├─ Connection: ⚠️  Failed (not critical for self-test)");
            if let Some(ref error) = nats_status.error {
                println!("└─ Error: {}", error);
            }
            // NATS failure is not critical for self-test
        }
    }

    async fn print_final_results(all_tests_passed: bool) {
        let platform = health::PlatformInfo::detect();
        let security = health::SecurityStatus::detect();

        println!("\n📊 Self-Test Summary:");
        println!(
            "├─ Platform: {}",
            if platform.is_linux {
                "✅ Supported"
            } else {
                "⚠️  Demo Only"
            }
        );
        println!(
            "├─ Security: {}",
            if security.overall_secure {
                "✅ Full"
            } else {
                "⚠️  Partial"
            }
        );
        println!(
            "├─ Isolation: {}",
            if all_tests_passed {
                "✅ Working"
            } else {
                "❌ Issues Detected"
            }
        );
        println!(
            "└─ Configuration: {}",
            if all_tests_passed {
                "✅ Valid"
            } else {
                "❌ Issues Detected"
            }
        );

        println!(
            "\n🚀 Final Status: {}",
            if all_tests_passed {
                if platform.is_linux && security.overall_secure {
                    "✅ READY FOR PRODUCTION"
                } else {
                    "⚠️  READY FOR DEVELOPMENT"
                }
            } else {
                "❌ CONFIGURATION ISSUES DETECTED"
            }
        );
    }

    fn print_troubleshooting_tips() {
        println!("\n⚠️  Issues detected during self-test:");
        println!("   - Review the failed checks above");
        println!("   - Fix configuration or system setup");
        println!("   - Re-run self-test to verify fixes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_test_command_struct() {
        let _cmd = SelfTestCommand;
        assert!(std::mem::size_of::<SelfTestCommand>() == 0); // Zero-sized type
    }

    #[test]
    fn test_print_troubleshooting_tips() {
        // Just verify it doesn't panic
        SelfTestCommand::print_troubleshooting_tips();
    }

    #[tokio::test]
    async fn test_run_platform_check() {
        // Should always return true (informational only)
        let result = SelfTestCommand::run_platform_check().await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_run_security_check() {
        // Should always return true (informational only)
        let result = SelfTestCommand::run_security_check().await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_print_final_results_passed() {
        // Just verify it doesn't panic
        SelfTestCommand::print_final_results(true).await;
    }

    #[tokio::test]
    async fn test_print_final_results_failed() {
        // Just verify it doesn't panic
        SelfTestCommand::print_final_results(false).await;
    }

    #[tokio::test]
    async fn test_run_isolation_tests_quick() {
        // Quick isolation tests should return a boolean
        let _result = SelfTestCommand::run_isolation_tests(false).await;
        // Result depends on platform - just verify it completes
    }
}
