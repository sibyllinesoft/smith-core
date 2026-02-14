/*!
# Common Utilities for Isolation Tests

This module provides shared utilities for all isolation test modules,
including fork-test patterns, exit codes, and result structures.
*/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Exit codes used by child processes in isolation tests
#[derive(Debug, Clone, Copy)]
pub enum TestExitCode {
    Success = 0,
    SeccompFailed = 2,
    AllowedSyscallFailed = 3,
    ForbiddenSyscallSucceeded = 4,
    UnexpectedError = 5,
    ShouldNotReachHere = 6,
}

impl TestExitCode {
    pub fn from_status(exit_code: i32) -> Result<Self> {
        match exit_code {
            0 => Ok(TestExitCode::Success),
            2 => Ok(TestExitCode::SeccompFailed),
            3 => Ok(TestExitCode::AllowedSyscallFailed),
            4 => Ok(TestExitCode::ForbiddenSyscallSucceeded),
            5 => Ok(TestExitCode::UnexpectedError),
            6 => Ok(TestExitCode::ShouldNotReachHere),
            _ => Err(anyhow::anyhow!("Unknown exit code: {}", exit_code)),
        }
    }

    pub fn to_error_message(self, context: &str) -> String {
        match self {
            TestExitCode::Success => "Success".to_string(),
            TestExitCode::SeccompFailed => "Failed to apply seccomp filter".to_string(),
            TestExitCode::AllowedSyscallFailed => {
                format!("{} allowed syscall failed after seccomp", context)
            }
            TestExitCode::ForbiddenSyscallSucceeded => {
                format!("{} succeeded when it should have been blocked", context)
            }
            TestExitCode::UnexpectedError => format!("{} failed with unexpected error", context),
            TestExitCode::ShouldNotReachHere => "Should not reach this point".to_string(),
        }
    }
}

/// Execute a test in a forked child process with standardized error handling
pub async fn execute_fork_test<F>(test_name: &str, child_test: F) -> Result<String>
where
    F: FnOnce() -> TestExitCode + Send + 'static,
{
    let test_name = test_name.to_string();

    tokio::task::spawn_blocking(move || -> Result<String> {
        let child_pid = unsafe { libc::fork() };

        if child_pid == 0 {
            // Child process: run the test and exit with appropriate code
            let exit_code = child_test();
            std::process::exit(exit_code as i32);
        } else if child_pid > 0 {
            // Parent process: wait for child and analyze results
            wait_for_child_process(child_pid, &test_name)
        } else {
            Err(anyhow::anyhow!(
                "Failed to fork child process for {}",
                test_name
            ))
        }
    })
    .await?
}

/// Wait for child process and interpret results
fn wait_for_child_process(child_pid: libc::pid_t, test_name: &str) -> Result<String> {
    let mut status: libc::c_int = 0;
    let timeout = Duration::from_secs(10);
    let start = Instant::now();

    loop {
        let result = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };

        if result == child_pid {
            // Child has exited
            break;
        } else if result == 0 {
            // Child still running, check for timeout
            if start.elapsed() > timeout {
                // Kill the child process
                unsafe { libc::kill(child_pid, libc::SIGKILL) };
                // Wait for it to actually die
                unsafe { libc::waitpid(child_pid, &mut status, 0) };
                return Err(anyhow::anyhow!(
                    "Test {} timed out after {:?}",
                    test_name,
                    timeout
                ));
            }
            // Sleep briefly before checking again
            std::thread::sleep(Duration::from_millis(10));
        } else {
            return Err(anyhow::anyhow!(
                "waitpid failed for test {}: errno {}",
                test_name,
                std::io::Error::last_os_error()
            ));
        }
    }

    // Analyze exit status
    if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        let test_exit_code = TestExitCode::from_status(exit_code)
            .with_context(|| format!("Invalid exit code from test {}", test_name))?;

        match test_exit_code {
            TestExitCode::Success => Ok(format!("{} completed successfully", test_name)),
            _ => Err(anyhow::anyhow!(
                "{}: {}",
                test_name,
                test_exit_code.to_error_message(test_name)
            )),
        }
    } else if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        let signal_name = match signal {
            libc::SIGKILL => "SIGKILL",
            libc::SIGSEGV => "SIGSEGV",
            libc::SIGABRT => "SIGABRT",
            libc::SIGTERM => "SIGTERM",
            libc::SIGPIPE => "SIGPIPE",
            libc::SIGSYS => "SIGSYS (seccomp violation)",
            _ => "Unknown signal",
        };

        // SIGSYS is expected for seccomp violations
        if signal == libc::SIGSYS {
            Ok(format!(
                "{} properly blocked by seccomp (SIGSYS)",
                test_name
            ))
        } else {
            Err(anyhow::anyhow!(
                "{} killed by signal {} ({})",
                test_name,
                signal,
                signal_name
            ))
        }
    } else {
        Err(anyhow::anyhow!(
            "Test {} exited with unknown status: {}",
            test_name,
            status
        ))
    }
}

/// Test results structure for isolation tests
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IsolationTestResults {
    #[serde(skip)]
    pub start_time: Option<Instant>,
    #[serde(skip)]
    pub end_time: Option<Instant>,
    pub platform_supported: bool,

    // Seccomp results
    pub seccomp_passed: bool,
    pub seccomp_details: String,

    // Landlock results
    pub landlock_passed: bool,
    pub landlock_details: String,

    // Cgroups results
    pub cgroups_passed: bool,
    pub cgroups_details: String,
}

impl IsolationTestResults {
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn finalize(&mut self) {
        self.end_time = Some(Instant::now());
    }

    pub fn duration(&self) -> Duration {
        match (self.start_time, self.end_time) {
            (Some(start), Some(end)) => end - start,
            _ => Duration::from_secs(0),
        }
    }

    pub fn passed_tests_count(&self) -> u32 {
        let mut count = 0;
        if self.seccomp_passed {
            count += 1;
        }
        if self.landlock_passed {
            count += 1;
        }
        if self.cgroups_passed {
            count += 1;
        }
        count
    }

    pub fn total_tests_count(&self) -> u32 {
        3 // seccomp, landlock, cgroups
    }

    pub fn all_tests_passed(&self) -> bool {
        self.seccomp_passed && self.landlock_passed && self.cgroups_passed
    }

    pub fn any_tests_passed(&self) -> bool {
        self.seccomp_passed || self.landlock_passed || self.cgroups_passed
    }

    /// Check if all tests passed (overall security status)
    pub fn overall_passed(&self) -> bool {
        self.seccomp_passed && self.landlock_passed && self.cgroups_passed
    }
}

/// Platform detection utilities
pub fn is_linux_platform() -> bool {
    cfg!(target_os = "linux")
}

pub fn skip_tests_non_linux(mut results: IsolationTestResults) -> IsolationTestResults {
    warn!("⚠️  Isolation tests are only supported on Linux");
    warn!("   Current platform does not support seccomp, landlock, or cgroups");
    results.platform_supported = false;
    results.finalize();
    results
}

/// Log comprehensive test results
pub fn log_final_test_results(results: &IsolationTestResults) {
    let duration = results.duration();
    let passed = results.passed_tests_count();
    let total = results.total_tests_count();

    info!("");
    info!("🔒 ISOLATION TEST RESULTS");
    info!("========================");
    info!("Platform supported: {}", results.platform_supported);
    info!("Tests passed: {}/{}", passed, total);
    info!("Duration: {:?}", duration);
    info!("");
    info!("Detailed Results:");
    info!(
        "  Seccomp: {} - {}",
        if results.seccomp_passed {
            "✅ PASS"
        } else {
            "❌ FAIL"
        },
        results.seccomp_details
    );
    info!(
        "  Landlock: {} - {}",
        if results.landlock_passed {
            "✅ PASS"
        } else {
            "❌ FAIL"
        },
        results.landlock_details
    );
    info!(
        "  Cgroups: {} - {}",
        if results.cgroups_passed {
            "✅ PASS"
        } else {
            "❌ FAIL"
        },
        results.cgroups_details
    );
    info!("");

    if results.all_tests_passed() {
        info!("🎉 ALL ISOLATION TESTS PASSED - System is properly secured");
    } else if results.any_tests_passed() {
        warn!("⚠️  PARTIAL ISOLATION - Some security layers failed");
    } else {
        error!("🚨 CRITICAL - NO ISOLATION LAYERS WORKING");
    }
}

/// Verify basic system calls work before applying filters
pub fn verify_allowed_syscall_before_filter() -> Result<()> {
    // Test a simple, universally allowed syscall (getpid)
    let pid = unsafe { libc::getpid() };
    if pid <= 0 {
        return Err(anyhow::anyhow!(
            "Basic syscall (getpid) failed before filters applied"
        ));
    }
    debug!("✅ Basic syscalls working (getpid returned {})", pid);
    Ok(())
}
