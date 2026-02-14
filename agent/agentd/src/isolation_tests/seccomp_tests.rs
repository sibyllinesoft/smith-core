/*!
# Seccomp Isolation Tests

Tests seccomp-based syscall filtering to ensure dangerous system calls are blocked
while allowing necessary operations for normal execution.
*/

use anyhow::{Context, Result};
use std::ffi::CString;
use tracing::{debug, info};

use smith_jailer::seccomp::{
    apply_seccomp_filter, create_capability_seccomp_config, SeccompConfig,
};

use super::common::{
    execute_fork_test, verify_allowed_syscall_before_filter, IsolationTestResults, TestExitCode,
};

/// Execute seccomp isolation test
pub async fn execute_seccomp_test(results: &mut IsolationTestResults) {
    info!("🔒 Testing seccomp syscall filtering...");
    match test_seccomp_isolation().await {
        Ok(details) => {
            results.seccomp_passed = true;
            results.seccomp_details = details;
            info!("✅ Seccomp test passed");
        }
        Err(e) => {
            results.seccomp_details = format!("Failed: {}", e);
            tracing::error!("❌ Seccomp test failed: {}", e);
        }
    }
}

/// Main seccomp isolation test function
pub async fn test_seccomp_isolation() -> Result<String> {
    // Verify basic syscalls work before applying seccomp
    verify_allowed_syscall_before_filter().context("Basic syscalls failed before seccomp")?;

    // Create seccomp configuration for file read capability
    let seccomp_config = create_capability_seccomp_config("fs.read.v1");

    info!(
        "Testing seccomp syscall filtering with {} rules",
        seccomp_config.allowed_syscalls.len()
    );

    // Execute forbidden syscall tests
    let forbidden_tests = execute_forbidden_syscall_tests(&seccomp_config)
        .await
        .context("Failed to execute forbidden syscall tests")?;

    let test_summary = format!(
        "Seccomp syscall filtering working correctly. {} forbidden syscalls properly blocked: {}",
        forbidden_tests.len(),
        forbidden_tests.join(", ")
    );

    Ok(test_summary)
}

/// Execute tests for syscalls that should be blocked by seccomp
async fn execute_forbidden_syscall_tests(seccomp_config: &SeccompConfig) -> Result<Vec<String>> {
    let mut successful_blocks = Vec::new();

    // Test ptrace blocking
    match test_ptrace_blocked(seccomp_config).await {
        Ok(result) => {
            successful_blocks.push("ptrace".to_string());
            debug!("ptrace test: {}", result);
        }
        Err(e) => {
            return Err(anyhow::anyhow!("ptrace blocking test failed: {}", e));
        }
    }

    // Test raw socket creation blocking
    match test_raw_socket_blocked(seccomp_config).await {
        Ok(result) => {
            successful_blocks.push("raw_socket".to_string());
            debug!("raw socket test: {}", result);
        }
        Err(e) => {
            return Err(anyhow::anyhow!("raw socket blocking test failed: {}", e));
        }
    }

    // Test mount syscall blocking
    match test_mount_blocked(seccomp_config).await {
        Ok(result) => {
            successful_blocks.push("mount".to_string());
            debug!("mount test: {}", result);
        }
        Err(e) => {
            return Err(anyhow::anyhow!("mount blocking test failed: {}", e));
        }
    }

    Ok(successful_blocks)
}

/// Test that ptrace syscall is blocked by seccomp
async fn test_ptrace_blocked(seccomp_config: &SeccompConfig) -> Result<String> {
    let config = seccomp_config.clone();
    execute_fork_test("ptrace_blocked", move || {
        test_ptrace_in_child_process(&config)
    })
    .await
}

/// Child process function for testing ptrace blocking
fn test_ptrace_in_child_process(config: &SeccompConfig) -> TestExitCode {
    // Apply seccomp filter
    if let Err(_) = apply_seccomp_filter(config) {
        return TestExitCode::SeccompFailed;
    }

    // Verify basic syscalls still work after seccomp
    let pid = unsafe { libc::getpid() };
    if pid <= 0 {
        return TestExitCode::AllowedSyscallFailed;
    }

    // Attempt ptrace - should be blocked
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };

    if result == 0 {
        // ptrace succeeded when it should have been blocked
        TestExitCode::ForbiddenSyscallSucceeded
    } else {
        // ptrace was properly blocked - this is the expected behavior
        // Check if errno indicates it was blocked by seccomp
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EPERM || errno == libc::EACCES {
            TestExitCode::Success
        } else {
            TestExitCode::UnexpectedError
        }
    }
}

/// Test that raw socket creation is blocked by seccomp
async fn test_raw_socket_blocked(seccomp_config: &SeccompConfig) -> Result<String> {
    let config = seccomp_config.clone();
    execute_fork_test("raw_socket_blocked", move || {
        test_raw_socket_in_child_process(&config)
    })
    .await
}

/// Child process function for testing raw socket blocking
fn test_raw_socket_in_child_process(config: &SeccompConfig) -> TestExitCode {
    // Apply seccomp filter
    if let Err(_) = apply_seccomp_filter(config) {
        return TestExitCode::SeccompFailed;
    }

    // Verify basic syscalls still work
    let pid = unsafe { libc::getpid() };
    if pid <= 0 {
        return TestExitCode::AllowedSyscallFailed;
    }

    // Attempt to create raw socket - should be blocked
    let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };

    if socket_fd >= 0 {
        // Close the socket if it was created
        unsafe { libc::close(socket_fd) };
        TestExitCode::ForbiddenSyscallSucceeded
    } else {
        // Socket creation was blocked - check the reason
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EPERM || errno == libc::EACCES {
            TestExitCode::Success
        } else {
            TestExitCode::UnexpectedError
        }
    }
}

/// Test that mount syscall is blocked by seccomp
async fn test_mount_blocked(seccomp_config: &SeccompConfig) -> Result<String> {
    let config = seccomp_config.clone();
    execute_fork_test("mount_blocked", move || {
        test_mount_in_child_process(&config)
    })
    .await
}

/// Child process function for testing mount blocking
fn test_mount_in_child_process(config: &SeccompConfig) -> TestExitCode {
    // Apply seccomp filter
    if let Err(_) = apply_seccomp_filter(config) {
        return TestExitCode::SeccompFailed;
    }

    // Verify basic syscalls still work
    let pid = unsafe { libc::getpid() };
    if pid <= 0 {
        return TestExitCode::AllowedSyscallFailed;
    }

    // Attempt mount - should be blocked
    let source = CString::new("tmpfs").unwrap();
    let target = CString::new("/tmp/test_mount").unwrap();
    let fstype = CString::new("tmpfs").unwrap();
    let data = CString::new("").unwrap();

    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            data.as_ptr() as *const libc::c_void,
        )
    };

    if result == 0 {
        // Mount succeeded when it should have been blocked
        // Try to unmount to clean up
        unsafe { libc::umount(target.as_ptr()) };
        TestExitCode::ForbiddenSyscallSucceeded
    } else {
        // Mount was blocked - check the reason
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EPERM || errno == libc::EACCES {
            TestExitCode::Success
        } else {
            TestExitCode::UnexpectedError
        }
    }
}
