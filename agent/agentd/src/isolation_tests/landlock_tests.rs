/*!
# Landlock Isolation Tests

Tests Landlock filesystem access control to ensure file operations are properly
restricted to allowed paths while blocking access to forbidden locations.
*/

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tracing::{debug, info, warn};

use smith_jailer::landlock::{
    apply_landlock_rules, is_landlock_available, LandlockAccess, LandlockConfig, LandlockRule,
};

use super::common::{execute_fork_test, IsolationTestResults, TestExitCode};

/// Execute landlock isolation test
pub async fn execute_landlock_test(results: &mut IsolationTestResults) {
    info!("📁 Testing Landlock filesystem restrictions...");
    match test_landlock_isolation().await {
        Ok(details) => {
            results.landlock_passed = true;
            results.landlock_details = details;
            info!("✅ Landlock test passed");
        }
        Err(e) => {
            results.landlock_details = format!("Failed: {}", e);
            tracing::error!("❌ Landlock test failed: {}", e);
        }
    }
}

/// Main landlock isolation test function
pub async fn test_landlock_isolation() -> Result<String> {
    // Check if Landlock is available on this system
    if !is_landlock_available() {
        let msg = "Landlock LSM not available on this system (requires Linux 5.13+)";
        warn!("{}", msg);
        return Ok(format!("SKIPPED: {}", msg));
    }

    info!("Landlock LSM is available, testing filesystem restrictions...");

    // Set up test directory structure
    let test_structure = setup_landlock_test_paths()
        .await
        .context("Failed to set up test directory structure")?;

    // Create Landlock configuration allowing only specific paths
    let landlock_config = create_test_landlock_config(&test_structure)
        .context("Failed to create Landlock configuration")?;

    // Test allowed file access
    test_allowed_file_access(&landlock_config, &test_structure)
        .await
        .context("Allowed file access test failed")?;

    // Test forbidden file access
    test_forbidden_file_access(&landlock_config, &test_structure)
        .await
        .context("Forbidden file access test failed")?;

    // Test directory traversal blocking
    test_directory_traversal_blocking(&landlock_config, &test_structure)
        .await
        .context("Directory traversal blocking test failed")?;

    let test_summary = format!(
        "Landlock filesystem restrictions working correctly. \
         Allowed paths accessible, forbidden paths blocked, \
         directory traversal prevented. Test structure: allowed={}, forbidden={}",
        test_structure.allowed_dir.path().display(),
        test_structure.forbidden_dir.path().display()
    );

    Ok(test_summary)
}

/// Test structure for Landlock filesystem tests
#[derive(Debug)]
struct LandlockTestStructure {
    _temp_root: TempDir,
    allowed_dir: TempDir,
    forbidden_dir: TempDir,
    allowed_file: PathBuf,
    forbidden_file: PathBuf,
    traversal_target: PathBuf,
}

/// Set up test directory structure for Landlock tests
async fn setup_landlock_test_paths() -> Result<LandlockTestStructure> {
    // Create temporary root directory
    let temp_root = TempDir::new().context("Failed to create temporary root directory")?;

    // Create allowed directory
    let allowed_dir =
        TempDir::new_in(temp_root.path()).context("Failed to create allowed directory")?;

    // Create forbidden directory
    let forbidden_dir =
        TempDir::new_in(temp_root.path()).context("Failed to create forbidden directory")?;

    // Create test files
    let allowed_file = allowed_dir.path().join("allowed_test.txt");
    fs::write(&allowed_file, "This file should be accessible")
        .context("Failed to create allowed test file")?;

    let forbidden_file = forbidden_dir.path().join("forbidden_test.txt");
    fs::write(&forbidden_file, "This file should be blocked")
        .context("Failed to create forbidden test file")?;

    // Create a file for directory traversal test
    let traversal_target = temp_root.path().join("secret.txt");
    fs::write(
        &traversal_target,
        "This should not be accessible via traversal",
    )
    .context("Failed to create traversal target file")?;

    debug!("Landlock test structure created:");
    debug!("  Allowed dir: {}", allowed_dir.path().display());
    debug!("  Forbidden dir: {}", forbidden_dir.path().display());
    debug!("  Allowed file: {}", allowed_file.display());
    debug!("  Forbidden file: {}", forbidden_file.display());
    debug!("  Traversal target: {}", traversal_target.display());

    Ok(LandlockTestStructure {
        _temp_root: temp_root,
        allowed_dir,
        forbidden_dir,
        allowed_file,
        forbidden_file,
        traversal_target,
    })
}

/// Create Landlock configuration for testing
fn create_test_landlock_config(test_structure: &LandlockTestStructure) -> Result<LandlockConfig> {
    let mut rules = Vec::new();

    // Add read-only rules for allowed paths
    rules.push(LandlockRule::read_only(
        test_structure
            .allowed_dir
            .path()
            .to_str()
            .context("Failed to convert allowed dir path to string")?,
    ));

    // Add some common system paths that might be needed (read-only)
    rules.push(LandlockRule::read_only("/lib"));
    rules.push(LandlockRule::read_only("/lib64"));
    rules.push(LandlockRule::read_only("/usr/lib"));

    // Add write access to the allowed directory
    rules.push(LandlockRule::read_write(
        test_structure
            .allowed_dir
            .path()
            .to_str()
            .context("Failed to convert allowed dir path to string")?,
    ));

    // Add execute access to common system paths
    rules.push(LandlockRule {
        path: "/bin".to_string(),
        access_rights: LandlockAccess::FsExecute as u64,
    });
    rules.push(LandlockRule {
        path: "/usr/bin".to_string(),
        access_rights: LandlockAccess::FsExecute as u64,
    });

    Ok(LandlockConfig {
        enabled: true,
        rules,
        default_deny: true,
    })
}

/// Test that allowed file access works after Landlock is applied
async fn test_allowed_file_access(
    landlock_config: &LandlockConfig,
    test_structure: &LandlockTestStructure,
) -> Result<String> {
    let config = landlock_config.clone();
    let allowed_file = test_structure.allowed_file.clone();

    execute_fork_test("allowed_file_access", move || {
        test_allowed_file_in_child_process(&config, &allowed_file)
    })
    .await
}

/// Child process function for testing allowed file access
fn test_allowed_file_in_child_process(
    config: &LandlockConfig,
    allowed_file: &Path,
) -> TestExitCode {
    // Apply Landlock rules
    if let Err(_) = apply_landlock_rules(config) {
        return TestExitCode::UnexpectedError;
    }

    // Try to read the allowed file
    match fs::read_to_string(allowed_file) {
        Ok(content) => {
            if content.contains("This file should be accessible") {
                TestExitCode::Success
            } else {
                TestExitCode::UnexpectedError
            }
        }
        Err(_) => TestExitCode::AllowedSyscallFailed,
    }
}

/// Test that forbidden file access is blocked by Landlock
async fn test_forbidden_file_access(
    landlock_config: &LandlockConfig,
    test_structure: &LandlockTestStructure,
) -> Result<String> {
    let config = landlock_config.clone();
    let forbidden_file = test_structure.forbidden_file.clone();

    execute_fork_test("forbidden_file_access", move || {
        test_forbidden_file_in_child_process(&config, &forbidden_file)
    })
    .await
}

/// Child process function for testing forbidden file access
fn test_forbidden_file_in_child_process(
    config: &LandlockConfig,
    forbidden_file: &Path,
) -> TestExitCode {
    // Apply Landlock rules
    if let Err(_) = apply_landlock_rules(config) {
        return TestExitCode::UnexpectedError;
    }

    // Try to read the forbidden file - should fail
    match fs::read_to_string(forbidden_file) {
        Ok(_) => {
            // File was accessible when it should have been blocked
            TestExitCode::ForbiddenSyscallSucceeded
        }
        Err(e) => {
            // File access was blocked - check if it's the expected error
            match e.kind() {
                std::io::ErrorKind::PermissionDenied => TestExitCode::Success,
                std::io::ErrorKind::NotFound => TestExitCode::Success, // Landlock can also make files "not found"
                _ => TestExitCode::UnexpectedError,
            }
        }
    }
}

/// Test that directory traversal is blocked by Landlock
async fn test_directory_traversal_blocking(
    landlock_config: &LandlockConfig,
    test_structure: &LandlockTestStructure,
) -> Result<String> {
    let config = landlock_config.clone();
    let allowed_dir = test_structure.allowed_dir.path().to_path_buf();
    let traversal_target = test_structure.traversal_target.clone();

    execute_fork_test("directory_traversal_blocking", move || {
        test_directory_traversal_in_child_process(&config, &allowed_dir, &traversal_target)
    })
    .await
}

/// Child process function for testing directory traversal blocking
fn test_directory_traversal_in_child_process(
    config: &LandlockConfig,
    allowed_dir: &Path,
    traversal_target: &Path,
) -> TestExitCode {
    // Apply Landlock rules
    if let Err(_) = apply_landlock_rules(config) {
        return TestExitCode::UnexpectedError;
    }

    // First verify we can access files in the allowed directory
    if let Ok(entries) = fs::read_dir(allowed_dir) {
        let mut found_allowed_file = false;
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .contains("allowed_test.txt")
            {
                found_allowed_file = true;
                break;
            }
        }
        if !found_allowed_file {
            return TestExitCode::AllowedSyscallFailed;
        }
    } else {
        return TestExitCode::AllowedSyscallFailed;
    }

    // Try to access a file outside the allowed directory using relative paths
    let traversal_attempts = vec!["../secret.txt", "../../secret.txt", "../../../secret.txt"];

    for traversal_path in traversal_attempts {
        let full_path = allowed_dir.join(traversal_path);
        match fs::read_to_string(&full_path) {
            Ok(_) => {
                // Directory traversal succeeded when it should have been blocked
                return TestExitCode::ForbiddenSyscallSucceeded;
            }
            Err(e) => {
                // Check that it's blocked for the right reason
                match e.kind() {
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound => {
                        // Good - traversal was blocked
                        continue;
                    }
                    _ => {
                        // Unexpected error
                        return TestExitCode::UnexpectedError;
                    }
                }
            }
        }
    }

    // Try direct access to the traversal target - should also be blocked
    match fs::read_to_string(traversal_target) {
        Ok(_) => TestExitCode::ForbiddenSyscallSucceeded,
        Err(e) => match e.kind() {
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound => {
                TestExitCode::Success
            }
            _ => TestExitCode::UnexpectedError,
        },
    }
}
