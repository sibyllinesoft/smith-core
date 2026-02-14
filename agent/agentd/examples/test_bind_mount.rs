//! E2E test for custom bind mounts in container backend
//!
//! This test verifies that ~/Projects can be mapped to /opt/projects inside a container sandbox.
//!
//! Run with: cargo run --example test_bind_mount

use agentd::core::intent::Command;
use agentd::core::isolation::{BindMount, ExecContext, IsolationBackend, SandboxSpec};
use agentd::isolation::ContainerBackend;
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("agentd=debug")
        .init();

    println!("=== Container Bind Mount E2E Test ===\n");

    // Get the home directory
    let home = std::env::var("HOME").expect("HOME not set");
    let projects_path = PathBuf::from(&home).join("Projects");

    if !projects_path.exists() {
        anyhow::bail!("~/Projects does not exist");
    }

    println!("Source path: {}", projects_path.display());
    println!("Target path: /opt/projects\n");

    // Create a temporary work directory
    let temp_dir = tempfile::TempDir::new()?;
    let work_root = temp_dir.path();

    // Create the container backend
    let backend = ContainerBackend::new(work_root, None)?;
    println!("Backend: {}", backend.name());

    // Probe capabilities
    let caps = backend.probe().await?;
    println!("Filesystem isolation: {}", caps.filesystem_isolation);
    println!("Features: {:?}\n", caps.platform_features);

    // Create a sandbox spec with custom bind mount
    let spec = SandboxSpec {
        profile: "test".to_string(),
        workdir: PathBuf::from("/opt/projects"),
        allowed_paths_ro: vec![],
        allowed_paths_rw: vec![],
        bind_mounts: vec![BindMount {
            source: projects_path.clone(),
            target: PathBuf::from("/opt/projects"),
            readonly: false,
        }],
        allowed_network: vec![],
        environment: vec![],
        limits: Default::default(),
        network_enabled: false,
        seccomp_profile: None,
        creation_timeout: Duration::from_secs(30),
        labels: vec![],
    };

    println!("Creating sandbox with bind mount...");
    let sandbox = backend.create_sandbox(&spec).await?;
    println!("Sandbox created: {}\n", sandbox.id().as_str());

    // Test 1: List contents of /opt/projects
    println!("=== Test 1: List /opt/projects ===");
    let cmd = Command {
        program: "ls".to_string(),
        args: vec!["-la".to_string(), "/opt/projects".to_string()],
        workdir: None,
        env: vec![].into_iter().collect(),
        stdin: None,
        timeout: Some(Duration::from_secs(10)),
        inherit_env: false,
    };

    let ctx = ExecContext {
        trace_id: "test-1".to_string(),
        request_id: "req-1".to_string(),
        workdir: None,
        extra_env: vec![],
        timeout: Some(Duration::from_secs(10)),
        capture_stdout: true,
        capture_stderr: true,
        stream_output: false,
    };

    let result = sandbox.exec(&cmd, &ctx).await?;
    println!("Exit code: {}", result.exit_code);
    println!("stdout:\n{}", String::from_utf8_lossy(&result.stdout));
    if !result.stderr.is_empty() {
        println!("stderr:\n{}", String::from_utf8_lossy(&result.stderr));
    }

    // Test 2: Check if agentd directory exists
    println!("\n=== Test 2: Check /opt/projects/agentd exists ===");
    let cmd2 = Command {
        program: "ls".to_string(),
        args: vec!["-la".to_string(), "/opt/projects/agentd".to_string()],
        workdir: None,
        env: vec![].into_iter().collect(),
        stdin: None,
        timeout: Some(Duration::from_secs(10)),
        inherit_env: false,
    };

    let result2 = sandbox.exec(&cmd2, &ctx).await?;
    println!("Exit code: {}", result2.exit_code);
    if result2.exit_code == 0 {
        println!("✓ /opt/projects/agentd exists!");
        // Show first few lines
        let stdout = String::from_utf8_lossy(&result2.stdout);
        for line in stdout.lines().take(5) {
            println!("  {}", line);
        }
    } else {
        println!("✗ /opt/projects/agentd not found");
        println!("stderr: {}", String::from_utf8_lossy(&result2.stderr));
    }

    // Test 3: Create a test file to verify write access
    println!("\n=== Test 3: Create test file ===");
    let test_file = format!(
        "/opt/projects/.agentd-bind-mount-test-{}",
        std::process::id()
    );
    let cmd3 = Command {
        program: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            format!(
                "echo 'bind mount test' > {} && cat {}",
                test_file, test_file
            ),
        ],
        workdir: None,
        env: vec![].into_iter().collect(),
        stdin: None,
        timeout: Some(Duration::from_secs(10)),
        inherit_env: false,
    };

    let result3 = sandbox.exec(&cmd3, &ctx).await?;
    println!("Exit code: {}", result3.exit_code);
    if result3.exit_code == 0 {
        println!("✓ Write access works!");
        println!(
            "Content: {}",
            String::from_utf8_lossy(&result3.stdout).trim()
        );
    } else {
        println!("✗ Write failed");
        println!("stderr: {}", String::from_utf8_lossy(&result3.stderr));
    }

    // Test 4: Verify the file exists on the host
    println!("\n=== Test 4: Verify file on host ===");
    let host_test_file =
        projects_path.join(format!(".agentd-bind-mount-test-{}", std::process::id()));
    if host_test_file.exists() {
        let content = std::fs::read_to_string(&host_test_file)?;
        println!("✓ File exists on host at: {}", host_test_file.display());
        println!("Content: {}", content.trim());
        // Clean up
        std::fs::remove_file(&host_test_file)?;
        println!("✓ Test file cleaned up");
    } else {
        println!("✗ File NOT found on host");
        println!("Expected at: {}", host_test_file.display());
    }

    // Test 5: Verify we cannot write outside the bind mount
    println!("\n=== Test 5: Verify write outside bind mount fails ===");
    let cmd5 = Command {
        program: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "echo 'should fail' > /etc/test-file 2>&1 || echo 'Write correctly blocked'"
                .to_string(),
        ],
        workdir: None,
        env: vec![].into_iter().collect(),
        stdin: None,
        timeout: Some(Duration::from_secs(10)),
        inherit_env: false,
    };

    let result5 = sandbox.exec(&cmd5, &ctx).await?;
    println!(
        "stdout: {}",
        String::from_utf8_lossy(&result5.stdout).trim()
    );
    if String::from_utf8_lossy(&result5.stdout).contains("blocked")
        || String::from_utf8_lossy(&result5.stderr).contains("Read-only")
    {
        println!("✓ Writes outside bind mount are blocked");
    }

    // Clean up
    println!("\n=== Cleanup ===");
    sandbox.destroy().await?;
    println!("Sandbox destroyed");

    println!("\n=== All tests completed ===");
    Ok(())
}
