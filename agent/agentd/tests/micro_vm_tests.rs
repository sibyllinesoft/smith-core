use std::path::PathBuf;

use agentd::runners::shell_exec::ShellExecRunner;
use agentd::runners::{create_exec_context, MemoryOutputSink, Scope, SessionContext};
use agentd::vm::{MicroVmManager, VmPoolRuntimeConfig};
use agentd::{ExecutionLimits, Runner};
use anyhow::Result;
use serde_json::json;
use smith_config::executor::VmPoolConfig;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

fn default_limits() -> ExecutionLimits {
    ExecutionLimits {
        cpu_ms_per_100ms: 50,
        mem_bytes: 256 * 1024 * 1024,
        io_bytes: 10 * 1024 * 1024,
        pids_max: 32,
        timeout_ms: 60_000,
    }
}

fn test_vm_pool_config(volume_root: PathBuf) -> VmPoolConfig {
    VmPoolConfig {
        enabled: true,
        volume_root,
        nix_profile: None,
        shell: PathBuf::from("/usr/bin/env"),
        shell_args: vec!["bash".to_string(), "-lc".to_string()],
        env: Default::default(),
        max_vms: 4,
        idle_shutdown_seconds: 60,
        prune_after_seconds: 120,
        backup_after_seconds: None,
        backup_destination: None,
        bootstrap_command: None,
    }
}

#[tokio::test]
async fn shell_exec_uses_persistent_vm_for_session() -> Result<()> {
    let temp = TempDir::new()?;
    let volume_root = temp.path().join("vm-root");
    let vm_config = test_vm_pool_config(volume_root.clone());
    let runtime_config = VmPoolRuntimeConfig::from(&vm_config);
    let vm_manager = MicroVmManager::new(runtime_config)?;

    let shell_runner = ShellExecRunner::new(Some(vm_manager.clone()));

    let session_id = Uuid::new_v4();
    let workdir = temp.path().join("ephemeral-work");
    std::fs::create_dir_all(&workdir)?;

    let mut ctx = create_exec_context(
        &workdir,
        default_limits(),
        Scope {
            paths: vec![workdir.to_string_lossy().to_string()],
            urls: vec![],
        },
        "vm-test-trace".to_string(),
    );

    ctx.session = Some(SessionContext {
        session_id,
        domain: Some("test-domain".to_string()),
        vm_profile: None,
    });

    // First command prints pwd so we can assert it ran inside the VM volume.
    let mut sink = MemoryOutputSink::new();
    let params = json!({
        "command": "pwd",
        "timeout_ms": 2000,
    });
    shell_runner.execute(&ctx, params, &mut sink).await?;
    let stdout = String::from_utf8(sink.stdout.clone()).unwrap();

    let vm_volume = volume_root.join(session_id.to_string()).join("volume");
    assert_eq!(
        stdout.trim(),
        vm_volume.to_string_lossy(),
        "expected command to run inside VM volume"
    );

    // Second command writes a file; verify it persists on the VM volume.
    let mut sink = MemoryOutputSink::new();
    let command = format!(
        "cd {} && echo 'hello vm' >> state.txt",
        vm_volume.to_string_lossy()
    );
    let params = json!({ "command": command, "timeout_ms": 2000 });
    shell_runner.execute(&ctx, params, &mut sink).await?;

    let persisted_file = vm_volume.join("state.txt");
    assert!(
        persisted_file.exists(),
        "state file should persist in VM volume"
    );
    let contents = std::fs::read_to_string(persisted_file)?;
    assert!(contents.contains("hello vm"));

    Ok(())
}

#[tokio::test]
async fn shell_exec_falls_back_without_session() -> Result<()> {
    let temp = TempDir::new()?;
    let volume_root = temp.path().join("vm-root");
    let vm_config = test_vm_pool_config(volume_root);
    let runtime_config = VmPoolRuntimeConfig::from(&vm_config);
    let vm_manager = MicroVmManager::new(runtime_config)?;

    let shell_runner = ShellExecRunner::new(Some(vm_manager));

    let workdir = temp.path().join("ephemeral-work");
    std::fs::create_dir_all(&workdir)?;

    let mut ctx = create_exec_context(
        &workdir,
        default_limits(),
        Scope {
            paths: vec![workdir.to_string_lossy().to_string()],
            urls: vec![],
        },
        "fallback-test".to_string(),
    );
    ctx.session = None;

    let mut sink = MemoryOutputSink::new();
    let params = json!({
        "command": "pwd",
        "timeout_ms": 2000,
    });
    shell_runner.execute(&ctx, params, &mut sink).await?;
    let stdout = String::from_utf8(sink.stdout.clone()).unwrap();

    assert_eq!(
        stdout.trim(),
        workdir.to_string_lossy(),
        "expected fallback execution in host workdir"
    );

    Ok(())
}

#[tokio::test]
async fn micro_vm_idle_shutdown_and_prune() -> Result<()> {
    let temp = TempDir::new()?;
    let volume_root = temp.path().join("vm-root");
    let mut vm_config = test_vm_pool_config(volume_root.clone());
    vm_config.idle_shutdown_seconds = 1;
    vm_config.prune_after_seconds = 2;

    let runtime_config = VmPoolRuntimeConfig::from(&vm_config);
    let vm_manager = MicroVmManager::new(runtime_config)?;
    let shell_runner = ShellExecRunner::new(Some(vm_manager.clone()));

    let session_id = Uuid::new_v4();
    let workdir = temp.path().join("workdir");
    std::fs::create_dir_all(&workdir)?;

    let mut ctx = create_exec_context(
        &workdir,
        default_limits(),
        Scope {
            paths: vec![workdir.to_string_lossy().to_string()],
            urls: vec![],
        },
        "maintenance-test".to_string(),
    );
    ctx.session = Some(SessionContext {
        session_id,
        domain: Some("maintenance".into()),
        vm_profile: None,
    });

    // Touch the VM to ensure it exists.
    let mut sink = MemoryOutputSink::new();
    let params = json!({ "command": "pwd", "timeout_ms": 2000 });
    shell_runner.execute(&ctx, params, &mut sink).await?;

    let vm_volume = volume_root.join(session_id.to_string());
    assert!(vm_volume.exists());

    sleep(Duration::from_millis(1_200)).await;
    vm_manager.run_maintenance_now().await?;
    assert!(
        vm_volume.exists(),
        "VM should still exist after idle shutdown"
    );

    sleep(Duration::from_millis(2_500)).await;
    vm_manager.run_maintenance_now().await?;
    assert!(
        !vm_volume.exists(),
        "VM volume should be pruned after exceeding prune_after_seconds"
    );

    Ok(())
}
