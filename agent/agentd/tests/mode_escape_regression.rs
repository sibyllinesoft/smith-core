//! Mode escape regression tests
//!
//! These tests verify that security behavior differs by mode only where expected,
//! and that insecure bypasses require explicit opt-in.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Mutex;

use agentd::capabilities::shell_exec_v1::ShellExecV1Capability;
use agentd::capability::{Capability, ExecCtx, ExecutionScope, SandboxConfig};
use agentd::config::{load_config, AgentdConfig, Config, IsolationBackendType};
use agentd::policy::PolicyEngine;
use once_cell::sync::Lazy;
use serde_json::json;
use smith_protocol::{Capability as ProtoCapability, Intent, SandboxMode};
use tempfile::NamedTempFile;

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn make_shell_intent(params: serde_json::Value) -> Intent {
    Intent::new(
        ProtoCapability::ShellExec,
        "mode-regression".to_string(),
        params,
        30_000,
        "tester".to_string(),
    )
}

fn make_exec_ctx(mode: SandboxMode) -> ExecCtx {
    ExecCtx {
        workdir: std::env::temp_dir(),
        limits: smith_protocol::ExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "mode-escape-regression".to_string(),
        sandbox: SandboxConfig {
            mode,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    }
}

#[test]
fn test_profile_backend_matrix_defaults() {
    assert_eq!(
        AgentdConfig::workstation().isolation.default_backend,
        IsolationBackendType::HostDirect
    );
    assert_eq!(
        AgentdConfig::server().isolation.default_backend,
        IsolationBackendType::LinuxNative
    );
    assert_eq!(
        AgentdConfig::paranoid().isolation.default_backend,
        IsolationBackendType::LinuxNative
    );
}

#[tokio::test]
async fn test_shell_exec_absolute_cwd_blocked_only_in_full_mode() {
    let capability = ShellExecV1Capability::new();

    let cases = vec![
        (SandboxMode::Full, true),
        (SandboxMode::Demo, false),
        (SandboxMode::Unsafe, false),
    ];

    for (mode, should_block) in cases {
        let intent = make_shell_intent(json!({
            "command": "echo",
            "args": ["ok"],
            "cwd": "/tmp"
        }));
        let result = capability
            .execute(intent, make_exec_ctx(mode.clone()))
            .await;

        if should_block {
            assert!(result.is_err(), "mode {:?} should block absolute cwd", mode);
            let err = result.unwrap_err();
            assert_eq!(err.code, "INVALID_CWD");
        } else {
            assert!(result.is_ok(), "mode {:?} should allow absolute cwd", mode);
        }
    }
}

#[tokio::test]
async fn test_shell_exec_blocked_env_key_blocked_only_in_full_mode() {
    let capability = ShellExecV1Capability::new();

    let cases = vec![
        (SandboxMode::Full, true),
        (SandboxMode::Demo, false),
        (SandboxMode::Unsafe, false),
    ];

    for (mode, should_block) in cases {
        let intent = make_shell_intent(json!({
            "command": "echo",
            "args": ["ok"],
            "env": {"ENV": "evil"}
        }));
        let result = capability
            .execute(intent, make_exec_ctx(mode.clone()))
            .await;

        if should_block {
            assert!(
                result.is_err(),
                "mode {:?} should block env injection",
                mode
            );
            let err = result.unwrap_err();
            assert_eq!(err.code, "INVALID_ENV");
        } else {
            assert!(result.is_ok(), "mode {:?} should allow this env key", mode);
        }
    }
}

#[tokio::test]
async fn test_shell_exec_host_env_leak_prevented_in_full_and_demo() {
    let _guard = ENV_LOCK.lock().unwrap();
    let env_key = "AGENTD_MODE_ESCAPE_REGRESSION_SECRET";
    let env_value = "super_secret_value";
    std::env::set_var(env_key, env_value);

    let capability = ShellExecV1Capability::new();
    let intent = make_shell_intent(json!({
        "command": "/bin/sh",
        "args": ["-c", "printf \"%s\" \"$AGENTD_MODE_ESCAPE_REGRESSION_SECRET\""]
    }));

    let full_result = capability
        .execute(intent.clone(), make_exec_ctx(SandboxMode::Full))
        .await
        .unwrap();
    let demo_result = capability
        .execute(intent.clone(), make_exec_ctx(SandboxMode::Demo))
        .await
        .unwrap();
    let unsafe_result = capability
        .execute(intent, make_exec_ctx(SandboxMode::Unsafe))
        .await
        .unwrap();

    std::env::remove_var(env_key);

    let full_stdout = full_result.output.unwrap()["stdout"]
        .as_str()
        .unwrap()
        .to_string();
    let demo_stdout = demo_result.output.unwrap()["stdout"]
        .as_str()
        .unwrap()
        .to_string();
    let unsafe_stdout = unsafe_result.output.unwrap()["stdout"]
        .as_str()
        .unwrap()
        .to_string();

    assert!(full_stdout.is_empty(), "full mode leaked host env");
    assert!(demo_stdout.is_empty(), "demo mode leaked host env");
    assert_eq!(
        unsafe_stdout, env_value,
        "unsafe mode should preserve host env visibility"
    );
}

#[tokio::test]
async fn test_policy_disable_env_override_is_gated_by_enforcement_mode() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("SMITH_EXECUTOR_DISABLE_POLICY", "1");

    let mut enforcing_config = Config::testing();
    enforcing_config.executor.capabilities.enforcement_enabled = true;
    let enforcing_engine = PolicyEngine::new(&enforcing_config).unwrap();

    let permissive_config = Config::testing();
    let permissive_engine = PolicyEngine::new(&permissive_config).unwrap();

    let intent = make_shell_intent(json!({
        "command": "echo",
        "args": ["ok"]
    }));

    let enforcing_result = enforcing_engine.evaluate(&intent).await.unwrap();
    let permissive_result = permissive_engine.evaluate(&intent).await.unwrap();

    std::env::remove_var("SMITH_EXECUTOR_DISABLE_POLICY");

    assert_ne!(
        enforcing_result.policy_id.as_deref(),
        Some("policy.disabled.override")
    );
    assert_eq!(
        permissive_result.policy_id.as_deref(),
        Some("policy.disabled.override")
    );
}

#[test]
fn test_invalid_config_does_not_fallback_without_explicit_opt_in() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK");

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "not valid toml = [").unwrap();

    let result = load_config(file.path());
    assert!(result.is_err());

    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Failed to load config"));
    assert!(msg.contains("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK=1"));
}

#[test]
fn test_invalid_config_fallback_requires_explicit_opt_in() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK", "1");

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "not valid toml = [").unwrap();

    let result = load_config(file.path());
    std::env::remove_var("SMITH_EXECUTOR_ALLOW_INSECURE_FALLBACK");

    assert!(result.is_ok());
    let config = result.unwrap();
    assert!(!config.executor.capabilities.enforcement_enabled);
}
