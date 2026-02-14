/*!
 * Daemon command implementation
 *
 * Extracted from main.rs to reduce complexity and improve maintainability.
 * Handles the main executor daemon startup and worker management.
 */

use anyhow::{Context, Result};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::bootstrap::{setup_signal_handlers, validate_security_capabilities};
use crate::config::{self, Config};
use crate::{
    audit, health, idempotency, metrics, nats, policy, runners, schema, security,
    vm::{MicroVmManager, VmPoolRuntimeConfig},
};
use smith_config::PolicyDerivations;

#[cfg(feature = "grpc")]
use crate::adapters::GrpcAdapter;
#[cfg(feature = "grpc")]
use crate::core::ingest::{
    CapabilityInfo, HealthStatus, IngestAdapter, IntentHandler, OutputChunk, RequestContext,
};
#[cfg(feature = "grpc")]
use crate::core::intent::Command;
#[cfg(feature = "grpc")]
use crate::core::intent::{
    ExecutionResult, IntentRequest, IntentResponse, IntentStatus, ResponseTiming,
};
#[cfg(feature = "grpc")]
use crate::core::isolation::{
    ExecContext as SandboxExecContext, ResourceLimits, SandboxSpec, StreamOutput,
};
#[cfg(feature = "grpc")]
use crate::core::sandbox::{
    DefaultSandboxManager, SandboxManager, SandboxManagerConfig, SandboxSelectionOptions,
};
#[cfg(feature = "grpc")]
use crate::desktop::compositor;
#[cfg(feature = "grpc")]
use crate::desktop::types::{UiBounds, UiWindowRecord};
#[cfg(feature = "grpc")]
use crate::isolation;
#[cfg(feature = "grpc")]
use async_trait::async_trait;
#[cfg(feature = "grpc")]
use once_cell::sync::Lazy;
#[cfg(feature = "grpc")]
use regex::Regex;
#[cfg(feature = "grpc")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "grpc")]
use std::net::SocketAddr;
#[cfg(feature = "grpc")]
use std::time::Duration;
#[cfg(feature = "grpc")]
use tokio::process::Command as TokioCommand;

/// Intent handler for gRPC adapter that uses the sandbox manager for isolation
#[cfg(feature = "grpc")]
struct DaemonIntentHandler {
    sandbox_manager: Arc<dyn SandboxManager>,
    config: Config,
    isolation_backend: String,
}

/// Parameters for shell.exec.v1 capability (matches pi-mono client format)
#[cfg(feature = "grpc")]
#[derive(Debug, serde::Deserialize)]
struct ShellExecParams {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: Option<HashMap<String, String>>,
}

/// Parameters for accessibility.query.v1 capability.
///
/// This capability performs read-only D-Bus queries against AT-SPI interfaces.
#[cfg(feature = "grpc")]
#[derive(Debug, serde::Deserialize)]
struct AccessibilityQueryParams {
    /// D-Bus destination (service name)
    #[serde(default = "default_a11y_destination")]
    destination: String,
    /// Object path to query
    #[serde(default = "default_a11y_object_path")]
    object_path: String,
    /// D-Bus interface
    #[serde(default = "default_a11y_interface")]
    interface: String,
    /// D-Bus method (read-only allowlist)
    #[serde(default = "default_a11y_method")]
    method: String,
    /// Optional D-Bus call arguments as `gdbus` literals
    #[serde(default)]
    args: Vec<String>,
    /// Optional explicit D-Bus address; if omitted, use session bus
    #[serde(default)]
    dbus_address: Option<String>,
    /// Timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    /// Optional relative working directory
    #[serde(default)]
    cwd: Option<String>,
    /// Optional environment overrides (desktop/session-only keys)
    #[serde(default)]
    env: Option<HashMap<String, String>>,
}

/// Parameters for screenshot.capture.v1 capability.
///
/// Region mode accepts bounds that may come directly from accessibility tree
/// extents (for example, AT-SPI Component.GetExtents).
#[cfg(feature = "grpc")]
#[derive(Debug, serde::Deserialize)]
struct ScreenshotCaptureParams {
    /// Capture mode: "full" or "region"
    #[serde(default = "default_screenshot_mode")]
    mode: String,
    /// Capture rectangle for region mode
    #[serde(default, alias = "bounds")]
    rect: Option<ScreenshotRect>,
    /// Optional normalized target selector.
    #[serde(default)]
    target: Option<ScreenshotTarget>,
    /// Timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    /// Optional relative working directory
    #[serde(default)]
    cwd: Option<String>,
    /// Optional environment overrides (desktop/session-only keys)
    #[serde(default)]
    env: Option<HashMap<String, String>>,
}

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, serde::Deserialize)]
struct ScreenshotTarget {
    /// full | rect | window | node
    kind: String,
    #[serde(default)]
    window_id: Option<String>,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default, alias = "bounds")]
    rect: Option<ScreenshotRect>,
}

#[cfg(feature = "grpc")]
#[derive(Debug, serde::Deserialize)]
struct UiWindowsListParams {
    #[serde(default = "default_windows_limit")]
    limit: u32,
    #[serde(default = "default_true")]
    include_titles: bool,
    #[serde(default = "default_true")]
    include_roles: bool,
    #[serde(default = "default_false")]
    include_bounds: bool,
    #[serde(default = "compositor::default_backend_name")]
    compositor_backend: String,
    #[serde(default)]
    dbus_address: Option<String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default)]
    env: Option<HashMap<String, String>>,
}

#[cfg(feature = "grpc")]
#[derive(Debug, serde::Deserialize)]
struct UiNodeInspectParams {
    node_id: String,
    #[serde(default = "default_true")]
    include_name: bool,
    #[serde(default = "default_true")]
    include_role: bool,
    #[serde(default = "default_true")]
    include_children: bool,
    #[serde(default = "default_false")]
    include_interfaces: bool,
    #[serde(default = "default_false")]
    include_bounds: bool,
    #[serde(default = "default_children_limit")]
    child_limit: u32,
    #[serde(default)]
    dbus_address: Option<String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default)]
    env: Option<HashMap<String, String>>,
}

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, serde::Serialize)]
struct UiNodeRef {
    node_id: String,
    destination: String,
    object_path: String,
}

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, Copy, serde::Deserialize)]
struct ScreenshotRect {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, Copy)]
enum ScreenshotBackend {
    Grim,
    ImageMagickImport,
}

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, Copy)]
enum ResponseOutputMode {
    Text,
    BinaryStdout,
}

#[cfg(feature = "grpc")]
struct ExecutionPlan {
    cmd: Command,
    exec_ctx: SandboxExecContext,
    output_mode: ResponseOutputMode,
}

#[cfg(feature = "grpc")]
const BLOCKED_ENV_KEYS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
];

#[cfg(feature = "grpc")]
const DESKTOP_BASE_ENV_KEYS: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XAUTHORITY",
];

#[cfg(feature = "grpc")]
const ACCESSIBILITY_READONLY_METHODS: &[&str] = &[
    "GetAddress",
    "GetChildren",
    "GetName",
    "GetDescription",
    "GetRole",
    "GetRoleName",
    "GetLocalizedRoleName",
    "GetState",
    "GetAttributes",
    "GetInterfaces",
    "GetParent",
    "GetIndexInParent",
    "GetExtents",
    "GetPosition",
    "GetSize",
    "Contains",
    "Introspect",
];

#[cfg(feature = "grpc")]
const fn default_timeout_ms() -> u64 {
    30_000
}

#[cfg(feature = "grpc")]
fn default_a11y_destination() -> String {
    "org.a11y.atspi.Registry".to_string()
}

#[cfg(feature = "grpc")]
fn default_a11y_object_path() -> String {
    "/org/a11y/atspi/accessible/root".to_string()
}

#[cfg(feature = "grpc")]
fn default_a11y_interface() -> String {
    "org.a11y.atspi.Accessible".to_string()
}

#[cfg(feature = "grpc")]
fn default_a11y_method() -> String {
    "GetChildren".to_string()
}

#[cfg(feature = "grpc")]
fn default_screenshot_mode() -> String {
    "full".to_string()
}

#[cfg(feature = "grpc")]
const fn default_windows_limit() -> u32 {
    50
}

#[cfg(feature = "grpc")]
const fn default_children_limit() -> u32 {
    200
}

#[cfg(feature = "grpc")]
const fn default_true() -> bool {
    true
}

#[cfg(feature = "grpc")]
const fn default_false() -> bool {
    false
}

#[cfg(feature = "grpc")]
fn parse_shell_exec_params(raw: &serde_json::Value) -> Result<ShellExecParams> {
    let params: ShellExecParams =
        serde_json::from_value(raw.clone()).context("Failed to parse shell.exec parameters")?;

    if params.command.trim().is_empty() {
        anyhow::bail!("shell.exec command must not be empty");
    }
    if params.command.len() > 4096 {
        anyhow::bail!("shell.exec command exceeds 4096 characters");
    }
    if params.timeout_ms == 0 || params.timeout_ms > 600_000 {
        anyhow::bail!("shell.exec timeout_ms must be between 1 and 600000");
    }

    if let Some(cwd) = &params.cwd {
        validate_relative_subpath(cwd)?;
    }

    if params.args.iter().any(|arg| arg.len() > 4096) {
        anyhow::bail!("shell.exec args must be <= 4096 characters each");
    }

    if let Some(env) = &params.env {
        validate_env_map(env, false)?;
    }

    Ok(params)
}

#[cfg(feature = "grpc")]
fn parse_accessibility_query_params(raw: &serde_json::Value) -> Result<AccessibilityQueryParams> {
    let params: AccessibilityQueryParams = serde_json::from_value(raw.clone())
        .context("Failed to parse accessibility.query parameters")?;

    validate_non_empty_limited(
        "destination",
        &params.destination,
        256,
        "accessibility.query destination must not be empty",
    )?;
    validate_non_empty_limited(
        "object_path",
        &params.object_path,
        512,
        "accessibility.query object_path must not be empty",
    )?;
    validate_non_empty_limited(
        "interface",
        &params.interface,
        256,
        "accessibility.query interface must not be empty",
    )?;
    validate_non_empty_limited(
        "method",
        &params.method,
        128,
        "accessibility.query method must not be empty",
    )?;

    validate_dbus_destination(&params.destination)?;
    validate_dbus_object_path(&params.object_path)?;
    validate_dbus_interface(&params.interface)?;
    validate_a11y_method(&params.method)?;

    if params.args.len() > 16 {
        anyhow::bail!("accessibility.query supports at most 16 method arguments");
    }
    if params.args.iter().any(|arg| arg.len() > 1024) {
        anyhow::bail!("accessibility.query method arguments must be <= 1024 chars each");
    }

    if let Some(address) = params.dbus_address.as_deref() {
        if address.len() > 1024 {
            anyhow::bail!("accessibility.query dbus_address exceeds 1024 characters");
        }
        if !(address.starts_with("unix:") || address.starts_with("tcp:")) {
            anyhow::bail!("accessibility.query dbus_address must start with unix: or tcp:");
        }
    }

    if params.timeout_ms == 0 || params.timeout_ms > 120_000 {
        anyhow::bail!("accessibility.query timeout_ms must be between 1 and 120000");
    }

    if let Some(cwd) = &params.cwd {
        validate_relative_subpath(cwd)?;
    }

    if let Some(env) = &params.env {
        validate_env_map(env, true)?;
    }

    Ok(params)
}

#[cfg(feature = "grpc")]
fn parse_screenshot_capture_params(raw: &serde_json::Value) -> Result<ScreenshotCaptureParams> {
    let params: ScreenshotCaptureParams =
        serde_json::from_value(raw.clone()).context("Failed to parse screenshot.capture params")?;

    match params.mode.as_str() {
        "full" | "region" => {}
        _ => anyhow::bail!("screenshot.capture mode must be 'full' or 'region'"),
    }

    if params.timeout_ms == 0 || params.timeout_ms > 120_000 {
        anyhow::bail!("screenshot.capture timeout_ms must be between 1 and 120000");
    }

    if let Some(cwd) = &params.cwd {
        validate_relative_subpath(cwd)?;
    }

    if let Some(env) = &params.env {
        validate_env_map(env, true)?;
    }

    let effective_rect = params
        .target
        .as_ref()
        .and_then(|target| target.rect)
        .or(params.rect);

    if let Some(target) = params.target.as_ref() {
        match target.kind.as_str() {
            "full" => {
                if effective_rect.is_some() {
                    anyhow::bail!("screenshot.capture target.kind=full does not accept rect");
                }
            }
            "rect" => {
                let Some(rect) = effective_rect else {
                    anyhow::bail!("screenshot.capture target.kind=rect requires rect");
                };
                validate_screenshot_rect(rect)?;
            }
            "node" => {
                if target.node_id.as_deref().unwrap_or_default().is_empty() {
                    anyhow::bail!("screenshot.capture target.kind=node requires node_id");
                }
                let Some(rect) = effective_rect else {
                    anyhow::bail!(
                        "screenshot.capture target.kind=node currently requires rect from ui.node.inspect.v1 bounds"
                    );
                };
                validate_screenshot_rect(rect)?;
            }
            "window" => {
                if target.window_id.as_deref().unwrap_or_default().is_empty() {
                    anyhow::bail!("screenshot.capture target.kind=window requires window_id");
                }
                let Some(rect) = effective_rect else {
                    anyhow::bail!(
                        "screenshot.capture target.kind=window currently requires rect from ui.node.inspect.v1 or ui.windows.list.v1 bounds"
                    );
                };
                validate_screenshot_rect(rect)?;
            }
            _ => anyhow::bail!(
                "screenshot.capture target.kind must be one of: full, rect, node, window"
            ),
        }
    } else {
        match params.mode.as_str() {
            "full" => {
                if params.rect.is_some() {
                    anyhow::bail!("screenshot.capture rect is only valid for mode=region");
                }
            }
            "region" => {
                let Some(rect) = params.rect else {
                    anyhow::bail!("screenshot.capture mode=region requires rect");
                };
                validate_screenshot_rect(rect)?;
            }
            _ => unreachable!("mode validated above"),
        }
    }

    Ok(params)
}

#[cfg(feature = "grpc")]
fn validate_screenshot_rect(rect: ScreenshotRect) -> Result<()> {
    if rect.width == 0 || rect.height == 0 {
        anyhow::bail!("screenshot.capture rect width and height must be > 0");
    }
    if rect.width > 16_384 || rect.height > 16_384 {
        anyhow::bail!("screenshot.capture rect width/height must be <= 16384");
    }
    if rect.x < -16_384 || rect.y < -16_384 || rect.x > 65_535 || rect.y > 65_535 {
        anyhow::bail!("screenshot.capture rect coordinates are out of allowed bounds");
    }
    Ok(())
}

#[cfg(feature = "grpc")]
fn validate_env_map(env: &HashMap<String, String>, desktop_only: bool) -> Result<()> {
    for (key, value) in env {
        if !is_valid_env_key(key) {
            anyhow::bail!("Invalid environment variable name: {}", key);
        }
        if BLOCKED_ENV_KEYS
            .iter()
            .any(|blocked| key.eq_ignore_ascii_case(blocked))
        {
            anyhow::bail!("Environment variable '{}' is not allowed", key);
        }
        if desktop_only && !is_desktop_env_key(key) {
            anyhow::bail!(
                "Environment variable '{}' is not allowed for desktop capabilities",
                key
            );
        }
        if value.len() > 8192 {
            anyhow::bail!("Environment variable '{}' value exceeds 8192 chars", key);
        }
    }
    Ok(())
}

#[cfg(feature = "grpc")]
fn is_desktop_env_key(key: &str) -> bool {
    DESKTOP_BASE_ENV_KEYS.contains(&key)
        || compositor::COMPOSITOR_ENV_KEYS.contains(&key)
        || key.starts_with("GTK_")
        || key.starts_with("QT_")
        || key.starts_with("GDK_")
}

#[cfg(feature = "grpc")]
fn validate_non_empty_limited(
    field: &str,
    value: &str,
    max_len: usize,
    empty_message: &str,
) -> Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{}", empty_message);
    }
    if value.len() > max_len {
        anyhow::bail!("{} exceeds {} characters", field, max_len);
    }
    Ok(())
}

#[cfg(feature = "grpc")]
fn is_valid_dbus_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' || c == ':'
}

#[cfg(feature = "grpc")]
fn validate_dbus_destination(destination: &str) -> Result<()> {
    if !destination.chars().all(is_valid_dbus_name_char) {
        anyhow::bail!("accessibility.query destination contains invalid characters");
    }

    let is_org_name = destination.starts_with("org.a11y.");
    let is_unique_name = destination.starts_with(':');
    if !(is_org_name || is_unique_name) {
        anyhow::bail!("accessibility.query destination must target org.a11y.* or a unique name");
    }

    Ok(())
}

#[cfg(feature = "grpc")]
fn validate_dbus_object_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        anyhow::bail!("accessibility.query object_path must start with '/'");
    }
    if path.contains("..") {
        anyhow::bail!("accessibility.query object_path must not contain '..'");
    }
    if !path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '/')
    {
        anyhow::bail!("accessibility.query object_path contains invalid characters");
    }
    Ok(())
}

#[cfg(feature = "grpc")]
fn validate_dbus_interface(interface: &str) -> Result<()> {
    let valid = interface == "org.freedesktop.DBus.Introspectable"
        || interface.starts_with("org.a11y.")
        || interface.starts_with("org.a11y.atspi.");
    if !valid {
        anyhow::bail!("accessibility.query interface must target org.a11y.*");
    }
    if !interface
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        anyhow::bail!("accessibility.query interface contains invalid characters");
    }
    Ok(())
}

#[cfg(feature = "grpc")]
fn validate_a11y_method(method: &str) -> Result<()> {
    if !method
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        anyhow::bail!("accessibility.query method contains invalid characters");
    }

    if !ACCESSIBILITY_READONLY_METHODS.contains(&method) {
        anyhow::bail!(
            "accessibility.query method '{}' is not in the read-only allowlist",
            method
        );
    }
    Ok(())
}

#[cfg(feature = "grpc")]
fn enforce_desktop_backend(capability: &str, backend: &str) -> Result<()> {
    if is_host_direct_backend(backend) {
        return Ok(());
    }

    anyhow::bail!(
        "{} requires host-direct backend with access to user desktop session (got backend '{}')",
        capability,
        backend
    );
}

#[cfg(feature = "grpc")]
fn collect_desktop_env(overrides: Option<&HashMap<String, String>>) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/bin:/bin:/usr/local/bin".to_string(),
    );

    for key in DESKTOP_BASE_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            env.insert((*key).to_string(), value);
        }
    }
    for key in compositor::COMPOSITOR_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            env.insert((*key).to_string(), value);
        }
    }

    if let Some(extra) = overrides {
        env.extend(extra.clone());
    }

    env
}

#[cfg(feature = "grpc")]
fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = dir.join(name);
                candidate.is_file()
            })
        })
        .unwrap_or(false)
}

#[cfg(feature = "grpc")]
fn select_screenshot_backend() -> Result<ScreenshotBackend> {
    if command_exists("grim") {
        return Ok(ScreenshotBackend::Grim);
    }
    if command_exists("import") {
        return Ok(ScreenshotBackend::ImageMagickImport);
    }

    anyhow::bail!(
        "screenshot.capture requires either 'grim' (Wayland) or 'import' (ImageMagick/X11) installed"
    )
}

#[cfg(feature = "grpc")]
fn build_execution_plan(
    request: &IntentRequest,
    request_id: &str,
    backend: &str,
    stream_output: bool,
) -> Result<ExecutionPlan> {
    match request.capability.as_str() {
        "shell.exec.v1" => {
            let params = parse_shell_exec_params(&request.params)?;
            let workdir_path = params.cwd.as_ref().map(std::path::PathBuf::from);
            let env = params.env.clone().unwrap_or_default();

            let cmd = Command {
                program: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), params.command.clone()],
                workdir: workdir_path.clone(),
                env: env.clone(),
                inherit_env: false,
                stdin: None,
                timeout: Some(Duration::from_millis(params.timeout_ms)),
            };

            let exec_ctx = SandboxExecContext {
                trace_id: request_id.to_string(),
                request_id: request_id.to_string(),
                workdir: workdir_path,
                extra_env: env.into_iter().collect(),
                timeout: Some(Duration::from_millis(params.timeout_ms)),
                capture_stdout: true,
                capture_stderr: true,
                stream_output,
            };

            Ok(ExecutionPlan {
                cmd,
                exec_ctx,
                output_mode: ResponseOutputMode::Text,
            })
        }
        "accessibility.query.v1" | "ui.accessibility.query.v1" => {
            enforce_desktop_backend("accessibility.query.v1", backend)?;
            if !command_exists("gdbus") {
                anyhow::bail!("accessibility.query requires 'gdbus' installed on host");
            }
            let params = parse_accessibility_query_params(&request.params)?;
            let workdir_path = params.cwd.as_ref().map(std::path::PathBuf::from);
            let env = collect_desktop_env(params.env.as_ref());

            let mut args = vec!["call".to_string()];
            if let Some(address) = params.dbus_address {
                args.push("--address".to_string());
                args.push(address);
            } else {
                args.push("--session".to_string());
            }
            args.push("--dest".to_string());
            args.push(params.destination.clone());
            args.push("--object-path".to_string());
            args.push(params.object_path.clone());
            args.push("--method".to_string());
            args.push(format!("{}.{}", params.interface, params.method));
            args.extend(params.args.clone());

            let cmd = Command {
                program: "gdbus".to_string(),
                args,
                workdir: workdir_path.clone(),
                env: env.clone(),
                inherit_env: false,
                stdin: None,
                timeout: Some(Duration::from_millis(params.timeout_ms)),
            };

            let exec_ctx = SandboxExecContext {
                trace_id: request_id.to_string(),
                request_id: request_id.to_string(),
                workdir: workdir_path,
                extra_env: env.into_iter().collect(),
                timeout: Some(Duration::from_millis(params.timeout_ms)),
                capture_stdout: true,
                capture_stderr: true,
                stream_output: false,
            };

            Ok(ExecutionPlan {
                cmd,
                exec_ctx,
                output_mode: ResponseOutputMode::Text,
            })
        }
        "screenshot.capture.v1" | "ui.screenshot.v1" => {
            enforce_desktop_backend("screenshot.capture.v1", backend)?;
            let params = parse_screenshot_capture_params(&request.params)?;
            let backend = select_screenshot_backend()?;
            let workdir_path = params.cwd.as_ref().map(std::path::PathBuf::from);
            let env = collect_desktop_env(params.env.as_ref());

            let effective_rect = params
                .target
                .as_ref()
                .and_then(|target| target.rect)
                .or(params.rect);
            let use_region = if let Some(target) = params.target.as_ref() {
                !matches!(target.kind.as_str(), "full")
            } else {
                params.mode == "region"
            };

            let (program, args) = match backend {
                ScreenshotBackend::Grim => {
                    let mut args = Vec::new();
                    if use_region {
                        let rect = effective_rect.expect("validated region rect");
                        args.push("-g".to_string());
                        args.push(format!(
                            "{},{} {}x{}",
                            rect.x, rect.y, rect.width, rect.height
                        ));
                    }
                    args.push("-".to_string());
                    ("grim".to_string(), args)
                }
                ScreenshotBackend::ImageMagickImport => {
                    let mut args = vec!["-window".to_string(), "root".to_string()];
                    if use_region {
                        let rect = effective_rect.expect("validated region rect");
                        if rect.x < 0 || rect.y < 0 {
                            anyhow::bail!(
                                "screenshot.capture with import backend requires non-negative region coordinates"
                            );
                        }
                        args.push("-crop".to_string());
                        args.push(format!(
                            "{}x{}+{}+{}",
                            rect.width, rect.height, rect.x, rect.y
                        ));
                    }
                    args.push("png:-".to_string());
                    ("import".to_string(), args)
                }
            };

            let cmd = Command {
                program,
                args,
                workdir: workdir_path.clone(),
                env: env.clone(),
                inherit_env: false,
                stdin: None,
                timeout: Some(Duration::from_millis(params.timeout_ms)),
            };

            let exec_ctx = SandboxExecContext {
                trace_id: request_id.to_string(),
                request_id: request_id.to_string(),
                workdir: workdir_path,
                extra_env: env.into_iter().collect(),
                timeout: Some(Duration::from_millis(params.timeout_ms)),
                capture_stdout: true,
                capture_stderr: true,
                stream_output: false,
            };

            Ok(ExecutionPlan {
                cmd,
                exec_ctx,
                output_mode: ResponseOutputMode::BinaryStdout,
            })
        }
        unsupported => anyhow::bail!("Unsupported capability '{}'", unsupported),
    }
}

#[cfg(feature = "grpc")]
fn parse_ui_windows_list_params(raw: &serde_json::Value) -> Result<UiWindowsListParams> {
    let params: UiWindowsListParams =
        serde_json::from_value(raw.clone()).context("Failed to parse ui.windows.list params")?;

    if params.limit == 0 || params.limit > 500 {
        anyhow::bail!("ui.windows.list limit must be between 1 and 500");
    }
    if params.timeout_ms == 0 || params.timeout_ms > 120_000 {
        anyhow::bail!("ui.windows.list timeout_ms must be between 1 and 120000");
    }
    if let Some(address) = params.dbus_address.as_deref() {
        if address.len() > 1024 {
            anyhow::bail!("ui.windows.list dbus_address exceeds 1024 characters");
        }
        if !(address.starts_with("unix:") || address.starts_with("tcp:")) {
            anyhow::bail!("ui.windows.list dbus_address must start with unix: or tcp:");
        }
    }
    if let Some(env) = params.env.as_ref() {
        validate_env_map(env, true)?;
    }
    compositor::parse_backend_mode(&params.compositor_backend)?;

    Ok(params)
}

#[cfg(feature = "grpc")]
fn parse_ui_node_inspect_params(raw: &serde_json::Value) -> Result<UiNodeInspectParams> {
    let params: UiNodeInspectParams =
        serde_json::from_value(raw.clone()).context("Failed to parse ui.node.inspect params")?;

    if params.timeout_ms == 0 || params.timeout_ms > 120_000 {
        anyhow::bail!("ui.node.inspect timeout_ms must be between 1 and 120000");
    }
    if params.child_limit == 0 || params.child_limit > 1000 {
        anyhow::bail!("ui.node.inspect child_limit must be between 1 and 1000");
    }
    let (destination, object_path) = decode_node_id(&params.node_id)?;
    validate_dbus_destination(&destination)?;
    validate_dbus_object_path(&object_path)?;

    if let Some(address) = params.dbus_address.as_deref() {
        if address.len() > 1024 {
            anyhow::bail!("ui.node.inspect dbus_address exceeds 1024 characters");
        }
        if !(address.starts_with("unix:") || address.starts_with("tcp:")) {
            anyhow::bail!("ui.node.inspect dbus_address must start with unix: or tcp:");
        }
    }
    if let Some(env) = params.env.as_ref() {
        validate_env_map(env, true)?;
    }

    Ok(params)
}

#[cfg(feature = "grpc")]
fn encode_node_id(destination: &str, object_path: &str) -> String {
    format!("{}|{}", destination, object_path)
}

#[cfg(feature = "grpc")]
fn decode_node_id(node_id: &str) -> Result<(String, String)> {
    let Some((destination, object_path)) = node_id.split_once('|') else {
        anyhow::bail!(
            "node_id must be in '<destination>|<object_path>' format, got '{}'",
            node_id
        );
    };
    if destination.is_empty() || object_path.is_empty() {
        anyhow::bail!("node_id must include both destination and object_path");
    }
    Ok((destination.to_string(), object_path.to_string()))
}

#[cfg(feature = "grpc")]
static DBUS_REF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\(\s*'([^']+)'\s*,\s*(?:objectpath\s+)?'(/[^']*)'\s*\)")
        .expect("dbus ref regex must compile")
});

#[cfg(feature = "grpc")]
static QUOTED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"'([^']*)'").expect("quoted regex must compile"));

#[cfg(feature = "grpc")]
static INTEGER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"-?\d+").expect("integer regex must compile"));

#[cfg(feature = "grpc")]
fn parse_gdbus_refs(raw: &str) -> Vec<UiNodeRef> {
    DBUS_REF_RE
        .captures_iter(raw)
        .filter_map(|capture| {
            let destination = capture.get(1)?.as_str().to_string();
            let object_path = capture.get(2)?.as_str().to_string();
            Some(UiNodeRef {
                node_id: encode_node_id(&destination, &object_path),
                destination,
                object_path,
            })
        })
        .collect()
}

#[cfg(feature = "grpc")]
fn parse_first_quoted(raw: &str) -> Option<String> {
    QUOTED_RE
        .captures(raw)
        .and_then(|capture| capture.get(1).map(|m| m.as_str().to_string()))
}

#[cfg(feature = "grpc")]
fn parse_quoted_strings(raw: &str) -> Vec<String> {
    QUOTED_RE
        .captures_iter(raw)
        .filter_map(|capture| capture.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

#[cfg(feature = "grpc")]
fn parse_bounds_from_output(raw: &str) -> Option<UiBounds> {
    let values: Vec<i64> = INTEGER_RE
        .find_iter(raw)
        .filter_map(|m| m.as_str().parse::<i64>().ok())
        .collect();
    if values.len() < 4 {
        return None;
    }
    let x = i32::try_from(values[0]).ok()?;
    let y = i32::try_from(values[1]).ok()?;
    let width = u32::try_from(values[2]).ok()?;
    let height = u32::try_from(values[3]).ok()?;
    Some(UiBounds {
        x,
        y,
        width,
        height,
    })
}

#[cfg(feature = "grpc")]
async fn run_host_command(
    program: &str,
    args: &[String],
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<(i32, String, String)> {
    let mut cmd = TokioCommand::new(program);
    cmd.args(args);
    cmd.env_clear();
    cmd.envs(env.clone());
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn command '{}'", program))?;
    let output = tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait_with_output())
        .await
        .with_context(|| format!("Command '{}' timed out after {}ms", program, timeout_ms))?
        .with_context(|| format!("Failed to wait for command '{}'", program))?;

    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

#[cfg(feature = "grpc")]
async fn run_gdbus_call(
    destination: &str,
    object_path: &str,
    method: &str,
    method_args: &[String],
    dbus_address: Option<&str>,
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<String> {
    let mut args = vec!["call".to_string()];
    if let Some(address) = dbus_address {
        args.push("--address".to_string());
        args.push(address.to_string());
    } else {
        args.push("--session".to_string());
    }
    args.push("--dest".to_string());
    args.push(destination.to_string());
    args.push("--object-path".to_string());
    args.push(object_path.to_string());
    args.push("--method".to_string());
    args.push(method.to_string());
    args.extend(method_args.iter().cloned());

    let (exit_code, stdout, stderr) = run_host_command("gdbus", &args, env, timeout_ms).await?;
    if exit_code != 0 {
        anyhow::bail!(
            "gdbus call failed (exit={}): method={} dest={} path={} stderr={}",
            exit_code,
            method,
            destination,
            object_path,
            stderr.trim()
        );
    }
    Ok(stdout)
}

#[cfg(feature = "grpc")]
async fn try_gdbus_call(
    destination: &str,
    object_path: &str,
    method: &str,
    method_args: &[String],
    dbus_address: Option<&str>,
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Option<String> {
    match run_gdbus_call(
        destination,
        object_path,
        method,
        method_args,
        dbus_address,
        env,
        timeout_ms,
    )
    .await
    {
        Ok(output) => Some(output),
        Err(err) => {
            warn!(
                method,
                destination,
                object_path,
                error = %err,
                "Best-effort AT-SPI call failed"
            );
            None
        }
    }
}

#[cfg(feature = "grpc")]
fn normalize_accessible_text(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unnamed") {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(feature = "grpc")]
async fn get_dbus_property_string(
    destination: &str,
    object_path: &str,
    interface: &str,
    property: &str,
    dbus_address: Option<&str>,
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Option<String> {
    try_gdbus_call(
        destination,
        object_path,
        "org.freedesktop.DBus.Properties.Get",
        &[interface.to_string(), property.to_string()],
        dbus_address,
        env,
        timeout_ms,
    )
    .await
    .and_then(|out| parse_first_quoted(&out))
    .and_then(|value| normalize_accessible_text(Some(value)))
}

#[cfg(feature = "grpc")]
async fn get_accessible_name(
    destination: &str,
    object_path: &str,
    dbus_address: Option<&str>,
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Option<String> {
    let method_name = try_gdbus_call(
        destination,
        object_path,
        "org.a11y.atspi.Accessible.GetName",
        &[],
        dbus_address,
        env,
        timeout_ms,
    )
    .await
    .and_then(|out| parse_first_quoted(&out))
    .and_then(|value| normalize_accessible_text(Some(value)));

    if method_name.is_some() {
        return method_name;
    }

    get_dbus_property_string(
        destination,
        object_path,
        "org.a11y.atspi.Accessible",
        "Name",
        dbus_address,
        env,
        timeout_ms,
    )
    .await
}

#[cfg(feature = "grpc")]
async fn get_accessible_role(
    destination: &str,
    object_path: &str,
    dbus_address: Option<&str>,
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Option<String> {
    try_gdbus_call(
        destination,
        object_path,
        "org.a11y.atspi.Accessible.GetRoleName",
        &[],
        dbus_address,
        env,
        timeout_ms,
    )
    .await
    .and_then(|out| parse_first_quoted(&out))
    .and_then(|value| normalize_accessible_text(Some(value)))
}

#[cfg(feature = "grpc")]
async fn get_accessible_bounds(
    destination: &str,
    object_path: &str,
    dbus_address: Option<&str>,
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Option<UiBounds> {
    try_gdbus_call(
        destination,
        object_path,
        "org.a11y.atspi.Component.GetExtents",
        &["0".to_string()],
        dbus_address,
        env,
        timeout_ms,
    )
    .await
    .and_then(|out| parse_bounds_from_output(&out))
}

#[cfg(feature = "grpc")]
async fn get_accessible_children(
    destination: &str,
    object_path: &str,
    dbus_address: Option<&str>,
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Vec<UiNodeRef> {
    try_gdbus_call(
        destination,
        object_path,
        "org.a11y.atspi.Accessible.GetChildren",
        &[],
        dbus_address,
        env,
        timeout_ms,
    )
    .await
    .map(|out| parse_gdbus_refs(&out))
    .unwrap_or_default()
}

#[cfg(feature = "grpc")]
fn is_window_like_role(role: Option<&str>) -> bool {
    let Some(role) = role else {
        return false;
    };
    matches!(
        role.to_ascii_lowercase().as_str(),
        "window"
            | "frame"
            | "dialog"
            | "panel"
            | "alert"
            | "notification"
            | "terminal"
            | "tool tip"
            | "popup menu"
            | "menu"
    )
}

#[cfg(feature = "grpc")]
fn has_positive_bounds(bounds: Option<&UiBounds>) -> bool {
    bounds.map(|b| b.width > 0 && b.height > 0).unwrap_or(false)
}

#[cfg(feature = "grpc")]
fn should_include_window_candidate(
    role: Option<&str>,
    bounds: Option<&UiBounds>,
    title: Option<&str>,
) -> bool {
    is_window_like_role(role)
        || has_positive_bounds(bounds)
        || title.map(|t| !t.trim().is_empty()).unwrap_or(false)
}

#[cfg(feature = "grpc")]
async fn execute_ui_windows_list(params: UiWindowsListParams) -> Result<serde_json::Value> {
    if !command_exists("gdbus") {
        anyhow::bail!("ui.windows.list requires 'gdbus' installed on host");
    }

    let env = collect_desktop_env(params.env.as_ref());
    let dbus_address = params.dbus_address.as_deref();
    let raw_children = run_gdbus_call(
        "org.a11y.atspi.Registry",
        "/org/a11y/atspi/accessible/root",
        "org.a11y.atspi.Accessible.GetChildren",
        &[],
        dbus_address,
        &env,
        params.timeout_ms,
    )
    .await?;

    let app_roots = parse_gdbus_refs(&raw_children);
    let mut windows: Vec<UiWindowRecord> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    for app_root in app_roots {
        let app_id = get_dbus_property_string(
            &app_root.destination,
            &app_root.object_path,
            "org.a11y.atspi.Accessible",
            "AccessibleId",
            dbus_address,
            &env,
            params.timeout_ms,
        )
        .await;

        let child_nodes = get_accessible_children(
            &app_root.destination,
            &app_root.object_path,
            dbus_address,
            &env,
            params.timeout_ms,
        )
        .await;

        let candidates: Vec<(UiNodeRef, bool)> = if child_nodes.is_empty() {
            vec![(app_root.clone(), true)]
        } else {
            child_nodes
                .into_iter()
                .map(|node| (node, false))
                .collect::<Vec<_>>()
        };

        for (node, is_root_fallback) in candidates {
            if seen_ids.contains(&node.node_id) {
                continue;
            }

            let title = if params.include_titles {
                get_accessible_name(
                    &node.destination,
                    &node.object_path,
                    dbus_address,
                    &env,
                    params.timeout_ms,
                )
                .await
            } else {
                None
            };

            let role_for_filter = get_accessible_role(
                &node.destination,
                &node.object_path,
                dbus_address,
                &env,
                params.timeout_ms,
            )
            .await;
            let bounds_for_filter = get_accessible_bounds(
                &node.destination,
                &node.object_path,
                dbus_address,
                &env,
                params.timeout_ms,
            )
            .await;

            let include_candidate = if is_root_fallback {
                is_window_like_role(role_for_filter.as_deref())
                    || has_positive_bounds(bounds_for_filter.as_ref())
            } else {
                should_include_window_candidate(
                    role_for_filter.as_deref(),
                    bounds_for_filter.as_ref(),
                    title.as_deref(),
                )
            };
            if !include_candidate {
                continue;
            }

            seen_ids.insert(node.node_id.clone());
            windows.push(UiWindowRecord {
                window_id: node.node_id,
                destination: node.destination,
                object_path: node.object_path,
                title,
                role: if params.include_roles {
                    role_for_filter
                } else {
                    None
                },
                bounds: if params.include_bounds {
                    bounds_for_filter
                } else {
                    None
                },
                source: Some("atspi".to_string()),
                inspectable: Some(true),
                app_id: app_id.clone(),
                class_name: None,
                workspace: None,
            });
        }
    }

    let compositor_backends = compositor::resolve_backends(&params.compositor_backend, &env)?;
    if !compositor_backends.is_empty() {
        let compositor_windows =
            compositor::collect_windows(&compositor_backends, &env, params.timeout_ms).await;
        compositor::merge_windows(&mut windows, compositor_windows);
    }

    windows.truncate(params.limit as usize);
    let inspectable_count = windows
        .iter()
        .filter(|window| window.inspectable.unwrap_or(true))
        .count();
    let compositor_backends_applied = compositor::applied_backend_names(&compositor_backends);

    Ok(serde_json::json!({
        "windows": windows,
        "count": windows.len(),
        "inspectable_count": inspectable_count,
        "compositor_only_count": windows.len().saturating_sub(inspectable_count),
        "compositor_backends_applied": compositor_backends_applied,
    }))
}

#[cfg(feature = "grpc")]
async fn execute_ui_node_inspect(params: UiNodeInspectParams) -> Result<serde_json::Value> {
    if !command_exists("gdbus") {
        anyhow::bail!("ui.node.inspect requires 'gdbus' installed on host");
    }

    let env = collect_desktop_env(params.env.as_ref());
    let dbus_address = params.dbus_address.as_deref();
    let (destination, object_path) = decode_node_id(&params.node_id)?;

    let name = if params.include_name {
        try_gdbus_call(
            &destination,
            &object_path,
            "org.a11y.atspi.Accessible.GetName",
            &[],
            dbus_address,
            &env,
            params.timeout_ms,
        )
        .await
        .and_then(|out| parse_first_quoted(&out))
    } else {
        None
    };

    let role = if params.include_role {
        try_gdbus_call(
            &destination,
            &object_path,
            "org.a11y.atspi.Accessible.GetRoleName",
            &[],
            dbus_address,
            &env,
            params.timeout_ms,
        )
        .await
        .and_then(|out| parse_first_quoted(&out))
    } else {
        None
    };

    let children = if params.include_children {
        try_gdbus_call(
            &destination,
            &object_path,
            "org.a11y.atspi.Accessible.GetChildren",
            &[],
            dbus_address,
            &env,
            params.timeout_ms,
        )
        .await
        .map(|out| {
            parse_gdbus_refs(&out)
                .into_iter()
                .take(params.child_limit as usize)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
    } else {
        vec![]
    };

    let interfaces = if params.include_interfaces {
        try_gdbus_call(
            &destination,
            &object_path,
            "org.a11y.atspi.Accessible.GetInterfaces",
            &[],
            dbus_address,
            &env,
            params.timeout_ms,
        )
        .await
        .map(|out| parse_quoted_strings(&out))
        .unwrap_or_default()
    } else {
        vec![]
    };

    let bounds = if params.include_bounds {
        try_gdbus_call(
            &destination,
            &object_path,
            "org.a11y.atspi.Component.GetExtents",
            &["0".to_string()],
            dbus_address,
            &env,
            params.timeout_ms,
        )
        .await
        .and_then(|out| parse_bounds_from_output(&out))
    } else {
        None
    };

    Ok(serde_json::json!({
        "node": {
            "node_id": params.node_id,
            "destination": destination,
            "object_path": object_path,
            "name": name,
            "role": role,
            "bounds": bounds,
            "interfaces": interfaces,
            "children": children,
            "children_count": children.len()
        }
    }))
}

#[cfg(feature = "grpc")]
fn validate_relative_subpath(path: &str) -> Result<()> {
    let parsed = Path::new(path);
    if parsed.is_absolute() {
        anyhow::bail!("workdir must be relative to sandbox root");
    }

    for component in parsed.components() {
        if matches!(component, Component::ParentDir | Component::RootDir) {
            anyhow::bail!("workdir must not contain parent traversal");
        }
        #[cfg(windows)]
        if matches!(component, Component::Prefix(_)) {
            anyhow::bail!("workdir contains unsupported prefix component");
        }
    }

    Ok(())
}

#[cfg(feature = "grpc")]
fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }

    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Error response helper for missing sandbox
#[cfg(feature = "grpc")]
fn sandbox_required_error(request_id: &str, received_at_ms: u64) -> IntentResponse {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    IntentResponse {
        request_id: uuid::Uuid::parse_str(request_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
        status: IntentStatus::Error,
        code: "NO_SANDBOX_CONFIGURED".to_string(),
        message: "No sandbox is configured. The user needs to create a sandbox for you to use.".to_string(),
        result: None,
        error: Some(crate::core::intent::ErrorDetails {
            code: "NO_SANDBOX_CONFIGURED".to_string(),
            message: "No sandbox is available for execution. A sandbox must be configured by the user before commands can run.".to_string(),
            details: Some(serde_json::json!({
                "action_required": "user_configuration",
                "suggestion": "Ask the user to configure a sandbox environment, or check if sandbox setup was missed during session initialization."
            })),
            retryable: false,
            retry_after_ms: None,
        }),
        timing: ResponseTiming {
            received_at_ms,
            started_at_ms: now_ms,
            completed_at_ms: now_ms,
            queue_time_ms: 0,
            setup_time_ms: 0,
            exec_time_ms: 0,
            total_time_ms: now_ms.saturating_sub(received_at_ms),
        },
        sandbox_info: None,
    }
}

/// Error response for sandbox not found
#[cfg(feature = "grpc")]
fn sandbox_not_found_error(
    request_id: &str,
    sandbox_id: &str,
    received_at_ms: u64,
) -> IntentResponse {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    IntentResponse {
        request_id: uuid::Uuid::parse_str(request_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
        status: IntentStatus::Error,
        code: "SANDBOX_NOT_FOUND".to_string(),
        message: format!("Sandbox '{}' not found or has expired. Create a new sandbox using CreateSandbox RPC.", sandbox_id),
        result: None,
        error: Some(crate::core::intent::ErrorDetails {
            code: "SANDBOX_NOT_FOUND".to_string(),
            message: format!("The sandbox '{}' does not exist or has been terminated. Create a new sandbox first.", sandbox_id),
            details: Some(serde_json::json!({
                "sandbox_id": sandbox_id,
                "hint": "Call CreateSandbox RPC to create a new sandbox"
            })),
            retryable: false,
            retry_after_ms: None,
        }),
        timing: ResponseTiming {
            received_at_ms,
            started_at_ms: now_ms,
            completed_at_ms: now_ms,
            queue_time_ms: 0,
            setup_time_ms: 0,
            exec_time_ms: 0,
            total_time_ms: now_ms.saturating_sub(received_at_ms),
        },
        sandbox_info: None,
    }
}

#[cfg(feature = "grpc")]
impl DaemonIntentHandler {
    async fn handle_normalized_ui_capability(
        &self,
        request: IntentRequest,
        ctx: RequestContext,
    ) -> Result<IntentResponse> {
        let received_at = std::time::Instant::now();
        let received_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        enforce_desktop_backend(&request.capability, &self.isolation_backend)?;

        let started_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let output = match request.capability.as_str() {
            "ui.windows.list.v1" => {
                let params = parse_ui_windows_list_params(&request.params)?;
                execute_ui_windows_list(params).await?
            }
            "ui.node.inspect.v1" => {
                let params = parse_ui_node_inspect_params(&request.params)?;
                execute_ui_node_inspect(params).await?
            }
            _ => anyhow::bail!(
                "Unsupported normalized UI capability '{}'",
                request.capability
            ),
        };

        let completed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let total_time_ms = received_at.elapsed().as_millis() as u64;

        let result = ExecutionResult {
            exit_code: 0,
            stdout: None,
            stdout_bytes: None,
            stderr: Some(String::new()),
            output: Some(output),
            artifacts: vec![],
            resource_usage: None,
        };

        Ok(IntentResponse {
            request_id: uuid::Uuid::parse_str(&ctx.request_id)
                .unwrap_or_else(|_| uuid::Uuid::new_v4()),
            status: IntentStatus::Ok,
            code: "OK".to_string(),
            message: String::new(),
            result: Some(result),
            error: None,
            timing: ResponseTiming {
                received_at_ms,
                started_at_ms,
                completed_at_ms,
                queue_time_ms: 0,
                setup_time_ms: 0,
                exec_time_ms: total_time_ms,
                total_time_ms,
            },
            sandbox_info: None,
        })
    }
}

#[cfg(feature = "grpc")]
#[async_trait]
impl IntentHandler for DaemonIntentHandler {
    async fn handle(&self, request: IntentRequest, ctx: RequestContext) -> Result<IntentResponse> {
        let received_at = std::time::Instant::now();
        let received_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        info!(
            request_id = %ctx.request_id,
            capability = %request.capability,
            "Handling gRPC request via sandbox manager"
        );

        if matches!(
            request.capability.as_str(),
            "ui.windows.list.v1" | "ui.node.inspect.v1"
        ) {
            return self.handle_normalized_ui_capability(request, ctx).await;
        }

        // Resolve sandbox: explicit ID > existing client session > default sandbox
        let setup_start = std::time::Instant::now();
        let (sandbox_id, attach_result) = match &request.sandbox_prefs.sandbox_id {
            Some(id) if !id.is_empty() => {
                // Use explicitly provided sandbox_id
                let sandbox_id = crate::core::sandbox::SandboxId::from_string(id.clone());
                let attach_request = crate::core::sandbox::AttachRequest {
                    sandbox_id: sandbox_id.clone(),
                    client_id: ctx.client_id.clone(),
                    create_if_missing: false,
                    create_spec: None,
                };
                match self.sandbox_manager.attach(attach_request).await {
                    Ok(r) => (sandbox_id, r),
                    Err(e) => {
                        warn!(request_id = %ctx.request_id, sandbox_id = %sandbox_id, error = %e, "Failed to attach to sandbox");
                        return Ok(sandbox_not_found_error(&ctx.request_id, id, received_at_ms));
                    }
                }
            }
            _ => {
                // Check for existing session for this client
                if let Ok(Some(existing_session)) = self
                    .sandbox_manager
                    .get_session_by_client(&ctx.client_id)
                    .await
                {
                    info!(request_id = %ctx.request_id, session_id = %existing_session.session_id, "Reusing existing client session");
                    let sandbox_id = existing_session.sandbox_id.clone();
                    let attach_request = crate::core::sandbox::AttachRequest {
                        sandbox_id: sandbox_id.clone(),
                        client_id: ctx.client_id.clone(),
                        create_if_missing: false,
                        create_spec: None,
                    };
                    match self.sandbox_manager.attach(attach_request).await {
                        Ok(r) => (sandbox_id, r),
                        Err(e) => {
                            warn!(request_id = %ctx.request_id, error = %e, "Failed to reattach to client session");
                            return Ok(sandbox_required_error(&ctx.request_id, received_at_ms));
                        }
                    }
                } else if let Some(default_id) = self.sandbox_manager.get_default_sandbox().await {
                    // Use default sandbox
                    info!(request_id = %ctx.request_id, sandbox_id = %default_id, "Using default sandbox");
                    let attach_request = crate::core::sandbox::AttachRequest {
                        sandbox_id: default_id.clone(),
                        client_id: ctx.client_id.clone(),
                        create_if_missing: false,
                        create_spec: None,
                    };
                    match self.sandbox_manager.attach(attach_request).await {
                        Ok(r) => (default_id, r),
                        Err(e) => {
                            warn!(request_id = %ctx.request_id, error = %e, "Failed to attach to default sandbox");
                            return Ok(sandbox_required_error(&ctx.request_id, received_at_ms));
                        }
                    }
                } else {
                    warn!(request_id = %ctx.request_id, "No sandbox_id provided and no default sandbox configured");
                    return Ok(sandbox_required_error(&ctx.request_id, received_at_ms));
                }
            }
        };

        let session = attach_result.session;
        let setup_time_ms = setup_start.elapsed().as_millis() as u64;

        info!(
            sandbox_id = %session.sandbox_id,
            backend = %attach_result.capabilities.backend,
            newly_created = attach_result.newly_created,
            "Attached to sandbox"
        );

        // Get sandbox for execution - we need to acquire to get the actual sandbox object
        let spec = SandboxSpec {
            profile: attach_result.capabilities.profile.clone(),
            workdir: self.config.executor.work_root.clone(),
            ..Default::default()
        };
        let options = SandboxSelectionOptions {
            preferred_id: Some(sandbox_id.clone()),
            require_fresh: false,
            required_capabilities: Default::default(),
            preferred_backend: None,
            required_labels: Default::default(),
            use_pool: false,
        };
        let (_, sandbox) = self
            .sandbox_manager
            .acquire(&spec, &options, &ctx.client_id)
            .await
            .context("Failed to get sandbox for execution")?;

        let execution_plan = build_execution_plan(
            &request,
            &ctx.request_id,
            &attach_result.capabilities.backend,
            false,
        )?;

        // Execute in sandbox
        let exec_start = std::time::Instant::now();
        let exec_result = sandbox
            .exec(&execution_plan.cmd, &execution_plan.exec_ctx)
            .await;
        let exec_time_ms = exec_start.elapsed().as_millis() as u64;

        // Release sandbox (keep alive for potential reuse)
        let _ = self.sandbox_manager.release(&session, true).await;

        let completed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let total_time_ms = received_at.elapsed().as_millis() as u64;

        match exec_result {
            Ok(output) => {
                let sandbox_caps = sandbox.capabilities();
                Ok(IntentResponse {
                    request_id: uuid::Uuid::parse_str(&ctx.request_id)
                        .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                    status: if output.exit_code == 0 {
                        IntentStatus::Ok
                    } else {
                        IntentStatus::Error
                    },
                    code: if output.exit_code == 0 { "OK" } else { "ERROR" }.to_string(),
                    message: String::new(),
                    result: Some(ExecutionResult {
                        exit_code: output.exit_code,
                        stdout: if matches!(execution_plan.output_mode, ResponseOutputMode::Text) {
                            Some(String::from_utf8_lossy(&output.stdout).to_string())
                        } else {
                            None
                        },
                        stdout_bytes: if matches!(
                            execution_plan.output_mode,
                            ResponseOutputMode::BinaryStdout
                        ) {
                            Some(output.stdout.clone())
                        } else {
                            None
                        },
                        stderr: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                        output: None,
                        artifacts: vec![],
                        resource_usage: output.resource_usage.map(|u| {
                            crate::core::intent::ResourceUsageStats {
                                peak_memory_bytes: u.peak_memory_bytes,
                                cpu_time_ms: u.cpu_time_ms,
                                wall_time_ms: u.wall_time_ms,
                                disk_write_bytes: u.bytes_written,
                                disk_read_bytes: u.bytes_read,
                                network_tx_bytes: 0, // Not tracked by isolation backend
                                network_rx_bytes: 0,
                            }
                        }),
                    }),
                    error: None,
                    timing: ResponseTiming {
                        received_at_ms,
                        started_at_ms: received_at_ms + setup_time_ms,
                        completed_at_ms,
                        queue_time_ms: 0,
                        setup_time_ms,
                        exec_time_ms,
                        total_time_ms,
                    },
                    sandbox_info: Some(crate::core::intent::SandboxInfo {
                        sandbox_id: session.sandbox_id.to_string(),
                        backend: sandbox_caps.backend.clone(),
                        profile: sandbox_caps.profile.clone(),
                        newly_created: true,
                        capabilities: crate::core::intent::SandboxCapabilitiesInfo {
                            can_write: sandbox_caps.can_write_filesystem,
                            readable_paths: sandbox_caps
                                .readable_paths
                                .iter()
                                .map(|p| p.to_string_lossy().to_string())
                                .collect(),
                            writable_paths: sandbox_caps
                                .writable_paths
                                .iter()
                                .map(|p| p.to_string_lossy().to_string())
                                .collect(),
                            has_network: sandbox_caps.has_network,
                            limits: crate::core::intent::ResourceLimitsInfo {
                                max_memory_bytes: sandbox_caps.limits.max_memory_bytes,
                                max_cpu_ms: sandbox_caps.limits.max_cpu_time_ms,
                                max_wall_ms: sandbox_caps.limits.max_wall_time_ms,
                                max_output_bytes: sandbox_caps.limits.max_output_bytes,
                            },
                        },
                    }),
                })
            }
            Err(e) => {
                error!(error = %e, "Sandbox execution failed");
                Ok(IntentResponse {
                    request_id: uuid::Uuid::parse_str(&ctx.request_id)
                        .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                    status: IntentStatus::Error,
                    code: "EXEC_ERROR".to_string(),
                    message: e.to_string(),
                    result: None,
                    error: Some(crate::core::intent::ErrorDetails {
                        code: "SANDBOX_EXEC_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                        retryable: false,
                        retry_after_ms: None,
                    }),
                    timing: ResponseTiming {
                        received_at_ms,
                        started_at_ms: received_at_ms + setup_time_ms,
                        completed_at_ms,
                        queue_time_ms: 0,
                        setup_time_ms,
                        exec_time_ms,
                        total_time_ms,
                    },
                    sandbox_info: None,
                })
            }
        }
    }

    async fn handle_streaming(
        &self,
        request: IntentRequest,
        ctx: RequestContext,
        output_tx: tokio::sync::mpsc::Sender<OutputChunk>,
    ) -> Result<IntentResponse> {
        let received_at = std::time::Instant::now();
        let received_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        info!(
            request_id = %ctx.request_id,
            capability = %request.capability,
            "Handling streaming gRPC request via sandbox manager"
        );

        if request.capability != "shell.exec.v1" {
            // Non-shell capabilities are request/response style and should not
            // stream intermediate output chunks.
            return self.handle(request, ctx).await;
        }

        // Resolve sandbox: explicit ID > existing client session > default sandbox
        let setup_start = std::time::Instant::now();
        let (sandbox_id, attach_result) = match &request.sandbox_prefs.sandbox_id {
            Some(id) if !id.is_empty() => {
                // Use explicitly provided sandbox_id
                let sandbox_id = crate::core::sandbox::SandboxId::from_string(id.clone());
                let attach_request = crate::core::sandbox::AttachRequest {
                    sandbox_id: sandbox_id.clone(),
                    client_id: ctx.client_id.clone(),
                    create_if_missing: false,
                    create_spec: None,
                };
                match self.sandbox_manager.attach(attach_request).await {
                    Ok(r) => (sandbox_id, r),
                    Err(e) => {
                        warn!(request_id = %ctx.request_id, sandbox_id = %sandbox_id, error = %e, "Failed to attach to sandbox");
                        return Ok(sandbox_not_found_error(&ctx.request_id, id, received_at_ms));
                    }
                }
            }
            _ => {
                // Check for existing session for this client
                if let Ok(Some(existing_session)) = self
                    .sandbox_manager
                    .get_session_by_client(&ctx.client_id)
                    .await
                {
                    info!(request_id = %ctx.request_id, session_id = %existing_session.session_id, "Reusing existing client session");
                    let sandbox_id = existing_session.sandbox_id.clone();
                    let attach_request = crate::core::sandbox::AttachRequest {
                        sandbox_id: sandbox_id.clone(),
                        client_id: ctx.client_id.clone(),
                        create_if_missing: false,
                        create_spec: None,
                    };
                    match self.sandbox_manager.attach(attach_request).await {
                        Ok(r) => (sandbox_id, r),
                        Err(e) => {
                            warn!(request_id = %ctx.request_id, error = %e, "Failed to reattach to client session");
                            return Ok(sandbox_required_error(&ctx.request_id, received_at_ms));
                        }
                    }
                } else if let Some(default_id) = self.sandbox_manager.get_default_sandbox().await {
                    // Use default sandbox
                    info!(request_id = %ctx.request_id, sandbox_id = %default_id, "Using default sandbox");
                    let attach_request = crate::core::sandbox::AttachRequest {
                        sandbox_id: default_id.clone(),
                        client_id: ctx.client_id.clone(),
                        create_if_missing: false,
                        create_spec: None,
                    };
                    match self.sandbox_manager.attach(attach_request).await {
                        Ok(r) => (default_id, r),
                        Err(e) => {
                            warn!(request_id = %ctx.request_id, error = %e, "Failed to attach to default sandbox");
                            return Ok(sandbox_required_error(&ctx.request_id, received_at_ms));
                        }
                    }
                } else {
                    warn!(request_id = %ctx.request_id, "No sandbox_id provided and no default sandbox configured");
                    return Ok(sandbox_required_error(&ctx.request_id, received_at_ms));
                }
            }
        };

        let session = attach_result.session;

        info!(
            sandbox_id = %session.sandbox_id,
            backend = %attach_result.capabilities.backend,
            "Attached to sandbox for streaming"
        );

        // Get sandbox for execution
        let spec = SandboxSpec {
            profile: attach_result.capabilities.profile.clone(),
            workdir: self.config.executor.work_root.clone(),
            ..Default::default()
        };
        let options = SandboxSelectionOptions {
            preferred_id: Some(sandbox_id.clone()),
            require_fresh: false,
            required_capabilities: Default::default(),
            preferred_backend: None,
            required_labels: Default::default(),
            use_pool: false,
        };
        let (_, sandbox) = self
            .sandbox_manager
            .acquire(&spec, &options, &ctx.client_id)
            .await
            .context("Failed to get sandbox for execution")?;
        let setup_time_ms = setup_start.elapsed().as_millis() as u64;

        let execution_plan = build_execution_plan(
            &request,
            &ctx.request_id,
            &attach_result.capabilities.backend,
            true,
        )?;

        // Create channel for streaming output from sandbox
        let (stream_tx, mut stream_rx) = tokio::sync::mpsc::channel::<StreamOutput>(100);

        // Spawn task to forward output
        let output_tx_clone = output_tx.clone();
        tokio::spawn(async move {
            while let Some(output) = stream_rx.recv().await {
                let chunk = match output {
                    StreamOutput::Stdout(data) => OutputChunk::Stdout(data),
                    StreamOutput::Stderr(data) => OutputChunk::Stderr(data),
                    StreamOutput::Exit { .. } => {
                        // Exit is handled by the final response
                        continue;
                    }
                };
                if output_tx_clone.send(chunk).await.is_err() {
                    break;
                }
            }
        });

        // Execute in sandbox with streaming
        let exec_start = std::time::Instant::now();
        let exec_result = sandbox
            .exec_streaming(&execution_plan.cmd, &execution_plan.exec_ctx, stream_tx)
            .await;
        let exec_time_ms = exec_start.elapsed().as_millis() as u64;

        // Release sandbox
        let _ = self.sandbox_manager.release(&session, true).await;

        let completed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let total_time_ms = received_at.elapsed().as_millis() as u64;

        match exec_result {
            Ok(output) => {
                let sandbox_caps = sandbox.capabilities();
                Ok(IntentResponse {
                    request_id: uuid::Uuid::parse_str(&ctx.request_id)
                        .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                    status: if output.exit_code == 0 {
                        IntentStatus::Ok
                    } else {
                        IntentStatus::Error
                    },
                    code: if output.exit_code == 0 { "OK" } else { "ERROR" }.to_string(),
                    message: String::new(),
                    result: Some(ExecutionResult {
                        exit_code: output.exit_code,
                        stdout: None, // Already streamed
                        stdout_bytes: None,
                        stderr: None, // Already streamed
                        output: None,
                        artifacts: vec![],
                        resource_usage: None,
                    }),
                    error: None,
                    timing: ResponseTiming {
                        received_at_ms,
                        started_at_ms: received_at_ms + setup_time_ms,
                        completed_at_ms,
                        queue_time_ms: 0,
                        setup_time_ms,
                        exec_time_ms,
                        total_time_ms,
                    },
                    sandbox_info: Some(crate::core::intent::SandboxInfo {
                        sandbox_id: session.sandbox_id.to_string(),
                        backend: sandbox_caps.backend.clone(),
                        profile: sandbox_caps.profile.clone(),
                        newly_created: true,
                        capabilities: crate::core::intent::SandboxCapabilitiesInfo {
                            can_write: sandbox_caps.can_write_filesystem,
                            readable_paths: sandbox_caps
                                .readable_paths
                                .iter()
                                .map(|p| p.to_string_lossy().to_string())
                                .collect(),
                            writable_paths: sandbox_caps
                                .writable_paths
                                .iter()
                                .map(|p| p.to_string_lossy().to_string())
                                .collect(),
                            has_network: sandbox_caps.has_network,
                            limits: crate::core::intent::ResourceLimitsInfo {
                                max_memory_bytes: sandbox_caps.limits.max_memory_bytes,
                                max_cpu_ms: sandbox_caps.limits.max_cpu_time_ms,
                                max_wall_ms: sandbox_caps.limits.max_wall_time_ms,
                                max_output_bytes: sandbox_caps.limits.max_output_bytes,
                            },
                        },
                    }),
                })
            }
            Err(e) => {
                error!(error = %e, "Sandbox streaming execution failed");
                Ok(IntentResponse {
                    request_id: uuid::Uuid::parse_str(&ctx.request_id)
                        .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                    status: IntentStatus::Error,
                    code: "EXEC_ERROR".to_string(),
                    message: e.to_string(),
                    result: None,
                    error: Some(crate::core::intent::ErrorDetails {
                        code: "SANDBOX_EXEC_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                        retryable: false,
                        retry_after_ms: None,
                    }),
                    timing: ResponseTiming {
                        received_at_ms,
                        started_at_ms: received_at_ms + setup_time_ms,
                        completed_at_ms,
                        queue_time_ms: 0,
                        setup_time_ms,
                        exec_time_ms,
                        total_time_ms,
                    },
                    sandbox_info: None,
                })
            }
        }
    }

    async fn supports_capability(&self, capability: &str) -> bool {
        matches!(
            capability,
            "shell.exec.v1"
                | "accessibility.query.v1"
                | "screenshot.capture.v1"
                | "ui.accessibility.query.v1"
                | "ui.screenshot.v1"
                | "ui.windows.list.v1"
                | "ui.node.inspect.v1"
        )
    }

    async fn list_capabilities(&self) -> Vec<CapabilityInfo> {
        vec![
            CapabilityInfo {
                name: "shell.exec.v1".to_string(),
                description: "Execute shell commands in isolated sandbox".to_string(),
                version: 1,
                param_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "Shell command to execute" },
                        "timeout_ms": { "type": "integer", "description": "Execution timeout in milliseconds", "default": 30000 },
                        "cwd": { "type": "string", "description": "Working directory (relative to sandbox root)" },
                        "env": { "type": "object", "description": "Environment variables" }
                    },
                    "required": ["command"]
                })),
                requires_elevated: false,
                supports_streaming: true,
                tags: vec!["shell".to_string(), "exec".to_string()],
            },
            CapabilityInfo {
                name: "accessibility.query.v1".to_string(),
                description:
                    "Run read-only accessibility D-Bus queries (AT-SPI) against desktop apps"
                        .to_string(),
                version: 1,
                param_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "destination": { "type": "string", "description": "D-Bus destination (org.a11y.* or unique name)" },
                        "object_path": { "type": "string", "description": "D-Bus object path (for example /org/a11y/atspi/accessible/root)" },
                        "interface": { "type": "string", "description": "D-Bus interface (org.a11y.atspi.*)" },
                        "method": { "type": "string", "description": "Read-only method name (allowlisted)" },
                        "args": { "type": "array", "items": { "type": "string" }, "description": "gdbus literal arguments" },
                        "dbus_address": { "type": "string", "description": "Optional explicit D-Bus bus address" },
                        "timeout_ms": { "type": "integer", "minimum": 1, "maximum": 120000, "default": 30000 }
                    }
                })),
                requires_elevated: true,
                supports_streaming: false,
                tags: vec![
                    "desktop".to_string(),
                    "accessibility".to_string(),
                    "dbus".to_string(),
                ],
            },
            CapabilityInfo {
                name: "screenshot.capture.v1".to_string(),
                description: "Capture desktop screenshots (full screen or region) as PNG bytes"
                    .to_string(),
                version: 1,
                param_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "mode": { "type": "string", "enum": ["full", "region"], "default": "full" },
                        "rect": {
                            "type": "object",
                            "properties": {
                                "x": { "type": "integer" },
                                "y": { "type": "integer" },
                                "width": { "type": "integer", "minimum": 1 },
                                "height": { "type": "integer", "minimum": 1 }
                            },
                            "required": ["x", "y", "width", "height"],
                            "description": "Capture rectangle. May be sourced from accessibility extents."
                        },
                        "target": {
                            "type": "object",
                            "properties": {
                                "kind": { "type": "string", "enum": ["full", "rect", "window", "node"] },
                                "window_id": { "type": "string" },
                                "node_id": { "type": "string" },
                                "rect": {
                                    "type": "object",
                                    "properties": {
                                        "x": { "type": "integer" },
                                        "y": { "type": "integer" },
                                        "width": { "type": "integer", "minimum": 1 },
                                        "height": { "type": "integer", "minimum": 1 }
                                    },
                                    "required": ["x", "y", "width", "height"]
                                }
                            },
                            "required": ["kind"],
                            "description": "Normalized screenshot target selector"
                        },
                        "timeout_ms": { "type": "integer", "minimum": 1, "maximum": 120000, "default": 30000 }
                    }
                })),
                requires_elevated: true,
                supports_streaming: false,
                tags: vec![
                    "desktop".to_string(),
                    "screenshot".to_string(),
                    "ui".to_string(),
                ],
            },
            CapabilityInfo {
                name: "ui.windows.list.v1".to_string(),
                description:
                    "List desktop windows with normalized IDs (AT-SPI primary, compositor-enriched when available)"
                        .to_string(),
                version: 1,
                param_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 },
                        "include_titles": { "type": "boolean", "default": true },
                        "include_roles": { "type": "boolean", "default": true },
                        "include_bounds": { "type": "boolean", "default": false },
                        "compositor_backend": { "type": "string", "enum": ["auto", "none", "hyprland"], "default": "auto", "description": "Compositor backend selection. 'auto' picks supported backends for current session." },
                        "timeout_ms": { "type": "integer", "minimum": 1, "maximum": 120000, "default": 30000 }
                    }
                })),
                requires_elevated: true,
                supports_streaming: false,
                tags: vec![
                    "desktop".to_string(),
                    "accessibility".to_string(),
                    "windows".to_string(),
                ],
            },
            CapabilityInfo {
                name: "ui.node.inspect.v1".to_string(),
                description: "Inspect an accessibility node and return normalized structure"
                    .to_string(),
                version: 1,
                param_schema: Some(serde_json::json!({
                    "type": "object",
                    "required": ["node_id"],
                    "properties": {
                        "node_id": { "type": "string", "description": "<destination>|<object_path>" },
                        "include_name": { "type": "boolean", "default": true },
                        "include_role": { "type": "boolean", "default": true },
                        "include_children": { "type": "boolean", "default": true },
                        "include_interfaces": { "type": "boolean", "default": false },
                        "include_bounds": { "type": "boolean", "default": false },
                        "child_limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 200 },
                        "timeout_ms": { "type": "integer", "minimum": 1, "maximum": 120000, "default": 30000 }
                    }
                })),
                requires_elevated: true,
                supports_streaming: false,
                tags: vec![
                    "desktop".to_string(),
                    "accessibility".to_string(),
                    "inspect".to_string(),
                ],
            },
        ]
    }

    async fn health(&self) -> HealthStatus {
        match self.sandbox_manager.health().await {
            Ok(true) => HealthStatus::Healthy,
            Ok(false) => HealthStatus::Unhealthy {
                reason: "Sandbox manager unhealthy".to_string(),
            },
            Err(e) => HealthStatus::Unhealthy {
                reason: e.to_string(),
            },
        }
    }
}

/// Handles the daemon command
pub struct DaemonCommand;

impl DaemonCommand {
    pub async fn execute(
        config_path: PathBuf,
        demo_mode: bool,
        autobootstrap: bool,
        capability_digest: String,
        isolation_backend: String,
    ) -> Result<()> {
        log_daemon_startup(demo_mode);
        let validated_capability_digest = validate_capability_digest(capability_digest)?;
        let config = load_and_validate_config(&config_path).await?;
        validate_mode_backend_compatibility(&config, demo_mode, &isolation_backend)?;
        let derivations = load_policy_derivations(&config).await?;

        validate_security_capabilities(&config, demo_mode)?;

        let daemon_services = initialize_daemon_services(&config).await?;
        let nats_clients = initialize_nats_clients(&config, autobootstrap).await?;
        let execution_components = initialize_execution_components(&config).await?;

        let _policy_sync = execution_components
            .policy_engine
            .start_policy_listener(nats_clients.nats_client.clone(), &config.executor.policy)
            .await?;

        let worker_handles = start_worker_pools(
            &config,
            nats_clients.nats_client,
            execution_components.idempotency_store,
            execution_components.policy_engine,
            execution_components.schema_validator,
            execution_components.runner_registry.clone(),
            execution_components.trusted_signers,
            daemon_services.metrics_handle,
            daemon_services.audit_logger,
            validated_capability_digest,
            derivations,
        )
        .await?;

        // Start gRPC adapter if enabled - keep alive for daemon lifetime
        #[cfg(feature = "grpc")]
        let (_grpc_adapter, _sandbox_manager) = {
            let grpc_addr: SocketAddr = std::env::var("AGENTD_GRPC_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:9500".to_string())
                .parse()
                .context("Invalid AGENTD_GRPC_LISTEN address")?;

            info!("Starting gRPC adapter on {}", grpc_addr);

            // Create isolation backend and sandbox manager
            let backend =
                isolation::create_backend(&isolation_backend, &config.executor.work_root).context(
                    format!("Failed to create isolation backend '{}'", isolation_backend),
                )?;
            let backend_caps = backend
                .probe()
                .await
                .context("Failed to probe isolation backend")?;
            info!(
                "Using isolation backend '{}' (filesystem={}, network={}, process={})",
                backend_caps.name,
                backend_caps.filesystem_isolation,
                backend_caps.network_isolation,
                backend_caps.process_isolation
            );

            if config.executor.security.strict_sandbox
                && !demo_mode
                && backend_caps.is_soft_isolation()
            {
                anyhow::bail!(
                    "strict_sandbox is enabled but backend '{}' provides only soft isolation",
                    backend_caps.name
                );
            }

            let sandbox_manager: Arc<dyn SandboxManager> = Arc::new(DefaultSandboxManager::new(
                vec![backend],
                SandboxManagerConfig::default(),
            ));

            let intent_handler = Arc::new(DaemonIntentHandler {
                sandbox_manager: sandbox_manager.clone(),
                config: config.clone(),
                isolation_backend: isolation_backend.clone(),
            });

            // Default sandbox paths - can be overridden by client
            let default_paths_ro = vec![
                std::path::PathBuf::from("/usr"),
                std::path::PathBuf::from("/lib"),
                std::path::PathBuf::from("/lib64"),
                std::path::PathBuf::from("/bin"),
                std::path::PathBuf::from("/etc"),
            ];
            let default_paths_rw = vec![std::path::PathBuf::from("/home/nathan/Projects")];
            let grpc_adapter = Arc::new(GrpcAdapter::with_sandbox_defaults(
                grpc_addr,
                default_paths_ro,
                default_paths_rw,
            ));
            grpc_adapter
                .set_sandbox_manager(sandbox_manager.clone())
                .await;
            grpc_adapter
                .start(intent_handler)
                .await
                .context("Failed to start gRPC adapter")?;

            info!("gRPC adapter started successfully on {}", grpc_addr);
            (grpc_adapter, sandbox_manager)
        };

        info!("All worker pools started. Executor is ready to process intents.");
        setup_signal_handlers().await;

        futures::future::try_join_all(worker_handles).await?;
        info!("Executor daemon shutting down");
        Ok(())
    }
}

pub struct DaemonServices {
    pub audit_logger: Arc<tokio::sync::Mutex<audit::AuditLogger>>,
    pub metrics_handle: Arc<tokio::sync::RwLock<metrics::ExecutorMetrics>>,
}

pub struct NatsClients {
    pub nats_client: nats::NatsClient,
    pub _smith_bus: smith_bus::SmithBus,
}

pub struct ExecutionComponents {
    pub idempotency_store: idempotency::IdempotencyStore,
    pub policy_engine: policy::PolicyEngine,
    pub schema_validator: Arc<schema::SchemaValidator>,
    pub runner_registry: Arc<runners::RunnerRegistry>,
    pub trusted_signers: Arc<security::TrustedSigners>,
    pub vm_manager: Option<Arc<MicroVmManager>>,
}

fn log_daemon_startup(demo_mode: bool) {
    if demo_mode {
        warn!("⚠️  RUNNING IN DEMO MODE - SECURITY FEATURES DISABLED ⚠️");
        warn!("⚠️  THIS IS UNSAFE FOR PRODUCTION USE ⚠️");
    }
    info!("🚀 Starting Smith Executor Daemon");
}

fn validate_capability_digest(capability_digest: String) -> Result<String> {
    if capability_digest.len() != 64 || !capability_digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "Invalid capability digest format. Expected 64 hex characters, got: {}",
            capability_digest
        ));
    }
    info!("Capability digest validated: {}", capability_digest);
    Ok(capability_digest)
}

fn is_host_direct_backend(isolation_backend: &str) -> bool {
    let normalized = normalize_backend_name(isolation_backend);
    matches!(
        normalized.as_str(),
        "none" | "host" | "host-direct" | "workstation"
    )
}

fn normalize_backend_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

fn validate_mode_backend_compatibility(
    config: &Config,
    demo_mode: bool,
    isolation_backend: &str,
) -> Result<()> {
    if config.executor.security.strict_sandbox && is_host_direct_backend(isolation_backend) {
        if demo_mode {
            warn!(
                backend = isolation_backend,
                "Strict sandbox is configured but host-direct backend requested in demo mode"
            );
            return Ok(());
        }

        anyhow::bail!(
            "strict_sandbox is enabled but backend '{}' disables isolation. \
Use landlock/container/firecracker, or pass --demo only for local development.",
            isolation_backend
        );
    }

    Ok(())
}

async fn load_and_validate_config(config_path: &PathBuf) -> Result<Config> {
    let config = config::load_config(config_path)?;
    info!(
        "Configuration loaded successfully from {}",
        config_path.display()
    );
    Ok(config)
}

async fn load_policy_derivations(config: &Config) -> Result<Arc<PolicyDerivations>> {
    let derivations =
        config::load_policy_derivations(config).context("Failed to load policy derivations")?;
    info!(
        "Policy derivations loaded successfully with {} capabilities",
        derivations.seccomp_allow.len()
    );
    Ok(Arc::new(derivations))
}

async fn initialize_daemon_services(config: &Config) -> Result<DaemonServices> {
    // Initialize audit logging
    let audit_logger = Arc::new(tokio::sync::Mutex::new(audit::AuditLogger::new(
        &config.executor.audit_dir,
    )?));

    // Initialize and start metrics services
    let metrics_exporter = metrics::MetricsExporter::new(config)?;
    let metrics_handle = metrics_exporter.metrics();

    // Start metrics HTTP server in background (if configured)
    if let Some(metrics_port) = config.executor.metrics_port {
        let metrics_server = metrics_exporter.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics_server.start_http_server(metrics_port).await {
                error!("Metrics HTTP server failed: {}", e);
            }
        });
        info!("Metrics server will start on port {}", metrics_port);
    }

    // Start health HTTP server in background
    let health_port = config.executor.metrics_port.map(|p| p + 1);
    let _health_service = health::setup_health_service(health_port).await?;
    info!("Health service initialized{}", &{
        if let Some(port) = health_port {
            format!(" on port {}", port)
        } else {
            String::new()
        }
    });

    Ok(DaemonServices {
        audit_logger,
        metrics_handle,
    })
}

async fn initialize_nats_clients(config: &Config, autobootstrap: bool) -> Result<NatsClients> {
    // Initialize NATS client and JetStream consumers
    let nats_client = nats::NatsClient::new(&config.executor.nats_config).await?;
    info!("Connected to NATS server");

    if let Err(err) = nats_client.maybe_spawn_debug_result_tap().await {
        warn!("Failed to start executor debug result tap: {err}");
    }

    // Initialize Smith Bus for enhanced JetStream operations
    let smith_bus = smith_bus::SmithBus::connect(&config.nats.url).await?;

    // Bootstrap JetStream streams if requested
    if autobootstrap {
        info!("Bootstrapping JetStream streams...");
        let stream_manager = smith_bus.stream_manager();
        stream_manager
            .bootstrap_streams()
            .await
            .context("Failed to bootstrap JetStream streams")?;
        info!("JetStream streams bootstrapped successfully");
    }

    Ok(NatsClients {
        nats_client,
        _smith_bus: smith_bus,
    })
}

async fn initialize_execution_components(config: &Config) -> Result<ExecutionComponents> {
    // Initialize idempotency store
    let idempotency_store = idempotency::IdempotencyStore::new(&config.executor.state_dir).await?;
    info!("Idempotency store initialized");

    // Initialize policy engine
    let policy_engine = policy::PolicyEngine::new(config)?;
    info!(
        "Policy engine initialized with {} policies",
        policy_engine.policy_count()
    );

    // Initialize schema validator
    let schema_validator = Arc::new(schema::SchemaValidator::new()?);
    info!("Schema validator initialized");

    // Initialize capability registry
    let _capability_registry = Arc::new(crate::capabilities::register_builtin_capabilities());
    info!(
        "Capability registry initialized with {} capabilities",
        _capability_registry.list().len()
    );

    // Initialize micro-VM manager (optional)
    let vm_manager = if config.executor.vm_pool.enabled {
        let runtime_config = VmPoolRuntimeConfig::from(&config.executor.vm_pool);
        match MicroVmManager::new(runtime_config) {
            Ok(manager) => {
                info!(
                    volume_root = %config.executor.vm_pool.volume_root.display(),
                    "Micro-VM pool initialized"
                );
                Some(manager)
            }
            Err(err) => {
                warn!(
                    error = %err,
                    "Failed to initialize micro-VM pool; continuing without persistent shells"
                );
                None
            }
        }
    } else {
        None
    };

    // Initialize runner registry
    let runner_registry = Arc::new(runners::RunnerRegistry::new(vm_manager.clone()));
    info!("Runner registry initialized");

    let trusted_signers = Arc::new(
        security::TrustedSigners::load_from_dir(&config.executor.security.pubkeys_dir)
            .context("Failed to load trusted signer keys")?,
    );
    if trusted_signers.is_empty() {
        warn!(
            "No trusted signer keys loaded from {}",
            config.executor.security.pubkeys_dir.display()
        );
    }

    Ok(ExecutionComponents {
        idempotency_store,
        policy_engine,
        schema_validator,
        runner_registry,
        trusted_signers,
        vm_manager,
    })
}

#[allow(clippy::too_many_arguments)]
async fn start_worker_pools(
    config: &Config,
    nats_client: nats::NatsClient,
    idempotency_store: idempotency::IdempotencyStore,
    policy_engine: policy::PolicyEngine,
    schema_validator: Arc<schema::SchemaValidator>,
    runner_registry: Arc<runners::RunnerRegistry>,
    trusted_signers: Arc<security::TrustedSigners>,
    metrics_handle: Arc<tokio::sync::RwLock<metrics::ExecutorMetrics>>,
    audit_logger: Arc<tokio::sync::Mutex<audit::AuditLogger>>,
    capability_digest: String,
    derivations: Arc<PolicyDerivations>,
) -> Result<Vec<tokio::task::JoinHandle<Result<()>>>> {
    let mut worker_handles = Vec::new();

    for (capability, stream_config) in &config.executor.intent_streams {
        info!("Starting worker pool for capability: {}", capability);
        for worker_id in 0..stream_config.workers {
            let handle = tokio::spawn(crate::worker::run_worker(
                capability.clone(),
                worker_id,
                nats_client.clone(),
                idempotency_store.clone(),
                policy_engine.clone(),
                schema_validator.clone(),
                runner_registry.clone(),
                trusted_signers.clone(),
                config.clone(),
                metrics_handle.clone(),
                audit_logger.clone(),
                capability_digest.clone(),
                derivations.clone(),
            ));
            worker_handles.push(handle);
        }
    }

    Ok(worker_handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "grpc")]
    use serde_json::json;

    #[test]
    fn test_validate_capability_digest_valid() {
        let valid_digest = "a".repeat(64);
        let result = validate_capability_digest(valid_digest.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_digest);
    }

    #[test]
    fn test_validate_capability_digest_valid_hex() {
        let valid_digest = "0123456789abcdef".repeat(4);
        let result = validate_capability_digest(valid_digest.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_digest);
    }

    #[test]
    fn test_validate_capability_digest_mixed_case() {
        let valid_digest = "AbCdEf0123456789".repeat(4);
        let result = validate_capability_digest(valid_digest.clone());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_capability_digest_too_short() {
        let short_digest = "abc123".to_string();
        let result = validate_capability_digest(short_digest);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid capability digest format"));
    }

    #[test]
    fn test_validate_capability_digest_too_long() {
        let long_digest = "a".repeat(65);
        let result = validate_capability_digest(long_digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_digest_non_hex() {
        let invalid_digest = "g".repeat(64); // 'g' is not hex
        let result = validate_capability_digest(invalid_digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_digest_empty() {
        let result = validate_capability_digest(String::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_digest_spaces() {
        let invalid_digest = format!("{}  {}", "a".repeat(31), "b".repeat(31));
        let result = validate_capability_digest(invalid_digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mode_backend_compatibility_rejects_host_direct_in_strict_mode() {
        let mut config = Config::testing();
        config.executor.security.strict_sandbox = true;

        let result = validate_mode_backend_compatibility(&config, false, "host-direct");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("strict_sandbox"));
    }

    #[test]
    fn test_validate_mode_backend_compatibility_rejects_host_direct_snake_case_in_strict_mode() {
        let mut config = Config::testing();
        config.executor.security.strict_sandbox = true;

        let result = validate_mode_backend_compatibility(&config, false, "host_direct");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("strict_sandbox"));
    }

    #[test]
    fn test_validate_mode_backend_compatibility_allows_host_direct_in_demo_mode() {
        let mut config = Config::testing();
        config.executor.security.strict_sandbox = true;

        let result = validate_mode_backend_compatibility(&config, true, "host-direct");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_mode_backend_compatibility_allows_isolated_backend_in_strict_mode() {
        let mut config = Config::testing();
        config.executor.security.strict_sandbox = true;

        let result = validate_mode_backend_compatibility(&config, false, "landlock");
        assert!(result.is_ok());
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_shell_exec_params_rejects_absolute_workdir() {
        let raw = json!({
            "command": "echo hello",
            "cwd": "/tmp",
            "timeout_ms": 1000
        });
        let result = parse_shell_exec_params(&raw);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("workdir must be relative"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_shell_exec_params_rejects_parent_traversal_workdir() {
        let raw = json!({
            "command": "echo hello",
            "cwd": "../escape",
            "timeout_ms": 1000
        });
        let result = parse_shell_exec_params(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parent traversal"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_shell_exec_params_rejects_dangerous_env_keys() {
        let raw = json!({
            "command": "echo hello",
            "env": {"LD_PRELOAD": "/tmp/libhack.so"},
            "timeout_ms": 1000
        });
        let result = parse_shell_exec_params(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not allowed"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_shell_exec_params_accepts_safe_values() {
        let raw = json!({
            "command": "echo hello",
            "cwd": "project",
            "env": {"SAFE_KEY": "value"},
            "timeout_ms": 1000
        });
        let result = parse_shell_exec_params(&raw);
        assert!(result.is_ok());
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_accessibility_query_params_accepts_defaults() {
        let raw = json!({});
        let result = parse_accessibility_query_params(&raw);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.destination, "org.a11y.atspi.Registry");
        assert_eq!(parsed.method, "GetChildren");
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_accessibility_query_params_rejects_non_allowlisted_method() {
        let raw = json!({
            "destination": "org.a11y.atspi.Registry",
            "object_path": "/org/a11y/atspi/accessible/root",
            "interface": "org.a11y.atspi.Accessible",
            "method": "DoAction"
        });
        let result = parse_accessibility_query_params(&raw);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("read-only allowlist"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_accessibility_query_params_rejects_non_desktop_env() {
        let raw = json!({
            "method": "GetChildren",
            "env": {"RUST_LOG": "debug"}
        });
        let result = parse_accessibility_query_params(&raw);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("desktop capabilities"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_screenshot_capture_params_region_requires_rect() {
        let raw = json!({
            "mode": "region"
        });
        let result = parse_screenshot_capture_params(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires rect"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_screenshot_capture_params_rejects_zero_size_rect() {
        let raw = json!({
            "mode": "region",
            "rect": {"x": 10, "y": 20, "width": 0, "height": 32}
        });
        let result = parse_screenshot_capture_params(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be > 0"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_screenshot_capture_params_target_node_requires_rect() {
        let raw = json!({
            "target": {
                "kind": "node",
                "node_id": "org.a11y.atspi.Registry|/org/a11y/atspi/accessible/1"
            }
        });
        let result = parse_screenshot_capture_params(&raw);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires rect from ui.node.inspect.v1 bounds"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_screenshot_capture_params_target_node_with_rect_ok() {
        let raw = json!({
            "target": {
                "kind": "node",
                "node_id": "org.a11y.atspi.Registry|/org/a11y/atspi/accessible/1",
                "rect": {"x": 10, "y": 20, "width": 300, "height": 200}
            }
        });
        let result = parse_screenshot_capture_params(&raw);
        assert!(result.is_ok());
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_enforce_desktop_backend_rejects_non_host_direct() {
        let result = enforce_desktop_backend("accessibility.query.v1", "linux-native");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("host-direct"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_enforce_desktop_backend_accepts_workstation_alias() {
        let result = enforce_desktop_backend("ui.windows.list.v1", "workstation");
        assert!(result.is_ok());
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_build_execution_plan_accessibility_uses_gdbus() {
        if !command_exists("gdbus") {
            return;
        }
        let request = IntentRequest::new("accessibility.query.v1", json!({}));
        let plan = build_execution_plan(&request, "trace-123", "host-direct", false).unwrap();

        assert_eq!(plan.cmd.program, "gdbus");
        assert!(matches!(plan.output_mode, ResponseOutputMode::Text));
        assert!(plan.cmd.args.contains(&"call".to_string()));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_build_execution_plan_accessibility_alias_supported() {
        if !command_exists("gdbus") {
            return;
        }
        let request = IntentRequest::new("ui.accessibility.query.v1", json!({}));
        let plan = build_execution_plan(&request, "trace-123", "host-direct", false).unwrap();
        assert_eq!(plan.cmd.program, "gdbus");
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_build_execution_plan_desktop_capability_rejects_non_host_backend() {
        let request = IntentRequest::new("accessibility.query.v1", json!({}));
        let result = build_execution_plan(&request, "trace-123", "linux-native", false);
        assert!(result.is_err());
        let err = result.err().expect("expected non-host backend rejection");
        assert!(err.to_string().contains("host-direct"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_ui_windows_list_params_rejects_invalid_limit() {
        let raw = json!({
            "limit": 0
        });
        let result = parse_ui_windows_list_params(&raw);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("between 1 and 500"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_ui_windows_list_params_defaults_backend_auto() {
        let raw = json!({});
        let result = parse_ui_windows_list_params(&raw).expect("params should parse");
        assert_eq!(result.compositor_backend, "auto");
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_ui_windows_list_params_rejects_invalid_compositor_backend() {
        let raw = json!({
            "compositor_backend": "not-a-backend"
        });
        let result = parse_ui_windows_list_params(&raw);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("compositor_backend must be one of"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_compositor_backend_mode_accepts_supported_values() {
        assert!(matches!(
            compositor::parse_backend_mode("auto").expect("auto should parse"),
            compositor::CompositorBackendMode::Auto
        ));
        assert!(matches!(
            compositor::parse_backend_mode("none").expect("none should parse"),
            compositor::CompositorBackendMode::None
        ));
        assert!(matches!(
            compositor::parse_backend_mode("hyprland").expect("hyprland should parse"),
            compositor::CompositorBackendMode::Explicit(compositor::CompositorBackend::Hyprland)
        ));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_resolve_compositor_backends_supports_none_backend() {
        let env = HashMap::new();
        let result = compositor::resolve_backends("none", &env).expect("resolve should succeed");
        assert!(result.is_empty());
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_ui_node_inspect_params_rejects_bad_node_id() {
        let raw = json!({
            "node_id": "bad-node-id"
        });
        let result = parse_ui_node_inspect_params(&raw);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("destination>|<object_path"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_parse_gdbus_refs_extracts_node_ids() {
        let raw = "( [( 'org.a11y.atspi.Registry', objectpath '/org/a11y/atspi/accessible/3') ], )";
        let refs = parse_gdbus_refs(raw);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].destination, "org.a11y.atspi.Registry");
        assert_eq!(refs[0].object_path, "/org/a11y/atspi/accessible/3");
        assert_eq!(
            refs[0].node_id,
            "org.a11y.atspi.Registry|/org/a11y/atspi/accessible/3"
        );
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_normalize_accessible_text_filters_empty_and_unnamed() {
        assert_eq!(normalize_accessible_text(None), None);
        assert_eq!(normalize_accessible_text(Some("".to_string())), None);
        assert_eq!(normalize_accessible_text(Some("Unnamed".to_string())), None);
        assert_eq!(
            normalize_accessible_text(Some("  Home  ".to_string())),
            Some("Home".to_string())
        );
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_merge_compositor_windows_enriches_matching_atspi_window() {
        let mut windows = vec![UiWindowRecord {
            window_id: ":1.6|/window/1".to_string(),
            destination: ":1.6".to_string(),
            object_path: "/window/1".to_string(),
            title: None,
            role: Some("window".to_string()),
            bounds: Some(UiBounds {
                x: 0,
                y: 0,
                width: 100,
                height: 80,
            }),
            source: Some("atspi".to_string()),
            inspectable: Some(true),
            app_id: Some("com.mitchellh.ghostty".to_string()),
            class_name: None,
            workspace: None,
        }];

        let hypr = UiWindowRecord {
            window_id: "hyprland|/client/0xabc".to_string(),
            destination: "hyprland".to_string(),
            object_path: "/client/0xabc".to_string(),
            title: Some("Shell".to_string()),
            role: Some("window".to_string()),
            bounds: Some(UiBounds {
                x: 0,
                y: 0,
                width: 100,
                height: 80,
            }),
            source: Some("hyprland".to_string()),
            inspectable: Some(false),
            app_id: Some("com.mitchellh.ghostty".to_string()),
            class_name: Some("com.mitchellh.ghostty".to_string()),
            workspace: Some("2 (2)".to_string()),
        };

        compositor::merge_windows(&mut windows, vec![hypr]);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].title.as_deref(), Some("Shell"));
        assert_eq!(
            windows[0].class_name.as_deref(),
            Some("com.mitchellh.ghostty")
        );
        assert_eq!(windows[0].workspace.as_deref(), Some("2 (2)"));
        assert_eq!(windows[0].source.as_deref(), Some("atspi+compositor"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_merge_compositor_windows_appends_unmatched_window() {
        let mut windows = vec![];
        let hypr = UiWindowRecord {
            window_id: "hyprland|/client/0xdef".to_string(),
            destination: "hyprland".to_string(),
            object_path: "/client/0xdef".to_string(),
            title: Some("Brave".to_string()),
            role: Some("window".to_string()),
            bounds: Some(UiBounds {
                x: 10,
                y: 10,
                width: 200,
                height: 120,
            }),
            source: Some("hyprland".to_string()),
            inspectable: Some(false),
            app_id: Some("brave-browser".to_string()),
            class_name: Some("brave-browser".to_string()),
            workspace: Some("2 (2)".to_string()),
        };

        compositor::merge_windows(&mut windows, vec![hypr]);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].inspectable, Some(false));
        assert_eq!(windows[0].source.as_deref(), Some("hyprland"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_merge_compositor_windows_does_not_match_non_inspectable_targets() {
        let mut windows = vec![UiWindowRecord {
            window_id: "hyprland|/client/0x111".to_string(),
            destination: "hyprland".to_string(),
            object_path: "/client/0x111".to_string(),
            title: Some("Existing".to_string()),
            role: Some("window".to_string()),
            bounds: Some(UiBounds {
                x: 0,
                y: 0,
                width: 100,
                height: 80,
            }),
            source: Some("hyprland".to_string()),
            inspectable: Some(false),
            app_id: Some("brave-browser".to_string()),
            class_name: Some("brave-browser".to_string()),
            workspace: Some("2 (2)".to_string()),
        }];

        let hypr = UiWindowRecord {
            window_id: "hyprland|/client/0x222".to_string(),
            destination: "hyprland".to_string(),
            object_path: "/client/0x222".to_string(),
            title: Some("New".to_string()),
            role: Some("window".to_string()),
            bounds: Some(UiBounds {
                x: 0,
                y: 0,
                width: 100,
                height: 80,
            }),
            source: Some("hyprland".to_string()),
            inspectable: Some(false),
            app_id: Some("brave-browser".to_string()),
            class_name: Some("brave-browser".to_string()),
            workspace: Some("2 (2)".to_string()),
        };

        compositor::merge_windows(&mut windows, vec![hypr]);
        assert_eq!(windows.len(), 2);
        assert!(windows.iter().all(|w| w.inspectable == Some(false)));
        assert!(windows
            .iter()
            .all(|w| w.source.as_deref() == Some("hyprland")));
    }

    #[test]
    fn test_log_daemon_startup_demo_mode() {
        // Just verify it doesn't panic
        log_daemon_startup(true);
    }

    #[test]
    fn test_log_daemon_startup_normal_mode() {
        // Just verify it doesn't panic
        log_daemon_startup(false);
    }

    #[test]
    fn test_daemon_services_struct() {
        // Test struct can be created (requires async context in real usage)
        assert!(std::mem::size_of::<DaemonServices>() > 0);
    }

    #[test]
    fn test_nats_clients_struct() {
        assert!(std::mem::size_of::<NatsClients>() > 0);
    }

    #[test]
    fn test_execution_components_struct() {
        assert!(std::mem::size_of::<ExecutionComponents>() > 0);
    }

    #[test]
    fn test_daemon_command_struct() {
        let _cmd = DaemonCommand;
        assert!(std::mem::size_of::<DaemonCommand>() == 0); // Zero-sized type
    }
}
