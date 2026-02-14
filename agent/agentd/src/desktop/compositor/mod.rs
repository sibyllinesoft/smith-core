#[cfg(feature = "grpc")]
mod hyprland;

#[cfg(feature = "grpc")]
use anyhow::{Context, Result};
#[cfg(feature = "grpc")]
use std::collections::HashMap;
#[cfg(feature = "grpc")]
use std::time::Duration;
#[cfg(feature = "grpc")]
use tokio::process::Command as TokioCommand;
#[cfg(feature = "grpc")]
use tracing::warn;

#[cfg(feature = "grpc")]
use crate::desktop::types::{UiBounds, UiWindowRecord};

#[cfg(feature = "grpc")]
pub(crate) const COMPOSITOR_ENV_KEYS: &[&str] = &[
    "HYPRLAND_INSTANCE_SIGNATURE",
    "SWAYSOCK",
    "I3SOCK",
    "NIRI_SOCKET",
];

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompositorBackend {
    Hyprland,
}

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompositorBackendMode {
    Auto,
    None,
    Explicit(CompositorBackend),
}

#[cfg(feature = "grpc")]
pub(crate) fn default_backend_name() -> String {
    "auto".to_string()
}

#[cfg(feature = "grpc")]
pub(crate) fn parse_backend_mode(raw: &str) -> Result<CompositorBackendMode> {
    match raw {
        "auto" => Ok(CompositorBackendMode::Auto),
        "none" => Ok(CompositorBackendMode::None),
        "hyprland" => Ok(CompositorBackendMode::Explicit(CompositorBackend::Hyprland)),
        _ => {
            anyhow::bail!("ui.windows.list compositor_backend must be one of: auto, none, hyprland")
        }
    }
}

#[cfg(feature = "grpc")]
pub(crate) const fn backend_name(backend: CompositorBackend) -> &'static str {
    match backend {
        CompositorBackend::Hyprland => "hyprland",
    }
}

#[cfg(feature = "grpc")]
pub(crate) fn applied_backend_names(backends: &[CompositorBackend]) -> Vec<&'static str> {
    backends
        .iter()
        .map(|backend| backend_name(*backend))
        .collect()
}

#[cfg(feature = "grpc")]
fn backend_is_supported(backend: CompositorBackend, env: &HashMap<String, String>) -> bool {
    match backend {
        CompositorBackend::Hyprland => {
            command_exists("hyprctl")
                && env
                    .get("HYPRLAND_INSTANCE_SIGNATURE")
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false)
        }
    }
}

#[cfg(feature = "grpc")]
fn detect_supported_backends(env: &HashMap<String, String>) -> Vec<CompositorBackend> {
    [CompositorBackend::Hyprland]
        .into_iter()
        .filter(|backend| backend_is_supported(*backend, env))
        .collect()
}

#[cfg(feature = "grpc")]
pub(crate) fn resolve_backends(
    requested_backend: &str,
    env: &HashMap<String, String>,
) -> Result<Vec<CompositorBackend>> {
    match parse_backend_mode(requested_backend)? {
        CompositorBackendMode::None => Ok(vec![]),
        CompositorBackendMode::Auto => Ok(detect_supported_backends(env)),
        CompositorBackendMode::Explicit(backend) => {
            if backend_is_supported(backend, env) {
                Ok(vec![backend])
            } else {
                warn!(
                    backend = backend_name(backend),
                    "Requested compositor backend is not supported in current session"
                );
                Ok(vec![])
            }
        }
    }
}

#[cfg(feature = "grpc")]
pub(crate) async fn collect_windows(
    backends: &[CompositorBackend],
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Vec<UiWindowRecord> {
    let mut windows = Vec::new();
    for backend in backends {
        let mut backend_windows = match backend {
            CompositorBackend::Hyprland => hyprland::collect_windows(env, timeout_ms).await,
        };
        windows.append(&mut backend_windows);
    }
    windows
}

#[cfg(feature = "grpc")]
fn bounds_equal(a: Option<&UiBounds>, b: Option<&UiBounds>) -> bool {
    matches!(
        (a, b),
        (Some(a), Some(b))
            if a.x == b.x && a.y == b.y && a.width == b.width && a.height == b.height
    )
}

#[cfg(feature = "grpc")]
pub(crate) fn merge_windows(
    windows: &mut Vec<UiWindowRecord>,
    compositor_windows: Vec<UiWindowRecord>,
) {
    for compositor_window in compositor_windows {
        let candidate_indexes: Vec<usize> = windows
            .iter()
            .enumerate()
            .filter(|(_, atspi)| atspi.inspectable.unwrap_or(true))
            .filter(|(_, atspi)| {
                bounds_equal(atspi.bounds.as_ref(), compositor_window.bounds.as_ref())
            })
            .map(|(index, _)| index)
            .collect();

        let compositor_class = compositor_window
            .class_name
            .as_deref()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        let compositor_title = compositor_window
            .title
            .as_deref()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();

        let mut matched_index: Option<usize> = None;
        for index in &candidate_indexes {
            let atspi = &windows[*index];
            let app_match = atspi
                .app_id
                .as_deref()
                .map(|app_id| {
                    let app_norm = app_id.to_ascii_lowercase();
                    !compositor_class.is_empty()
                        && (app_norm == compositor_class
                            || app_norm.contains(&compositor_class)
                            || compositor_class.contains(&app_norm))
                })
                .unwrap_or(false);
            let title_match = atspi
                .title
                .as_deref()
                .map(|title| {
                    !compositor_title.is_empty() && title.to_ascii_lowercase() == compositor_title
                })
                .unwrap_or(false);
            if app_match || title_match {
                matched_index = Some(*index);
                break;
            }
        }

        if matched_index.is_none() && candidate_indexes.len() == 1 {
            matched_index = candidate_indexes.first().copied();
        }

        if let Some(index) = matched_index {
            let atspi = &mut windows[index];
            if atspi.title.is_none() {
                atspi.title = compositor_window.title.clone();
            }
            if atspi.class_name.is_none() {
                atspi.class_name = compositor_window.class_name.clone();
            }
            if atspi.workspace.is_none() {
                atspi.workspace = compositor_window.workspace.clone();
            }
            atspi.inspectable = Some(true);
            atspi.source = Some("atspi+compositor".to_string());
            continue;
        }

        windows.push(compositor_window);
    }
}

#[cfg(feature = "grpc")]
pub(super) fn command_exists(name: &str) -> bool {
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
pub(super) async fn run_host_command(
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

    let child = cmd
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
