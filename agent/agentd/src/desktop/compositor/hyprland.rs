#[cfg(feature = "grpc")]
use std::collections::HashMap;
#[cfg(feature = "grpc")]
use tracing::warn;

#[cfg(feature = "grpc")]
use crate::desktop::types::{UiBounds, UiWindowRecord};

#[cfg(feature = "grpc")]
use super::{command_exists, run_host_command};

#[cfg(feature = "grpc")]
#[derive(Debug, serde::Deserialize)]
struct HyprWorkspace {
    id: i32,
    name: String,
}

#[cfg(feature = "grpc")]
#[derive(Debug, serde::Deserialize)]
struct HyprClient {
    address: String,
    mapped: bool,
    hidden: bool,
    at: Vec<i32>,
    size: Vec<i32>,
    class: Option<String>,
    title: Option<String>,
    workspace: Option<HyprWorkspace>,
}

#[cfg(feature = "grpc")]
fn normalize_window_text(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(feature = "grpc")]
fn parse_bounds(client: &HyprClient) -> Option<UiBounds> {
    if client.at.len() < 2 || client.size.len() < 2 {
        return None;
    }
    let width = u32::try_from(client.size[0]).ok()?;
    let height = u32::try_from(client.size[1]).ok()?;
    if width == 0 || height == 0 {
        return None;
    }
    Some(UiBounds {
        x: client.at[0],
        y: client.at[1],
        width,
        height,
    })
}

#[cfg(feature = "grpc")]
pub(super) async fn collect_windows(
    env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Vec<UiWindowRecord> {
    if !command_exists("hyprctl") {
        return vec![];
    }
    if env
        .get("HYPRLAND_INSTANCE_SIGNATURE")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        return vec![];
    }

    let args = vec!["-j".to_string(), "clients".to_string()];
    let (exit_code, stdout, stderr) =
        match run_host_command("hyprctl", &args, env, timeout_ms).await {
            Ok(output) => output,
            Err(err) => {
                warn!(error = %err, "Failed to query Hyprland clients");
                return vec![];
            }
        };

    if exit_code != 0 {
        warn!(
            exit_code,
            stderr = %stderr.trim(),
            "hyprctl clients query failed"
        );
        return vec![];
    }

    let clients: Vec<HyprClient> = match serde_json::from_str::<Vec<HyprClient>>(&stdout) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(error = %err, "Failed to parse hyprctl clients JSON");
            return vec![];
        }
    };

    clients
        .into_iter()
        .filter(|client| client.mapped && !client.hidden)
        .filter_map(|client| {
            let bounds = parse_bounds(&client)?;
            let workspace = client
                .workspace
                .as_ref()
                .map(|ws| format!("{} ({})", ws.name, ws.id));
            let class_name = normalize_window_text(client.class.clone());
            let title = normalize_window_text(client.title.clone());
            Some(UiWindowRecord {
                window_id: format!("hyprland|/client/{}", client.address),
                destination: "hyprland".to_string(),
                object_path: format!("/client/{}", client.address),
                title,
                role: Some("window".to_string()),
                bounds: Some(bounds),
                source: Some("hyprland".to_string()),
                inspectable: Some(false),
                app_id: class_name.clone(),
                class_name,
                workspace,
            })
        })
        .collect()
}
