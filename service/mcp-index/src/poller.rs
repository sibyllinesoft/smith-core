use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::oauth::OAuthState;

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Upstream {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerEntry {
    pub name: String,
    pub url: String,
    pub healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<Value>,
    pub tools_count: usize,
    pub tools: Vec<ToolEntry>,
    pub last_polled: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub auth_type: String,
    pub needs_auth: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    pub server: String,
}

pub struct IndexState {
    pub servers: RwLock<Vec<ServerEntry>>,
    pub upstreams: Vec<Upstream>,
    pub client: reqwest::Client,
    pub oauth: Arc<OAuthState>,
    pub base_url: String,
    pub api_token: Option<String>,
    pub upstream_api_token: Option<String>,
}

// ── Upstream health response ────────────────────────────────────────────

#[derive(Deserialize)]
struct HealthResponse {
    server_info: Option<Value>,
    #[allow(dead_code)]
    tools_count: Option<usize>,
}

#[derive(Deserialize)]
struct McpTool {
    name: String,
    description: Option<String>,
    #[serde(rename = "inputSchema")]
    input_schema: Option<Value>,
}

// ── Parsing ─────────────────────────────────────────────────────────────

/// Parse upstream string like "fs=http://mcp-fs:9100,gh=http://mcp-gh:9100"
pub fn parse_upstreams(input: &str) -> Vec<Upstream> {
    input
        .split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            let (name, url) = pair.split_once('=')?;
            Some(Upstream {
                name: name.trim().to_string(),
                url: url.trim().trim_end_matches('/').to_string(),
            })
        })
        .collect()
}

// ── Poller ──────────────────────────────────────────────────────────────

pub fn spawn_poller(state: Arc<IndexState>, interval: Duration) {
    tokio::spawn(async move {
        loop {
            poll_all(&state.client, &state).await;
            tokio::time::sleep(interval).await;
        }
    });
}

async fn poll_all(client: &reqwest::Client, state: &IndexState) {
    let mut entries = Vec::with_capacity(state.upstreams.len());

    for upstream in &state.upstreams {
        let mut entry = poll_one(client, upstream, state.upstream_api_token.as_deref()).await;

        // Set auth fields based on OAuth provider config
        if let Some(provider) = state.oauth.providers.get(&upstream.name) {
            entry.auth_type = "oauth".to_string();
            entry.needs_auth = !crate::oauth::has_valid_credentials(provider);
        }

        tracing::info!(
            server = %entry.name,
            healthy = entry.healthy,
            tools = entry.tools_count,
            auth_type = %entry.auth_type,
            needs_auth = entry.needs_auth,
            "polled upstream"
        );
        entries.push(entry);
    }

    *state.servers.write().await = entries;
}

async fn poll_one(
    client: &reqwest::Client,
    upstream: &Upstream,
    upstream_api_token: Option<&str>,
) -> ServerEntry {
    let now = chrono_now();

    // Fetch health
    let health_url = format!("{}/health", upstream.url);
    let health = match authed_request(client.get(&health_url), upstream_api_token)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<HealthResponse>().await {
            Ok(h) => Some(h),
            Err(e) => {
                return make_error_entry(upstream, &now, format!("health parse error: {e}"));
            }
        },
        Ok(resp) => {
            return make_error_entry(upstream, &now, format!("health returned {}", resp.status()));
        }
        Err(e) => {
            return make_error_entry(upstream, &now, format!("health fetch error: {e}"));
        }
    };

    // Fetch tools
    let tools_url = format!("{}/tools", upstream.url);
    let tools: Vec<McpTool> = match authed_request(client.get(&tools_url), upstream_api_token)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                return make_error_entry(upstream, &now, format!("tools parse error: {e}"));
            }
        },
        Ok(resp) => {
            return make_error_entry(upstream, &now, format!("tools returned {}", resp.status()));
        }
        Err(e) => {
            return make_error_entry(upstream, &now, format!("tools fetch error: {e}"));
        }
    };

    let health = health.unwrap();
    let tool_entries: Vec<ToolEntry> = tools
        .into_iter()
        .map(|t| ToolEntry {
            name: t.name,
            description: t.description,
            input_schema: t.input_schema,
            server: upstream.name.clone(),
        })
        .collect();

    ServerEntry {
        name: upstream.name.clone(),
        url: upstream.url.clone(),
        healthy: true,
        server_info: health.server_info,
        tools_count: tool_entries.len(),
        tools: tool_entries,
        last_polled: now,
        error: None,
        auth_type: "none".to_string(),
        needs_auth: false,
    }
}

fn authed_request(
    request: reqwest::RequestBuilder,
    upstream_api_token: Option<&str>,
) -> reqwest::RequestBuilder {
    if let Some(token) = upstream_api_token {
        request
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .header("x-smith-token", token)
    } else {
        request
    }
}

fn make_error_entry(upstream: &Upstream, now: &str, error: String) -> ServerEntry {
    ServerEntry {
        name: upstream.name.clone(),
        url: upstream.url.clone(),
        healthy: false,
        server_info: None,
        tools_count: 0,
        tools: vec![],
        last_polled: now.to_string(),
        error: Some(error),
        auth_type: "none".to_string(),
        needs_auth: false,
    }
}

fn chrono_now() -> String {
    // Use a simple approach without pulling in chrono
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s", now.as_secs())
}
