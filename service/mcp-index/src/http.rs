use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::oauth;
use crate::poller::IndexState;

type AppState = Arc<IndexState>;

fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(authz) = headers.get(header::AUTHORIZATION) {
        if let Ok(authz) = authz.to_str() {
            if let Some(rest) = authz.strip_prefix("Bearer ") {
                return Some(rest.trim().to_string());
            }
            if let Some(rest) = authz.strip_prefix("bearer ") {
                return Some(rest.trim().to_string());
            }
        }
    }

    headers
        .get("x-smith-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().to_string())
}

fn require_api_token(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<Value>)> {
    let Some(expected) = state.api_token.as_ref() else {
        return Ok(());
    };

    let provided = extract_token(headers).unwrap_or_default();
    if provided == *expected {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid API token" })),
        ))
    }
}

pub fn router(state: Arc<IndexState>) -> Router {
    Router::new()
        .route("/", get(index_html))
        .route("/health", get(health))
        .route("/api/servers", get(servers))
        .route("/api/tools", get(tools))
        .route("/api/tools/search", get(tools_search))
        .route("/api/tools/call", post(tools_call))
        .route("/api/auth/start", get(auth_start))
        .route("/api/auth/callback", get(auth_callback))
        .with_state(state)
}

// ── GET / ─────────────────────────────────────────────────────────────

async fn index_html() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

// ── GET /health ─────────────────────────────────────────────────────────

async fn health(State(state): State<AppState>) -> Json<Value> {
    let servers = state.servers.read().await;
    let total = servers.len();
    let healthy = servers.iter().filter(|s| s.healthy).count();
    let tools_total: usize = servers
        .iter()
        .filter(|s| s.healthy)
        .map(|s| s.tools_count)
        .sum();

    Json(json!({
        "status": "ok",
        "servers_total": total,
        "servers_healthy": healthy,
        "servers_unhealthy": total - healthy,
        "tools_total": tools_total,
    }))
}

// ── GET /api/servers ────────────────────────────────────────────────────

async fn servers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_api_token(&state, &headers)?;
    let servers = state.servers.read().await;
    Ok(Json(json!(*servers)))
}

// ── GET /api/tools ──────────────────────────────────────────────────────

async fn tools(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_api_token(&state, &headers)?;
    let servers = state.servers.read().await;
    let all_tools: Vec<_> = servers
        .iter()
        .filter(|s| s.healthy)
        .flat_map(|s| s.tools.iter().cloned())
        .collect();
    Ok(Json(json!(all_tools)))
}

// ── GET /api/tools/search?q=&server= ────────────────────────────────────

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
    server: Option<String>,
}

async fn tools_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_api_token(&state, &headers)?;

    let q = match &params.q {
        Some(q) if !q.is_empty() => q.to_lowercase(),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing required query parameter: q" })),
            ));
        }
    };

    let servers = state.servers.read().await;
    let results: Vec<_> = servers
        .iter()
        .filter(|s| s.healthy)
        .filter(|s| {
            params
                .server
                .as_ref()
                .map_or(true, |srv| s.name.eq_ignore_ascii_case(srv))
        })
        .flat_map(|s| s.tools.iter().cloned())
        .filter(|t| {
            t.name.to_lowercase().contains(&q)
                || t.description
                    .as_ref()
                    .is_some_and(|d| d.to_lowercase().contains(&q))
        })
        .collect();

    Ok(Json(json!(results)))
}

// ── POST /api/tools/call ──────────────────────────────────────────────

#[derive(Deserialize)]
struct ToolCallRequest {
    server: String,
    tool: String,
    #[serde(default)]
    arguments: Value,
}

async fn tools_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ToolCallRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_api_token(&state, &headers)?;

    let servers = state.servers.read().await;

    // Find the server
    let server = servers
        .iter()
        .find(|s| s.name == req.server)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("server '{}' not found", req.server) })),
            )
        })?;

    if !server.healthy {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("server '{}' is not healthy", req.server) })),
        ));
    }

    // Validate tool exists on this server
    if !server.tools.iter().any(|t| t.name == req.tool) {
        return Err((
            StatusCode::NOT_FOUND,
            Json(
                json!({ "error": format!("tool '{}' not found on server '{}'", req.tool, req.server) }),
            ),
        ));
    }

    let upstream_url = format!("{}/tools/{}", server.url, req.tool);
    // Drop the read lock before making the HTTP call
    drop(servers);

    let resp = state
        .client
        .post(&upstream_url)
        .json(&req.arguments)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("upstream request failed: {e}") })),
            )
        })?;

    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .unwrap_or_else(|e| json!({ "error": format!("failed to parse upstream response: {e}") }));

    if status.is_success() {
        Ok(Json(body))
    } else {
        Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(body),
        ))
    }
}

// ── GET /api/auth/start?server= ─────────────────────────────────────────

#[derive(Deserialize)]
struct AuthStartQuery {
    server: String,
}

async fn auth_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuthStartQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_api_token(&state, &headers)?;

    let provider = state.oauth.providers.get(&params.server).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("no OAuth provider for server '{}'", params.server) })),
        )
    })?;

    let state_token = uuid::Uuid::new_v4().to_string();
    state
        .oauth
        .insert_pending(state_token.clone(), params.server.clone())
        .await;

    let redirect_uri = format!("{}/api/auth/callback", state.base_url);
    let url = oauth::build_auth_url(provider, &redirect_uri, &state_token);

    Ok(Json(json!({ "url": url })))
}

// ── GET /api/auth/callback?code=&state= ─────────────────────────────────

#[derive(Deserialize)]
struct AuthCallbackQuery {
    code: String,
    state: String,
}

async fn auth_callback(
    State(state): State<AppState>,
    Query(params): Query<AuthCallbackQuery>,
) -> Html<String> {
    // Validate CSRF state token
    let pending = match state.oauth.take_pending(&params.state).await {
        Some(p) => p,
        None => return auth_error_page("Invalid or expired state token. Please try again."),
    };

    let provider = match state.oauth.providers.get(&pending.server) {
        Some(p) => p.clone(),
        None => return auth_error_page("OAuth provider configuration not found."),
    };

    let redirect_uri = format!("{}/api/auth/callback", state.base_url);

    // Exchange code for tokens
    let refresh_token =
        match oauth::exchange_code(&state.client, &provider, &params.code, &redirect_uri).await {
            Ok(t) => t,
            Err(e) => return auth_error_page(&format!("Token exchange failed: {e}")),
        };

    // Write credentials to shared volume
    if let Err(e) = oauth::write_credentials(&provider, &refresh_token).await {
        return auth_error_page(&format!("Failed to write credentials: {e}"));
    }

    // Trigger reload on the upstream shim
    let upstream = state.upstreams.iter().find(|u| u.name == pending.server);
    if let Some(upstream) = upstream {
        let reload_url = format!("{}/reload", upstream.url);
        match state.client.post(&reload_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(server = %pending.server, "triggered shim reload");
            }
            Ok(resp) => {
                tracing::warn!(server = %pending.server, status = %resp.status(), "shim reload returned non-200");
            }
            Err(e) => {
                tracing::warn!(server = %pending.server, error = %e, "failed to trigger shim reload");
            }
        }
    }

    auth_success_page(&pending.server)
}

fn auth_success_page(server: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html><head><meta charset="UTF-8"><title>OAuth Complete</title>
<style>body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a0a0a;color:#e5e5e5}}
.card{{text-align:center;padding:40px;border-radius:12px;background:#1a1a1a;border:1px solid #333}}
.check{{color:#22c55e;font-size:48px;margin-bottom:16px}}
p{{margin:8px 0;color:#a3a3a3}}</style></head>
<body><div class="card">
<div class="check">&#10003;</div>
<h2>Connected to {server}</h2>
<p>This window will close automatically.</p>
</div>
<script>
window.opener?.postMessage({{ type: 'oauth-complete', server: '{server}' }}, '*');
setTimeout(() => window.close(), 1500);
</script></body></html>"#,
        server = server,
    ))
}

fn auth_error_page(error: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html><head><meta charset="UTF-8"><title>OAuth Error</title>
<style>body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a0a0a;color:#e5e5e5}}
.card{{text-align:center;padding:40px;border-radius:12px;background:#1a1a1a;border:1px solid #333;max-width:400px}}
.x{{color:#ef4444;font-size:48px;margin-bottom:16px}}
p{{margin:8px 0;color:#a3a3a3;word-break:break-word}}</style></head>
<body><div class="card">
<div class="x">&#10007;</div>
<h2>Authentication Failed</h2>
<p>{error}</p>
<p style="margin-top:20px"><a href="javascript:window.close()" style="color:#60a5fa">Close window</a></p>
</div></body></html>"#,
        error = error,
    ))
}
