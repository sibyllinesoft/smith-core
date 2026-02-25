use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::time::timeout;

use crate::mcp_client::McpClient;
use crate::middleware::config::MiddlewareConfig;
use crate::middleware::filter::{evaluate_filters, FilterResult};
use crate::middleware::transform::{apply_input_transforms, apply_output_transforms};
use crate::AppState;

type SharedState = Arc<AppState>;

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

fn require_api_token(state: &SharedState, headers: &HeaderMap) -> Result<(), AppError> {
    let Some(expected) = state.api_token.as_ref() else {
        return Ok(());
    };

    let provided = extract_token(headers).unwrap_or_default();
    if provided == *expected {
        Ok(())
    } else {
        Err(AppError::Unauthorized(
            "missing or invalid API token".to_string(),
        ))
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/tools", get(list_tools))
        .route("/tools/:name", post(call_tool))
        .route("/resources", get(list_resources))
        .route("/resources/*uri", get(read_resource))
        .route("/reload", post(reload))
        .with_state(state)
}

async fn health(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    require_api_token(&state, &headers)?;

    let client = state.client.read().await;
    Ok(Json(json!({
        "status": "ok",
        "server_info": client.server_info,
        "tools_count": client.tools.len(),
    })))
}

async fn list_tools(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    require_api_token(&state, &headers)?;

    let client = state.client.read().await;
    let mw = state.middleware.read().await;

    let tools: Vec<_> = match mw.as_ref() {
        Some(mw) => client
            .tools
            .iter()
            .filter(|t| !mw.tools.get(&t.name).map(|tm| tm.hidden).unwrap_or(false))
            .collect(),
        None => client.tools.iter().collect(),
    };

    Ok(Json(json!(tools)))
}

async fn call_tool(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    require_api_token(&state, &headers)?;

    let client = state.client.read().await;

    // Check if tool exists
    if !client.tools.iter().any(|t| t.name == name) {
        return Err(AppError::NotFound(format!("tool not found: {name}")));
    }

    let mut arguments = if body.is_object() {
        body
    } else {
        Value::Object(serde_json::Map::new())
    };

    let mw = state.middleware.read().await;

    if let Some(mw) = mw.as_ref() {
        let tool_mw = mw.tools.get(&name);

        // Hidden check
        if tool_mw.map(|t| t.hidden).unwrap_or(false) {
            return Err(AppError::NotFound(format!("tool not found: {name}")));
        }

        // Global filters
        if let FilterResult::Deny(msg) = evaluate_filters(&arguments, &mw.global.filters) {
            return Err(AppError::Filtered(msg));
        }

        // Per-tool filters
        if let Some(tm) = tool_mw {
            if let FilterResult::Deny(msg) = evaluate_filters(&arguments, &tm.filters) {
                return Err(AppError::Filtered(msg));
            }
        }

        // Global input transforms
        apply_input_transforms(&mut arguments, &mw.global.input.transforms)
            .map_err(|e| AppError::TransformError(e.to_string()))?;

        // Per-tool input transforms
        if let Some(tm) = tool_mw {
            apply_input_transforms(&mut arguments, &tm.input.transforms)
                .map_err(|e| AppError::TransformError(e.to_string()))?;
        }
    }

    let call_future = client.call_tool(&name, arguments);
    let call_result = if let Some(dur) = state.call_timeout {
        match timeout(dur, call_future).await {
            Ok(inner) => inner,
            Err(_) => {
                return Err(AppError::McpServerError(format!(
                    "tool call '{name}' timed out after {}s",
                    dur.as_secs()
                )))
            }
        }
    } else {
        call_future.await
    };

    let mut result = match call_result {
        Ok(result) => result,
        Err(e) => {
            if e.downcast_ref::<crate::mcp_client::JsonRpcError>()
                .is_some()
            {
                return Err(AppError::ToolError(e.to_string()));
            } else {
                return Err(AppError::McpServerError(e.to_string()));
            }
        }
    };

    // Output transforms
    if let Some(mw) = mw.as_ref() {
        let tool_mw = mw.tools.get(&name);

        // Global output transforms
        apply_output_transforms(&mut result, &mw.global.output.transforms)
            .map_err(|e| AppError::TransformError(e.to_string()))?;

        // Per-tool output transforms
        if let Some(tm) = tool_mw {
            apply_output_transforms(&mut result, &tm.output.transforms)
                .map_err(|e| AppError::TransformError(e.to_string()))?;
        }
    }

    Ok(Json(result))
}

async fn list_resources(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    require_api_token(&state, &headers)?;

    let client = state.client.read().await;
    match client.list_resources().await {
        Ok(resources) => Ok(Json(json!(resources))),
        Err(e) => Err(AppError::McpServerError(e.to_string())),
    }
}

async fn read_resource(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(uri): Path<String>,
) -> Result<Json<Value>, AppError> {
    require_api_token(&state, &headers)?;

    let client = state.client.read().await;
    match client.read_resource(&uri).await {
        Ok(content) => Ok(Json(content)),
        Err(e) => Err(AppError::McpServerError(e.to_string())),
    }
}

// ── POST /reload ─────────────────────────────────────────────────────

async fn reload(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    require_api_token(&state, &headers)?;

    tracing::info!("reload requested — shutting down current MCP server");

    // Shut down the old client
    {
        let old_client = state.client.read().await;
        old_client.shutdown().await;
    }

    // Spawn a new client from the stored config
    let new_client = McpClient::spawn_from_config(&state.config)
        .await
        .map_err(|e| AppError::McpServerError(format!("reload failed: {e}")))?;

    let tools_count = new_client.tools.len();

    // Replace the client
    *state.client.write().await = new_client;

    // Reload middleware config if path is configured
    if let Some(ref path) = state.middleware_path {
        match MiddlewareConfig::load(path) {
            Ok(config) => {
                *state.middleware.write().await = Some(Arc::new(config));
                tracing::info!("middleware config reloaded");
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to reload middleware config, keeping old config");
            }
        }
    }

    tracing::info!(tools_count, "reload complete");
    Ok(Json(json!({
        "status": "reloaded",
        "tools_count": tools_count,
    })))
}

// ── Error handling ──────────────────────────────────────────────────────

enum AppError {
    Unauthorized(String),
    NotFound(String),
    ToolError(String),
    Filtered(String),
    TransformError(String),
    McpServerError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Self::ToolError(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            Self::Filtered(msg) => (StatusCode::FORBIDDEN, msg),
            Self::TransformError(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            Self::McpServerError(msg) => (StatusCode::BAD_GATEWAY, msg),
        };

        let body = json!({ "error": message });
        (status, Json(body)).into_response()
    }
}
