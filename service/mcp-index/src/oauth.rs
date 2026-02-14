use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::sync::Mutex;

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OAuthProvider {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub credential_dir: PathBuf,
}

pub struct OAuthState {
    pub providers: HashMap<String, OAuthProvider>,
    pub pending: Mutex<HashMap<String, PendingAuth>>,
}

pub struct PendingAuth {
    pub server: String,
    pub created_at: Instant,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[allow(dead_code)]
    access_token: String,
    refresh_token: Option<String>,
}

// ── Auth URL ────────────────────────────────────────────────────────────

pub fn build_auth_url(provider: &OAuthProvider, redirect_uri: &str, state_token: &str) -> String {
    let scopes = provider.scopes.join(" ");
    format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&access_type=offline&prompt=consent",
        provider.auth_url,
        urlencoding::encode(&provider.client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(state_token),
    )
}

// ── Token Exchange ──────────────────────────────────────────────────────

pub async fn exchange_code(
    http: &reqwest::Client,
    provider: &OAuthProvider,
    code: &str,
    redirect_uri: &str,
) -> Result<String> {
    let resp = http
        .post(&provider.token_url)
        .form(&[
            ("client_id", provider.client_id.as_str()),
            ("client_secret", provider.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .context("token exchange request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("token exchange returned {status}: {body}");
    }

    let token: TokenResponse = resp.json().await.context("failed to parse token response")?;
    token
        .refresh_token
        .context("no refresh_token in response (user may have already granted access — revoke and retry)")
}

// ── Credential Writer ───────────────────────────────────────────────────

pub async fn write_credentials(
    provider: &OAuthProvider,
    refresh_token: &str,
) -> Result<()> {
    tokio::fs::create_dir_all(&provider.credential_dir)
        .await
        .with_context(|| format!("failed to create credential dir: {:?}", provider.credential_dir))?;

    // Plain refresh token file (used by google-workspace MCP server)
    let token_path = provider.credential_dir.join("refresh_token");
    tokio::fs::write(&token_path, refresh_token.trim())
        .await
        .with_context(|| format!("failed to write refresh token to {token_path:?}"))?;

    // ADC-compatible authorized_user JSON (used by analytics-mcp and other ADC consumers)
    let adc = serde_json::json!({
        "type": "authorized_user",
        "client_id": provider.client_id,
        "client_secret": provider.client_secret,
        "refresh_token": refresh_token.trim(),
    });
    let adc_path = provider.credential_dir.join("credentials.json");
    tokio::fs::write(&adc_path, serde_json::to_string_pretty(&adc)?)
        .await
        .with_context(|| format!("failed to write ADC credentials to {adc_path:?}"))?;

    tracing::info!(?token_path, ?adc_path, "wrote Google credentials");
    Ok(())
}

// ── Credential Check ────────────────────────────────────────────────────

pub fn has_valid_credentials(provider: &OAuthProvider) -> bool {
    let token_path = provider.credential_dir.join("refresh_token");
    let adc_path = provider.credential_dir.join("credentials.json");
    // Either file having content means we have credentials
    std::fs::read_to_string(&token_path)
        .map(|c| !c.trim().is_empty())
        .unwrap_or(false)
        || std::fs::read_to_string(&adc_path)
            .map(|c| !c.trim().is_empty())
            .unwrap_or(false)
}

// ── Provider Factory ────────────────────────────────────────────────────

pub fn google_provider_from_env(credentials_dir: &Path) -> Option<OAuthProvider> {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").ok().filter(|s| !s.is_empty())?;
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").ok().filter(|s| !s.is_empty())?;

    Some(OAuthProvider {
        name: "google".to_string(),
        client_id,
        client_secret,
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
        token_url: "https://oauth2.googleapis.com/token".to_string(),
        scopes: vec![
            "https://www.googleapis.com/auth/gmail.modify".to_string(),
            "https://www.googleapis.com/auth/calendar".to_string(),
            "https://www.googleapis.com/auth/drive".to_string(),
            "https://www.googleapis.com/auth/analytics.readonly".to_string(),
        ],
        credential_dir: credentials_dir.join("google"),
    })
}

// ── Pending Auth Cleanup ────────────────────────────────────────────────

const PENDING_TTL_SECS: u64 = 1800; // 30 minutes

impl OAuthState {
    pub fn new(providers: HashMap<String, OAuthProvider>) -> Self {
        Self {
            providers,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub async fn insert_pending(&self, token: String, server: String) {
        let mut pending = self.pending.lock().await;
        // Evict expired entries
        pending.retain(|_, v| v.created_at.elapsed().as_secs() < PENDING_TTL_SECS);
        pending.insert(token, PendingAuth {
            server,
            created_at: Instant::now(),
        });
    }

    pub async fn take_pending(&self, token: &str) -> Option<PendingAuth> {
        let mut pending = self.pending.lock().await;
        let entry = pending.remove(token)?;
        if entry.created_at.elapsed().as_secs() >= PENDING_TTL_SECS {
            return None; // expired
        }
        Some(entry)
    }
}
