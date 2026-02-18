//! Microsoft Teams Gateway that polls the Graph API for channel messages and
//! publishes them to NATS as BridgeMessageEnvelope payloads.
//!
//! Uses client credentials OAuth flow (Azure AD app registration) to authenticate.
//! Polls `/teams/{team-id}/channels/{channel-id}/messages/delta` for incremental updates.

use anyhow::{Context, Result};
use chat_bridge::gateway_common::{build_envelope, connect_nats, GatewayContext, SenderInfo};
use chrono::{Duration, Utc};
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration as TokioDuration};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Microsoft Teams Gateway → NATS bridge for Smith"
)]
struct Cli {
    /// Azure AD tenant ID
    #[arg(long, env = "TEAMS_TENANT_ID")]
    tenant_id: String,

    /// Azure AD application (client) ID
    #[arg(long, env = "TEAMS_CLIENT_ID")]
    client_id: String,

    /// Azure AD client secret
    #[arg(long, env = "TEAMS_CLIENT_SECRET")]
    client_secret: String,

    /// Teams team ID to monitor
    #[arg(long, env = "TEAMS_TEAM_ID")]
    team_id: String,

    /// Teams channel ID to monitor
    #[arg(long, env = "TEAMS_CHANNEL_ID")]
    channel_id: String,

    /// NATS server URL
    #[arg(long, env = "SMITH_NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// NATS subject to publish bridge envelopes to
    #[arg(
        long,
        env = "CHAT_BRIDGE_INGEST_SUBJECT",
        default_value = "smith.chatbridge.ingest"
    )]
    ingest_subject: String,

    /// Optional shared secret included in envelopes
    #[arg(long, env = "CHAT_BRIDGE_EVENT_SECRET")]
    event_secret: Option<String>,

    /// Polling interval in seconds
    #[arg(long, env = "TEAMS_POLL_INTERVAL_SECS", default_value_t = 5)]
    poll_interval_secs: u64,
}

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    value: Vec<Value>,
    #[serde(default, rename = "@odata.deltaLink")]
    delta_link: Option<String>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
}

struct TeamsState {
    token_cache: RwLock<Option<CachedToken>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();

    let cli = Cli::parse();
    let nats = connect_nats(&cli.nats_url).await?;
    let http = reqwest::Client::new();

    let gw = GatewayContext {
        nats,
        ingest_subject: cli.ingest_subject.clone(),
        event_secret: cli.event_secret.clone(),
        platform: "teams",
    };

    let state = Arc::new(TeamsState {
        token_cache: RwLock::new(None),
    });

    let poll_interval = TokioDuration::from_secs(cli.poll_interval_secs);

    info!(
        team_id = %cli.team_id,
        channel_id = %cli.channel_id,
        interval_secs = cli.poll_interval_secs,
        "Starting Teams polling loop"
    );

    // Initial delta link: fetch recent messages to get a starting point
    let mut delta_link: Option<String> = None;
    let mut consecutive_errors: u32 = 0;

    loop {
        match poll_messages(&cli, &http, &gw, &state, delta_link.as_deref()).await {
            Ok(new_delta) => {
                delta_link = new_delta.or(delta_link);
                consecutive_errors = 0;
            }
            Err(err) => {
                consecutive_errors += 1;
                let backoff = TokioDuration::from_secs((2u64).pow(consecutive_errors.min(5)));
                error!(
                    error = ?err,
                    consecutive_errors,
                    backoff_secs = backoff.as_secs(),
                    "Teams poll failed"
                );
                sleep(backoff).await;
                continue;
            }
        }
        sleep(poll_interval).await;
    }
}

async fn get_access_token(cli: &Cli, http: &reqwest::Client, state: &TeamsState) -> Result<String> {
    {
        let guard = state.token_cache.read().await;
        if let Some(token) = guard.as_ref() {
            if token.expires_at > Utc::now() + Duration::seconds(30) {
                return Ok(token.access_token.clone());
            }
        }
    }

    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        cli.tenant_id
    );

    let resp = http
        .post(&token_url)
        .form(&[
            ("client_id", cli.client_id.as_str()),
            ("client_secret", cli.client_secret.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .context("failed to request Teams access token")?;

    let payload: TokenResponse = resp.json().await?;
    let access_token = payload
        .access_token
        .ok_or_else(|| anyhow::anyhow!("missing access_token in Teams OAuth response"))?;
    let ttl = payload.expires_in.unwrap_or(3600).saturating_sub(60);

    let mut guard = state.token_cache.write().await;
    *guard = Some(CachedToken {
        access_token: access_token.clone(),
        expires_at: Utc::now() + Duration::seconds(ttl),
    });

    Ok(access_token)
}

async fn poll_messages(
    cli: &Cli,
    http: &reqwest::Client,
    gw: &GatewayContext,
    state: &TeamsState,
    delta_link: Option<&str>,
) -> Result<Option<String>> {
    let token = get_access_token(cli, http, state).await?;

    let url = if let Some(link) = delta_link {
        link.to_string()
    } else {
        format!(
            "https://graph.microsoft.com/v1.0/teams/{}/channels/{}/messages/delta",
            cli.team_id, cli.channel_id
        )
    };

    let resp = http
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .context("Teams Graph API request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Teams messages delta returned {status}: {body}");
    }

    let page: MessagesResponse = resp.json().await?;
    let mut new_delta = page.delta_link;

    // Process messages
    for msg in &page.value {
        if let Err(err) = handle_graph_message(cli, gw, msg).await {
            warn!(error = ?err, "Failed to handle Teams message");
        }
    }

    // Handle pagination
    if let Some(next_link) = page.next_link {
        // More pages to fetch — recursively get them
        if let Ok(more_delta) = Box::pin(poll_messages_url(cli, http, gw, state, &next_link)).await
        {
            new_delta = more_delta.or(new_delta);
        }
    }

    Ok(new_delta)
}

async fn poll_messages_url(
    cli: &Cli,
    http: &reqwest::Client,
    gw: &GatewayContext,
    state: &TeamsState,
    url: &str,
) -> Result<Option<String>> {
    let token = get_access_token(cli, http, state).await?;

    let resp = http.get(url).bearer_auth(&token).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Teams pagination request failed: {}", resp.status());
    }

    let page: MessagesResponse = resp.json().await?;
    for msg in &page.value {
        if let Err(err) = handle_graph_message(cli, gw, msg).await {
            warn!(error = ?err, "Failed to handle Teams message (paginated)");
        }
    }

    Ok(page.delta_link)
}

async fn handle_graph_message(cli: &Cli, gw: &GatewayContext, msg: &Value) -> Result<()> {
    let body = msg.get("body");
    let content = body
        .and_then(|b| b.get("content"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if content.is_empty() {
        return Ok(());
    }

    let message_id = msg.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let reply_to = msg
        .get("replyToId")
        .and_then(|v| v.as_str())
        .unwrap_or(message_id);

    let from = msg.get("from").and_then(|f| f.get("user"));
    let sender_id = from
        .and_then(|u| u.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let display_name = from
        .and_then(|u| u.get("displayName"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Skip system/application messages
    if msg.get("from").and_then(|f| f.get("application")).is_some() {
        debug!("Skipping application message");
        return Ok(());
    }

    let sender = SenderInfo {
        id: sender_id.to_string(),
        username: None,
        display_name,
        is_bot: false,
    };

    let envelope = build_envelope(
        "teams",
        &cli.team_id,
        &cli.channel_id,
        message_id,
        reply_to,
        content,
        &sender,
        gw.event_secret.as_deref(),
        Vec::new(),
        Vec::new(),
    );

    info!(
        message_id,
        sender = sender_id,
        content_len = content.len(),
        "Publishing Teams message to NATS"
    );

    gw.publish_envelope(envelope).await?;
    Ok(())
}
