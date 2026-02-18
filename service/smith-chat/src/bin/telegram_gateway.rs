//! Telegram Gateway that polls the Bot API's `getUpdates` endpoint for incoming
//! messages and publishes them to NATS as BridgeMessageEnvelope payloads.

use anyhow::{Context, Result};
use chat_bridge::gateway_common::{build_envelope, connect_nats, GatewayContext, SenderInfo};
use clap::Parser;
use serde::Deserialize;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(author, version, about = "Telegram Gateway → NATS bridge for Smith")]
struct Cli {
    /// Telegram Bot API token (from @BotFather)
    #[arg(long, env = "TELEGRAM_BOT_TOKEN")]
    bot_token: String,

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

    /// Long-poll timeout in seconds (Telegram server holds connection open)
    #[arg(long, env = "TELEGRAM_POLL_TIMEOUT_SECS", default_value_t = 30)]
    poll_timeout_secs: u64,

    /// Comma-separated list of allowed Telegram user IDs (empty = allow all)
    #[arg(long, env = "TELEGRAM_ALLOWED_USER_IDS", value_delimiter = ',')]
    allowed_user_ids: Vec<i64>,
}

#[derive(Debug, Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    description: Option<String>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct TelegramUpdate {
    update_id: i64,
    #[serde(default)]
    message: Option<TelegramMessage>,
}

#[derive(Debug, Deserialize)]
struct TelegramMessage {
    message_id: i64,
    #[allow(dead_code)]
    date: i64,
    #[serde(default)]
    from: Option<TelegramUser>,
    #[serde(default)]
    chat: Option<TelegramChat>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    reply_to_message: Option<Box<TelegramReplyRef>>,
}

#[derive(Debug, Deserialize)]
struct TelegramUser {
    id: i64,
    #[serde(default)]
    is_bot: Option<bool>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramChat {
    id: i64,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    r#type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramReplyRef {
    message_id: i64,
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
        platform: "telegram",
    };

    info!("Starting Telegram polling loop");

    let mut offset: Option<i64> = None;
    let mut consecutive_errors: u32 = 0;

    loop {
        match poll_updates(&cli, &http, &gw, offset).await {
            Ok(new_offset) => {
                offset = new_offset;
                consecutive_errors = 0;
            }
            Err(err) => {
                consecutive_errors += 1;
                let backoff = Duration::from_secs((2u64).pow(consecutive_errors.min(5)));
                error!(
                    error = ?err,
                    consecutive_errors,
                    backoff_secs = backoff.as_secs(),
                    "Telegram poll failed"
                );
                sleep(backoff).await;
            }
        }
    }
}

async fn poll_updates(
    cli: &Cli,
    http: &reqwest::Client,
    gw: &GatewayContext,
    offset: Option<i64>,
) -> Result<Option<i64>> {
    let url = format!("https://api.telegram.org/bot{}/getUpdates", cli.bot_token);

    let mut query: Vec<(&str, String)> = vec![
        ("timeout", cli.poll_timeout_secs.to_string()),
        ("allowed_updates", r#"["message"]"#.to_string()),
    ];
    if let Some(off) = offset {
        query.push(("offset", off.to_string()));
    }

    let resp = http
        .get(&url)
        .query(&query)
        .timeout(Duration::from_secs(cli.poll_timeout_secs + 10))
        .send()
        .await
        .context("failed to call Telegram getUpdates")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Telegram getUpdates returned {status}: {body}");
    }

    let payload: TelegramResponse<Vec<TelegramUpdate>> = resp.json().await?;
    if !payload.ok {
        let desc = payload
            .description
            .unwrap_or_else(|| "unknown error".into());
        anyhow::bail!("Telegram getUpdates failed: {desc}");
    }

    let updates = payload.result.unwrap_or_default();
    let mut new_offset = offset;

    for update in &updates {
        // Track offset for next poll (highest update_id + 1)
        new_offset = Some(update.update_id + 1);

        let msg = match &update.message {
            Some(m) => m,
            None => continue,
        };

        let text = match &msg.text {
            Some(t) if !t.is_empty() => t.clone(),
            _ => continue,
        };

        let from = match &msg.from {
            Some(f) => f,
            None => continue,
        };

        // Skip bot messages
        if from.is_bot.unwrap_or(false) {
            debug!("Skipping bot message");
            continue;
        }

        // Filter by allowed user IDs if configured
        if !cli.allowed_user_ids.is_empty() && !cli.allowed_user_ids.contains(&from.id) {
            debug!(user_id = from.id, "Ignoring message from non-allowed user");
            continue;
        }

        let chat_id = msg
            .chat
            .as_ref()
            .map(|c| c.id.to_string())
            .unwrap_or_default();

        let message_id = msg.message_id.to_string();

        let thread_root = msg
            .reply_to_message
            .as_ref()
            .map(|r| r.message_id.to_string())
            .unwrap_or_else(|| message_id.clone());

        let display_name = from.first_name.as_ref().map(|f| {
            if let Some(l) = &from.last_name {
                format!("{f} {l}")
            } else {
                f.clone()
            }
        });

        let sender = SenderInfo {
            id: from.id.to_string(),
            username: from.username.clone(),
            display_name,
            is_bot: false,
        };

        // Use chat title or type as team context
        let team_id = msg
            .chat
            .as_ref()
            .and_then(|c| c.title.as_deref())
            .unwrap_or("");

        let envelope = build_envelope(
            "telegram",
            team_id,
            &chat_id,
            &message_id,
            &thread_root,
            &text,
            &sender,
            cli.event_secret.as_deref(),
            Vec::new(),
            Vec::new(),
        );

        info!(
            message_id,
            chat_id,
            sender = from.username.as_deref().unwrap_or("unknown"),
            content_len = text.len(),
            "Publishing Telegram message to NATS"
        );

        gw.publish_envelope(envelope).await?;
    }

    if !updates.is_empty() {
        info!(count = updates.len(), "Processed Telegram updates");
    }

    Ok(new_offset)
}
