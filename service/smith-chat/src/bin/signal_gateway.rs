//! Signal Gateway that polls signal-cli's JSON-RPC REST API for incoming
//! messages and publishes them to NATS as BridgeMessageEnvelope payloads.

use anyhow::{Context, Result};
use chat_bridge::gateway_common::{build_envelope, connect_nats, GatewayContext, SenderInfo};
use clap::Parser;
use serde::Deserialize;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Signal (signal-cli) Gateway → NATS bridge for Smith"
)]
struct Cli {
    /// signal-cli REST API base URL
    #[arg(long, env = "SIGNAL_CLI_URL", default_value = "http://127.0.0.1:8080")]
    signal_cli_url: String,

    /// Phone number registered with signal-cli (e.g. +15551234567)
    #[arg(long, env = "SIGNAL_PHONE_NUMBER")]
    phone_number: String,

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
    #[arg(long, env = "SIGNAL_POLL_INTERVAL_SECS", default_value_t = 2)]
    poll_interval_secs: u64,
}

#[derive(Debug, Deserialize)]
struct SignalMessage {
    #[serde(default)]
    envelope: Option<SignalEnvelope>,
}

#[derive(Debug, Deserialize)]
struct SignalEnvelope {
    #[serde(default)]
    source: Option<String>,
    #[serde(default, rename = "sourceName")]
    source_name: Option<String>,
    #[serde(default)]
    timestamp: Option<i64>,
    #[serde(default, rename = "dataMessage")]
    data_message: Option<SignalDataMessage>,
}

#[derive(Debug, Deserialize)]
struct SignalDataMessage {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    timestamp: Option<i64>,
    #[serde(default, rename = "groupInfo")]
    group_info: Option<SignalGroupInfo>,
}

#[derive(Debug, Deserialize)]
struct SignalGroupInfo {
    #[serde(default, rename = "groupId")]
    group_id: Option<String>,
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
        platform: "signal",
    };

    let poll_interval = Duration::from_secs(cli.poll_interval_secs);
    info!(
        phone = %cli.phone_number,
        interval_secs = cli.poll_interval_secs,
        "Starting Signal polling loop"
    );

    let mut consecutive_errors: u32 = 0;

    loop {
        match poll_signal(&cli, &http, &gw).await {
            Ok(count) => {
                if count > 0 {
                    info!(count, "Processed Signal messages");
                }
                consecutive_errors = 0;
            }
            Err(err) => {
                consecutive_errors += 1;
                let backoff = Duration::from_secs((2u64).pow(consecutive_errors.min(5)));
                error!(
                    error = ?err,
                    consecutive_errors,
                    backoff_secs = backoff.as_secs(),
                    "Signal poll failed"
                );
                sleep(backoff).await;
                continue;
            }
        }
        sleep(poll_interval).await;
    }
}

async fn poll_signal(cli: &Cli, http: &reqwest::Client, gw: &GatewayContext) -> Result<usize> {
    let encoded_number = urlencoding::encode(&cli.phone_number);
    let url = format!("{}/v1/receive/{encoded_number}", cli.signal_cli_url);

    let resp = http
        .get(&url)
        .send()
        .await
        .context("failed to call signal-cli receive")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("signal-cli receive returned {status}: {body}");
    }

    let messages: Vec<SignalMessage> = resp.json().await?;
    let mut count = 0;

    for msg in messages {
        let envelope = match msg.envelope {
            Some(e) => e,
            None => continue,
        };

        let data = match envelope.data_message {
            Some(d) => d,
            None => continue,
        };

        let text = match &data.message {
            Some(t) if !t.is_empty() => t.clone(),
            _ => continue,
        };

        let source = envelope.source.unwrap_or_default();

        // Skip own messages
        if source == cli.phone_number {
            debug!("Skipping self-message");
            continue;
        }

        let channel_id = data
            .group_info
            .and_then(|g| g.group_id)
            .unwrap_or_else(|| source.clone());

        let ts = data
            .timestamp
            .or(envelope.timestamp)
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
        let message_id = format!("{source}-{ts}");

        let sender = SenderInfo {
            id: source.clone(),
            username: Some(source),
            display_name: envelope.source_name,
            is_bot: false,
        };

        let env = build_envelope(
            "signal",
            "",
            &channel_id,
            &message_id,
            &message_id,
            &text,
            &sender,
            cli.event_secret.as_deref(),
            Vec::new(),
            Vec::new(),
        );

        gw.publish_envelope(env).await?;
        count += 1;
    }

    Ok(count)
}
