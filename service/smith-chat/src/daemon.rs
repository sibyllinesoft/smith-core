use std::{
    collections::HashMap,
    sync::atomic::{AtomicU32, Ordering},
    sync::Arc,
    time::Duration,
};

use crate::{
    adapter::OutgoingMessage,
    allowlist::{Allowlist, AllowlistAction, AllowlistConfig},
    bridge::ChatBridge,
    config::ChatBridgeConfig,
    identity::IdentityClaims,
    message::{
        Attachment, ChannelAddress, ChatPlatform, MessageContent, Participant, ParticipantRole,
    },
    pairing_store::{DmPolicy, PairingStore},
    session_key::{SessionKey, SessionScope},
};
use anyhow::{Context, Result};
use async_nats::{Client as NatsClient, Message};
use clap::Parser;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use futures::{FutureExt, SinkExt, StreamExt};
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{signal, sync::watch, sync::Mutex, time::timeout};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

#[derive(Debug, Parser, Clone)]
#[command(author, version, about = "Smith chat bridge ingestion daemon", long_about = None)]
pub struct Cli {
    /// NATS server URL (e.g. nats://127.0.0.1:4222)
    #[arg(long, env = "SMITH_NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// NATS subject to subscribe to for Mattermost bridge events
    #[arg(
        long,
        env = "CHAT_BRIDGE_INGEST_SUBJECT",
        default_value = "smith.chatbridge.ingest"
    )]
    ingest_subject: String,

    /// Optional shared secret to authenticate envelopes
    #[arg(long, env = "CHAT_BRIDGE_EVENT_SECRET")]
    event_secret: Option<String>,

    /// Logical label used in logs/metrics
    #[arg(long, env = "CHAT_BRIDGE_ADAPTER_LABEL", default_value = "chat-bridge")]
    adapter_label: String,

    /// Redis connection string (shared with observability stack)
    #[arg(long, env = "REDIS_URL", default_value = "redis://127.0.0.1:6379")]
    redis_url: String,

    /// TTL (seconds) for cached thread metadata
    #[arg(long, env = "CHAT_BRIDGE_THREAD_TTL_SECS", default_value_t = 3600)]
    thread_ttl_secs: u64,

    /// Timeout (seconds) when waiting for smith.core.sessions.start reply
    #[arg(long, env = "CHAT_BRIDGE_SESSION_TIMEOUT_SECS", default_value_t = 10)]
    session_timeout_secs: u64,

    /// Number of prior thread messages to include when starting a new session
    #[arg(long, env = "CHAT_BRIDGE_THREAD_HISTORY_LIMIT", default_value_t = 20)]
    thread_history_limit: i64,

    /// managerd websocket endpoint used for streaming agent updates
    #[arg(
        long,
        env = "SMITH_HTTP_WS_URL",
        default_value = "ws://localhost:6174/ws"
    )]
    smith_ws_url: String,

    /// Path to a ChatBridge config TOML file used for outbound Mattermost posts
    #[arg(long, env = "CHAT_BRIDGE_CONFIG")]
    chat_bridge_config: String,

    /// Adapter ID registered inside the ChatBridge config
    #[arg(long, env = "CHAT_BRIDGE_ADAPTER_ID")]
    chat_bridge_adapter_id: String,

    /// DM policy: pairing, allowlist, or open
    #[arg(long, env = "CHAT_BRIDGE_DM_POLICY", default_value = "pairing")]
    dm_policy: String,

    /// TTL (seconds) for unredeemed pairing codes
    #[arg(long, env = "CHAT_BRIDGE_PAIRING_CODE_TTL", default_value_t = 300)]
    pairing_code_ttl: u64,

    /// TTL (seconds) for active pairings
    #[arg(long, env = "CHAT_BRIDGE_PAIRING_TTL", default_value_t = 86400)]
    pairing_ttl: u64,

    /// Path to allowlist config TOML file
    #[arg(long, env = "CHAT_BRIDGE_ALLOWLIST_CONFIG")]
    allowlist_config: Option<String>,

    /// Secret used for signing identity JWTs
    #[arg(long, env = "CHAT_BRIDGE_IDENTITY_SECRET")]
    identity_secret: Option<String>,

    /// Port to serve webhook ingestion endpoints
    #[arg(long, env = "CHAT_BRIDGE_WEBHOOK_PORT", default_value_t = 8092)]
    webhook_port: u16,

    /// Require authenticated/signed webhook requests (recommended for production)
    #[arg(
        long,
        env = "CHAT_BRIDGE_REQUIRE_SIGNED_WEBHOOKS",
        default_value_t = true
    )]
    require_signed_webhooks: bool,

    /// Telegram webhook secret token expected in X-Telegram-Bot-Api-Secret-Token
    #[arg(long, env = "CHAT_BRIDGE_TELEGRAM_WEBHOOK_SECRET")]
    telegram_webhook_secret: Option<String>,

    /// Discord interactions public key (hex) for X-Signature-Ed25519 verification
    #[arg(long, env = "CHAT_BRIDGE_DISCORD_PUBLIC_KEY")]
    discord_public_key: Option<String>,

    /// WhatsApp webhook verify token (for GET verification handshake)
    #[arg(long, env = "CHAT_BRIDGE_WHATSAPP_VERIFY_TOKEN")]
    whatsapp_verify_token: Option<String>,

    /// WhatsApp app secret for X-Hub-Signature-256 validation
    #[arg(long, env = "CHAT_BRIDGE_WHATSAPP_APP_SECRET")]
    whatsapp_app_secret: Option<String>,

    /// GitHub webhook secret for validating X-Hub-Signature-256
    #[arg(long, env = "CHAT_BRIDGE_GITHUB_WEBHOOK_SECRET")]
    github_webhook_secret: Option<String>,

    /// NATS subject for normalized GitHub webhook orchestration events
    #[arg(
        long,
        env = "CHAT_BRIDGE_GITHUB_INGEST_SUBJECT",
        default_value = "smith.orch.ingest.github"
    )]
    github_ingest_subject: String,

    /// Bearer token for admin API endpoints (empty = no auth)
    #[arg(long, env = "CHAT_BRIDGE_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// NATS subject for session start requests (must match the agent bridge)
    #[arg(
        long,
        env = "CHAT_BRIDGE_SESSION_START_SUBJECT",
        default_value = "smith.chatbridge.sessions.start"
    )]
    session_start_subject: String,

    /// Agent profile ID used when starting new sessions
    #[arg(long, env = "SMITH_AGENT_ID", default_value = "default")]
    agent_id: String,

    /// PostgreSQL connection string for reading agent config
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgresql://smith:smith-dev@localhost:5432/smith"
    )]
    database_url: String,

    /// Message debounce window in milliseconds (0 = disabled).
    /// When enabled, rapid successive messages from the same user in the same
    /// thread are batched into a single combined message.
    #[arg(long, env = "CHAT_BRIDGE_DEBOUNCE_MS", default_value_t = 1500)]
    debounce_ms: u64,
}

#[derive(Clone)]
struct AppState {
    config: Cli,
    nats: NatsClient,
    thread_store: Arc<ThreadStore>,
    chat_bridge: Arc<ChatBridge>,
    adapter_id: String,
    agent_id: String,
    session_watchers: Arc<SessionWatchManager>,
    pairing_store: Arc<PairingStore>,
    allowlist: Option<Arc<Allowlist>>,
    dm_policy: DmPolicy,
    identity_secret: Option<Vec<u8>>,
    pg_pool: Pool,
    active_sessions: Arc<AtomicU32>,
    /// Typing indicator cancellation senders, keyed by "channel_id:thread_root".
    typing_stops: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
}

impl AppState {
    fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.config.session_timeout_secs)
    }
}

#[derive(Default)]
struct SessionWatchManager {
    tasks: Mutex<HashMap<Uuid, tokio::task::JoinHandle<()>>>,
}

impl SessionWatchManager {
    async fn ensure_watching(&self, state: Arc<AppState>, record: ThreadRecord) {
        let Some(session_id) = record.session_id else {
            return;
        };
        let mut tasks = self.tasks.lock().await;
        // Drop completed watcher handles to avoid stale entries and map growth.
        tasks.retain(|_, handle| !handle.is_finished());
        if tasks.contains_key(&session_id) {
            return;
        }
        let handle = tokio::spawn(run_session_watcher(state, record));
        tasks.insert(session_id, handle);
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    info!(target = "chat_bridge_daemon", label = %cli.adapter_label, subject = %cli.ingest_subject, "Starting chat bridge daemon");

    let bridge_config_str =
        std::fs::read_to_string(&cli.chat_bridge_config).with_context(|| {
            format!(
                "failed to read chat bridge config at {}",
                cli.chat_bridge_config
            )
        })?;
    let bridge_config: ChatBridgeConfig =
        toml::from_str(&bridge_config_str).with_context(|| "failed to parse chat bridge config")?;
    let chat_bridge = Arc::new(ChatBridge::build_from_config(bridge_config).await?);

    let client = async_nats::ConnectOptions::new()
        .request_timeout(Some(Duration::from_secs(cli.session_timeout_secs)))
        .connect(&cli.nats_url)
        .await
        .with_context(|| format!("failed to connect to NATS at {}", cli.nats_url))?;
    info!(url = %cli.nats_url, "Connected to NATS");

    let thread_store = Arc::new(
        ThreadStore::new(&cli.redis_url, cli.thread_ttl_secs)
            .await
            .with_context(|| format!("failed to connect to redis at {}", cli.redis_url))?,
    );
    info!(url = %cli.redis_url, ttl_secs = cli.thread_ttl_secs, "Connected to Redis");

    let session_watchers = Arc::new(SessionWatchManager::default());

    let dm_policy: DmPolicy = cli
        .dm_policy
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // Build PostgreSQL connection pool
    let pg_config: tokio_postgres::Config = cli
        .database_url
        .parse()
        .context("failed to parse DATABASE_URL")?;
    let pg_mgr = Manager::from_config(
        pg_config,
        tokio_postgres::NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    let pg_pool = Pool::builder(pg_mgr)
        .max_size(8)
        .build()
        .context("failed to build postgres connection pool")?;
    // Verify connectivity at startup
    let _ = pg_pool
        .get()
        .await
        .context("failed to connect to postgres via pool")?;
    info!("PostgreSQL connection pool ready (max_size=8)");

    let pairing_store = Arc::new(
        PairingStore::new(
            &cli.redis_url,
            pg_pool.clone(),
            cli.pairing_code_ttl,
            cli.pairing_ttl,
        )
        .await
        .context("failed to create pairing store")?,
    );

    let allowlist = if let Some(path) = &cli.allowlist_config {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read allowlist config at {path}"))?;
        let config: AllowlistConfig =
            toml::from_str(&content).with_context(|| "failed to parse allowlist config")?;
        Some(Arc::new(Allowlist::new(config)))
    } else {
        None
    };

    let identity_secret = cli.identity_secret.as_ref().map(|s| s.as_bytes().to_vec());

    let state = Arc::new(AppState {
        config: cli.clone(),
        nats: client.clone(),
        thread_store: Arc::clone(&thread_store),
        chat_bridge,
        adapter_id: cli.chat_bridge_adapter_id.clone(),
        agent_id: cli.agent_id.clone(),
        session_watchers,
        pairing_store,
        allowlist,
        dm_policy,
        identity_secret,
        pg_pool,
        active_sessions: Arc::new(AtomicU32::new(0)),
        typing_stops: Arc::new(Mutex::new(HashMap::new())),
    });

    // Spawn webhook ingestion server.
    #[cfg(feature = "webhooks")]
    {
        let webhook_state = Arc::new(crate::webhook::WebhookState {
            nats: client.clone(),
            require_signed_webhooks: cli.require_signed_webhooks,
            telegram_webhook_secret: cli.telegram_webhook_secret.clone(),
            discord_public_key: cli.discord_public_key.clone(),
            whatsapp_verify_token: cli.whatsapp_verify_token.clone(),
            whatsapp_app_secret: cli.whatsapp_app_secret.clone(),
            github_webhook_secret: cli.github_webhook_secret.clone(),
            github_ingest_subject: cli.github_ingest_subject.clone(),
            pairing_store: Arc::clone(&state.pairing_store),
            admin_token: cli.admin_token.clone(),
        });
        let app = crate::webhook::router(webhook_state);
        let addr: std::net::SocketAddr = ([0, 0, 0, 0], cli.webhook_port).into();
        info!(%addr, "Starting webhook ingestion server");
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind webhook server on {addr}"))?;
        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                error!(error = ?err, "Webhook server error");
            }
        });
    }

    let mut subscriber = client
        .subscribe(cli.ingest_subject.clone())
        .await
        .with_context(|| format!("failed to subscribe to {}", cli.ingest_subject))?;

    // Optionally set up message debouncing.
    let debouncer = if cli.debounce_ms > 0 {
        let debounce_state = Arc::clone(&state);
        let (debouncer, _handle) =
            crate::debounce::Debouncer::spawn(cli.debounce_ms, move |envelope| {
                let st = Arc::clone(&debounce_state);
                tokio::spawn(async move {
                    if let Err(err) = process_envelope(st, envelope).await {
                        error!(error = ?err, "Failed to process debounced message");
                    }
                });
            });
        info!(debounce_ms = cli.debounce_ms, "Message debouncing enabled");
        Some(debouncer)
    } else {
        info!("Message debouncing disabled");
        None
    };

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutdown signal received; exiting");
                // Drop the debouncer so its channel closes and it flushes pending buffers.
                drop(debouncer);
                break;
            }
            maybe_msg = subscriber.next() => {
                match maybe_msg {
                    Some(msg) => {
                        if let Some(ref debouncer) = debouncer {
                            match serde_json::from_slice::<BridgeMessageEnvelope>(&msg.payload) {
                                Ok(envelope) => {
                                    if let Err(env) = debouncer.send(envelope) {
                                        warn!(post_id = %env.post_id, "Debouncer channel closed, processing directly");
                                        tokio::spawn(process_envelope(Arc::clone(&state), env).map(|r| {
                                            if let Err(err) = r { error!(error = ?err, "Failed to process message"); }
                                        }));
                                    }
                                }
                                Err(err) => {
                                    warn!(error = ?err, "Failed to parse bridge message JSON");
                                }
                            }
                        } else {
                            tokio::spawn(handle_message(Arc::clone(&state), msg));
                        }
                    }
                    None => {
                        warn!("NATS subscription closed; exiting");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn handle_message(state: Arc<AppState>, msg: Message) {
    if let Err(err) = process_message(state, msg).await {
        error!(error = ?err, "Failed to process bridge message");
    }
}

async fn process_message(state: Arc<AppState>, msg: Message) -> Result<()> {
    let envelope: BridgeMessageEnvelope = serde_json::from_slice(&msg.payload)
        .with_context(|| "failed to parse bridge message JSON")?;
    process_envelope(state, envelope).await
}

/// Core envelope processing logic, separated from deserialization so the
/// debouncer can call it directly with a combined envelope.
async fn process_envelope(state: Arc<AppState>, envelope: BridgeMessageEnvelope) -> Result<()> {

    if let Some(expected) = &state.config.event_secret {
        match envelope.secret.as_deref() {
            Some(secret) if secret == expected => {}
            _ => {
                warn!(post_id = %envelope.post_id, "Discarding envelope with invalid secret");
                return Ok(());
            }
        }
    }

    info!(
        post_id = %envelope.post_id,
        channel_id = %envelope.channel_id,
        team_id = %envelope.team_id,
        username = envelope
            .sender
            .username
            .as_deref()
            .unwrap_or("unknown"),
        attachments = envelope.attachments.len(),
        "Received bridge message"
    );

    // Build a Participant for allowlist evaluation
    let participant = Participant {
        id: envelope.sender.id.clone(),
        display_name: envelope.sender.display_name.clone(),
        role: if envelope.sender.is_bot {
            ParticipantRole::Bot
        } else {
            ParticipantRole::User
        },
        username: envelope.sender.username.clone(),
        tags: Vec::new(),
    };

    let platform = parse_envelope_platform(&envelope.platform);

    // Allowlist check
    if let Some(allowlist) = &state.allowlist {
        if allowlist.evaluate(&participant, platform) == AllowlistAction::Deny {
            info!(
                sender_id = %envelope.sender.id,
                platform = %envelope.platform,
                "Message denied by allowlist"
            );
            return Ok(());
        }
    }

    // DM pairing gate
    if state.dm_policy == DmPolicy::Pairing {
        let is_dm = envelope.team_id.is_empty();
        let trimmed = envelope.message.trim();

        // Only accept pairing codes in DMs
        if is_dm && trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
            let code = trimmed.to_uppercase();
            match state
                .pairing_store
                .redeem_code(&code, platform, &envelope.sender.id, &envelope.channel_id)
                .await
            {
                Ok(Some(pairing)) => {
                    info!(
                        agent_id = %pairing.agent_id,
                        sender_id = %envelope.sender.id,
                        "Pairing code redeemed successfully"
                    );

                    // Auto-create user identity so pi-bridge resolves this
                    // user with proper role/tool access on subsequent turns.
                    let username = envelope
                        .sender
                        .username
                        .as_deref()
                        .unwrap_or(&envelope.sender.id);
                    let display_name = envelope.sender.display_name.as_deref().unwrap_or(username);
                    match ensure_user_identity(
                        &state.pg_pool,
                        &envelope.platform,
                        &envelope.sender.id,
                        username,
                        display_name,
                    )
                    .await
                    {
                        Ok(role) => info!(
                            platform = %envelope.platform,
                            sender_id = %envelope.sender.id,
                            role,
                            "User identity linked on pairing"
                        ),
                        Err(err) => warn!(
                            error = ?err,
                            "Failed to auto-create user identity on pairing"
                        ),
                    }

                    send_reply(
                        &state,
                        &envelope,
                        &format!("Paired successfully with agent `{}`.", pairing.agent_id),
                    )
                    .await?;
                    return Ok(());
                }
                Ok(None) => {
                    send_reply(&state, &envelope, "Invalid or expired pairing code.").await?;
                    return Ok(());
                }
                Err(err) => {
                    warn!(error = ?err, "Failed to redeem pairing code");
                    return Ok(());
                }
            }
        }

        // Check for active pairing
        match state
            .pairing_store
            .lookup_pairing(platform, &envelope.sender.id)
            .await
        {
            Ok(Some(_)) => { /* paired, continue processing */ }
            Ok(None) => {
                // No pairing — check if the user has a known identity in the
                // database (e.g. admin-created). If so, auto-create a pairing
                // so they don't need to go through the code flow.
                let has_identity =
                    check_known_identity(&state.pg_pool, &envelope.platform, &envelope.sender.id)
                        .await;

                if has_identity {
                    info!(
                        sender_id = %envelope.sender.id,
                        platform = %envelope.platform,
                        "Auto-pairing user with existing identity"
                    );
                    // Create a pairing so future lookups hit the fast path.
                    if let Err(err) = auto_create_pairing(
                        &state.pairing_store,
                        platform,
                        &envelope.sender.id,
                        &envelope.channel_id,
                        &state.agent_id,
                        state.pairing_store.pairing_ttl_secs,
                    )
                    .await
                    {
                        warn!(error = ?err, "Failed to auto-create pairing from identity");
                    }
                } else if is_dm {
                    // DM from unpaired user — prompt them to pair
                    send_reply(
                        &state,
                        &envelope,
                        "You are not paired with an agent. Please submit a 6-character pairing code.",
                    )
                    .await?;
                    return Ok(());
                } else {
                    // Guild message from unpaired user — silently ignore
                    debug!(
                        sender_id = %envelope.sender.id,
                        channel_id = %envelope.channel_id,
                        "Ignoring guild message from unpaired user"
                    );
                    return Ok(());
                }
            }
            Err(err) => {
                warn!(error = ?err, "Failed to look up pairing");
                return Ok(());
            }
        }
    }

    let mut record = match state
        .thread_store
        .fetch_for(&envelope)
        .await
        .context("failed to fetch thread record")?
    {
        Some(record) => record,
        None => ThreadRecord::from_envelope(&envelope),
    };

    let is_new_session = record.session_id.is_none() || record.steering_subject.is_none();

    if is_new_session {
        // Enforce per-agent concurrent session limit
        let max = fetch_max_concurrent_sessions(&state.pg_pool, &state.agent_id).await;
        let active = state.active_sessions.load(Ordering::Relaxed);
        if active >= max {
            info!(
                active,
                max,
                agent_id = %state.agent_id,
                "Concurrent session limit reached, rejecting message"
            );
            send_reply(
                &state,
                &envelope,
                &format!(
                    "I'm currently handling {active} conversations (limit: {max}). Please try again shortly."
                ),
            )
            .await?;
            return Ok(());
        }

        state.active_sessions.fetch_add(1, Ordering::Relaxed);
        let session = match start_new_session(&state, &envelope).await {
            Ok(s) => s,
            Err(e) => {
                state.active_sessions.fetch_sub(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        record.session_id = Some(session.session_id);
        record.steering_subject = Some(session.steering_subject);
        record.trace_id = Some(session.trace_id);
        record.response_subject = session.response_subject;
    }

    // Deliver the user message via steering (request/reply with timeout for liveness check).
    // Skip for new sessions — the goal is already delivered in the session start request,
    // and pi-bridge fires runAgentPrompt immediately. Sending again causes double-prompt.
    if !is_new_session
        && publish_user_message(&state, &record, &envelope)
            .await
            .is_err()
    {
        // Existing session appears dead — recreate and retry
        warn!(session_id = ?record.session_id, "Session appears dead, creating new session");

        let max = fetch_max_concurrent_sessions(&state.pg_pool, &state.agent_id).await;
        let active = state.active_sessions.load(Ordering::Relaxed);
        if active >= max {
            send_reply(
                &state,
                &envelope,
                &format!(
                    "I'm currently handling {active} conversations (limit: {max}). Please try again shortly."
                ),
            )
            .await?;
            return Ok(());
        }

        state.active_sessions.fetch_add(1, Ordering::Relaxed);
        let session = match start_new_session(&state, &envelope).await {
            Ok(s) => s,
            Err(e) => {
                state.active_sessions.fetch_sub(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        record.session_id = Some(session.session_id);
        record.steering_subject = Some(session.steering_subject);
        record.trace_id = Some(session.trace_id);
        record.response_subject = session.response_subject;
        publish_user_message(&state, &record, &envelope).await?;
    }

    record.last_post_id = envelope.post_id.clone();
    record.last_post_at = envelope.timestamp;
    record.last_sender_id = envelope.sender.id.clone();
    record.last_sender_username = envelope.sender.username.clone();

    state
        .thread_store
        .persist(&record)
        .await
        .context("failed to persist thread record")?;

    // Start typing indicator (cancels any existing one for this thread)
    {
        let key = typing_key(&record.channel_id, &record.thread_root);
        let (tx, rx) = watch::channel(false);
        // Cancel any prior typing loop for this thread before starting a new one
        if let Some(old) = state.typing_stops.lock().await.insert(key, tx) {
            let _ = old.send(true);
        }
        let typing_state = Arc::clone(&state);
        let channel_id = record.channel_id.clone();
        tokio::spawn(async move {
            typing_loop(typing_state, channel_id, rx).await;
        });
    }

    state
        .session_watchers
        .ensure_watching(Arc::clone(&state), record)
        .await;

    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryMessage {
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct BridgeMessageEnvelope {
    pub platform: String,
    pub team_id: String,
    #[serde(default)]
    pub team_name: Option<String>,
    pub channel_id: String,
    #[serde(default)]
    pub channel_name: Option<String>,
    pub post_id: String,
    pub thread_root: String,
    pub message: String,
    #[serde(default)]
    pub props: HashMap<String, Value>,
    #[serde(default)]
    pub attachments: Vec<AttachmentEnvelope>,
    pub timestamp: i64,
    #[serde(default)]
    pub secret: Option<String>,
    pub sender: SenderEnvelope,
    #[serde(default)]
    pub thread_history: Vec<HistoryMessage>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttachmentEnvelope {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub mime_type: Option<String>,
    pub size_bytes: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SenderEnvelope {
    pub id: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub is_bot: bool,
}

struct ThreadStore {
    manager: ConnectionManager,
    ttl_secs: u64,
}

impl ThreadStore {
    async fn new(redis_url: &str, ttl_secs: u64) -> Result<Self> {
        let client = redis::Client::open(redis_url.to_string())
            .with_context(|| format!("failed to open redis client for {}", redis_url))?;
        let manager = client
            .get_connection_manager()
            .await
            .with_context(|| "failed to connect to redis")?;
        Ok(Self { manager, ttl_secs })
    }

    async fn fetch_for(&self, envelope: &BridgeMessageEnvelope) -> Result<Option<ThreadRecord>> {
        self.fetch(
            &envelope.platform,
            &envelope.team_id,
            &envelope.channel_id,
            &envelope.thread_root,
        )
        .await
    }

    async fn fetch(
        &self,
        platform: &str,
        team_id: &str,
        channel_id: &str,
        thread_root: &str,
    ) -> Result<Option<ThreadRecord>> {
        let key = Self::key(platform, team_id, channel_id, thread_root);
        let mut conn = self.manager.clone();
        let raw: Option<String> = conn
            .get(&key)
            .await
            .with_context(|| format!("failed to read record {key} from redis"))?;
        if let Some(raw) = raw {
            let record = serde_json::from_str(&raw)
                .with_context(|| format!("failed to deserialize record {key}"))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    async fn persist(&self, record: &ThreadRecord) -> Result<()> {
        let key = Self::key(
            &record.platform,
            &record.team_id,
            &record.channel_id,
            &record.thread_root,
        );
        let payload = serde_json::to_string(record)?;
        let mut conn = self.manager.clone();
        conn.set_ex::<_, _, ()>(key, payload, self.ttl_secs)
            .await
            .with_context(|| "failed to write thread record to redis")?;
        Ok(())
    }

    fn key(platform: &str, team_id: &str, channel_id: &str, thread_root: &str) -> String {
        format!("chatbridge:thread:{platform}:{team_id}:{channel_id}:{thread_root}")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ThreadRecord {
    platform: String,
    team_id: String,
    channel_id: String,
    thread_root: String,
    last_post_id: String,
    last_post_at: i64,
    last_sender_id: String,
    last_sender_username: Option<String>,
    session_id: Option<Uuid>,
    steering_subject: Option<String>,
    trace_id: Option<Uuid>,
    /// When set, the daemon subscribes to this NATS subject for agent
    /// responses instead of using the managerd WebSocket.
    response_subject: Option<String>,
}

impl ThreadRecord {
    fn from_envelope(envelope: &BridgeMessageEnvelope) -> Self {
        Self {
            platform: envelope.platform.clone(),
            team_id: envelope.team_id.clone(),
            channel_id: envelope.channel_id.clone(),
            thread_root: envelope.thread_root.clone(),
            last_post_id: envelope.post_id.clone(),
            last_post_at: envelope.timestamp,
            last_sender_id: envelope.sender.id.clone(),
            last_sender_username: envelope.sender.username.clone(),
            session_id: None,
            steering_subject: None,
            trace_id: None,
            response_subject: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SessionStartResponse {
    request_id: Uuid,
    session_id: Uuid,
    steering_subject: String,
    trace_id: Uuid,
    /// When present, the daemon subscribes to this NATS subject for agent
    /// responses instead of connecting to the managerd WebSocket.
    #[serde(default)]
    response_subject: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionStartRequestPayload {
    goal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
    #[serde(default)]
    immediate: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    thread_history: Vec<HistoryMessage>,
}

/// Default concurrent session limit when the agent has no config override.
const DEFAULT_MAX_CONCURRENT_SESSIONS: u32 = 10;

/// Read `max_concurrent_sessions` from `agents.config` JSONB in Postgres.
/// Returns the default if the agent row doesn't exist or the key is absent.
async fn fetch_max_concurrent_sessions(pool: &Pool, agent_id: &str) -> u32 {
    let result = async {
        let client = pool.get().await.context("pool connection")?;

        let row = client
            .query_opt("SELECT config FROM agents WHERE id = $1", &[&agent_id])
            .await?;

        if let Some(row) = row {
            let config: Value = row.get(0);
            if let Some(limit) = config
                .get("max_concurrent_sessions")
                .and_then(|v| v.as_u64())
            {
                return Ok::<u32, anyhow::Error>(limit as u32);
            }
        }

        Ok(DEFAULT_MAX_CONCURRENT_SESSIONS)
    }
    .await;

    match result {
        Ok(limit) => limit,
        Err(err) => {
            warn!(error = ?err, "Failed to read agent config from Postgres, using default");
            DEFAULT_MAX_CONCURRENT_SESSIONS
        }
    }
}

/// Ensure a `users` + `user_identities` row exists for this platform user.
/// If the identity already exists, returns the existing role.
/// Otherwise creates a new user with role "user" and links the identity.
/// Returns the user's role on success.
async fn ensure_user_identity(
    pool: &Pool,
    platform: &str,
    platform_user_id: &str,
    username: &str,
    display_name: &str,
) -> Result<String> {
    let client = pool.get().await.context("pool connection")?;

    // Check if identity already exists
    let existing = client
        .query_opt(
            "SELECT u.role FROM users u
             JOIN user_identities ui ON ui.user_id = u.id
             WHERE ui.platform = $1 AND ui.platform_user_id = $2",
            &[&platform, &platform_user_id],
        )
        .await?;

    if let Some(row) = existing {
        return Ok(row.get::<_, String>("role"));
    }

    // Check if a user with this username already exists — if so, link
    // the identity to them rather than creating a duplicate account.
    // This handles the common case where the admin pre-created the user.
    let existing_user = client
        .query_opt(
            "SELECT id, role FROM users WHERE username = $1 AND active = true",
            &[&username],
        )
        .await?;

    let (final_user_id, role) = if let Some(row) = existing_user {
        (row.get::<_, String>("id"), row.get::<_, String>("role"))
    } else {
        // Create a new user with "user" role.
        let new_id = Uuid::new_v4().to_string();
        client
            .execute(
                "INSERT INTO users (id, username, display_name, role)
                 VALUES ($1, $2, $3, 'user')",
                &[&new_id, &username, &display_name],
            )
            .await
            .context("failed to insert new user")?;
        (new_id, "user".to_string())
    };

    // Link identity
    client
        .execute(
            "INSERT INTO user_identities (id, user_id, platform, platform_user_id, platform_username)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (platform, platform_user_id) DO NOTHING",
            &[
                &Uuid::new_v4().to_string(),
                &final_user_id,
                &platform,
                &platform_user_id,
                &username,
            ],
        )
        .await
        .context("failed to insert user identity")?;

    info!(
        user_id = %final_user_id,
        username = %username,
        platform,
        platform_user_id,
        "Auto-created user and identity on pairing"
    );

    Ok(role)
}

/// Check if a user has an existing identity in the database (e.g. admin-created).
async fn check_known_identity(pool: &Pool, platform: &str, platform_user_id: &str) -> bool {
    let result = async {
        let client = pool.get().await.context("pool connection")?;

        let row = client
            .query_opt(
                "SELECT 1 FROM user_identities WHERE platform = $1 AND platform_user_id = $2",
                &[&platform, &platform_user_id],
            )
            .await?;

        Ok::<bool, anyhow::Error>(row.is_some())
    }
    .await;

    match result {
        Ok(found) => found,
        Err(err) => {
            warn!(error = ?err, "Failed to check user identity in database");
            false
        }
    }
}

/// Create an active pairing for a user that already has a known identity,
/// so they bypass the pairing code flow on subsequent messages.
async fn auto_create_pairing(
    pairing_store: &PairingStore,
    platform: ChatPlatform,
    user_id: &str,
    channel_id: &str,
    agent_id: &str,
    ttl_secs: u64,
) -> Result<()> {
    use redis::AsyncCommands;

    let now = chrono::Utc::now();
    let pairing = crate::pairing_store::Pairing {
        code: String::new(),
        agent_id: agent_id.to_string(),
        platform,
        user_id: user_id.to_string(),
        channel_id: channel_id.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
        metadata: serde_json::Value::Null,
    };

    // Write to Redis
    let platform_str = format!("{platform:?}").to_lowercase();
    let key = format!("chatbridge:pairing:active:{platform_str}:{user_id}");
    let payload = serde_json::to_string(&pairing)?;
    let mut conn = pairing_store.redis_conn();
    conn.set_ex::<_, _, ()>(&key, &payload, ttl_secs)
        .await
        .context("failed to store auto-pairing in redis")?;

    Ok(())
}

struct SessionContext {
    session_id: Uuid,
    steering_subject: String,
    trace_id: Uuid,
    response_subject: Option<String>,
}

async fn start_new_session(
    state: &AppState,
    envelope: &BridgeMessageEnvelope,
) -> Result<SessionContext> {
    let mut thread_history = fetch_thread_history(
        &state.pg_pool,
        &envelope.platform,
        &envelope.channel_id,
        &envelope.thread_root,
        state.config.thread_history_limit,
    )
    .await;

    // Fall back to gateway-provided history (e.g. Discord API messages)
    // when the database has no prior session history for this thread.
    if thread_history.is_empty() && !envelope.thread_history.is_empty() {
        thread_history = envelope.thread_history.clone();
        info!(
            count = thread_history.len(),
            "Using gateway-provided thread history (no DB history available)"
        );
    }

    let attachments: Vec<Value> = envelope
        .attachments
        .iter()
        .map(|att| {
            json!({
                "id": att.id,
                "name": att.name,
                "mime_type": att.mime_type,
                "size_bytes": att.size_bytes,
            })
        })
        .collect();

    let metadata = json!({
        "source": &envelope.platform,
        "team_id": envelope.team_id,
        "team_name": envelope.team_name,
        "channel_id": envelope.channel_id,
        "channel_name": envelope.channel_name,
        "thread_id": envelope.thread_root,
        "thread_root": envelope.thread_root,
        "post_id": envelope.post_id,
        "sender_id": envelope.sender.id,
        "sender_username": envelope.sender.username,
        "sender_display_name": envelope.sender.display_name,
        "attachments": attachments,
        "agent_id": state.agent_id,
    });

    let payload = SessionStartRequestPayload {
        goal: envelope.message.clone(),
        metadata: Some(metadata),
        immediate: true,
        thread_history,
    };

    let bytes = serde_json::to_vec(&payload)?;
    let subject = state.config.session_start_subject.clone();
    let response = timeout(
        state.session_timeout(),
        state.nats.request(subject, bytes.into()),
    )
    .await
    .context("session start request timed out")??;

    let parsed: SessionStartResponse = serde_json::from_slice(&response.payload)
        .context("failed to decode session start response")?;

    info!(
        session_id = %parsed.session_id,
        thread_root = %envelope.thread_root,
        "Created new Smith session"
    );

    Ok(SessionContext {
        session_id: parsed.session_id,
        steering_subject: parsed.steering_subject,
        trace_id: parsed.trace_id,
        response_subject: parsed.response_subject,
    })
}

async fn publish_user_message(
    state: &AppState,
    record: &ThreadRecord,
    envelope: &BridgeMessageEnvelope,
) -> Result<()> {
    let subject = record
        .steering_subject
        .as_ref()
        .context("thread record missing steering_subject")?;

    // Build identity metadata if secret is configured
    let identity_meta = if let Some(secret) = &state.identity_secret {
        let platform = parse_envelope_platform(&record.platform);
        let session_key = SessionKey {
            agent_id: record
                .session_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            channel: platform,
            scope: SessionScope::Dm {
                recipient_id: envelope.sender.id.clone(),
            },
        };

        let claims = IdentityClaims::from_context(
            platform,
            &envelope.sender.id,
            &session_key,
            envelope.sender.display_name.clone(),
            envelope.channel_name.clone(),
            record.session_id.map(|id| id.to_string()),
            chrono::Duration::hours(1),
        );

        let mut meta = claims.to_metadata();
        if let Ok(jwt) = claims.to_jwt(secret) {
            meta.insert("x-oc-identity-token".to_string(), Value::String(jwt));
        }
        Some(meta)
    } else {
        None
    };

    let mut metadata = json!({
        "source": record.platform,
        "team_id": envelope.team_id,
        "channel_id": envelope.channel_id,
        "thread_id": envelope.thread_root,
        "thread_root": envelope.thread_root,
        "post_id": envelope.post_id,
        "sender_id": envelope.sender.id,
        "sender_username": envelope.sender.username,
        "trace_id": record.trace_id.map(|id| id.to_string()),
    });

    if let Some(identity) = identity_meta {
        if let Value::Object(ref mut map) = metadata {
            for (k, v) in identity {
                map.insert(k, v);
            }
        }
    }

    let payload = json!({
        "content": envelope.message,
        "role": "user",
        "metadata": metadata,
    });

    // Use request/reply with timeout so we detect dead sessions.
    // Pi-bridge sends an immediate ack; if nobody is listening the request times out.
    match timeout(
        Duration::from_secs(5),
        state
            .nats
            .request(subject.clone(), payload.to_string().into()),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow::anyhow!("steering request failed: {e}")),
        Err(_) => Err(anyhow::anyhow!(
            "steering request timed out — session is dead"
        )),
    }
}

async fn run_session_watcher(state: Arc<AppState>, record: ThreadRecord) {
    let result = session_watcher_task(Arc::clone(&state), record).await;
    state.active_sessions.fetch_sub(1, Ordering::Relaxed);
    if let Err(err) = result {
        warn!(error = ?err, "Session watcher exited with error");
    }
}

async fn session_watcher_task(state: Arc<AppState>, record: ThreadRecord) -> Result<()> {
    // If the session provider gave us a NATS response subject, use that
    // instead of the managerd WebSocket.
    if let Some(response_subject) = record.response_subject.clone() {
        return nats_response_watcher(state, record, response_subject).await;
    }

    let session_id = record.session_id.context("record missing session_id")?;
    let (mut ws, _) = connect_async(&state.config.smith_ws_url)
        .await
        .with_context(|| "failed to connect to managerd websocket")?;

    let subscription = json!({
        "type": "UpdateSubscription",
        "data": {
            "session_ids": [session_id.to_string()],
            "agent_types": Value::Null,
            "event_types": Value::Null,
            "min_activity_level": Value::Null,
            "include_performance": false,
            "include_logs": true,
            "log_level_filter": "info",
        }
    });
    ws.send(WsMessage::Text(subscription.to_string())).await?;

    while let Some(frame) = ws.next().await {
        match frame {
            Ok(WsMessage::Text(text)) => {
                if let Some(message) = parse_log_message(&text) {
                    if let Err(err) = handle_session_log(&state, &record, &message, &[]).await {
                        warn!(error = ?err, "Failed to relay WS message to chat, continuing");
                    }
                }
            }
            Ok(WsMessage::Ping(payload)) => {
                ws.send(WsMessage::Pong(payload)).await?;
            }
            Ok(WsMessage::Close(_)) => break,
            Ok(_) => {}
            Err(err) => {
                return Err(anyhow::anyhow!("websocket error: {err}"));
            }
        }
    }

    Ok(())
}

async fn fetch_thread_history(
    pool: &Pool,
    source: &str,
    channel_id: &str,
    thread_id: &str,
    limit: i64,
) -> Vec<HistoryMessage> {
    if limit <= 0 {
        return Vec::new();
    }

    let result = async {
        let client = pool.get().await.context("pool connection")?;

        let mut history =
            query_thread_history(&client, source, channel_id, Some(thread_id), limit).await?;

        // Backward compatibility: older session rows may have NULL thread_id.
        if history.is_empty() && !thread_id.is_empty() {
            history = query_thread_history(&client, source, channel_id, None, limit).await?;
        }

        Ok::<Vec<HistoryMessage>, anyhow::Error>(history)
    }
    .await;

    match result {
        Ok(history) => history,
        Err(err) => {
            warn!(
                error = ?err,
                source,
                channel_id,
                thread_id,
                "Failed to load thread history, continuing without bootstrap history"
            );
            Vec::new()
        }
    }
}

async fn query_thread_history(
    client: &tokio_postgres::Client,
    source: &str,
    channel_id: &str,
    thread_id: Option<&str>,
    limit: i64,
) -> Result<Vec<HistoryMessage>> {
    let rows = if let Some(thread_id) = thread_id {
        client
            .query(
                "SELECT role, content, username, created_at::text AS created_at FROM (
                    SELECT cm.role, cm.content, cm.username, cm.created_at
                    FROM chat_messages cm
                    JOIN chat_sessions cs ON cm.session_id = cs.id
                    WHERE cs.source = $1
                      AND cs.channel_id = $2
                      AND cs.thread_id = $3
                      AND cm.role IN ('user', 'assistant')
                      AND cm.content <> ''
                    ORDER BY cm.created_at DESC
                    LIMIT $4
                 ) recent
                 ORDER BY created_at ASC",
                &[&source, &channel_id, &thread_id, &limit],
            )
            .await?
    } else {
        client
            .query(
                "SELECT role, content, username, created_at::text AS created_at FROM (
                    SELECT cm.role, cm.content, cm.username, cm.created_at
                    FROM chat_messages cm
                    JOIN chat_sessions cs ON cm.session_id = cs.id
                    WHERE cs.source = $1
                      AND cs.channel_id = $2
                      AND cs.thread_id IS NULL
                      AND cm.role IN ('user', 'assistant')
                      AND cm.content <> ''
                    ORDER BY cm.created_at DESC
                    LIMIT $3
                 ) recent
                 ORDER BY created_at ASC",
                &[&source, &channel_id, &limit],
            )
            .await?
    };

    let history = rows
        .into_iter()
        .map(|row| HistoryMessage {
            role: row.get::<_, String>("role"),
            content: row.get::<_, String>("content"),
            username: row.get::<_, Option<String>>("username"),
            timestamp: row.get::<_, Option<String>>("created_at"),
        })
        .collect::<Vec<_>>();

    Ok(history)
}

/// Watch for agent responses via NATS subscription (used by pi-bridge and
/// other non-managerd session providers).
///
/// Expected message format:
/// ```json
/// { "type": "message", "content": "...", "done": false }
/// { "type": "message", "content": "final text", "done": true }
/// { "type": "error", "content": "error description" }
/// ```
async fn nats_response_watcher(
    state: Arc<AppState>,
    record: ThreadRecord,
    response_subject: String,
) -> Result<()> {
    let session_id = record
        .session_id
        .map(|id| id.to_string())
        .unwrap_or_default();
    info!(
        session_id,
        response_subject, "Starting NATS response watcher"
    );

    let mut subscriber = state
        .nats
        .subscribe(response_subject.clone())
        .await
        .with_context(|| format!("failed to subscribe to {response_subject}"))?;

    while let Some(msg) = subscriber.next().await {
        let payload: Value = match serde_json::from_slice(&msg.payload) {
            Ok(v) => v,
            Err(err) => {
                warn!(error = ?err, "Failed to parse NATS response payload");
                continue;
            }
        };

        let msg_type = payload
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("message");
        let content = payload
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let done = payload
            .get("done")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Parse optional attachments array from the response
        let attachments: Vec<Attachment> = payload
            .get("attachments")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        Some(Attachment {
                            id: a.get("id").and_then(|v| v.as_str()).map(String::from),
                            title: a
                                .get("title")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                                .or_else(|| {
                                    a.get("filename").and_then(|v| v.as_str()).map(String::from)
                                }),
                            url: a.get("url").and_then(|v| v.as_str())?.to_string(),
                            mime_type: a
                                .get("mime_type")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                                .or_else(|| {
                                    a.get("content_type")
                                        .and_then(|v| v.as_str())
                                        .map(String::from)
                                }),
                            size_bytes: a.get("size_bytes").and_then(|v| v.as_u64()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        if content.is_empty() && attachments.is_empty() && !done {
            continue;
        }

        match msg_type {
            "message" => {
                if !content.is_empty() || !attachments.is_empty() {
                    if let Err(err) =
                        handle_session_log(&state, &record, content, &attachments).await
                    {
                        warn!(
                            error = ?err,
                            session_id,
                            content_len = content.len(),
                            attachment_count = attachments.len(),
                            "Failed to relay message to chat, continuing"
                        );
                    }
                }
                if done {
                    debug!(session_id, "NATS response stream done");
                    break;
                }
            }
            "error" => {
                error!(session_id, error = content, "Agent returned error");
                let error_text = format!("Agent error: {content}");
                if let Err(err) = handle_session_log(&state, &record, &error_text, &[]).await {
                    warn!(error = ?err, session_id, "Failed to relay error to chat");
                }
                break;
            }
            _ => {
                debug!(session_id, msg_type, "Ignoring unknown response type");
            }
        }
    }

    Ok(())
}

fn parse_log_message(raw: &str) -> Option<String> {
    let value: Value = serde_json::from_str(raw).ok()?;
    if value.get("type")?.as_str()? != "Event" {
        return None;
    }
    let data = value.get("data")?;
    if data.get("type")?.as_str()? != "LogMessage" {
        return None;
    }
    data.get("data")?
        .get("message")?
        .as_str()
        .map(|s| s.to_string())
}

fn parse_envelope_platform(platform: &str) -> ChatPlatform {
    match platform.to_lowercase().as_str() {
        "slack" => ChatPlatform::Slack,
        "teams" => ChatPlatform::Teams,
        "mattermost" => ChatPlatform::Mattermost,
        "telegram" => ChatPlatform::Telegram,
        "discord" => ChatPlatform::Discord,
        "whatsapp" => ChatPlatform::WhatsApp,
        "signal" => ChatPlatform::Signal,
        "google_chat" => ChatPlatform::GoogleChat,
        "imessage" => ChatPlatform::IMessage,
        "matrix" => ChatPlatform::Matrix,
        _ => ChatPlatform::Unknown,
    }
}

async fn send_reply(state: &AppState, envelope: &BridgeMessageEnvelope, text: &str) -> Result<()> {
    let channel = ChannelAddress {
        team_id: Some(envelope.team_id.clone()),
        channel_id: envelope.channel_id.clone(),
        channel_name: None,
        thread_id: Some(envelope.thread_root.clone()),
    };
    let mut outgoing = OutgoingMessage::new(channel, MessageContent::plain(text));
    outgoing.reply_in_thread = Some(envelope.thread_root.clone());

    state
        .chat_bridge
        .send(&state.adapter_id, outgoing)
        .await
        .context("failed to send reply via chat bridge")?;
    Ok(())
}

/// Strip leaked LLM internal markup (thinking tags, tool-call XML) that some
/// models emit as plain text. Defense-in-depth — pi-bridge also strips these.
fn strip_llm_markup(text: &str) -> String {
    let mut s = text.to_string();
    for (open, close) in [
        ("<think>", "</think>"),
        ("<tool_call>", "</tool_call>"),
        ("<tool_result>", "</tool_result>"),
    ] {
        // Remove matched pairs (greedy — handles nested or multi-line)
        while let Some(start) = s.find(open) {
            if let Some(end) = s[start..].find(close) {
                s.replace_range(start..start + end + close.len(), "");
            } else {
                // Orphan opening tag — remove from tag to end of line
                let end = s[start..].find('\n').map(|i| start + i).unwrap_or(s.len());
                s.replace_range(start..end, "");
            }
        }
        // Remove any orphan closing tags
        while let Some(pos) = s.find(close) {
            s.replace_range(pos..pos + close.len(), "");
        }
    }
    // Collapse runs of blank lines
    while s.contains("\n\n\n") {
        s = s.replace("\n\n\n", "\n\n");
    }
    s.trim().to_string()
}

fn typing_key(channel_id: &str, thread_root: &str) -> String {
    format!("{channel_id}:{thread_root}")
}

async fn typing_loop(state: Arc<AppState>, channel_id: String, mut stop: watch::Receiver<bool>) {
    loop {
        if let Err(err) = state
            .chat_bridge
            .trigger_typing(&state.adapter_id, &channel_id)
            .await
        {
            debug!(error = ?err, "Failed to trigger typing indicator");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(8)) => {}
            _ = stop.changed() => break,
        }
    }
}

async fn handle_session_log(
    state: &AppState,
    record: &ThreadRecord,
    message: &str,
    attachments: &[Attachment],
) -> Result<()> {
    let channel = ChannelAddress {
        team_id: Some(record.team_id.clone()),
        channel_id: record.channel_id.clone(),
        channel_name: None,
        thread_id: Some(record.thread_root.clone()),
    };

    let cleaned = strip_llm_markup(message);
    if cleaned.is_empty() && attachments.is_empty() {
        return Ok(());
    }

    // Cancel typing indicator now that we have a response to deliver
    let key = typing_key(&record.channel_id, &record.thread_root);
    if let Some(tx) = state.typing_stops.lock().await.remove(&key) {
        let _ = tx.send(true);
    }
    let mut content = MessageContent::markdown(&cleaned);
    content.attachments = attachments.to_vec();
    let mut outgoing = OutgoingMessage::new(channel, content);
    outgoing.reply_in_thread = Some(record.thread_root.clone());

    state
        .chat_bridge
        .send(&state.adapter_id, outgoing)
        .await
        .context("failed to send message via chat bridge")?;
    Ok(())
}

pub fn init_tracing() {
    if tracing::dispatcher::has_been_set() {
        return;
    }

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}
