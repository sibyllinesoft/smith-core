use super::{
    AdapterCapabilities, AdapterStatus, ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::DiscordConfig;
use crate::error::{ChatBridgeError, Result};
use crate::message::{
    Attachment, BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, MessageFormat,
    Participant, ParticipantRole,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::warn;

const DISCORD_API_BASE: &str = "https://discord.com/api/v10";
const DISCORD_MAX_CHARS: usize = 2000;
const DISCORD_RATE_LIMIT_RETRIES: usize = 3;

#[derive(Clone)]
pub struct DiscordAdapter {
    id: String,
    label: String,
    client: Client,
    config: DiscordConfig,
}

impl DiscordAdapter {
    pub fn new(id: impl Into<String>, config: DiscordConfig) -> Result<Self> {
        if config.bot_token.trim().is_empty() {
            return Err(ChatBridgeError::InvalidConfig(
                "Discord bot token cannot be empty".into(),
            ));
        }

        let client = Client::builder().build()?;
        let id = id.into();
        let label = config.label.clone().unwrap_or_else(|| id.clone());

        Ok(Self {
            id,
            label,
            client,
            config,
        })
    }

    fn bot_auth(&self) -> String {
        format!("Bot {}", self.config.bot_token)
    }

    fn convert_message(
        &self,
        msg: DiscordMessage,
        channel: &ChannelAddress,
    ) -> Result<BridgeMessage> {
        let timestamp = DateTime::parse_from_rfc3339(&msg.timestamp)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|err| {
                ChatBridgeError::other(format!("invalid Discord timestamp `{}`: {err}", msg.timestamp))
            })?;

        let (sender_id, display_name, username, role) = if let Some(author) = msg.author {
            let is_bot = author.bot.unwrap_or(false);
            (
                author.id,
                author.global_name.or(Some(author.username.clone())),
                Some(author.username),
                if is_bot {
                    ParticipantRole::Bot
                } else {
                    ParticipantRole::User
                },
            )
        } else {
            ("unknown".to_string(), None, None, ParticipantRole::Unknown)
        };

        let mut attachments = Vec::new();
        if let Some(items) = msg.attachments {
            for att in items {
                attachments.push(Attachment {
                    id: Some(att.id),
                    title: Some(att.filename),
                    url: att.url,
                    mime_type: att.content_type,
                    size_bytes: att.size.map(|s| s as u64),
                });
            }
        }

        let mut metadata: HashMap<String, Value> = HashMap::new();
        if let Some(ref_msg) = &msg.message_reference {
            if let Some(ref_id) = &ref_msg.message_id {
                metadata.insert("reply_to".to_string(), Value::String(ref_id.clone()));
            }
        }

        let mut content = MessageContent {
            text: msg.content,
            format: MessageFormat::Markdown,
            attachments,
            extra: HashMap::new(),
        };
        if let Some(embeds) = msg.embeds {
            if !embeds.is_empty() {
                content
                    .extra
                    .insert("embeds".to_string(), Value::Array(embeds));
            }
        }

        let thread_root = msg
            .message_reference
            .and_then(|r| r.message_id);

        Ok(BridgeMessage {
            id: msg.id,
            platform: ChatPlatform::Discord,
            channel: channel.clone(),
            sender: Participant {
                id: sender_id,
                display_name,
                role,
                username,
                tags: Vec::new(),
            },
            content,
            timestamp,
            thread_root,
            identity: None,
            metadata,
        })
    }
}

#[async_trait]
impl ChatAdapter for DiscordAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn platform(&self) -> ChatPlatform {
        ChatPlatform::Discord
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            supports_threads: true,
            supports_ephemeral: true,
            supports_markdown: true,
        }
    }

    async fn health_check(&self) -> Result<AdapterStatus> {
        let response = self
            .client
            .get(format!("{DISCORD_API_BASE}/users/@me"))
            .header("Authorization", self.bot_auth())
            .send()
            .await?;

        let ok = response.status().is_success();
        let details = if ok {
            None
        } else {
            Some(format!("Discord health check returned {}", response.status()))
        };

        Ok(AdapterStatus {
            is_online: ok,
            last_checked_at: Utc::now(),
            details,
        })
    }

    async fn fetch_messages(&self, request: FetchRequest) -> Result<Vec<BridgeMessage>> {
        let mut url = format!(
            "{DISCORD_API_BASE}/channels/{}/messages",
            request.channel.channel_id
        );

        let mut query: Vec<(String, String)> = Vec::new();
        if let Some(limit) = request.limit {
            query.push(("limit".to_string(), limit.to_string()));
        }

        if !query.is_empty() {
            url.push('?');
            url.push_str(
                &query
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }

        let response = self
            .client
            .get(&url)
            .header("Authorization", self.bot_auth())
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Discord fetch messages failed ({status}): {body}"
            )));
        }

        let messages: Vec<DiscordMessage> = response.json().await?;
        let channel = request.channel.clone();
        let mut result = Vec::new();
        for msg in messages {
            result.push(self.convert_message(msg, &channel)?);
        }

        Ok(result)
    }

    async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
        let url = format!(
            "{DISCORD_API_BASE}/channels/{}/messages",
            message.channel.channel_id
        );

        let chunks = chunk_discord_text(&message.content.text);
        let has_attachments = !message.content.attachments.is_empty();
        let mut last_receipt: Option<SendReceipt> = None;

        for (i, chunk) in chunks.iter().enumerate() {
            let mut payload = json!({ "content": chunk });

            // Only the first chunk gets the thread reply reference
            if i == 0 {
                if let Some(thread) = &message.reply_in_thread {
                    payload["message_reference"] = json!({ "message_id": thread });
                }
            }

            // Attachments go with the first chunk only (multipart upload)
            let msg = if i == 0 && has_attachments {
                self.post_multipart_with_retry(&url, &payload, &message.content.attachments)
                    .await?
            } else {
                self.post_with_retry(&url, &payload).await?
            };

            let timestamp = DateTime::parse_from_rfc3339(&msg.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            last_receipt = Some(SendReceipt {
                message_id: msg.id,
                timestamp,
                platform: ChatPlatform::Discord,
                channel: message.channel.clone(),
            });
        }

        last_receipt.ok_or_else(|| ChatBridgeError::other("no chunks to send"))
    }
}

impl DiscordAdapter {
    /// POST a message payload with rate-limit retry (HTTP 429).
    async fn post_with_retry(&self, url: &str, payload: &Value) -> Result<DiscordMessage> {
        let mut last_err = None;

        for attempt in 0..DISCORD_RATE_LIMIT_RETRIES {
            let response = self
                .client
                .post(url)
                .header("Authorization", self.bot_auth())
                .json(payload)
                .send()
                .await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            let status = response.status();

            // Rate limited — wait and retry
            if status.as_u16() == 429 {
                let body: Value = response.json().await.unwrap_or_default();
                let retry_after = body
                    .get("retry_after")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1.0);
                let wait = std::time::Duration::from_secs_f64(retry_after.min(30.0));
                warn!(
                    attempt,
                    retry_after_secs = retry_after,
                    "Discord rate limited, waiting"
                );
                tokio::time::sleep(wait).await;
                last_err = Some(format!("rate limited (attempt {attempt})"));
                continue;
            }

            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Discord send message failed ({status}): {body}"
            )));
        }

        Err(ChatBridgeError::other(format!(
            "Discord send failed after {DISCORD_RATE_LIMIT_RETRIES} retries: {}",
            last_err.unwrap_or_default()
        )))
    }

    /// POST a multipart message with file attachments and rate-limit retry.
    async fn post_multipart_with_retry(
        &self,
        url: &str,
        payload_json: &Value,
        attachments: &[Attachment],
    ) -> Result<DiscordMessage> {
        let mut last_err = None;

        for attempt in 0..DISCORD_RATE_LIMIT_RETRIES {
            let form = self.build_multipart_form(payload_json, attachments).await?;

            let response = self
                .client
                .post(url)
                .header("Authorization", self.bot_auth())
                .multipart(form)
                .send()
                .await?;

            if response.status().is_success() {
                return Ok(response.json().await?);
            }

            let status = response.status();

            if status.as_u16() == 429 {
                let body: Value = response.json().await.unwrap_or_default();
                let retry_after = body
                    .get("retry_after")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1.0);
                let wait = std::time::Duration::from_secs_f64(retry_after.min(30.0));
                warn!(attempt, retry_after_secs = retry_after, "Discord rate limited, waiting");
                tokio::time::sleep(wait).await;
                last_err = Some(format!("rate limited (attempt {attempt})"));
                continue;
            }

            let body = response.text().await.unwrap_or_default();
            return Err(ChatBridgeError::other(format!(
                "Discord send multipart failed ({status}): {body}"
            )));
        }

        Err(ChatBridgeError::other(format!(
            "Discord multipart send failed after {DISCORD_RATE_LIMIT_RETRIES} retries: {}",
            last_err.unwrap_or_default()
        )))
    }

    /// Build a multipart/form-data payload with JSON metadata and file parts.
    async fn build_multipart_form(
        &self,
        payload_json: &Value,
        attachments: &[Attachment],
    ) -> Result<Form> {
        let mut form = Form::new().text("payload_json", payload_json.to_string());

        for (i, attachment) in attachments.iter().enumerate() {
            let bytes = fetch_attachment_bytes(&self.client, &attachment.url).await?;
            let filename = attachment
                .title
                .clone()
                .unwrap_or_else(|| format!("file{i}.bin"));

            let part = Part::bytes(bytes).file_name(filename);
            let part = if let Some(mime) = &attachment.mime_type {
                // mime_str consumes Part; it only fails on truly invalid MIME strings
                part.mime_str(mime).map_err(|e| {
                    ChatBridgeError::other(format!("invalid MIME type `{mime}`: {e}"))
                })?
            } else {
                part
            };

            form = form.part(format!("files[{i}]"), part);
        }

        Ok(form)
    }
}

/// Fetch attachment content from a URL, file path, or data URI.
///
/// Supported schemes:
/// - `data:...;base64,...` — decoded inline
/// - `file:///path` or bare `/path` — read from local filesystem
/// - `http://` / `https://` — fetched via HTTP
async fn fetch_attachment_bytes(client: &Client, url: &str) -> Result<Vec<u8>> {
    // Data URI: data:[<mediatype>][;base64],<data>
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some(comma_pos) = rest.find(',') {
            let header = &rest[..comma_pos];
            let data = &rest[comma_pos + 1..];
            if header.contains("base64") {
                use base64::Engine;
                return base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|e| ChatBridgeError::other(format!("base64 decode failed: {e}")));
            }
            // Non-base64 data URI (percent-encoded)
            return Ok(data.as_bytes().to_vec());
        }
        return Err(ChatBridgeError::other("malformed data URI"));
    }

    // Local file path
    let file_path = url
        .strip_prefix("file://")
        .or_else(|| if url.starts_with('/') { Some(url) } else { None });
    if let Some(path) = file_path {
        return tokio::fs::read(path)
            .await
            .map_err(|e| ChatBridgeError::other(format!("failed to read file {path}: {e}")));
    }

    // HTTP(S) URL
    let response = client.get(url).send().await.map_err(|e| {
        ChatBridgeError::other(format!("failed to fetch attachment from {url}: {e}"))
    })?;
    if !response.status().is_success() {
        return Err(ChatBridgeError::other(format!(
            "attachment fetch failed ({}) from {url}",
            response.status()
        )));
    }
    response
        .bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| ChatBridgeError::other(format!("failed to read attachment body: {e}")))
}

// ── Message chunking ────────────────────────────────────────────────────

/// Returns true if the line is a fenced code block delimiter (``` or ~~~).
fn is_fence_marker(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

/// Split text into chunks that fit within Discord's 2000-character limit.
///
/// Handles:
/// - Fenced code blocks: closes and reopens across chunk boundaries
/// - Paragraph-preferred splitting: prefers blank-line boundaries
/// - Word-boundary splitting for lines that exceed the limit on their own
fn chunk_discord_text(text: &str) -> Vec<String> {
    if text.chars().count() <= DISCORD_MAX_CHARS {
        return vec![text.to_string()];
    }

    let lines: Vec<&str> = text.split('\n').collect();
    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_chars: usize = 0;
    let mut open_fence: Option<String> = None; // the opening fence line, e.g. "```rust"

    for line in &lines {
        let line_chars = line.chars().count();
        // Cost of appending this line (\n + line content)
        let addition = if current.is_empty() { line_chars } else { line_chars + 1 };
        // Reserve space for a closing fence if we're inside a code block
        let fence_reserve = if open_fence.is_some() { 4 } else { 0 }; // "\n```"

        // Would adding this line exceed the limit?
        if !current.is_empty() && current_chars + addition + fence_reserve > DISCORD_MAX_CHARS {
            flush_chunk(&mut chunks, &mut current, &mut current_chars, &open_fence);

            // Reopen fence in new chunk
            if let Some(ref fence) = open_fence {
                current.push_str(fence);
                current.push('\n');
                current_chars = fence.chars().count() + 1;
            }
        }

        // Handle single lines that exceed the limit on their own
        if line_chars + fence_reserve >= DISCORD_MAX_CHARS {
            // Flush current content first
            if !current.is_empty() {
                flush_chunk(&mut chunks, &mut current, &mut current_chars, &open_fence);
                if let Some(ref fence) = open_fence {
                    current.push_str(fence);
                    current.push('\n');
                    current_chars = fence.chars().count() + 1;
                }
            }

            let max = DISCORD_MAX_CHARS - fence_reserve;
            let parts = split_long_line(line, max);
            for (i, part) in parts.iter().enumerate() {
                if i > 0 || !current.is_empty() {
                    // Flush previous part as its own chunk
                    if !current.is_empty() && current_chars + part.chars().count() + 1 + fence_reserve > DISCORD_MAX_CHARS {
                        flush_chunk(&mut chunks, &mut current, &mut current_chars, &open_fence);
                        if let Some(ref fence) = open_fence {
                            current.push_str(fence);
                            current.push('\n');
                            current_chars = fence.chars().count() + 1;
                        }
                    }
                }
                if !current.is_empty() {
                    current.push('\n');
                    current_chars += 1;
                }
                current.push_str(part);
                current_chars += part.chars().count();
            }

            // Update fence state for the original line
            if is_fence_marker(line) {
                if open_fence.is_some() {
                    open_fence = None;
                } else {
                    open_fence = Some(line.to_string());
                }
            }
            continue;
        }

        // Normal case: append line to current chunk
        if !current.is_empty() {
            current.push('\n');
            current_chars += 1;
        }
        current.push_str(line);
        current_chars += line_chars;

        // Track fence state
        if is_fence_marker(line) {
            if open_fence.is_some() {
                open_fence = None;
            } else {
                open_fence = Some(line.to_string());
            }
        }
    }

    // Flush remaining content
    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

/// Flush the current buffer into a completed chunk, closing any open fence.
fn flush_chunk(
    chunks: &mut Vec<String>,
    current: &mut String,
    current_chars: &mut usize,
    open_fence: &Option<String>,
) {
    if open_fence.is_some() {
        current.push_str("\n```");
    }
    if !current.trim().is_empty() {
        chunks.push(std::mem::take(current));
    } else {
        current.clear();
    }
    *current_chars = 0;
}

/// Split a single long line at word boundaries to fit within max_chars.
fn split_long_line(line: &str, max_chars: usize) -> Vec<String> {
    if line.chars().count() <= max_chars {
        return vec![line.to_string()];
    }

    let mut parts = Vec::new();
    let mut remaining = line;

    while remaining.chars().count() > max_chars {
        // Find the byte offset of the max_chars-th character
        let limit_byte = remaining
            .char_indices()
            .nth(max_chars)
            .map(|(idx, _)| idx)
            .unwrap_or(remaining.len());

        let window = &remaining[..limit_byte];

        // Prefer splitting at whitespace
        let split_byte = window
            .rfind(|c: char| c.is_whitespace())
            .unwrap_or(limit_byte);

        let (part, rest) = remaining.split_at(split_byte);
        if !part.is_empty() {
            parts.push(part.to_string());
        }
        remaining = rest.trim_start();
    }

    if !remaining.is_empty() {
        parts.push(remaining.to_string());
    }

    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_no_chunking() {
        let chunks = chunk_discord_text("Hello, world!");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "Hello, world!");
    }

    #[test]
    fn long_text_splits_at_lines() {
        let line = "a".repeat(100);
        let text = (0..25).map(|_| line.as_str()).collect::<Vec<_>>().join("\n");
        assert!(text.chars().count() > DISCORD_MAX_CHARS);
        let chunks = chunk_discord_text(&text);
        for chunk in &chunks {
            assert!(
                chunk.chars().count() <= DISCORD_MAX_CHARS,
                "chunk too long: {} chars",
                chunk.chars().count()
            );
        }
    }

    #[test]
    fn fenced_code_blocks_closed_and_reopened() {
        let mut lines = vec!["Here is code:", "```rust"];
        for _ in 0..30 {
            lines.push("let x = 42; // some code that takes up space in the message");
        }
        lines.push("```");
        lines.push("And here is more text after the code block.");
        let text = lines.join("\n");

        let chunks = chunk_discord_text(&text);
        for chunk in &chunks {
            assert!(
                chunk.chars().count() <= DISCORD_MAX_CHARS,
                "chunk too long: {} chars",
                chunk.chars().count()
            );
            // Every chunk that opens a fence should close it
            let opens = chunk.matches("```rust").count();
            let closes = chunk.matches("```").count() - opens; // plain ``` are closes
            if opens > 0 {
                assert!(closes >= opens, "unclosed fence in chunk: {chunk}");
            }
        }
    }

    #[test]
    fn single_long_line_splits_at_words() {
        let parts = split_long_line(&"word ".repeat(500), 100);
        for part in &parts {
            assert!(part.chars().count() <= 100, "part too long: {}", part.len());
        }
    }
}

#[derive(Debug, Deserialize)]
struct DiscordMessage {
    id: String,
    timestamp: String,
    content: String,
    #[serde(default)]
    author: Option<DiscordUser>,
    #[serde(default)]
    attachments: Option<Vec<DiscordAttachment>>,
    #[serde(default)]
    embeds: Option<Vec<Value>>,
    #[serde(default)]
    message_reference: Option<DiscordMessageReference>,
}

#[derive(Debug, Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    #[serde(default)]
    global_name: Option<String>,
    #[serde(default)]
    bot: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct DiscordAttachment {
    id: String,
    filename: String,
    url: String,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    size: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DiscordMessageReference {
    #[serde(default)]
    message_id: Option<String>,
}
