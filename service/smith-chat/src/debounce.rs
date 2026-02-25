//! Message debouncing for rapid-fire user messages.
//!
//! Users frequently send 2-3 messages in quick succession on Discord. This
//! module batches them into a single combined envelope so the agent sees one
//! coherent message instead of triggering separate session interactions.

use std::collections::HashMap;

use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tracing::{debug, info, warn};

use crate::daemon::BridgeMessageEnvelope;

/// Key used to group messages from the same sender in the same conversation.
pub fn debounce_key(envelope: &BridgeMessageEnvelope) -> String {
    format!(
        "{}:{}:{}",
        envelope.sender.id, envelope.channel_id, envelope.thread_root
    )
}

/// A buffer holding envelopes that arrived within the debounce window.
struct DebounceBuffer {
    envelopes: Vec<BridgeMessageEnvelope>,
    deadline: Instant,
}

/// Combines multiple envelopes into one.
///
/// - `message`: joined with `\n`
/// - `post_id`: last message's (latest)
/// - `thread_root`: first message's (establishes conversation)
/// - `attachments`: concatenated
/// - `timestamp`: latest
/// - `thread_history`: first message's only
pub fn combine_envelopes(mut envelopes: Vec<BridgeMessageEnvelope>) -> BridgeMessageEnvelope {
    assert!(!envelopes.is_empty(), "cannot combine zero envelopes");
    if envelopes.len() == 1 {
        return envelopes.remove(0);
    }

    let mut iter = envelopes.into_iter();
    let mut combined = iter.next().unwrap();

    for env in iter {
        combined.message.push('\n');
        combined.message.push_str(&env.message);
        combined.post_id = env.post_id;
        combined.timestamp = env.timestamp;
        combined.attachments.extend(env.attachments);
    }

    combined
}

/// Handle to send envelopes into the debouncer.
pub struct Debouncer {
    tx: mpsc::UnboundedSender<BridgeMessageEnvelope>,
}

impl Debouncer {
    /// Spawn a new debouncer background task.
    ///
    /// `debounce_ms` is the rolling deadline in milliseconds. When the deadline
    /// fires, buffered envelopes are combined and passed to `callback`.
    ///
    /// Envelopes with attachments are flushed immediately (no delay).
    ///
    /// Returns a handle and a `JoinHandle` for the background task.
    pub fn spawn<F>(debounce_ms: u64, callback: F) -> (Self, tokio::task::JoinHandle<()>)
    where
        F: Fn(BridgeMessageEnvelope) + Send + Sync + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(debounce_loop(rx, debounce_ms, callback));
        (Self { tx }, handle)
    }

    /// Submit an envelope for debouncing.
    pub fn send(&self, envelope: BridgeMessageEnvelope) -> Result<(), BridgeMessageEnvelope> {
        self.tx.send(envelope).map_err(|e| e.0)
    }
}

async fn debounce_loop<F>(
    mut rx: mpsc::UnboundedReceiver<BridgeMessageEnvelope>,
    debounce_ms: u64,
    callback: F,
) where
    F: Fn(BridgeMessageEnvelope) + Send + Sync + 'static,
{
    let window = std::time::Duration::from_millis(debounce_ms);
    let mut buffers: HashMap<String, DebounceBuffer> = HashMap::new();

    loop {
        // Find the earliest deadline across all buffers.
        let next_deadline = buffers.values().map(|b| b.deadline).min();

        let envelope = match next_deadline {
            Some(deadline) => {
                tokio::select! {
                    biased;
                    maybe = rx.recv() => {
                        match maybe {
                            Some(env) => Some(env),
                            None => {
                                // Channel closed — flush everything and exit.
                                flush_all(&mut buffers, &callback);
                                return;
                            }
                        }
                    }
                    _ = sleep_until(deadline) => None,
                }
            }
            None => {
                // No pending buffers — just wait for the next envelope.
                match rx.recv().await {
                    Some(env) => Some(env),
                    None => return, // channel closed, nothing to flush
                }
            }
        };

        if let Some(env) = envelope {
            let has_attachments = !env.attachments.is_empty();
            let key = debounce_key(&env);

            if has_attachments {
                // Flush any existing buffer for this key first, then flush
                // this envelope immediately (attachments bypass debouncing).
                if let Some(buf) = buffers.remove(&key) {
                    debug!(key = %key, count = buf.envelopes.len(), "Flushing buffer before attachment");
                    callback(combine_envelopes(buf.envelopes));
                }
                debug!(key = %key, "Immediate flush (has attachments)");
                callback(env);
            } else {
                let buf = buffers.entry(key.clone()).or_insert_with(|| DebounceBuffer {
                    envelopes: Vec::new(),
                    deadline: Instant::now() + window,
                });
                buf.envelopes.push(env);
                // Rolling deadline: reset on each new message.
                buf.deadline = Instant::now() + window;
            }
        }

        // Flush any buffers whose deadline has passed.
        let now = Instant::now();
        let expired_keys: Vec<String> = buffers
            .iter()
            .filter(|(_, b)| b.deadline <= now)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            if let Some(buf) = buffers.remove(&key) {
                info!(
                    key = %key,
                    count = buf.envelopes.len(),
                    "Debounce deadline reached, flushing"
                );
                callback(combine_envelopes(buf.envelopes));
            }
        }
    }
}

fn flush_all<F>(buffers: &mut HashMap<String, DebounceBuffer>, callback: &F)
where
    F: Fn(BridgeMessageEnvelope),
{
    for (key, buf) in buffers.drain() {
        warn!(key = %key, count = buf.envelopes.len(), "Flushing buffer on shutdown");
        callback(combine_envelopes(buf.envelopes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{AttachmentEnvelope, SenderEnvelope};
    use std::collections::HashMap;

    fn make_envelope(sender_id: &str, channel: &str, thread: &str, msg: &str) -> BridgeMessageEnvelope {
        BridgeMessageEnvelope {
            platform: "discord".to_string(),
            team_id: "guild1".to_string(),
            team_name: None,
            channel_id: channel.to_string(),
            channel_name: None,
            post_id: format!("post_{msg}"),
            thread_root: thread.to_string(),
            message: msg.to_string(),
            props: HashMap::new(),
            attachments: Vec::new(),
            timestamp: 1000,
            secret: None,
            sender: SenderEnvelope {
                id: sender_id.to_string(),
                username: Some("user".to_string()),
                display_name: None,
                is_bot: false,
            },
            thread_history: Vec::new(),
        }
    }

    fn make_envelope_with_attachment(sender_id: &str, channel: &str, thread: &str, msg: &str) -> BridgeMessageEnvelope {
        let mut env = make_envelope(sender_id, channel, thread, msg);
        env.attachments.push(AttachmentEnvelope {
            id: "att1".to_string(),
            name: "file.png".to_string(),
            mime_type: Some("image/png".to_string()),
            size_bytes: 1024,
        });
        env
    }

    #[test]
    fn combine_single_envelope() {
        let env = make_envelope("u1", "c1", "t1", "hello");
        let combined = combine_envelopes(vec![env]);
        assert_eq!(combined.message, "hello");
        assert_eq!(combined.post_id, "post_hello");
        assert_eq!(combined.thread_root, "t1");
    }

    #[test]
    fn combine_multiple_envelopes() {
        let mut e1 = make_envelope("u1", "c1", "t1", "hello");
        e1.timestamp = 1000;
        e1.post_id = "post1".to_string();

        let mut e2 = make_envelope("u1", "c1", "t1", "world");
        e2.timestamp = 2000;
        e2.post_id = "post2".to_string();

        let mut e3 = make_envelope("u1", "c1", "t1", "!!!");
        e3.timestamp = 3000;
        e3.post_id = "post3".to_string();

        let combined = combine_envelopes(vec![e1, e2, e3]);
        assert_eq!(combined.message, "hello\nworld\n!!!");
        assert_eq!(combined.post_id, "post3"); // last
        assert_eq!(combined.thread_root, "t1"); // first
        assert_eq!(combined.timestamp, 3000); // latest
    }

    #[test]
    fn combine_merges_attachments() {
        let mut e1 = make_envelope("u1", "c1", "t1", "look at this");
        e1.attachments.push(AttachmentEnvelope {
            id: "a1".to_string(),
            name: "pic.png".to_string(),
            mime_type: Some("image/png".to_string()),
            size_bytes: 1024,
        });

        let mut e2 = make_envelope("u1", "c1", "t1", "and this");
        e2.attachments.push(AttachmentEnvelope {
            id: "a2".to_string(),
            name: "doc.pdf".to_string(),
            mime_type: Some("application/pdf".to_string()),
            size_bytes: 2048,
        });

        let combined = combine_envelopes(vec![e1, e2]);
        assert_eq!(combined.attachments.len(), 2);
        assert_eq!(combined.attachments[0].id, "a1");
        assert_eq!(combined.attachments[1].id, "a2");
    }

    #[test]
    fn combine_keeps_first_thread_history() {
        use crate::daemon::HistoryMessage;

        let mut e1 = make_envelope("u1", "c1", "t1", "first");
        e1.thread_history = vec![HistoryMessage {
            role: "user".to_string(),
            content: "prior msg".to_string(),
            username: None,
            timestamp: None,
        }];

        let mut e2 = make_envelope("u1", "c1", "t1", "second");
        e2.thread_history = vec![HistoryMessage {
            role: "user".to_string(),
            content: "should be ignored".to_string(),
            username: None,
            timestamp: None,
        }];

        let combined = combine_envelopes(vec![e1, e2]);
        assert_eq!(combined.thread_history.len(), 1);
        assert_eq!(combined.thread_history[0].content, "prior msg");
    }

    #[test]
    fn debounce_key_format() {
        let env = make_envelope("user42", "channel7", "thread99", "hi");
        assert_eq!(debounce_key(&env), "user42:channel7:thread99");
    }

    #[tokio::test]
    async fn debouncer_flushes_on_deadline() {
        let (result_tx, mut result_rx) = mpsc::unbounded_channel();

        let (debouncer, _handle) = Debouncer::spawn(50, move |env| {
            let _ = result_tx.send(env);
        });

        debouncer.send(make_envelope("u1", "c1", "t1", "hello")).unwrap();
        debouncer.send(make_envelope("u1", "c1", "t1", "world")).unwrap();

        let combined = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            result_rx.recv(),
        )
        .await
        .expect("timeout waiting for debounce flush")
        .expect("channel closed");

        assert_eq!(combined.message, "hello\nworld");
    }

    #[tokio::test]
    async fn debouncer_immediate_flush_for_attachments() {
        let (result_tx, mut result_rx) = mpsc::unbounded_channel();

        let (debouncer, _handle) = Debouncer::spawn(500, move |env| {
            let _ = result_tx.send(env);
        });

        // Send a text message followed immediately by one with an attachment.
        debouncer.send(make_envelope("u1", "c1", "t1", "text")).unwrap();
        debouncer
            .send(make_envelope_with_attachment("u1", "c1", "t1", "pic"))
            .unwrap();

        // The text buffer should be flushed first, then the attachment immediately.
        let first = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            result_rx.recv(),
        )
        .await
        .expect("timeout")
        .expect("closed");
        assert_eq!(first.message, "text");

        let second = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            result_rx.recv(),
        )
        .await
        .expect("timeout")
        .expect("closed");
        assert_eq!(second.message, "pic");
        assert_eq!(second.attachments.len(), 1);
    }
}
