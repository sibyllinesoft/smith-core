use crate::adapter::{
    discord::DiscordAdapter, google_chat::GoogleChatAdapter, imessage::IMessageAdapter,
    matrix::MatrixAdapter, mattermost::MattermostAdapter, signal::SignalAdapter,
    slack::SlackAdapter, teams::TeamsAdapter, telegram::TelegramAdapter, whatsapp::WhatsAppAdapter,
    ChatAdapter, FetchRequest, OutgoingMessage, SendReceipt,
};
use crate::config::{AdapterConfig, ChatBridgeConfig};
use crate::error::{ChatBridgeError, Result};
use crate::message::BridgeMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Default)]
pub struct ChatBridge {
    adapters: RwLock<HashMap<String, Arc<dyn ChatAdapter>>>,
}

impl ChatBridge {
    pub fn new() -> Self {
        Self {
            adapters: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register_adapter(&self, adapter: Arc<dyn ChatAdapter>) {
        let id = adapter.id().to_string();
        self.adapters.write().await.insert(id, adapter);
    }

    pub async fn unregister_adapter(&self, adapter_id: &str) {
        self.adapters.write().await.remove(adapter_id);
    }

    pub async fn adapter_ids(&self) -> Vec<String> {
        self.adapters
            .read()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    }

    pub async fn send(&self, adapter_id: &str, message: OutgoingMessage) -> Result<SendReceipt> {
        let adapter = self
            .adapters
            .read()
            .await
            .get(adapter_id)
            .cloned()
            .ok_or_else(|| ChatBridgeError::AdapterNotFound {
                adapter: adapter_id.to_string(),
            })?;
        adapter.send_message(message).await
    }

    pub async fn broadcast(&self, message: OutgoingMessage) -> Result<Vec<SendReceipt>> {
        let adapters = self
            .adapters
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut receipts = Vec::with_capacity(adapters.len());
        for adapter in adapters {
            receipts.push(adapter.send_message(message.clone()).await?);
        }
        Ok(receipts)
    }

    pub async fn fetch(
        &self,
        adapter_id: &str,
        request: FetchRequest,
    ) -> Result<Vec<BridgeMessage>> {
        let adapter = self
            .adapters
            .read()
            .await
            .get(adapter_id)
            .cloned()
            .ok_or_else(|| ChatBridgeError::AdapterNotFound {
                adapter: adapter_id.to_string(),
            })?;
        adapter.fetch_messages(request).await
    }

    pub async fn fetch_all(&self, request: FetchRequest) -> Result<Vec<BridgeMessage>> {
        let adapters = self
            .adapters
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();

        let mut messages = Vec::new();
        for adapter in adapters {
            messages.extend(adapter.fetch_messages(request.clone()).await?);
        }
        messages.sort_by_key(|msg| msg.timestamp);
        Ok(messages)
    }

    pub async fn health(&self) -> Result<HashMap<String, bool>> {
        let adapters = self
            .adapters
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();

        let mut map = HashMap::new();
        for adapter in adapters {
            let status = adapter.health_check().await?;
            map.insert(adapter.id().to_string(), status.is_online);
        }
        Ok(map)
    }

    pub async fn build_from_config(config: ChatBridgeConfig) -> Result<Self> {
        let bridge = ChatBridge::new();

        for (idx, adapter_config) in config.adapters.into_iter().enumerate() {
            let default_id = format!(
                "{}-{}",
                adapter_config.platform().to_string().to_lowercase(),
                idx + 1
            );

            let adapter: Arc<dyn ChatAdapter> = match adapter_config {
                AdapterConfig::Slack(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(SlackAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::Teams(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(TeamsAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::Mattermost(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(MattermostAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::Telegram(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(TelegramAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::Discord(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(DiscordAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::WhatsApp(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(WhatsAppAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::Signal(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(SignalAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::GoogleChat(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(GoogleChatAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::IMessage(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(IMessageAdapter::new(adapter_id, cfg)?)
                }
                AdapterConfig::Matrix(cfg) => {
                    let adapter_id = cfg.label.clone().unwrap_or_else(|| default_id.clone());
                    Arc::new(MatrixAdapter::new(adapter_id, cfg)?)
                }
            };

            bridge.register_adapter(adapter).await;
        }

        Ok(bridge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{AdapterCapabilities, AdapterStatus};
    use crate::message::{
        BridgeMessage, ChannelAddress, ChatPlatform, MessageContent, Participant, ParticipantRole,
    };
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct MockAdapter {
        id: String,
        platform: ChatPlatform,
        sent: Arc<Mutex<Vec<OutgoingMessage>>>,
        messages: Vec<BridgeMessage>,
    }

    #[async_trait]
    impl ChatAdapter for MockAdapter {
        fn id(&self) -> &str {
            &self.id
        }

        fn platform(&self) -> ChatPlatform {
            self.platform
        }

        fn label(&self) -> &str {
            &self.id
        }

        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities {
                supports_threads: true,
                supports_ephemeral: false,
                supports_markdown: true,
            }
        }

        async fn health_check(&self) -> Result<AdapterStatus> {
            Ok(AdapterStatus {
                is_online: true,
                last_checked_at: Utc::now(),
                details: None,
            })
        }

        async fn fetch_messages(&self, _request: FetchRequest) -> Result<Vec<BridgeMessage>> {
            Ok(self.messages.clone())
        }

        async fn send_message(&self, message: OutgoingMessage) -> Result<SendReceipt> {
            self.sent.lock().await.push(message.clone());
            Ok(SendReceipt {
                message_id: "mock".into(),
                timestamp: Utc::now(),
                platform: self.platform,
                channel: ChannelAddress::new("mock"),
            })
        }
    }

    #[tokio::test]
    async fn it_registers_and_dispatches() {
        let bridge = ChatBridge::new();

        let adapter = MockAdapter {
            id: "mock".into(),
            platform: ChatPlatform::Slack,
            sent: Arc::new(Mutex::new(Vec::new())),
            messages: vec![BridgeMessage {
                id: "1".into(),
                platform: ChatPlatform::Slack,
                channel: ChannelAddress::new("chan"),
                sender: Participant {
                    id: "user".into(),
                    display_name: None,
                    role: ParticipantRole::User,
                    username: None,
                    tags: Vec::new(),
                },
                content: MessageContent::plain("hello"),
                timestamp: Utc::now(),
                thread_root: None,
                identity: None,
                metadata: HashMap::new(),
            }],
        };

        let sent_ref = adapter.sent.clone();
        bridge
            .register_adapter(Arc::new(adapter) as Arc<dyn ChatAdapter>)
            .await;

        bridge
            .send(
                "mock",
                OutgoingMessage::new(ChannelAddress::new("chan"), MessageContent::plain("hi")),
            )
            .await
            .unwrap();

        let sent = sent_ref.lock().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].content.text, "hi");

        let messages = bridge
            .fetch("mock", FetchRequest::for_channel("chan"))
            .await
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content.text, "hello");
    }

    #[tokio::test]
    async fn it_broadcasts_to_all_adapters() {
        let bridge = ChatBridge::new();

        let adapter_a = MockAdapter {
            id: "a".into(),
            platform: ChatPlatform::Slack,
            sent: Arc::new(Mutex::new(Vec::new())),
            messages: Vec::new(),
        };

        let adapter_b = MockAdapter {
            id: "b".into(),
            platform: ChatPlatform::Mattermost,
            sent: Arc::new(Mutex::new(Vec::new())),
            messages: Vec::new(),
        };

        let sent_a = adapter_a.sent.clone();
        let sent_b = adapter_b.sent.clone();

        bridge
            .register_adapter(Arc::new(adapter_a) as Arc<dyn ChatAdapter>)
            .await;
        bridge
            .register_adapter(Arc::new(adapter_b) as Arc<dyn ChatAdapter>)
            .await;

        bridge
            .broadcast(OutgoingMessage::new(
                ChannelAddress::new("chan"),
                MessageContent::plain("broadcast"),
            ))
            .await
            .unwrap();

        assert_eq!(sent_a.lock().await.len(), 1);
        assert_eq!(sent_b.lock().await.len(), 1);
    }
}
