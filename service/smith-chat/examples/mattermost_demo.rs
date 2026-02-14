use chat_bridge::{
    adapter::FetchRequest, AdapterConfig, ChannelAddress, ChatBridge, ChatBridgeConfig,
    MattermostConfig, MessageContent, OutgoingMessage,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::{env, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = env::var("MATTERMOST_BASE_URL")?;
    let access_token = env::var("MATTERMOST_ACCESS_TOKEN")?;
    let team_id = env::var("MATTERMOST_TEAM_ID")?;
    let channel_id = env::var("MATTERMOST_CHANNEL_ID")?;

    let use_agent_bridge = env::var("MATTERMOST_USE_AGENT_BRIDGE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let plugin_id = env::var("MATTERMOST_PLUGIN_ID").ok();
    let bridge_url = env::var("MATTERMOST_BRIDGE_URL").ok();
    let webhook_secret = env::var("MATTERMOST_BRIDGE_SECRET").ok();
    let agent_id = env::var("MATTERMOST_AGENT_ID").ok();

    let mattermost_config = MattermostConfig {
        base_url,
        access_token,
        team_id: team_id.clone(),
        channel_id: channel_id.clone(),
        label: Some("mattermost-demo".to_string()),
        verify_tls: env::var("MATTERMOST_SKIP_TLS_VERIFY")
            .map(|value| !(value == "1" || value.eq_ignore_ascii_case("true")))
            .unwrap_or(true),
        use_agent_bridge,
        plugin_id,
        bridge_url,
        webhook_secret,
        agent_id,
    };

    let bridge_config = ChatBridgeConfig {
        adapters: vec![AdapterConfig::Mattermost(mattermost_config)],
        polling_interval_secs: None,
    };

    let mock_addr: SocketAddr = env::var("MATTERMOST_MOCK_SERVER_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8181".to_string())
        .parse()?;

    let mut mock_server = MockOpenAIServer::spawn(mock_addr).await?;
    sleep(Duration::from_millis(200)).await;

    let bridge = ChatBridge::build_from_config(bridge_config).await?;
    let adapter_id = "mattermost-demo";

    let channel = ChannelAddress {
        team_id: Some(team_id.clone()),
        channel_id: channel_id.clone(),
        channel_name: None,
        thread_id: None,
    };

    println!("Posting demo message to Mattermost channel {channel_id}...");
    let message = OutgoingMessage::new(
        channel.clone(),
        MessageContent::markdown("Hello from the Smith chat bridge demo!"),
    );
    let receipt = bridge.send(adapter_id, message).await?;
    println!("Message posted at {}", receipt.timestamp);

    println!("Fetching recent messages...");
    let mut request = FetchRequest::for_channel(channel_id.clone());
    request.limit = Some(5);
    let messages = bridge.fetch(adapter_id, request).await?;

    for msg in messages {
        println!("- [{}] {}", msg.timestamp, msg.content.text);
    }

    let bridge_secret = env::var("MATTERMOST_BRIDGE_SECRET")?;
    let completion: CompletionResponse = reqwest::Client::new()
        .post(format!(
            "{}/plugins/com.smith.mattermost-ai-bridge/external/bridge/completion/agent/{}",
            env::var("MATTERMOST_BASE_URL")?,
            find_agent_id(&bridge_secret).await?
        ))
        .header("Mattermost-Bridge-Secret", bridge_secret.clone())
        .json(&CompletionRequest {
            posts: vec![CompletionPost {
                role: "user".into(),
                message: "summarize the latest Smith activity".into(),
            }],
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!("Proxy completion response: {}", completion.completion);

    let mut reply = OutgoingMessage::new(
        channel,
        MessageContent::markdown(format!("Agent reply: {}", completion.completion)),
    );
    reply.reply_in_thread = Some(receipt.message_id.clone());
    bridge.send(adapter_id, reply).await?;

    mock_server.shutdown().await;

    Ok(())
}

async fn find_agent_id(secret: &str) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct AgentsResponse {
        agents: Vec<AgentInfo>,
    }

    #[derive(Deserialize)]
    struct AgentInfo {
        id: String,
        username: String,
    }

    let resp: AgentsResponse = reqwest::Client::new()
        .get(format!(
            "{}/plugins/com.smith.mattermost-ai-bridge/external/bridge/agents",
            env::var("MATTERMOST_BASE_URL")?
        ))
        .header("Mattermost-Bridge-Secret", secret)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    resp.agents
        .into_iter()
        .find(|agent| agent.username == "smith-echo")
        .map(|agent| agent.id)
        .ok_or_else(|| anyhow::anyhow!("smith-echo agent not found"))
}

#[derive(Serialize)]
struct CompletionRequest {
    posts: Vec<CompletionPost>,
}

#[derive(Serialize)]
struct CompletionPost {
    role: String,
    message: String,
}

#[derive(Deserialize)]
struct CompletionResponse {
    completion: String,
}

struct MockOpenAIServer {
    shutdown: Option<oneshot::Sender<()>>,
}

impl MockOpenAIServer {
    async fn spawn(addr: SocketAddr) -> anyhow::Result<Self> {
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            if let Err(err) = run_mock_server(addr, rx).await {
                eprintln!("mock server error: {err:?}");
            }
        });

        Ok(Self { shutdown: Some(tx) })
    }

    async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for MockOpenAIServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn run_mock_server(
    addr: SocketAddr,
    mut shutdown: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accept_result = listener.accept() => {
                let (mut socket, _) = accept_result?;
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 8192];
                    let mut total_read = 0usize;
                    loop {
                        match socket.read(&mut buffer[total_read..]).await {
                            Ok(0) => break,
                            Ok(n) => {
                                total_read += n;
                                if total_read == buffer.len() {
                                    buffer.resize(buffer.len() * 2, 0);
                                }
                                if buffer[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }

                    let request_bytes = &buffer[..total_read];
                    let request_str = String::from_utf8_lossy(request_bytes);
                    let mut parts = request_str.split("\r\n\r\n");
                    let header_str = parts.next().unwrap_or("");
                    let mut body_bytes = parts.next().unwrap_or("").as_bytes().to_vec();

                    let content_length = header_str
                        .lines()
                        .find(|line| line.to_lowercase().starts_with("content-length"))
                        .and_then(|line| line.split(':').nth(1))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(body_bytes.len());

                    while body_bytes.len() < content_length {
                        let mut chunk = vec![0u8; content_length - body_bytes.len()];
                        match socket.read(&mut chunk).await {
                            Ok(0) => break,
                            Ok(n) => body_bytes.extend_from_slice(&chunk[..n]),
                            Err(_) => return,
                        }
                    }

                    let response = if header_str.starts_with("POST") && header_str.contains("/chat/completions") {
                        let completion = generate_completion(&body_bytes);
                        sse_response(&completion)
                    } else {
                        let body = b"Not found".to_vec();
                        format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            String::from_utf8_lossy(&body)
                        )
                    };

                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        }
    }

    Ok(())
}

#[derive(Deserialize)]
struct ChatCompletionRequest {
    messages: Vec<ChatMessage>,
}

#[derive(Deserialize)]
struct ChatMessage {
    role: String,
    content: serde_json::Value,
}

fn generate_completion(body: &[u8]) -> String {
    let request: ChatCompletionRequest =
        serde_json::from_slice(body).unwrap_or(ChatCompletionRequest { messages: vec![] });

    let last_user_message = request
        .messages
        .iter()
        .rev()
        .find(|msg| msg.role == "user")
        .and_then(|msg| msg.content.as_str())
        .unwrap_or("(no prompt provided)");

    format!("(demo) Smith agent heard: {last_user_message}")
}

fn sse_response(message: &str) -> String {
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs() as i64)
        .unwrap_or_default();
    let message_event = json!({
        "id": "chatcmpl-smith-demo",
        "object": "chat.completion.chunk",
        "created": created,
        "model": "smith-echo-model",
        "choices": [
            {
                "index": 0,
                "delta": { "content": message },
                "finish_reason": serde_json::Value::Null
            }
        ]
    })
    .to_string();

    let stop_event = json!({
        "id": "chatcmpl-smith-demo",
        "object": "chat.completion.chunk",
        "created": created,
        "model": "smith-echo-model",
        "choices": [
            {
                "index": 0,
                "delta": serde_json::json!({}),
                "finish_reason": "stop"
            }
        ]
    })
    .to_string();

    let usage_event = json!({
        "id": "chatcmpl-smith-demo",
        "object": "chat.completion.chunk",
        "created": created,
        "model": "smith-echo-model",
        "choices": [],
        "usage": {
            "prompt_tokens": 1,
            "completion_tokens": 1,
            "total_tokens": 2
        }
    })
    .to_string();

    let body = format!(
        "data: {message_event}\n\n\
data: {stop_event}\n\n\
data: {usage_event}\n\n\
data: [DONE]\n\n"
    );

    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}
