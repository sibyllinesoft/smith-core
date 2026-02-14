# Chat Bridge

The chat bridge crate provides a single integration surface for Slack, Microsoft Teams, and Mattermost.
It exposes a small `ChatAdapter` trait plus ready-to-use adapters so other Smith services can
normalize chat messages, route responses, and broadcast announcements without hardcoding per-platform logic.

## Architecture

- `chat_bridge::adapter` defines the `ChatAdapter` trait, the shared `FetchRequest` and `OutgoingMessage`
  types, and concrete adapters in the `slack`, `teams`, and `mattermost` modules.
- `chat_bridge::message` declares the cross-platform `BridgeMessage` model, including author, channel, format,
  attachments, and metadata fields.
- `chat_bridge::bridge::ChatBridge` maintains a registry of adapters, provides `send`, `broadcast`,
  and `fetch` helpers, and can be constructed from a `ChatBridgeConfig`.

All adapters surface consistent error handling through `ChatBridgeError` and emit tracing-friendly metadata.

## Configuration

Adapters can be instantiated manually or built from `ChatBridgeConfig` (typically loaded from
`serde`-deserialized TOML/YAML). Each adapter type has a strongly-typed configuration struct:

```toml
[[adapters]]
type = "slack"
bot_token = "${SLACK_BOT_TOKEN}"
default_channel = "C0123456789"

[[adapters]]
type = "teams"
tenant_id = "${AZURE_TENANT}"
client_id = "${AZURE_CLIENT_ID}"
client_secret = "${AZURE_CLIENT_SECRET}"
team_id = "00000000-1111-2222-3333-444444444444"
channel_id = "19:abcd1234@thread.tacv2"

[[adapters]]
type = "mattermost"
base_url = "https://mattermost.example.com"
access_token = "${MATTERMOST_TOKEN}"
team_id = "smith"
channel_id = "smith-core"

[[adapters]]
type = "mattermost"
base_url = "https://mattermost.example.com"
team_id = "smith"
channel_id = "smith-core"
use_agent_bridge = true
webhook_secret = "${MATTERMOST_BRIDGE_SECRET}"
# Optional overrides:
# plugin_id = "com.mattermost.mattermost-ai"
# bridge_url = "https://mattermost.example.com/plugins/com.smith.mattermost-ai-bridge"
# agent_id = "smith-chat-bridge"
```

```rust
use chat_bridge::{ChatBridge, ChatBridgeConfig};

let config: ChatBridgeConfig = toml::from_str(include_str!("bridge.toml"))?;
let bridge = ChatBridge::build_from_config(config).await?;
let receipts = bridge
    .broadcast(
        OutgoingMessage::new(
            ChannelAddress::new("smith-core"),
            MessageContent::markdown("Bridge initialized (ok)"),
        )
    )
    .await?;
```

## Adapter specifics

| Adapter    | Notes                                                                                          |
|------------|------------------------------------------------------------------------------------------------|
| Slack      | Uses OAuth bot token for `chat.postMessage` and `conversations.history`. Supports threads.     |
| Teams      | Uses client-credential flow to obtain Graph access tokens. Replies post to `/messages/{id}/replies`. |
| Mattermost | Supports two modes: legacy personal access token flow (`/posts` + `/channels/.../posts`) and the Smith proxy for the Mattermost AI bridge (`/plugins/{plugin}/external/bridge/...`) when `use_agent_bridge = true`. |

All HTTP requests use `reqwest` with `rustls`. Mattermost can optionally disable TLS verification (for local
Docker testing) via `verify_tls = false`.

## Testing

Unit tests in `bridge.rs` exercise message routing via a `MockAdapter`. Platform adapters are designed so
they can be integration-tested against real chat services when credentials are available (e.g., the
dockerized Mattermost instance mentioned in the workspace README).

### Example: Mattermost round-trip

The crate ships with a small demo that posts a message to Mattermost and fetches the most recent
messages via the bridge adapter:

```bash
MATTERMOST_BASE_URL=http://localhost:8065 \
MATTERMOST_ACCESS_TOKEN=... \
MATTERMOST_TEAM_ID=your-team-id \
MATTERMOST_CHANNEL_ID=your-channel-id \
MATTERMOST_USE_AGENT_BRIDGE=true \
MATTERMOST_BRIDGE_SECRET=smith-secret \
cargo run -p chat-bridge --example mattermost_demo
```

Optional overrides are available via `MATTERMOST_PLUGIN_ID`, `MATTERMOST_BRIDGE_URL`, and
`MATTERMOST_AGENT_ID`. Set `MATTERMOST_SKIP_TLS_VERIFY=true` if you are targeting a local server with
self-signed certificates.

#### Local Docker walkthrough

The repository ships with a throwaway Mattermost stack under `ops/mattermost-local`
that you can use to exercise the AI bridge end-to-end. The steps below assume Docker
Desktop or a comparable runtime is available on the host.

1. **Boot Mattermost + Postgres**
   ```bash
   cd ops/mattermost-local
   docker compose up -d
   ```
   Wait for `docker compose ps` to report both containers as `healthy`, then browse to
   `http://localhost:8065` and sign in with the bootstrap credentials (`mm-admin` /
   `ChangeMe123!`). Create a team and a test channel (for example `smith-demo`).

2. **Install the plugins**
   - Fast path (recommended):
     ```bash
     cd ops/mattermost-local
     ./setup_ai_bridge.sh
     ```
    This script builds the Linux amd64 proxy binary (override with
    `MATTERMOST_BRIDGE_TARGETS` if you need more platforms), downloads the Mattermost AI
    plugin (v1.5.0 by default), installs both via `mmctl`, and applies the configuration
    patch that registers the `smith-echo` agent. You can also override
    `MATTERMOST_AI_PLUGIN_VERSION`, `MATTERMOST_AI_PLUGIN_URL`, `MATTERMOST_AI_PLUGIN_TGZ`,
    or `MATTERMOST_BRIDGE_SECRET` when needed.

   - Manual steps (if you prefer to manage artefacts yourself):
     ```bash
     cd service/mattermost-ai-bridge-plugin
     GOOS=linux GOARCH=amd64 go build -o server/dist/plugin-linux-amd64 ./server
     mkdir -p /tmp/com.smith.mattermost-ai-bridge/server /tmp/com.smith.mattermost-ai-bridge/webapp
     cp plugin.json /tmp/com.smith.mattermost-ai-bridge/
     cp -R server/dist /tmp/com.smith.mattermost-ai-bridge/server/
     cp -R webapp/dist /tmp/com.smith.mattermost-ai-bridge/webapp/
     tar -czf /tmp/com.smith.mattermost-ai-bridge.tar.gz -C /tmp com.smith.mattermost-ai-bridge

     cd ops/mattermost-local
     docker compose exec mattermost bin/mmctl --local plugin add --force <PATH_TO_MATTERMOST_AI_PLUGIN_TGZ>
     docker compose exec mattermost bin/mmctl --local plugin add --force /tmp/com.smith.mattermost-ai-bridge.tar.gz
     docker compose exec mattermost bin/mmctl --local plugin enable mattermost-ai
     docker compose exec mattermost bin/mmctl --local plugin enable com.smith.mattermost-ai-bridge
     ```
     Replace `<PATH_TO_MATTERMOST_AI_PLUGIN_TGZ>` with the tarball downloaded from the
     Mattermost marketplace. You can also install either plugin through the System Console
     UI instead of the CLI.

3. **Start the steering proxy**

   Launch the proxy that bridges OpenAI-compatible requests into Smith's NATS
   steering surface. Keep it running in its own terminal while you interact with
   Mattermost:

   ```bash
   cargo run -p mattermost-steering-proxy
   ```

   It honours several environment variables:

   - `SMITH_NATS_URL` (defaults to `nats://127.0.0.1:4222`)
   - `REDIS_URL` (defaults to `redis://127.0.0.1:6379`)
   - `SMITH_HTTP_WS_URL` (defaults to `ws://localhost:6174/ws`)
   - `MATTERMOST_PROXY_BEARER` (optional shared secret checked against the `Authorization` header)

4. **Configure the plugins**
   ```bash
   cat <<'JSON' > /tmp/ai_bridge_config_patch.json
   {
     "PluginSettings": {
       "Plugins": {
         "com.smith.mattermost-ai-bridge": {
           "bridge_secret": "smith-secret",
           "target_plugin_id": "mattermost-ai"
         },
         "mattermost-ai": {
           "config": {
             "services": [
               {
                 "id": "smith-echo-service",
                 "name": "Smith Echo Service",
                 "type": "openaicompatible",
                 "apiKey": "demo-key",
                 "apiURL": "http://host.docker.internal:8181/v1",
                 "defaultModel": "smith-echo-model",
                 "tokenLimit": 4096,
                 "outputTokenLimit": 1024,
                 "streamingTimeoutSeconds": 30,
                 "sendUserID": false,
                 "useResponsesAPI": false
               }
             ],
             "bots": [
               {
                 "id": "smith-echo-bot",
                 "name": "smith-echo",
                 "displayName": "Smith Echo",
                 "customInstructions": "Echo agent for demo",
                 "serviceID": "smith-echo-service",
                 "enableVision": false,
                 "disableTools": true,
                 "channelAccessLevel": 0,
                 "channelIDs": [],
                 "userAccessLevel": 0,
                 "userIDs": [],
                 "teamIDs": [],
                 "maxFileSize": 1048576,
                 "enabledNativeTools": []
               }
             ],
             "defaultBotName": "smith-echo"
           }
         }
       }
     }
   }
   JSON

   docker compose cp /tmp/ai_bridge_config_patch.json mattermost:/tmp/ai_bridge_config_patch.json
   docker compose exec mattermost bin/mmctl --local config patch /tmp/ai_bridge_config_patch.json
   ```
   This sets the shared secret used by the chat bridge (`smith-secret`) and registers a
   demo `smith-echo` agent that targets the mock server started by the Rust example.
   The compose file already maps `host.docker.internal` to the host network so the
   plugin can reach the mock service on port `8181`.

5. **Create a personal access token**
   In Mattermost, open **Profile ➜ Security ➜ Personal Access Tokens**, create a token
   (for example `chat-bridge-demo`), copy the token string, and export it locally as
   `MATTERMOST_ACCESS_TOKEN`. Capture the team and channel IDs via the UI or:
   ```bash
   docker compose exec mattermost bin/mmctl --local team list
   docker compose exec mattermost bin/mmctl --local channel list <team-id>
   ```

6. **Run the demo**
   ```bash
   export MATTERMOST_BASE_URL=http://localhost:8065
   export MATTERMOST_ACCESS_TOKEN=<token>
   export MATTERMOST_TEAM_ID=<team-id>
   export MATTERMOST_CHANNEL_ID=<channel-id>
   export MATTERMOST_USE_AGENT_BRIDGE=true
   export MATTERMOST_BRIDGE_SECRET=smith-secret
   # export MATTERMOST_MOCK_SERVER_ADDR=0.0.0.0:18181   # optional override
   cargo run -p chat-bridge --example mattermost_demo
   ```
   The program posts an announcement, fetches the latest posts, calls the bridge proxy to
   run a completion via the `smith-echo` agent, and replies in-thread with the mock
   response. If you override the mock server address, update the AI plugin service URL
   to match.

7. **Tear down**
   ```bash
   cd ops/mattermost-local
   docker compose down -v
   ```
   Use `docker compose stop` if you want to retain data between runs.
