---
description: Configure chat platform bridges by selecting platforms, collecting credentials, and writing bridge config
---
# Setup Chat Bridge

Run these read-only inspection commands to understand the current state:

```bash
# Check if config already exists
cat config/chat-bridge.toml 2>/dev/null || echo "NO_CONFIG"

# Check which gateway secrets are already set in .env
grep -E '^(DISCORD_BOT_TOKEN|TELEGRAM_BOT_TOKEN|SLACK_BOT_TOKEN|SLACK_APP_TOKEN|TEAMS_TENANT_ID|WHATSAPP_ACCESS_TOKEN|MATRIX_ACCESS_TOKEN|SIGNAL_RECIPIENT|MATTERMOST_TOKEN|GOOGLE_CHAT_WEBHOOK_URL)=' .env 2>/dev/null | sed 's/=.*/=<set>/'
```

## What It Does

This skill interactively configures one or more chat platform bridges by:

1. Asking the user which platforms they want to connect.
2. Walking them through creating bot credentials on each platform.
3. Writing `config/chat-bridge.toml` with the correct adapter stanzas.
4. Setting the required env vars in `.env`.

## Interactive Flow

Ask the user which platform(s) they want to configure. For each selected platform, walk through the setup guide below, collect the credentials, then write config and env vars.

## Platform Setup Guides

### Discord

1. Go to https://discord.com/developers/applications
2. Click **New Application**, give it a name, click **Create**.
3. Go to **Bot** in the left sidebar, click **Reset Token**, copy the token.
4. Under **Privileged Gateway Intents**, enable **Message Content Intent**.
5. Go to **OAuth2 > URL Generator**, select scopes `bot` + `applications.commands`, permissions `Send Messages` + `Read Message History`.
6. Open the generated URL to invite the bot to your server.

**Credentials needed:** Bot Token, Application ID (from General Information page)

**TOML stanza:**

```toml
[[adapters]]
type = "discord"
bot_token = "<DISCORD_BOT_TOKEN>"
application_id = "<APPLICATION_ID>"
```

**Env vars:** `DISCORD_BOT_TOKEN`

### Telegram

1. Open https://t.me/BotFather in Telegram.
2. Send `/newbot`, follow prompts to choose a name and username.
3. Copy the bot token BotFather gives you.

**Credentials needed:** Bot Token

**TOML stanza:**

```toml
[[adapters]]
type = "telegram"
bot_token = "<TELEGRAM_BOT_TOKEN>"
```

**Env vars:** `TELEGRAM_BOT_TOKEN`

### Slack

1. Go to https://api.slack.com/apps and click **Create New App > From scratch**.
2. Under **Socket Mode**, enable it and generate an App-Level Token (begins with `xapp-`).
3. Under **OAuth & Permissions**, add bot scopes: `chat:write`, `channels:history`, `groups:history`, `im:history`, `mpim:history`.
4. Install the app to your workspace and copy the Bot User OAuth Token (begins with `xoxb-`).
5. Under **Event Subscriptions**, enable events and subscribe to `message.channels`, `message.groups`, `message.im`, `message.mpim`.

**Credentials needed:** App Token (`xapp-...`), Bot Token (`xoxb-...`)

**TOML stanza:**

```toml
[[adapters]]
type = "slack"
bot_token = "<SLACK_BOT_TOKEN>"
app_token = "<SLACK_APP_TOKEN>"
```

**Env vars:** `SLACK_APP_TOKEN`, `SLACK_BOT_TOKEN`

### Microsoft Teams

1. Go to https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps
2. Click **New registration**, name it, select **Accounts in this organizational directory only**.
3. Under **Certificates & secrets**, create a new client secret and copy it.
4. Note the **Application (client) ID** and **Directory (tenant) ID** from the Overview page.
5. Under **API permissions**, add `ChannelMessage.Read.All`, `ChannelMessage.Send`, `Team.ReadBasic.All` (application permissions), then grant admin consent.
6. Get the Team ID and Channel ID from Teams (right-click channel > Get link to channel).

**Credentials needed:** Tenant ID, Client ID, Client Secret, Team ID, Channel ID

**TOML stanza:**

```toml
[[adapters]]
type = "teams"
tenant_id = "<TEAMS_TENANT_ID>"
client_id = "<TEAMS_CLIENT_ID>"
client_secret = "<TEAMS_CLIENT_SECRET>"
team_id = "<TEAM_ID>"
channel_id = "<CHANNEL_ID>"
```

**Env vars:** `TEAMS_TENANT_ID`, `TEAMS_CLIENT_ID`, `TEAMS_CLIENT_SECRET`

### Mattermost

1. In your Mattermost instance, go to **Integrations > Bot Accounts > Add Bot Account**.
2. Copy the access token.
3. Note the Team ID and Channel ID from the channel URL or API.

**Credentials needed:** Base URL (your Mattermost server), Access Token, Team ID, Channel ID

**TOML stanza:**

```toml
[[adapters]]
type = "mattermost"
base_url = "<MATTERMOST_URL>"
access_token = "<MATTERMOST_TOKEN>"
team_id = "<TEAM_ID>"
channel_id = "<CHANNEL_ID>"
```

**Env vars:** `MATTERMOST_TOKEN`

### WhatsApp

1. Go to https://developers.facebook.com/apps and create a new **Business** app.
2. Add the **WhatsApp** product.
3. Under **WhatsApp > API Setup**, copy the temporary Access Token, Phone Number ID, and Business Account ID.
4. For production, create a System User token with `whatsapp_business_messaging` permission.

**Credentials needed:** Access Token, Phone Number ID, Business Account ID

**TOML stanza:**

```toml
[[adapters]]
type = "whatsapp"
access_token = "<WHATSAPP_ACCESS_TOKEN>"
phone_number_id = "<PHONE_NUMBER_ID>"
business_account_id = "<BUSINESS_ACCOUNT_ID>"
```

**Env vars:** `WHATSAPP_ACCESS_TOKEN`

### Matrix

1. On your Matrix homeserver, create a bot user or use an existing account.
2. Generate an access token via `curl -XPOST 'https://<homeserver>/_matrix/client/r0/login' -d '{"type":"m.login.password","user":"<username>","password":"<password>"}'`.
3. Note the homeserver URL, access token, and full user ID (`@user:server`).

**Credentials needed:** Homeserver URL, Access Token, User ID

**TOML stanza:**

```toml
[[adapters]]
type = "matrix"
homeserver_url = "<MATRIX_HOMESERVER>"
access_token = "<MATRIX_ACCESS_TOKEN>"
user_id = "<USER_ID>"
```

**Env vars:** `MATRIX_HOMESERVER`, `MATRIX_ACCESS_TOKEN`

### Signal

1. Install `signal-cli` and register or link a phone number.
2. Run `signal-cli` in daemon/JSON-RPC mode: `signal-cli -u +<NUMBER> daemon --json-rpc`.
3. The default signal-cli URL is `http://127.0.0.1:8080`.

**Credentials needed:** Phone Number, signal-cli URL (if non-default)

**TOML stanza:**

```toml
[[adapters]]
type = "signal"
phone_number = "<PHONE_NUMBER>"
signal_cli_url = "http://127.0.0.1:8080"
```

**Env vars:** `SIGNAL_RECIPIENT`

### Google Chat

1. Go to https://console.cloud.google.com, create or select a project.
2. Enable the **Google Chat API**.
3. Create a **Service Account**, download the JSON key file.
4. In **Google Chat API > Configuration**, configure the bot and note the Space ID.

**Credentials needed:** Path to service account JSON file, Space ID

**TOML stanza:**

```toml
[[adapters]]
type = "google_chat"
service_account_json = "<PATH_TO_SERVICE_ACCOUNT_JSON>"
space_id = "<SPACE_ID>"
```

**Env vars:** `GOOGLE_CHAT_WEBHOOK_URL`

### iMessage (via BlueBubbles)

1. Install and run BlueBubbles server on a Mac: https://bluebubbles.app
2. Note the server URL and server password from BlueBubbles settings.

**Credentials needed:** Server URL, Server Password

**TOML stanza:**

```toml
[[adapters]]
type = "imessage"
server_url = "<BLUEBUBBLES_SERVER_URL>"
server_password = "<SERVER_PASSWORD>"
```

**Env vars:** None (config-only)

## Mutation Commands

After collecting credentials from the user, write the config and env vars:

### Write config/chat-bridge.toml

Assemble the file from the selected platform stanzas. Example for Discord + Telegram:

```toml
[[adapters]]
type = "discord"
bot_token = "MTIz..."
application_id = "1234567890"

[[adapters]]
type = "telegram"
bot_token = "7654321:AAH..."
```

### Set env vars in .env

Use the idempotent pattern (same as `configure-agentd`):

```bash
grep -q '^CHAT_BRIDGE_CONFIG=' .env || echo 'CHAT_BRIDGE_CONFIG=config/chat-bridge.toml' >> .env

# Generate a random admin token if not already set
grep -q '^CHAT_BRIDGE_ADMIN_TOKEN=.' .env || echo "CHAT_BRIDGE_ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env

# Per-platform env vars (set for each configured platform)
grep -q '^DISCORD_BOT_TOKEN=' .env && sed -i 's|^DISCORD_BOT_TOKEN=.*|DISCORD_BOT_TOKEN=<collected-value>|' .env || echo 'DISCORD_BOT_TOKEN=<collected-value>' >> .env
```

Repeat the `grep -q ... && sed -i ... || echo ...` pattern for each platform-specific env var.

## Prerequisites

- `.env` exists (run `configure-agentd` first if missing).
- `config/` directory exists.

## Expected Output

- `config/chat-bridge.toml` written with selected adapter stanzas.
- Platform credentials set in `.env`.
- `CHAT_BRIDGE_CONFIG` and `CHAT_BRIDGE_ADMIN_TOKEN` set in `.env`.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `.env` does not exist | `configure-agentd` not run | Run `configure-agentd` skill first |
| `config/` directory missing | Not at repository root | `cd` to smith-core root |
| Invalid bot token at runtime | Token was revoked or mistyped | Re-run this skill to update credentials |
| TOML parse error on daemon start | Malformed config | Check quoting in `config/chat-bridge.toml` |
