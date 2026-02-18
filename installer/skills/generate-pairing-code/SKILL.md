---
description: Generate a pairing code for DM authentication with the chat bridge
---
# Generate Pairing Code

Run these read-only inspection commands to understand the current state:

```bash
# Check DM policy
grep '^CHAT_BRIDGE_DM_POLICY=' .env 2>/dev/null || echo "CHAT_BRIDGE_DM_POLICY=pairing (default)"

# Check if admin token is set
grep -q '^CHAT_BRIDGE_ADMIN_TOKEN=.' .env 2>/dev/null && echo "ADMIN_TOKEN_SET" || echo "NO_ADMIN_TOKEN"

# Check webhook port
grep '^CHAT_BRIDGE_WEBHOOK_PORT=' .env 2>/dev/null || echo "CHAT_BRIDGE_WEBHOOK_PORT=8092 (default)"

# Check if daemon is running
pgrep -f smith-chat-daemon && echo "DAEMON_RUNNING" || echo "DAEMON_NOT_RUNNING"
```

## What It Does

This skill generates a short-lived pairing code that a user sends as a DM to the bot on their chat platform. The daemon validates the code and pairs the sender's chat identity with an agent, authorizing future DM conversations.

Pairing codes are 6 alphanumeric characters, uppercase, and expire after 5 minutes (`CHAT_BRIDGE_PAIRING_CODE_TTL`, default 300 seconds).

## Prerequisites

- **DM policy must be `pairing`** (the default). If `CHAT_BRIDGE_DM_POLICY` is set to `open` or `allowlist`, pairing codes are not needed — inform the user and skip.
- **Daemon must be running.** If not, tell the user to run the `start-chat-bridge` skill first.
- **Admin token must be set.** If `CHAT_BRIDGE_ADMIN_TOKEN` is empty or missing, generate one:

```bash
grep -q '^CHAT_BRIDGE_ADMIN_TOKEN=.' .env || echo "CHAT_BRIDGE_ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env
```

Note: if you set the admin token after the daemon started, the daemon must be restarted to pick up the new value.

## Mutation Command

Generate a pairing code:

```bash
curl -s -X POST "http://localhost:${CHAT_BRIDGE_WEBHOOK_PORT:-8092}/admin/pairing-codes" \
  -H "Authorization: Bearer ${CHAT_BRIDGE_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\": \"${AGENT_ID:-smith-default}\"}"
```

The response contains the pairing code:

```json
{
  "code": "A1B2C3",
  "agent_id": "smith-default",
  "expires_in_secs": 300
}
```

## User Instructions

After generating the code, tell the user:

> Send this 6-character code as a DM to the bot on your chat platform to pair. The code expires in 5 minutes. Once paired, you can chat with the agent directly via DM.

## Expected Output

- A JSON response with `code`, `agent_id`, and `expires_in_secs`.
- The user can then DM the code to the bot to complete pairing.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `DAEMON_NOT_RUNNING` | Daemon not started | Run `start-chat-bridge` skill first |
| `NO_ADMIN_TOKEN` | Admin token not configured | Generate one and add to `.env`, restart daemon |
| `401 Unauthorized` | Token mismatch | Ensure `.env` token matches what daemon loaded (restart daemon after changes) |
| `connection refused` on curl | Daemon not listening on expected port | Check `CHAT_BRIDGE_WEBHOOK_PORT` and daemon logs |
| Code not accepted by bot | Code expired (>5 min) or already redeemed | Generate a new code |
| `pairing` not required | DM policy is `open` or `allowlist` | No action needed; DMs are already authorized |

## Notes

- Each code can only be redeemed once.
- Active pairings expire after `CHAT_BRIDGE_PAIRING_TTL` seconds (default 86400 = 24 hours).
- To change the DM policy, set `CHAT_BRIDGE_DM_POLICY` in `.env` to `pairing`, `allowlist`, or `open` and restart the daemon.
