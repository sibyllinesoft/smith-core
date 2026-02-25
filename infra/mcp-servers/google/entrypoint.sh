#!/bin/sh
# Read refresh token from shared credential volume if it exists
REFRESH_TOKEN_FILE="/credentials/google/refresh_token"
if [ -f "$REFRESH_TOKEN_FILE" ]; then
  export GOOGLE_REFRESH_TOKEN="$(cat "$REFRESH_TOKEN_FILE")"
fi

# If we don't have all three required env vars, wait and retry
# (mcp-index will write the refresh_token after OAuth completes)
if [ -z "$GOOGLE_CLIENT_ID" ] || [ -z "$GOOGLE_CLIENT_SECRET" ] || [ -z "$GOOGLE_REFRESH_TOKEN" ]; then
  echo "Waiting for Google OAuth credentials (missing GOOGLE_REFRESH_TOKEN)..."
  echo "Complete the OAuth flow in the MCP Index UI to continue."
  # Sleep so Docker doesn't restart-loop aggressively
  sleep 30
  exit 1
fi

exec mcp-sidecar -- node /opt/google-mcp/build/index.js
