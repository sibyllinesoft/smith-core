#!/bin/sh
# Use ADC credentials from shared volume if available
ADC_FILE="/credentials/google/credentials.json"
if [ -f "$ADC_FILE" ]; then
  export GOOGLE_APPLICATION_CREDENTIALS="$ADC_FILE"
fi

if [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ] || [ ! -f "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  echo "Waiting for Google OAuth credentials..."
  echo "Complete the OAuth flow in the MCP Index UI to continue."
  sleep 30
  exit 1
fi

exec mcp-sidecar -- analytics-mcp
