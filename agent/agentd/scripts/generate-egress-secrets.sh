#!/usr/bin/env bash
#
# Generate OPA data file with egress credentials from environment variables
#
# This script reads API keys from environment and generates a JSON file
# that OPA can load for credential injection.
#
# Usage:
#   export OPENAI_API_KEY=sk-...
#   export ANTHROPIC_API_KEY=sk-ant-...
#   ./scripts/generate-egress-secrets.sh > policy/data/egress_secrets.json
#
# IMPORTANT: The output file contains secrets and should NOT be committed!

set -euo pipefail

# Generate JSON with actual credentials
cat << EOF
{
  "egress_credentials": {
    "openai": {
      "type": "bearer",
      "token": "${OPENAI_API_KEY:-}"
    },
    "anthropic": {
      "type": "api_key",
      "token": "${ANTHROPIC_API_KEY:-}"
    },
    "github": {
      "type": "bearer",
      "token": "${GITHUB_TOKEN:-}"
    },
    "slack": {
      "type": "bearer",
      "token": "${SLACK_BOT_TOKEN:-}"
    }
  }
}
EOF
