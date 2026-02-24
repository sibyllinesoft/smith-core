#!/usr/bin/env bash
# Google OAuth setup helper — obtains a refresh token for the google-workspace MCP server.
# Usage: ./infra/mcp-servers/google/oauth-setup.sh
#
# Requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env (or environment).
set -euo pipefail
cd "$(dirname "$0")/../../.."

# Load .env if present
if [ -f .env ]; then
  set -a; source .env; set +a
fi

: "${GOOGLE_CLIENT_ID:?Set GOOGLE_CLIENT_ID in .env}"
: "${GOOGLE_CLIENT_SECRET:?Set GOOGLE_CLIENT_SECRET in .env}"

REDIRECT_URI="http://localhost:8919"
SCOPES="https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/drive.readonly"

AUTH_URL="https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=$(printf '%s' "$SCOPES" | sed 's/ /%20/g')&access_type=offline&prompt=consent"

echo "Opening browser for Google OAuth consent..."
echo ""
echo "If the browser doesn't open, visit this URL:"
echo "$AUTH_URL"
echo ""

# Try to open browser
xdg-open "$AUTH_URL" 2>/dev/null || open "$AUTH_URL" 2>/dev/null || true

# Tiny HTTP listener to capture the redirect
echo "Waiting for OAuth callback on $REDIRECT_URI ..."
RESPONSE=$(python3 -c "
import http.server, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code = qs.get('code', [''])[0]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'<h2>Authorization complete. You can close this tab.</h2>')
        print(code)
        raise KeyboardInterrupt
    def log_message(self, *a): pass
try:
    http.server.HTTPServer(('127.0.0.1', 8919), H).serve_forever()
except KeyboardInterrupt:
    pass
")

AUTH_CODE="$RESPONSE"
if [ -z "$AUTH_CODE" ]; then
  echo "ERROR: No authorization code received." >&2
  exit 1
fi

echo "Exchanging authorization code for tokens..."
TOKEN_JSON=$(curl -s -X POST https://oauth2.googleapis.com/token \
  -d "code=${AUTH_CODE}" \
  -d "client_id=${GOOGLE_CLIENT_ID}" \
  -d "client_secret=${GOOGLE_CLIENT_SECRET}" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "grant_type=authorization_code")

REFRESH_TOKEN=$(echo "$TOKEN_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))")

if [ -z "$REFRESH_TOKEN" ]; then
  echo "ERROR: No refresh_token in response:" >&2
  echo "$TOKEN_JSON" >&2
  exit 1
fi

# Write refresh token into the mcp_credentials Docker volume
echo "Writing refresh token to mcp_credentials volume..."
docker run --rm -v smith-core_mcp_credentials:/credentials alpine sh -c \
  "mkdir -p /credentials/google && printf '%s' '$REFRESH_TOKEN' > /credentials/google/refresh_token"

# Also generate a credentials.json (ADC format) for google-analytics
echo "Writing ADC credentials.json for google-analytics..."
docker run --rm -v smith-core_mcp_credentials:/credentials alpine sh -c "
mkdir -p /credentials/google
cat > /credentials/google/credentials.json <<ADCEOF
{
  \"type\": \"authorized_user\",
  \"client_id\": \"${GOOGLE_CLIENT_ID}\",
  \"client_secret\": \"${GOOGLE_CLIENT_SECRET}\",
  \"refresh_token\": \"${REFRESH_TOKEN}\"
}
ADCEOF
"

echo ""
echo "Done! Restart the google MCP services to pick up the credentials:"
echo "  docker compose restart mcp-google mcp-google-analytics"
