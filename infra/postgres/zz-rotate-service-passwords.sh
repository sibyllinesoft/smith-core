#!/usr/bin/env bash
set -euo pipefail

psql \
  -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set=smith_app_password="$SMITH_APP_PASSWORD" \
  --set=smith_readonly_password="$SMITH_READONLY_PASSWORD" \
  --set=smith_gatekeeper_password="$SMITH_GATEKEEPER_PASSWORD" <<'SQL'
SELECT format('ALTER ROLE smith_app WITH PASSWORD %L', :'smith_app_password') \gexec
SELECT format('ALTER ROLE smith_readonly WITH PASSWORD %L', :'smith_readonly_password') \gexec
SELECT format('ALTER ROLE smith_gatekeeper WITH PASSWORD %L', :'smith_gatekeeper_password') \gexec
SQL
