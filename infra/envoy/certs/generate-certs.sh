#!/usr/bin/env bash
# Generate ECDSA P-256 certificates for smith-core Envoy mTLS.
#
# Output: infra/envoy/certs/generated/{ca,server,client}.{crt,key}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/generated"
DAYS=825
FORCE="${SMITH_FORCE_CERTS:-0}"

required=(ca.crt ca.key server.crt server.key client.crt client.key)
if [[ "$FORCE" != "1" ]]; then
  all_present=1
  for f in "${required[@]}"; do
    if [[ ! -f "$OUT/$f" ]]; then
      all_present=0
      break
    fi
  done
  if [[ "$all_present" -eq 1 ]]; then
    echo "Certificates already exist in $OUT (set SMITH_FORCE_CERTS=1 to regenerate)"
    exit 0
  fi
fi

mkdir -p "$OUT"

echo "==> Generating CA key + cert"
openssl ecparam -genkey -name prime256v1 -noout -out "$OUT/ca.key"
openssl req -new -x509 -sha256 -key "$OUT/ca.key" \
  -out "$OUT/ca.crt" -days "$DAYS" \
  -subj "/O=Smith Core/CN=Smith Core Dev CA"

echo "==> Generating server key + cert"
openssl ecparam -genkey -name prime256v1 -noout -out "$OUT/server.key"

cat > "$OUT/server.ext" <<EOT
[req]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no

[dn]
O  = Smith Core
CN = smith-gateway

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = smith-gateway
DNS.3 = envoy
IP.1  = 127.0.0.1
EOT

openssl req -new -sha256 -key "$OUT/server.key" \
  -out "$OUT/server.csr" -config "$OUT/server.ext"

openssl x509 -req -sha256 -in "$OUT/server.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/server.crt" -days "$DAYS" \
  -extfile "$OUT/server.ext" -extensions v3_req

echo "==> Generating client key + cert"
openssl ecparam -genkey -name prime256v1 -noout -out "$OUT/client.key"
openssl req -new -sha256 -key "$OUT/client.key" \
  -out "$OUT/client.csr" \
  -subj "/O=Smith Core/CN=smith-client"

openssl x509 -req -sha256 -in "$OUT/client.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/client.crt" -days "$DAYS"

chmod 644 "$OUT"/*.key
rm -f "$OUT"/*.csr "$OUT"/*.ext "$OUT"/*.srl

echo "==> Certificates written to $OUT"
ls -l "$OUT"
