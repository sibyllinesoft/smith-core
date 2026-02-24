ARG SMITH_VERSION=latest
FROM ghcr.io/sibyllinesoft/mcp-sidecar:${SMITH_VERSION} AS shim

FROM node:22-alpine

RUN apk add --no-cache git python3 make g++ && \
    git clone --depth 1 https://github.com/epaproditus/google-workspace-mcp-server.git /opt/google-mcp && \
    cd /opt/google-mcp && npm install && npm run build && \
    apk del git python3 make g++

COPY --from=shim /usr/local/bin/mcp-sidecar /usr/local/bin/mcp-sidecar
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
