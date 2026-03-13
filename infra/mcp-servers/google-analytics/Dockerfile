ARG SMITH_VERSION=0.2.5
FROM ghcr.io/sibyllinesoft/mcp-sidecar:${SMITH_VERSION} AS shim

FROM python:3.12-alpine

RUN pip install --no-cache-dir analytics-mcp

COPY --from=shim /usr/local/bin/mcp-sidecar /usr/local/bin/mcp-sidecar
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
