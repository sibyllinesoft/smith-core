ARG SMITH_VERSION=latest
FROM ghcr.io/sibyllinesoft/mcp-sidecar:${SMITH_VERSION} AS shim

FROM node:22-alpine
COPY --from=shim /usr/local/bin/mcp-sidecar /usr/local/bin/mcp-sidecar
RUN npm i -g @modelcontextprotocol/server-slack

ENTRYPOINT ["mcp-sidecar", "--"]
CMD ["npx", "-y", "@modelcontextprotocol/server-slack"]
