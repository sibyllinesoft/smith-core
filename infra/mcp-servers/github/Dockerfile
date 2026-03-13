ARG SMITH_VERSION=0.2.5
FROM ghcr.io/sibyllinesoft/mcp-sidecar:${SMITH_VERSION} AS shim

FROM node:22-alpine
COPY --from=shim /usr/local/bin/mcp-sidecar /usr/local/bin/mcp-sidecar
RUN npm i -g @modelcontextprotocol/server-github

ENTRYPOINT ["mcp-sidecar", "--"]
CMD ["npx", "-y", "@modelcontextprotocol/server-github"]
