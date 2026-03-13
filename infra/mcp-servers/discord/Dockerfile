ARG SMITH_VERSION=0.2.6
FROM ghcr.io/sibyllinesoft/mcp-sidecar:${SMITH_VERSION} AS shim

FROM node:22-alpine
COPY --from=shim /usr/local/bin/mcp-sidecar /usr/local/bin/mcp-sidecar
RUN npm i -g mcp-discord
COPY server-wrapper.mjs /usr/local/lib/node_modules/mcp-discord/server-wrapper.mjs

ENTRYPOINT ["mcp-sidecar", "--"]
CMD ["node", "/usr/local/lib/node_modules/mcp-discord/server-wrapper.mjs"]
