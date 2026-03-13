ARG SMITH_VERSION=0.2.6
FROM ghcr.io/sibyllinesoft/mcp-sidecar:${SMITH_VERSION} AS shim

FROM node:22-alpine
COPY --from=shim /usr/local/bin/mcp-sidecar /usr/local/bin/mcp-sidecar
WORKDIR /opt/mcp-cron
COPY package.json .
COPY server.js .
RUN npm install --production

ENTRYPOINT ["mcp-sidecar", "--"]
CMD ["node", "server.js"]
