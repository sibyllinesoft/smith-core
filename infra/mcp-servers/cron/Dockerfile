FROM mcp-sidecar AS shim

FROM node:22-alpine
COPY --from=shim /usr/local/bin/mcp-sidecar /usr/local/bin/mcp-sidecar
WORKDIR /opt/mcp-cron
COPY package.json .
COPY server.js .
RUN npm install --production

ENTRYPOINT ["mcp-sidecar", "--"]
CMD ["node", "server.js"]
