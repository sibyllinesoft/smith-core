FROM mcp-shim AS shim

FROM node:22-alpine
COPY --from=shim /usr/local/bin/mcp-shim /usr/local/bin/mcp-shim
WORKDIR /opt/mcp-users
COPY package.json .
COPY server.js .
RUN npm install --production

ENTRYPOINT ["mcp-shim", "--"]
CMD ["node", "server.js"]
