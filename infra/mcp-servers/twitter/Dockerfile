ARG SMITH_VERSION=latest
FROM ghcr.io/sibyllinesoft/mcp-sidecar:${SMITH_VERSION} AS shim

FROM node:22-alpine
COPY --from=shim /usr/local/bin/mcp-sidecar /usr/local/bin/mcp-sidecar
RUN npm i -g @enescinar/twitter-mcp

ENTRYPOINT ["mcp-sidecar", "--"]
CMD ["npx", "-y", "@enescinar/twitter-mcp"]
