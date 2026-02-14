FROM mcp-shim AS shim

FROM node:22-alpine
COPY --from=shim /usr/local/bin/mcp-shim /usr/local/bin/mcp-shim
RUN npm i -g @modelcontextprotocol/server-postgres

ENTRYPOINT ["mcp-shim", "--"]
CMD ["npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://smith_readonly:smith-readonly-dev@postgres:5432/smith?options=-c%20app.current_user_id%3Dadmin%20-c%20app.current_user_role%3Dadmin"]
