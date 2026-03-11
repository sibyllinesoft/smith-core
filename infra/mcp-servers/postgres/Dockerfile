FROM node:22-alpine
WORKDIR /opt/mcp-postgres
RUN apk add --no-cache postgresql-client
COPY package.json .
COPY server.js .
RUN npm install --production

CMD ["node", "server.js"]
