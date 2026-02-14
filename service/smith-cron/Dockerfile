FROM node:22-alpine
WORKDIR /opt/smith-cron
COPY package.json .
COPY cron.mjs .
RUN npm install --production
CMD ["node", "cron.mjs"]
