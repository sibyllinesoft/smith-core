FROM node:22-alpine

WORKDIR /opt/session-recorder
COPY package.json .
COPY recorder.mjs .
RUN npm install --production

CMD ["node", "recorder.mjs"]
