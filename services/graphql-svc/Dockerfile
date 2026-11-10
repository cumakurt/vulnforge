FROM node:20-alpine

WORKDIR /app
COPY package.json ./
COPY src/ ./src/

ENV NODE_ENV=production
EXPOSE 4000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5   CMD wget -qO- http://127.0.0.1:4000/health || exit 1

CMD ["node", "src/server.js"]
