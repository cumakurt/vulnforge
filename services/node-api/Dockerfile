FROM node:20-alpine

WORKDIR /app

# No third-party runtime dependencies: the service only uses Node built-ins,
# which keeps the image small and the build reproducible offline.
COPY package.json ./
COPY src/ ./src/

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
  CMD wget -qO- http://127.0.0.1:3000/health || exit 1

CMD ["node", "src/server.js"]
