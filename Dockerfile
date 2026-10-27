# Minimalist, secure Node.js Alpine image
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --only=production

# Production runtime stage
FROM node:20-alpine

WORKDIR /usr/src/app

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/usr/src/app/data

# Create data directory for session persistence and grant permissions to node user
RUN mkdir -p /usr/src/app/data && chown -R node:node /usr/src/app

USER node

COPY --chown=node:node --from=builder /usr/src/app/node_modules ./node_modules
COPY --chown=node:node package*.json ./
COPY --chown=node:node server.js hash-password.js set-password.js set-fido.js set-auth-method.js logout-sessions.js ./
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/auth/health || exit 1

CMD ["node", "server.js"]
