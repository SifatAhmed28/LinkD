FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

FROM node:20-alpine
WORKDIR /app
RUN addgroup -S linkd && adduser -S linkd -G linkd
COPY --from=builder /app .
RUN mkdir -p logs
USER linkd
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD wget -qO- http://localhost:3000/health || exit 1
CMD ["node", "src/server.js"]
