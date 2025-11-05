# syntax=docker/dockerfile:1
FROM node:20-alpine AS base
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Build
COPY tsconfig.json ./
COPY src ./src
COPY openapi.json ./openapi.json
RUN npm run build

# Runtime image
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Copy only runtime bits
COPY --from=base /app/package*.json ./
RUN npm ci --omit=dev
COPY --from=base /app/dist ./dist
COPY openapi.json ./openapi.json

# Default HTTP config (can be overridden)
ENV MCP_HTTP_ENABLED=true
ENV MCP_HTTP_PORT=8080
ENV MCP_HTTP_PATH=/mcp

EXPOSE 8080
CMD ["node","dist/index.js"]
