# Project Dockerfile
# For a Node.js backend (server) and React frontend (client)
# Multi-stage build for client
FROM node:18 AS client-build
WORKDIR /app/client
COPY client/package.json client/package-lock.json ./
RUN npm install
COPY client/ ./
RUN npm run build

# Backend build
FROM node:18 AS server-build
WORKDIR /app/server
COPY server/package.json ./
RUN npm install
COPY server/ ./

# Final image
FROM node:18-slim
WORKDIR /app
COPY --from=client-build /app/client/dist ./client/dist
COPY --from=server-build /app/server ./server
WORKDIR /app/server
EXPOSE 3000
CMD ["node", "server.js"]
