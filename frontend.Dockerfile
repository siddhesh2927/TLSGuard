# Stage 1: Build the React Application
FROM node:20-alpine AS builder
WORKDIR /app

# 1. Install ALL system tools required for native C++ compilation (better-sqlite3)
# Added gcc, libc-dev, and binutils which are required for Alpine
RUN apk update && apk add --no-cache \
    python3 \
    make \
    g++ \
    gcc \
    libc-dev \
    binutils

# 2. Prevent network timeouts for slow/unstable DNS (Fixes EAI_AGAIN)
RUN npm config set fetch-retry-maxtimeout 120000 && \
    npm config set fetch-retries 5

# 3. Handle Vite Build Args
ARG VITE_API_BASE_URL=http://localhost:4000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

# 4. Copy package files first to leverage Docker cache
COPY package*.json ./
COPY frontend/package.json ./frontend/
COPY backend/package.json ./backend/

# 5. Install dependencies
RUN npm install

# 6. Copy source and build
COPY . .
RUN cd frontend && npm run build

# Stage 2: Serve the final assets
FROM node:20-alpine AS runner
WORKDIR /app

# Install lightweight static file server globally
RUN npm install -g serve

# Copy only the compiled dist folder
COPY --from=builder /app/frontend/dist ./dist

EXPOSE 3000
CMD ["serve", "-s", "dist", "-l", "3000"]