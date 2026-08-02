# =============================
# Multi‑stage Dockerfile for the Gemma project
# Targets Google Cloud Run / GKE production deployments
# =============================
# ---------- Stage 1: Build the TypeScript front‑end & server ----------
FROM node:20-slim AS builder
WORKDIR /app

# Install pnpm (fast package manager)
RUN npm install -g pnpm

# Copy package metadata first for cache‑friendly install
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Copy the rest of the source code
COPY . ./

# Build the assets using the custom gcp‑build script (vite + esbuild)
# This will produce a static "dist" folder and a bundled server.js
RUN pnpm run gcp-build

# ---------- Stage 2: Runtime image (Node + Python) ----------
FROM node:20-slim

# Install Python 3 and pip – needed for the SOC Python agent
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the built artifacts from the builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/pnpm-lock.yaml ./

# Install only production Node dependencies
RUN npm install -g pnpm && pnpm install --prod --frozen-lockfile

# Install Python dependencies required by the SOC agent
# (google‑generativeai for the Gemma model, elasticsearch client for log queries)
RUN pip3 install --no-cache-dir google-generativeai elasticsearch

# Copy the Python backend source files
COPY backend ./backend

# ── Security: run as non-root user ──
RUN groupadd --system appgroup && \
    useradd --system --gid appgroup --create-home appuser && \
    chown -R appuser:appgroup /app
USER appuser

# Set production environment
ENV NODE_ENV=production

# Expose the port that Cloud Run will assign (default $PORT env var, fallback 8080)
EXPOSE 8080

# Start both the Node server and the Python SOC agent.
# Cloud Run expects the container to keep running; using "sh -c" allows us to start two processes.
CMD ["sh", "-c", "node dist/server.js & python3 backend/soc_agent.py"]


