# Dockerfile
# Sentinel Neuro-Symbolic Core
# "The Brain in a Box"

FROM python:3.11-slim

# Install system utilities for scanner tools
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    curl \
    git \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python Dependencies
# (In a real scenario, we'd copy requirements.txt first)
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    "httpx[cli]" \
    networkx \
    aiosqlite \
    beautifulsoup4 \
    python-multipart \
    cryptography \
    websockets

# Copy Source Code
COPY . /app

# Create artifacts directory for JIT Forge
RUN mkdir -p /app/artifacts/exploits

# Expose API Port
EXPOSE 8000

# ============================================================================
# SECURITY NOTICE: Host Binding Configuration
# ============================================================================
# By default, the container binds to 127.0.0.1 (localhost only).
# This is a SAFE DEFAULT - the API is not exposed to the network.
#
# To expose the API to the network, you MUST:
# 1. Set SENTINEL_API_HOST=0.0.0.0
# 2. Set SENTINEL_REQUIRE_AUTH=true
# 3. Set SENTINEL_API_TOKEN=<your-secure-token>
#
# The server will REFUSE to start if exposed without authentication.
# This is enforced by the Host-Aware Boot Interlock security feature.
#
# Example docker run command for network exposure:
#   docker run -e SENTINEL_API_HOST=0.0.0.0 \
#              -e SENTINEL_REQUIRE_AUTH=true \
#              -e SENTINEL_API_TOKEN=my-secret-token \
#              -p 8000:8000 sentinelforge
# ============================================================================

# Environment defaults (safe by default)
ENV SENTINEL_API_HOST=127.0.0.1
ENV SENTINEL_API_PORT=8000

# Start the Command Deck
# NOTE: We use shell form to enable environment variable substitution
CMD uvicorn core.server.api:app --host ${SENTINEL_API_HOST} --port ${SENTINEL_API_PORT}
