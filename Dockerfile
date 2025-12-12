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

# Start the Command Deck
CMD ["uvicorn", "core.api:app", "--host", "0.0.0.0", "--port", "8000"]
