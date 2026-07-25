#!/bin/bash
# scripts/start_servers.sh
# Unified launch script for SentinelForge backend servers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Environment paths
VENV_PYTHON="$PROJECT_ROOT/.venv/bin/python"
MLX_PYTHON="/Users/jason/miniforge3/envs/sentinelforge-mlx/bin/python"

# Ports
API_PORT=8765
BRAIN_PORT=8009

# PID files
API_PID_FILE="/tmp/sentinelforge_api.pid"
BRAIN_PID_FILE="/tmp/sentinelforge_brain.pid"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

kill_existing() {
    local port=$1
    local pid_file=$2
    
    # Kill by PID file if exists
    if [ -f "$pid_file" ]; then
        local old_pid=$(cat "$pid_file")
        if kill -0 "$old_pid" 2>/dev/null; then
            log "Killing existing process on port $port (PID: $old_pid)"
            kill -9 "$old_pid" 2>/dev/null || true
        fi
        rm -f "$pid_file"
    fi
    
    # Kill anything on the port
    local pids=$(lsof -t -i:$port 2>/dev/null || true)
    if [ -n "$pids" ]; then
        log "Killing stale processes on port $port: $pids"
        echo "$pids" | xargs kill -9 2>/dev/null || true
        sleep 1  # Wait for port to be released
    fi
}

wait_for_port() {
    local port=$1
    local name=$2
    local max_wait=30
    local waited=0
    
    while ! nc -z localhost $port 2>/dev/null; do
        sleep 0.5
        waited=$((waited + 1))
        if [ $waited -ge $((max_wait * 2)) ]; then
            log "❌ Timeout waiting for $name on port $port"
            return 1
        fi
    done
    log "✅ $name is ready on port $port"
}

start_api() {
    log "Starting FastAPI backend..."
    kill_existing $API_PORT $API_PID_FILE
    
    cd "$PROJECT_ROOT"
    nohup "$VENV_PYTHON" -m uvicorn core.server.api:app --host 127.0.0.1 --port $API_PORT > /tmp/sentinelforge_api.log 2>&1 &
    echo $! > "$API_PID_FILE"
    log "API started (PID: $(cat $API_PID_FILE))"
}

start_brain() {
    log "Starting Sentinel Brain (Gemma 9B)..."
    kill_existing $BRAIN_PORT $BRAIN_PID_FILE
    
    cd "$PROJECT_ROOT"
    nohup "$MLX_PYTHON" scripts/start_sentinel_brain.py > /tmp/sentinelforge_brain.log 2>&1 &
    echo $! > "$BRAIN_PID_FILE"
    log "Brain started (PID: $(cat $BRAIN_PID_FILE))"
}

main() {
    log "🚀 SentinelForge Server Launcher"
    
    start_api
    start_brain
    
    log "Waiting for servers to be ready..."
    wait_for_port $API_PORT "FastAPI"
    wait_for_port $BRAIN_PORT "Sentinel Brain"
    
    log "🎯 All servers ready!"
}

main "$@"
