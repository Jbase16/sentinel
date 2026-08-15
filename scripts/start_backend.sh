#!/bin/bash
# SentinelForge Backend Startup Script
# This script starts the Python backend server and displays the connection details

set -e

echo "🚀 Starting SentinelForge Backend Server..."
echo ""

# Change to project directory
cd "$(dirname "$0")/.."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found. Please install Python 3.8+"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "⚠️  No virtual environment found. Creating one..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies if needed
if [ ! -f "venv/.installed" ]; then
    echo "📦 Installing dependencies..."
    pip install -q -r requirements.txt
    touch venv/.installed
    echo "✅ Dependencies installed"
fi

# Check if Ollama is running (for AI features)
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "⚠️  Warning: Ollama not detected at http://localhost:11434"
    echo "   AI features will be unavailable or use fallback mode"
    echo "   Start Ollama with: ollama serve"
    echo ""
fi

# Start the backend server
echo "🔧 Starting backend server on http://127.0.0.1:8765"
echo "📝 Logs will be written to ~/.sentinelforge/sentinel.log"
echo ""
echo "API documentation: http://127.0.0.1:8765/docs"
echo 'Health check: curl -H "Authorization: Bearer $(cat ~/.sentinelforge/api_token)" http://127.0.0.1:8765/v1/ping'
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the server
python -m sentinelforge.cli.sentinel start
