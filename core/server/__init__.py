# ============================================================================
# core/server/__init__.py
# Server Package - FastAPI Web Server
# ============================================================================
#
# PURPOSE:
# Provides the HTTP API server that the UI communicates with. Think of this as
# the "waiter" that takes requests from the frontend and serves back responses.
#
# API ARCHITECTURE:
# Swift UI (macOS app) ← HTTP/WebSocket → FastAPI Server ← → Core Modules
#
# WHAT THE SERVER DOES:
# - **REST API**: Handles scan requests, fetches results, manages sessions
# - **WebSocket**: Streams live logs and events to UI in real-time
# - **Authentication**: Validates API tokens (if enabled)
# - **CORS**: Allows cross-origin requests from the UI
# - **Rate Limiting**: Prevents abuse and resource exhaustion
#
# KEY ENDPOINTS:
# - POST /scan - Start a new security scan
# - GET /results/{scan_id} - Retrieve scan findings
# - WebSocket /stream/logs - Real-time log streaming
# - WebSocket /stream/events - Real-time event streaming (findings, progress)
# - POST /exploit/compile - Generate proof-of-concept exploits
# - GET /sessions - List all scan sessions
#
# KEY MODULES:
# - **api.py**: FastAPI application definition and routes
# - **tls.py**: HTTPS/TLS certificate management
#
# KEY CONCEPTS:
# - **REST API**: Representational State Transfer (standard HTTP API pattern)
# - **WebSocket**: Persistent bidirectional communication channel
# - **CORS**: Cross-Origin Resource Sharing (allows UI to connect from different origin)
# - **Async**: Non-blocking request handling (can serve multiple clients simultaneously)
#
# ============================================================================
