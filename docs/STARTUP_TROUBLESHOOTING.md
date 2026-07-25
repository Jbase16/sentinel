# SentinelForge Startup Troubleshooting Guide

## Overview

This guide explains the common startup issues when running SentinelForge in Xcode and how to resolve them.

## Root Causes of Startup Issues

Based on analysis of the console logs, the following issues were identified:

### 1. Missing `scan_running` Field

**Error:**
```
[AppState] Status refresh failed: keyNotFound(CodingKeys(stringValue: "scan_running", intValue: nil), ...
```

**Cause:** The `/v1/status` endpoint was not returning the `scan_running` field when `scan_state` was `None`. The Swift `EngineStatus` struct expects this field as required.

**Fix:** Modified `core/server/api.py` to ensure `scan_running` is always included in the response, even when no scan is running:

```python
# Get scan state - ensure it's always present
scan_state = state.scan_state if state.scan_state else {}
scan_running = scan_state.get("status") == "running" if scan_state else False
```

### 2. WebSocket Connection Failures

**Error:**
```
Task <68E0F82F-EC40-4FE5-AFDF-FFFE1C27EF30>.<1> finished with error [-1011] 
Error Domain=NSURLErrorDomain Code=-1011 "There was a bad response from the server."
```

**Cause:** WebSocket handshake failures due to:
- Backend server not running
- Authentication mismatch
- Missing or invalid API token

**Fixes Applied:**
- Enhanced WebSocket logging in `core/server/routers/realtime.py` to log connection attempts and authentication details
- Added detailed debug logging for origin checks and token validation

### 3. Backend Server Not Running

**Root Cause:** The Xcode app attempts to connect to `ws://127.0.0.1:8765` but the backend Python server is not running.

**Solution:** The backend must be started separately before running the Xcode app.

## Proper Startup Procedure

### Step 1: Start the Backend Server

#### Option A: Using the Startup Script (Recommended)

```bash
./scripts/start_backend.sh
```

This script:
- Creates a virtual environment if needed
- Installs dependencies
- Checks for Ollama (for AI features)
- Starts the server on `http://127.0.0.1:8765`

#### Option B: Manual Start

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python -m sentinelforge.cli.sentinel start
```

#### Option C: Using uvicorn directly

```bash
uvicorn core.server.api:app --host 127.0.0.1 --port 8765 --reload
```

### Step 2: Verify Backend is Running

Open a new terminal and run:

```bash
curl http://127.0.0.1:8765/v1/ping
```

Expected response:
```json
{"status": "ok"}
```

Also check the status endpoint:

```bash
curl http://127.0.0.1:8765/v1/status
```

Expected response should include:
```json
{
  "status": "ok",
  "scan_running": false,
  "latest_target": null,
  "ai": {...},
  "tools": {...},
  "scan_state": {},
  "cancel_requested": false
}
```

### Step 3: Start the Xcode App

1. Open `ui/SentinelForge.xcodeproj` in Xcode
2. Build and run the project (⌘R)
3. The app should now connect successfully to the backend

### Step 4: Check the Logs

#### Backend Logs
Backend logs are written to:
- Console output (when running from terminal)
- File: `~/.sentinelforge/sentinel.log`

To view backend logs in real-time:
```bash
tail -f ~/.sentinelforge/sentinel.log
```

#### Xcode Console Logs
View the Xcode console (⇧⌘C) to see connection attempts and errors. Look for:
- `[AppState] Backend Ready` - Backend connection successful
- `[CortexStream] Connecting to ws://127.0.0.1:8765/ws/graph` - WebSocket connection attempts
- WebSocket error messages - Authentication or connection failures

## Authentication

The backend generates an API token automatically and writes it to:
```
~/.sentinelforge/api_token
```

The Xcode app automatically discovers this token and uses it for authentication.

### Authentication Flow

1. Backend starts up and generates a random API token
2. Token is written to `~/.sentinelforge/api_token`
3. Xcode app reads the token from this file
4. Xcode app uses token for all API requests and WebSocket connections
5. Backend validates token on each request

### Authentication Configuration

Default settings (from `core/base/config.py`):
- `api_host`: `127.0.0.1` (loopback only)
- `require_auth`: `false` (but token still used when available)
- `allowed_origins`: `http://127.0.0.1:*`, `http://localhost:*`, `tauri://localhost`

### Security Notes

- **Network Exposure Warning:** If you change `api_host` to `0.0.0.0`, authentication is **required**
- The security interlock prevents starting with exposed host + no authentication
- WebSocket connections validate origin headers and tokens
- The token changes each restart for security

## Common Issues and Solutions

### Issue: "Backend Ready" but WebSocket connection fails

**Symptoms:**
- `[AppState] Backend Ready. Connecting Services...`
- WebSocket handshake errors

**Solutions:**
1. Check backend logs for WebSocket connection attempts
2. Verify the API token exists at `~/.sentinelforge/api_token`
3. Ensure backend is running on the correct port (8765)
4. Check for firewall or network restrictions

### Issue: "There was a bad response from the server"

**Symptoms:**
- NSURLErrorDomain Code=-1011
- WebSocket handshake failure

**Causes:**
- Backend not running
- Port 8765 already in use
- Authentication mismatch
- CORS origin mismatch

**Solutions:**
1. Start the backend server (see Step 1)
2. Check if port 8765 is already in use: `lsof -i :8765`
3. Verify token file exists and is readable
4. Check allowed_origins configuration

### Issue: "No value associated with key scan_running"

**Symptoms:**
- Decoding error in Swift app
- Status refresh fails

**Cause:** Backend status endpoint not returning required field

**Solution:** This has been fixed in the code. Ensure you're running the latest version.

### Issue: Terminal shows connection errors

**Symptoms:**
- PTY WebSocket connection fails
- Terminal access not working

**Solutions:**
1. Ensure `terminal_enabled: true` in config
2. Check if terminal requires authentication
3. Verify token is valid
4. Check backend logs for PTY errors

## Debugging Tips

### Enable Verbose Logging

Set debug mode to see detailed logs:

```bash
SENTINEL_DEBUG=true python -m sentinelforge.cli.sentinel start
```

Or export the environment variable:

```bash
export SENTINEL_DEBUG=true
./scripts/start_backend.sh
```

### Test WebSocket Connection Manually

Using `websocat` or similar tools:

```bash
# Install websocat
brew install websocat

# Test graph WebSocket
websocat ws://127.0.0.1:8765/ws/graph

# Test PTY WebSocket
websocat ws://127.0.0.1:8765/ws/pty
```

### Check API Documentation

When the backend is running, visit:
```
http://127.0.0.1:8765/docs
```

This shows the full OpenAPI/Swagger documentation with all endpoints.

### Monitor WebSocket Logs

The enhanced logging in `core/server/routers/realtime.py` now logs:
- Connection attempts
- Origin checks
- Authentication validation
- Connection details

Watch for these logs in the backend output:
```
[WebSocket] /ws/graph - Connection attempt from ('127.0.0.1', 54321)
[WebSocket] /ws/graph - is_exposed: False, require_auth: False
[WebSocket] /ws/graph - Authentication successful
```

## Port Conflicts

If port 8765 is already in use:

```bash
# Check what's using the port
lsof -i :8765

# Kill the process using the port
kill -9 <PID>

# Or use a different port
SENTINEL_API_PORT=8766 python -m sentinelforge.cli.sentinel start
```

## Checklist Before Running Xcode

- [ ] Backend server is running on `http://127.0.0.1:8765`
- [ ] API health check passes: `curl http://127.0.0.1:8765/v1/ping`
- [ ] Status endpoint returns valid JSON with `scan_running` field
- [ ] API token exists at `~/.sentinelforge/api_token`
- [ ] Ollama is running (optional, for AI features): `ollama serve`
- [ ] No firewall blocking connections to 127.0.0.1:8765
- [ ] Port 8765 is not already in use

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Xcode App (Swift)                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  AppState                                           │  │
│  │  - Connects to backend on startup                   │  │
│  │  - Reads API token from ~/.sentinelforge/api_token  │  │
│  │  - Polls /v1/status for engine state                │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  CortexStream (WebSocket Client)                     │  │
│  │  - Connects to ws://127.0.0.1:8765/ws/graph          │  │
│  │  - Streams graph updates in real-time              │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  PTYClient (WebSocket Client)                       │  │
│  │  - Connects to ws://127.0.0.1:8765/ws/pty           │  │
│  │  - Provides terminal access in the UI               │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ HTTP/WebSocket
                              │
┌─────────────────────────────────────────────────────────────┐
│              Backend Server (Python/FastAPI)                │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  API Server (uvicorn)                                 │  │
│  │  - Listens on 127.0.0.1:8765                          │  │
│  │  - Serves REST endpoints (/v1/*)                      │  │
│  │  - Serves WebSocket endpoints (/ws/*)                 │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Authentication                                       │  │
│  │  - Generates API token on startup                    │  │
│  │  - Validates tokens on requests                      │  │
│  │  - Enforces origin checks                            │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Engine Components                                   │  │
│  │  - Scan Orchestrator                                 │  │
│  │  - AI Engine                                         │  │
│  │  - PTY Manager                                       │  │
│  │  - Event Store                                       │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Additional Resources

- API Documentation: http://127.0.0.1:8765/docs
- Backend Logs: `~/.sentinelforge/sentinel.log`
- API Token: `~/.sentinelforge/api_token`
- Configuration: `core/base/config.py`
- WebSocket Implementation: `core/server/routers/realtime.py`
- API Routes: `core/server/api.py`

## Getting Help

If issues persist after following this guide:

1. Check the backend logs: `tail -f ~/.sentinelforge/sentinel.log`
2. Enable debug mode: `SENTINEL_DEBUG=true`
3. Review Xcode console logs
4. Check for network restrictions or firewall rules
5. Verify all dependencies are installed

## Recent Fixes Applied

1. **Fixed `scan_running` field serialization** in `/v1/status` endpoint
2. **Enhanced WebSocket connection logging** for better debugging
3. **Improved error messages** for authentication failures
4. **Created startup script** for easier backend launching
5. **Documented startup procedure** and common issues

These fixes address the specific errors shown in the console logs and should resolve the startup issues when running in Xcode.