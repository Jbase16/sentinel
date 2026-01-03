# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

SentinelForge is an AI-augmented cybersecurity platform that combines a macOS SwiftUI cockpit (Helix) with a Python offensive engine (AraUltra). It's designed for authorized security testing with active reconnaissance capabilities.

### Core Architecture

SentinelForge follows the Centaur Model with three tightly integrated components:
1. **Helix (SwiftUI)** - macOS cockpit for visualization and control
2. **AraUltra (Python)** - execution engine for reconnaissance, analysis, and exploit assessment
3. **Cortex** - shared event and memory layer that synchronizes state across the system

### Key Directories

- `core/` - Main Python system logic (AI, Cortex, Engine, Scheduler, etc.)
- `cli/` - Command-line entry point for running SentinelForge
- `tools/` - Developer scripts and operations helpers
- `tests/` - Unit, integration, and verification tests
- `ui/` - Swift user interface for macOS
- `docs/` - Architecture and design documentation

## Development Commands

### Environment Setup

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install -e ".[dev]"

# Database initialization happens automatically on first run
```

### Running the Application

```bash
# Start the API server (default method)
python -m uvicorn core.server.api:app --reload --port 8000

# Alternative: Use the CLI entrypoint
python -m sentinelforge.cli.sentinel start

# Run a scan via CLI
python -m sentinelforge.cli.sentinel scan

# CLI commands supported: start, scan, debug
```

### Testing

```bash
# Run full test suite
pytest

# Run specific test file
pytest tests/integration/test_api_basic.py

# Run with coverage
pytest --cov=core tests/

# Run unit tests only
pytest tests/unit/ -v --cov=core --cov-report=xml

# Run integration tests only
pytest tests/integration/ -v
```

### Linting & Security

```bash
# Run local security check (do this before committing)
./scripts/local-security-check.sh

# Run ruff linting
ruff check .

# Type checking
mypy core/

# Run Bandit security analysis
bandit -r core/ -ll --quiet
```

### Swift UI Development

```bash
# Build Swift UI
cd ui
xcodebuild -project SentinelForge.xcodeproj \
  -scheme SentinelForge \
  -destination 'platform=macOS' \
  -configuration Debug \
  build \
  CODE_SIGNING_ALLOWED=NO

# Run Swift tests
cd ui
xcodebuild -project SentinelForge.xcodeproj \
  -scheme SentinelForge \
  -destination 'platform=macOS' \
  test \
  CODE_SIGNING_ALLOWED=NO
```

## Key Architecture Patterns

### Cortex - Memory and Events
- **Event-Sourced Execution**: Every meaningful action is recorded as an immutable event
- **Knowledge Graph**: Continuously updated graph modeling relationships between entities
- **Run Replayability**: Each execution is assigned a RUN_ID for post-mortem analysis

### Strategos - Decision Making Layer
- Uses a policy-driven control loop that consumes deltas from the Knowledge Graph
- All LLM interactions pass through a hardened client with rate limiting and validation
- Decisions are made relative to discovered structure, not static scripts

### ScannerEngine - Execution Layer
- Transactional persistence ensures interrupted runs leave the system in a consistent state
- Resource guardrails prevent host degradation
- All external tools execute with rigorous validation

### API Layer
- FastAPI-based REST API with JSON-only IPC
- Versioned endpoints under `/v1/` prefix (recommended)
- Legacy endpoints without `/v1/` prefix will be deprecated
- All sensitive endpoints use `verify_sensitive_token` which requires authentication when exposed to network

## Security Rules

### Critical Security Requirements

NEVER use these patterns in code (they will be blocked by CI):
- `shell=True` in subprocess calls (command injection risk)
- `eval()` or `exec()` with user input (code injection risk)
- `os.system()` - use subprocess with argument lists instead

### Security Checklist Before Committing
1. Run `./scripts/local-security-check.sh` to verify no critical security issues
2. Sanitize all inputs from external sources
3. Use parameterized queries for database operations
4. Never hardcode secrets - use environment variables

### Security CI/CD Gates
The security gate in CI will block commits with:
- Any `shell=True` found in the codebase
- Command injection vulnerabilities
- Critical security issues identified by Bandit

## API Development

When adding new API endpoints:
1. Add routes to `core/server/api.py`
2. Use FastAPI conventions with async def and Response models
3. Emit appropriate events via `event_bus.emit()`
4. Use `verify_token` for regular endpoints or `verify_sensitive_token` for dangerous ones
5. Add integration tests in `tests/integration/`

## Testing Strategy

### Test Structure
- Integration tests: `tests/integration/` - test API endpoints and workflows
- Unit tests: `tests/unit/` - test individual components
- Verification tests: `tests/verification/` - validate architecture and security properties

### Async Testing
Mark async tests with `@pytest.mark.asyncio` or use `asyncio_mode = "auto"` (configured)

## Common Workflows

### Adding a New Tool
1. Define tool in `core/toolkit/registry.py`
2. Add installation logic if needed
3. Register in TOOLS dictionary
4. Add tests in `tests/integration/`

### Debugging Session Issues
1. Check session logs in the session object
2. Use the time-travel debugging endpoints: `/debug/{session_id}/timeline`
3. Create replay capsules for completed scans with `/capsule/create`

### Working with the Knowledge Graph
1. Access via WebSocket endpoint: `/ws/graph` or `/v1/ws/graph`
2. Query current state via `/cortex/graph` or `/v1/cortex/graph`
3. The graph models relationships like Subdomain → IP → Port → Service → Credential

## Model Usage

### Local LLM Integration
- Uses Ollama for local model serving (default port 11434)
- Models include: llama3, phi3, deepseek-coder, gemma
- Model selection is handled by the model router in `core/ai/model_router.py`
- Offensive security tasks may route to specialized models

## IPC Communication (Swift ↔ Python)

Transport: local HTTP (default `http://127.0.0.1:8765`), JSON-only
Key endpoints:
- `GET /ping` → health check
- `POST /scan` with `{"target": "<url_or_host>"}` → starts scan
- `GET /logs` → streamed scan logs
- `GET /results` → structured results snapshot
- `POST /cancel` → best-effort scan cancellation

## Additional Context

### External Tool Requirements
- External tools needed: nmap, httpx, subfinder (available via Homebrew)
- Optional: Redis for high-concurrency setups
- Required: Ollama for LLM features
- Required: SQLite for data persistence

### Session Management
All scans are associated with sessions that provide:
- Isolation of findings, logs, and state
- Simplified cleanup and resource management
- Time-travel debugging capabilities
- Replay capsule generation