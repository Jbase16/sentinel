# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

SentinelForge is an AI-augmented hybrid cybersecurity platform combining a macOS SwiftUI frontend with a Python offensive security engine. It uses local LLMs (via Ollama) for AI-guided security analysis.

## Commands

### Running the Backend API
```bash
# Start the FastAPI server (default: 127.0.0.1:8765)
python -m uvicorn core.api:app --host 127.0.0.1 --port 8765

# Or use the module directly
python -m core.api
```

### Running with Docker
```bash
# Full stack with vulnerable target (Juice Shop)
docker-compose up

# Just the core backend
docker build -t sentinel-core . && docker run -p 8000:8000 sentinel-core
```

### Testing
```bash
# Run all tests with pytest
pytest tests/

# Run a specific test file
pytest tests/test_api_basic.py -v

# Verification scripts (manual integration tests)
python tests/verify_backend.py      # Tests /ping, /scan, /chat endpoints
python tests/verify_cortex.py       # Tests knowledge graph functionality
python tests/verify_forge.py        # Tests JIT exploit compiler
python tests/verify_god_tier.py     # Tests full autonomous loop
```

### Building the SwiftUI App
```bash
# Open in Xcode
open ui/SentinelForge.xcodeproj

# Or build via command line
xcodebuild -project ui/SentinelForge.xcodeproj -scheme SentinelForgeUI build
```

### Prerequisites
- Python 3.11+
- Ollama running locally on `127.0.0.1:11434` (models: `llama3:latest`, `phi3:mini`, `deepseek-coder:6.7b`)
- Optional recon tools: nmap, httpx, subfinder, nikto, nuclei

## Architecture

### Core Components

**Python Backend (`core/`)**
- `api.py` - FastAPI server exposing REST + WebSocket endpoints for Swift UI
- `ai_engine.py` - Central LLM interface using Ollama for analysis and chat
- `scan_orchestrator.py` - High-level scan sequencing and tool execution
- `scanner_engine.py` - Async tool runner with concurrency control
- `task_router.py` - Event bus linking tool output → AI → UI

**Neuro-Symbolic Subsystems (`core/cortex/`, `core/wraith/`, `core/ghost/`, `core/forge/`)**
- `cortex/memory.py` - NetworkX-based knowledge graph (`KnowledgeGraph`) storing assets, ports, services, findings
- `cortex/reasoning.py` - Attack path analysis and opportunity detection
- `wraith/evasion.py` - WAF bypass with mutation loop
- `ghost/flow.py` - User flow recording for logic fuzzing
- `forge/compiler.py` - JIT exploit generation via LLM

**SwiftUI Frontend (`ui/Sources/SentinelForgeUI/`)**
- `SentinelForgeApp.swift` - App entry point, spawns backend via `BackendManager`
- `Services/SentinelAPIClient.swift` - HTTP/SSE client for Python bridge
- `Services/BackendManager.swift` - Manages Python subprocess lifecycle
- `Views/MainWindowView.swift` - Navigation sidebar and view routing

### IPC Contract

Swift ↔ Python communication uses JSON over HTTP/SSE:
- `POST /scan` - Start scan with target
- `POST /chat` - Stream AI responses (SSE)
- `GET /events` - Subscribe to real-time findings/actions (SSE)
- `WS /ws/graph` - Live knowledge graph updates
- `POST /mission/start` - Trigger full autonomous loop

### Data Flow
1. UI sends scan target via `/scan`
2. `ScanOrchestrator` runs tools, populates `findings_store`, `KnowledgeGraph`
3. `TaskRouter` emits events to UI via SSE
4. `ReasoningEngine` analyzes graph, suggests next steps
5. `ActionDispatcher` gates dangerous tools (nmap, nuclei) requiring approval

### Key Patterns

**Singleton Services**: Most engines use `.instance()` static methods for shared state
```python
AIEngine.instance()
KnowledgeGraph.instance()
Orchestrator.instance()
```

**Event-Driven**: `TaskRouter.ui_event` and `ActionDispatcher.action_needed` emit signals
```python
TaskRouter.instance().ui_event.connect(callback)
```

**Tool Safety**: Tools are classified in `core/config.py`:
- `safe_tools`: auto-approved (httpx, dnsx, subfinder)
- `restricted_tools`: require user approval (nmap, nikto, sqlmap)

## Configuration

Environment variables (or defaults in `core/config.py`):
- `SENTINEL_AI_PROVIDER` - "ollama" (default)
- `SENTINEL_OLLAMA_URL` - "http://localhost:11434"
- `SENTINEL_AI_MODEL` - "llama3:latest"
- `SENTINEL_API_HOST` / `SENTINEL_API_PORT` - Backend address (127.0.0.1:8765)
- `SENTINEL_REQUIRE_AUTH` - Enable token auth (default: false for dev)

Data stored in `~/.sentinelforge/` (SQLite DB, evidence, reports).
