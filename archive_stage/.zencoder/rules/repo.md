---
description: Repository Information Overview
alwaysApply: true
---

# SentinelForge Repository Information

## Repository Summary

**SentinelForge** is a modular, AI-augmented hybrid cybersecurity platform combining a macOS SwiftUI cockpit (Helix lineage) with a Python offensive engine (AraUltra lineage). Designed for authorized bug-bounty workflows with local LLM integration (Ollama), it provides on-device AI-guided recon, scanning, fuzzing, payload generation, vulnerability analysis, and attack-chain correlation. The system uses JSON-based IPC between Swift UI and Python backend with streaming log/event handling.

## Repository Structure

- **core/** - Python FastAPI backend (port 8765) with modular security/AI subsystems
- **ui/** - macOS SwiftUI application (SentinelForge) with project/target management and LLM router
- **scripts/** - Launch and utility scripts for servers, brain, and scans
- **tests/** - Integration tests and verification suites (pytest)
- **docs/** - Architecture guides, CAL language documentation, and roadmaps
- **assets/** - Wordlists and reference data
- **models/** - Local LLM models (Gemma 9B SFT, surgical adapters)
- **artifacts/** - Exploit compilation and results storage
- **sentinel.py** - Main CLI entry point for server/scan/brain commands

## Projects Overview

### Core Backend (Python)

**Primary Entry Point**: `core/server/api.py` → FastAPI application  
**Configuration File**: `requirements.txt`  
**Launch Script**: `scripts/start_servers.sh`

#### Language & Runtime
- **Language**: Python 3.11+
- **Build System**: Pip + Venv
- **Package Manager**: pip
- **Framework**: FastAPI (async web framework) + Uvicorn
- **Deployment Target**: Docker (Python 3.11-slim) or native with virtual environment

#### Key Dependencies
- **Web**: fastapi≥0.104.0, uvicorn[standard]≥0.24.0, websockets≥12.0
- **HTTP**: httpx≥0.25.0, requests≥2.31.0
- **AI/ML**: openai≥1.3.0 (for OpenAI API integration; models use local Ollama)
- **Data**: aiosqlite≥0.19.0, networkx≥3.2, beautifulsoup4≥4.12.0
- **Security**: cryptography≥41.0.0, python-multipart≥0.0.6
- **Testing**: pytest≥7.4.0, pytest-asyncio≥0.21.0

#### Core Modules (Under `core/`)
- **ai/** - AIEngine (Ollama integration, JSON enforcement, heuristics fallback)
- **analyze/** - Vulnerability analysis and classification
- **base/** - ActionDispatcher, TaskRouter, Session, Config
- **chat/** - ChatEngine with graph awareness (CAL-integrated conversation)
- **cortex/** - ReasoningEngine, EventStore, reasoning logic
- **data/** - Database (aiosqlite) and data persistence
- **engine/** - Orchestrator for scanning/task coordination
- **forge/** - ExploitCompiler and SandboxRunner for payload/exploit generation
- **fuzz/** - Fuzzing engine and parameter mutation
- **ghost/** - FlowMapper for data flow analysis
- **payloads/** - Payload library and generation templates
- **recon/** - Reconnaissance module (scan orchestration)
- **server/** - FastAPI app definition, routes, middleware
- **toolkit/** - Tool registry and base classes for external tools
- **utils/** - Utility helpers
- **wraith/** - WraithEngine for evasion and anti-detection

#### Build & Installation
```bash
# Setup virtual environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start backend server (standalone)
python -m uvicorn core.server.api:app --host 127.0.0.1 --port 8765

# Or via unified launcher (starts API + Brain)
python scripts/start_servers.sh
```

#### API Endpoints (Core IPC Surface)
- **POST /scan** - Submit scan request with target/modules
- **GET /results/{scan_id}** - Retrieve scan findings
- **WebSocket /stream/logs** - Stream live logs during scan
- **WebSocket /stream/events** - Stream graph events (killchain updates)
- **POST /exploit/compile** - Compile exploit payload
- **POST /exploit/run** - Execute in sandbox
- Chat and reasoning endpoints for multi-turn AI interactions

#### Server Configuration
- **API Host**: 127.0.0.1 (localhost)
- **API Port**: 8765 (primary) or 8000 (Docker)
- **Brain Port**: 8009 (Gemma 9B inference server)
- **Ollama URL**: http://localhost:11434 (or host.docker.internal in Docker)
- **AI Model**: gemma:7b (default) or custom fine-tuned Gemma 9B
- **Environment Variables**: SENTINEL_AI_PROVIDER, SENTINEL_AI_MODEL, SENTINEL_OLLAMA_URL

### UI Frontend (Swift)

**Primary Entry Point**: `ui/Sources/App.swift` (macOS application target)  
**Configuration File**: `ui/project.yml` (SPM project definition)

#### Language & Runtime
- **Language**: Swift 5.0+
- **Platform**: macOS 14.0+ (Sonoma or newer)
- **Build System**: Swift Package Manager (SPM)
- **IDE**: Xcode 15.0+
- **Package Manager**: SPM (Swift Package Manager)

#### Key Frameworks & Dependencies
- **UI**: SwiftUI (native macOS framework)
- **Graphics**: Metal, MetalKit (GPU acceleration for visualization)
- **Services**: URLSession (HTTP), WebSocket (async streams)
- **Concurrency**: Swift async/await with MainActor
- **Local Process**: Process + pipe IPC to Python backend

#### UI Module Structure (Under `ui/Sources/`)
- **Services/** - LLMService (Ollama streaming), SentinelAPIClient (backend calls), BackendManager, ModelRouter, PTYClient (local process execution), CortexStream (WebSocket for events)
- **Views/ChatBubbleView.swift** - Thread-based chat UI
- **Views/MainWindowView.swift** - Primary app window (project/scan/report tabs)
- **Views/Dashboard/DashboardView.swift** - Live scan visualization and metrics
- **Views/Scan/ScanControlView.swift**, ActionRequestView.swift - Scan orchestration
- **Views/Report/ReportComposerView.swift** - Report generation and export
- **Models/** - HelixAppState (root state), ChatThread, ChatMessage, ScanTask
- **Components/** - StatusComponents, alert helpers, async loaders

#### Build & Installation
```bash
# Open in Xcode
open ui/project.yml

# Or build from command line
cd ui
xcodebuild -scheme SentinelForge -configuration Release

# Or run in development
xcodebuild -scheme SentinelForge
```

#### Configuration
- **Bundle ID**: com.sentinel.* (customizable)
- **Deployment Target**: macOS 14.0
- **Code Signing**: Automatic
- **Enable Previews**: YES (SwiftUI Canvas support)

## Docker Configuration

**Dockerfile**: `./Dockerfile` (Python 3.11-slim base)  
**Docker Compose**: `./docker-compose.yml` (orchestrates sentinel-core + target-dummy)

### Services
- **sentinel-core**: FastAPI backend on port 8000 with mounted artifacts/brain directories
- **target-dummy**: DVWA/Juice Shop vulnerable app (port 3000) for testing
- **Network**: cyber-range (bridge driver)

### Build & Run
```bash
# Build image
docker build -t sentinelforge:latest .

# Run with compose
docker-compose up -d

# View logs
docker-compose logs -f sentinel-core
```

## Testing & Validation

### Python Backend (Pytest)

**Framework**: pytest (async-aware via pytest-asyncio)  
**Test Locations**:
- `tests/integration/` - End-to-end API tests
- `tests/verification/` - Module-specific verification scripts
- `tests/unit/` - Unit tests (if present)

**Key Test Files**:
- `tests/integration/test_api_basic.py` - FastAPI endpoint validation
- `tests/integration/test_scan_flow.py` - Full scan workflow
- `tests/verification/verify_cortex.py` - ReasoningEngine validation
- `tests/verification/verify_killchain.py` - Attack chain construction
- `tests/verification/verify_architecture.py` - System architecture checks

**Configuration Files**:
- `pytest.ini` (if present) or inline in `pyproject.toml`
- Tests use asyncio event loop for async endpoint testing

**Run Command**:
```bash
pytest tests/ -v
pytest tests/integration/ -v -s
pytest tests/verification/ -v --tb=short
```

### Swift UI (Xcode Tests)

- Tests in `ui/Tests/` (following Xcode convention)
- Built-in XCTest framework for unit and UI tests
- Previews for SwiftUI component validation

## Main Entry Points & Scripts

- **sentinel.py** - CLI dispatcher (server/scan/brain commands)
- **scripts/start_servers.sh** - Unified backend launcher (API + Brain on separate ports)
- **scripts/start_sentinel_brain.py** - Standalone Gemma 9B brain server (MLX environment)
- **scripts/manual_scan.py** - Direct scan invocation without UI
- **scripts/debug_cortex.py** - Debugging aid for reasoning engine
- **core/server/api.py** - Main FastAPI app instantiation

## Configuration & Models

- **Local Models**: `/models/` directory with Gemma 9B SFT + surgical adapters
- **Ollama**: Required external service (http://localhost:11434) for model inference
- **Environment Setup**: .venv (Python) + sentinelforge-mlx (MLX environment for brain)
- **.vscode/settings.json** - Python interpreter + extension recommendations
- **sentinel.code-workspace** - Multi-root workspace config

## Architecture Highlights

- **IPC Contract**: Swift ↔ Python via JSON-only requests/responses + streaming WebSockets
- **AI Integration**: Local LLM router selects models per task; no cloud dependencies
- **Modularity**: Pluggable tool registry, normalized findings JSON
- **Event-Driven**: TaskRouter + EventStore enable reactive UI updates
- **Exploit Capability**: ExploitCompiler + SandboxRunner for payload generation/testing
- **Analysis Chain**: Raw classifiers → AIEngine → ReasoningEngine → UI narrative

## Development Workflow

1. Activate Python venv: `source .venv/bin/activate`
2. Ensure Ollama running: http://localhost:11434
3. Launch backend: `python scripts/start_servers.sh` (or `python sentinel.py server`)
4. Open UI in Xcode: `open ui/project.yml`
5. Run tests: `pytest tests/` or Xcode test runner
6. Build Docker: `docker-compose up -d` for containerized deployment

## Key Production Considerations

- Treat this as a production-grade system (per AGENTS.md)
- All changes must be reviewable and preserve existing behavior
- No speculative features or refactoring without explicit approval
- Fine-tuned Gemma model is a validated asset; do not alter without consultation
- Security posture is paramount (flag any changes that affect it)
