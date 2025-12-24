# Copilot Instructions for Sentinel

## Project Overview

Sentinel is a **security-focused, model-assisted cybersecurity platform** that combines the Helix macOS SwiftUI cockpit with the AraUltra offensive engine. It is designed for authorized bug bounty workflows with active testing.

**Core Principles:**
- Production-grade code only — not a prototype playground
- Security-first mindset in all changes
- Correctness and reproducibility over speed
- Local-first architecture (UI, engine, and LLM router run on-device)
- Modular design with pluggable components

## Architecture

- **SwiftUI front-end (ui/):** macOS app for visualization, project management, model control
- **Python back-end (core/):** recon, scanning, fuzzing, payload generation, vulnerability analysis
- **Local LLM router:** selects best local model per task via Ollama
- **Plugin system:** offensive modules register through `/core/api` with JSON-only IPC
- **IPC:** Swift ↔ Python via process invocation + pipes/local HTTP

## Technology Stack

- **Python:** 3.11+ (FastAPI, uvicorn, httpx, aiosqlite, networkx)
- **Swift:** SwiftUI for macOS
- **Local LLMs:** Ollama (llama3, phi3, deepseek-coder, gemma)
- **Testing:** pytest, pytest-asyncio, pytest-cov
- **Linting:** ruff, mypy
- **Security:** Bandit, Semgrep, custom security gates

## Code Modification Guidelines

### General Rules
- **Make minimal, surgical changes** — only modify what's necessary
- **Preserve existing behavior** unless explicitly changing it
- **Never remove working code** unless absolutely required or fixing a security vulnerability
- **Add tests** for new functionality (pytest style, see `tests/integration/`)
- **Run security checks** before committing (use `scripts/local-security-check.sh`)
- **Avoid speculative refactors** — refactor only when it measurably improves robustness

### Security-First Mindset
- **Never use `shell=True`** in subprocess calls (command injection risk)
- **Never use `eval()` or `exec()`** with user input
- **Avoid `os.system()`** — use subprocess with argument lists instead
- **Sanitize all inputs** from external sources
- **Use parameterized queries** for database operations
- **Never hardcode secrets** — use environment variables or config
- **Flag any change that could impact security posture**

### AI & Model Constraints
- **Do not alter model behavior, prompts, or fine-tuning logic** unless explicitly requested
- **Treat the fine-tuned Gemma model as a validated asset**
- **No "just add AI" suggestions** — AI must serve a clear security purpose
- **Model selection is handled by LLM router** — don't bypass it

### Code Style
- **Python:** Follow PEP 8, use type hints, prefer async where applicable
- **Swift:** Follow Swift API Design Guidelines, use structured concurrency
- **Comments:** Only add if they match existing style or explain complex logic
- **Error handling:** Use structured errors (`HelixError` in Swift, proper exceptions in Python)
- **Logging:** Use appropriate log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)

## Testing

### Running Tests
```bash
# Full test suite
pytest

# Specific test file
pytest tests/integration/test_api_basic.py

# With coverage
pytest --cov=core tests/
```

### Test Structure
- **Integration tests:** `tests/integration/` — test API endpoints and workflows
- **Verification tests:** `tests/verification/` — validate architecture and components
- **Test style:** Use unittest.TestCase or pytest fixtures
- **Async tests:** Mark with `@pytest.mark.asyncio` or use `asyncio_mode = "auto"`

### Writing Tests
- Test files should follow pattern: `test_*.py`
- Group related tests in classes: `class TestCoreAPI(unittest.TestCase)`
- Use descriptive test names: `test_01_ping()`, `test_02_status_structure()`
- Always clean up resources in teardown methods

## Building & Development

### Python Environment Setup
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On macOS/Linux
# or
.venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install -e ".[dev]"
```

### Running the Application
```bash
# Start API server
python -m core.server.api

# Start with custom port
python -m core.server.api --port 8766

# Run with Ollama (required for LLM features)
# Ensure Ollama is running on 127.0.0.1:11434
```

### Linting & Security Checks
```bash
# Run local security check (before committing)
./scripts/local-security-check.sh

# Ruff linting
ruff check .

# Type checking
mypy core/
```

## Key Modules

### core/server/api.py
- FastAPI server exposing REST endpoints
- Handles scan orchestration and results retrieval
- **Important:** Use `event_bus.emit()` for events, not direct `_store.append()`

### core/cortex/
- **scanner_engine.py:** Async tool runner with dynamic queueing
- **events.py:** EventBus for scan lifecycle events
- **memory.py:** KnowledgeGraph for attack path tracking

### core/ai/
- **ai_engine.py:** Ollama-first analysis with JSON enforcement
- **model_router.py:** Heuristic model selection per prompt

### core/toolkit/
- **registry.py:** Tool definitions and PATH bootstrapping
- **tools.py:** Tool discovery and installation helpers

### core/recon/, core/fuzz/, core/analyze/
- Pluggable modules for reconnaissance, fuzzing, and vulnerability analysis
- Each module registers through core/api.py

## Common Tasks

### Adding a New Tool
1. Define tool in `core/toolkit/registry.py`
2. Add installation logic if needed
3. Register in TOOLS dictionary
4. Add tests in `tests/integration/`

### Adding a New API Endpoint
1. Add route in `core/server/api.py`
2. Use FastAPI conventions (async def, Response models)
3. Emit appropriate events via `event_bus.emit()`
4. Add integration test in `tests/integration/`

### Adding a New Module (Recon/Fuzz/Analyze)
1. Create module directory under `core/`
2. Implement module interface
3. Register through `core/api.py`
4. Add tests and documentation

## CI/CD & Workflows

Sentinel has a comprehensive GitHub Actions setup:

- **ci.yml:** Main CI with security gate (blocks shell=True before tests)
- **fast-ci.yml:** Quick feedback for feature branches (unit tests only)
- **security-scan.yml:** Static analysis (Bandit, Semgrep, CVE scanning)
- **sentinel-health.yml:** Behavioral tests (fail-closed, state machines)
- **adversarial-ci.yml:** Sentinel attacks itself (manual trigger)
- **experimental-ci.yml:** Non-blocking checks for experiment branches

**All workflows are security-first** — violations block merges.

## Documentation

- **AGENTS.md:** Detailed agent role and philosophy (read this first!)
- **README.md:** Architecture overview and getting started
- **TODO.md:** Current stabilization work and known issues
- **GITHUB_ACTIONS_SETUP.md:** CI/CD pipeline documentation
- **docs/:** CAL language design, architecture, roadmap

## Communication Style

When working on Sentinel:
- **Be concise** — no fluff, no hype
- **Be explicit about risk** — call out security implications
- **If something is unsafe, say so directly**
- **If intent is unclear, stop and ask** — don't guess
- **Treat this project as if your reputation depends on it**

## When in Doubt

**Stop. Ask. Do not guess.**

This is a security platform. Incorrect assumptions can create vulnerabilities.

## References

- Project philosophy: See `AGENTS.md`
- Architecture details: See `README.md`
- Current work: See `TODO.md`
- CI/CD setup: See `GITHUB_ACTIONS_SETUP.md`
- Best practices: https://gh.io/copilot-coding-agent-tips
