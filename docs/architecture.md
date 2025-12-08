# Sentinel Architecture

This document tracks how the SwiftUI UI (Sentinel UI) talks to the Python engine (AraUltra lineage), and how the local LLM fits in. Kept intentionally simple so new contributors can follow along.

## Components
- **UI (SwiftUI)**: chat shell, scan controls, log viewer, findings panel. Talks to Python over localhost HTTP.
- **Python Core**: `ScanOrchestrator`, `ScannerEngine`, `AIEngine`, `TaskRouter`, classifiers, tool registry. Exposes a tiny HTTP bridge in `core/api.py`.
- **LLM**: Ollama-served local models (guardrail-free). Router in Swift chooses models for chat; AraUltra core uses LLM for findings/next steps.

## IPC (Swift ↔ Python)
Transport: local HTTP (default `http://127.0.0.1:8765`), JSON-only.

Endpoints (see `core/api.py`):
- `GET /ping` → `{"status":"ok"}` for health checks.
- `POST /scan` with `{"target": "<url_or_host>"}` → starts scan in background; returns 202.
- `GET /logs` → `{"lines": ["[scanner] ...", ...]}`; drains buffered logs since last call.
- `GET /results` → latest snapshot: `{"target","findings","issues","killchain_edges","phase_results","logs"}`; 204 if none.

Swift client: `SentinelAPIClient` wraps these endpoints; `HelixAppState` polls every ~2s to refresh logs/results.

## Data Shapes (high-level)
- **Findings** (from AraUltra): array of dicts with keys like `type`, `severity`, `tool`, `target`, `proof`, `tags`, `families`, `metadata`.
- **Issues**: enriched findings produced by `vuln_rules`.
- **Killchain edges**: graph edges (source, target, edge_type, severity) generated during enrichment.
- **Phase results**: per-phase outputs from `PhaseRunner`.

## Flow
1. UI POSTs `/scan` with target.
2. Python spawns background scan thread → `ScanOrchestrator` streams logs to `_log_queue`.
3. UI polls `/logs` → displays in log console.
4. When scan completes, `_latest_result` holds findings/issues/edges/phase_results → UI polls `/results`.
5. UI renders summary and findings sample (more detailed views to come).

## Future Improvements
- Add cancellation support (stop scan) in Python bridge and surface a Stop button.
- Switch logs to server-sent events or websockets for push-based streaming.
- Add module selection to `/scan` payload and honor it inside `ScanOrchestrator/ScannerEngine`.
- Validate/trim tool registry for macOS-safe defaults and “aggressive” opt-in flag.

## Model Strategy (guardrail-free)
- Ollama models: `llama3:latest`, `phi3:mini`, `deepseek-coder:6.7b`, plus a black-hat-tuned model for offensive reasoning.
- Potential fine-tune/adapter: Code_Vulnerability_Security_DPO (https://huggingface.co/datasets/CyberNative/Code_Vulnerability_Security_DPO) to bias toward vulnerability patterns and exploitation reasoning. Plan: prepare prompt/response pairs, train LoRA/adapter for compatible base (e.g., llama3), and route offensive tasks to that adapter locally.
