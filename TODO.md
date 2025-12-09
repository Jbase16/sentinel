# Sentinel TODO (high-level roadmap)

> Use this as the single source of truth for day-to-day tasks. Check items off or promote to issues.

## Immediate Setup
- [x] Create Python venv in `sentinelforge/.venv` and install AraUltra deps: `python -m venv .venv && source .venv/bin/activate && pip install -r ../AraUltra/requirements.txt`.
- [ ] Verify Ollama running on `127.0.0.1:11434` with models `llama3:latest`, `phi3:mini`, `deepseek-coder:6.7b`.
- [ ] Wire `core/api.py` to AraUltra engines (`AIEngine`, `ScanOrchestrator`, `ReasoningEngine`) and expose JSON-friendly methods for Swift.
- [x] Decide IPC transport (pipes vs. local HTTP). Implement a tiny shim in `core/api.py` to stream logs + results.

## SwiftUI (UI Layer)
- [ ] Rename target/bundle identifiers to `Sentinel` across Swift package/Xcode.
- [ ] Build a project/target selector view (targets list, add/remove, scope notes).
- [x] Add scan controls bound to IPC (start, stop, module selection).
- [x] Real-time log console and findings panel (streamed from Python).
- [ ] Model controls: pick model, toggle auto-routing, show Ollama status.
- [ ] Report export (Markdown/HTML/PDF) triggered from UI.

## Python Core (Engine Layer)
- [x] Port AraUltra `ScanOrchestrator`, `ScannerEngine`, `AIEngine`, `TaskRouter`, `raw_classifier`, `tools` into `core/` (initial copy done).
- [ ] Trim/modernize tool list for macOS; add capability flags per module (recon/fuzz/vuln-analysis).
- [x] Implement recon module entry in `core/recon/` (e.g., passive httpx + dnsx).
- [x] Implement fuzz module entry in `core/fuzz/` (parameter fuzzer stub).
- [ ] Define structured results schema (findings/issues/evidence/killchain) returned through `core/api.py`.
- [ ] Add unit tests for classifiers and IPC handlers.
- [ ] Evaluate fine-tune/adapter approach using vulnerability datasets (e.g., https://huggingface.co/datasets/CyberNative/Code_Vulnerability_Security_DPO) to bias local models toward vuln reasoning (guardrail-free).
- [ ] Strengthen cancellation: ensure UI shows cancelling state; confirm per-tool kills behave as expected in logs/results.

## Documentation
- [ ] Fill out `docs/architecture.md` with diagrams, IPC schemas, and threading model.
- [ ] Populate `docs/modules.md` with module capabilities and inputs/outputs.
- [ ] Track milestones in `docs/roadmap.md` and link to this TODO.

## Quality & Safety
- [ ] Add lint/format (ruff + black) config for Python; SwiftFormat/SwiftLint for Swift.
- [ ] Gate “aggressive” tooling behind explicit user opt-in (respect bounty scopes).
- [ ] Add logging and redaction rules for sensitive outputs (API keys, tokens).
- [ ] Add replay mode hooks and report templates for teaching workflow.
