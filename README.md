# Sentinel

Sentinel is a modular, AI-augmented hybrid cybersecurity platform that fuses the Helix macOS SwiftUI cockpit with the AraUltra offensive engine. It is built for authorized bug bounty workflows where active testing is permitted.

## Core Philosophy
- Not a wrapper: combines Helix orchestration with AraUltra scanning/analysis via a predictable API.
- Everything local: UI, engine, and LLM router run on-device (Ollama or custom models).
- Modular first: recon, fuzzing, payloads, analysis, and reporting are pluggable.
- AI-guided: models choose strategies, chain vulns, narrate findings, and emit clean reports.

## Architecture
- **SwiftUI front-end (Helix-based):** UI, visualization, project/target management, model control, log viewers, and report export. Includes menu-bar quick actions.
- **Python back-end (AraUltra-based):** recon, scanning, fuzzing, payload generation, vuln analysis, and attack chain correlation.
- **Local LLM router:** selects best local model per task (llama3, dolphin-llama, gemma, etc.) via Ollama.
- **Plugin system:** offensive modules (recon, fuzz, injection, analysis) register through a stable `/core/api` surface with JSON-only IPC.
- **IPC:** Swift ↔ Python via process invocation + pipes/local HTTP; JSON request/response plus streaming logs.

```
sentinel/
├── ui/                    # SwiftUI macOS app (Helix lineage)
│   ├── Models/
│   ├── Views/
│   ├── Services/
│   └── LLMRouter/
├── core/                  # Python engine (AraUltra lineage)
│   ├── recon/
│   ├── fuzz/
│   ├── analyze/
│   ├── payloads/
│   ├── utils/
│   └── api.py             # Swift ↔ Python bridge surface
├── docs/
│   ├── architecture.md
│   ├── roadmap.md
│   └── modules.md
└── README.md
```

## AI Responsibilities
- Module selection, payload generation/mutation, anomaly interpretation.
- Next-attack recommendations and autonomous chaining (within scope).
- Summaries, risk explanations, report writing, and exploit-chain visualization.
- Teaching mode: narrate attacks and replay steps for students.

## What We’re Reusing From Helix (SwiftUI)
- Streaming chat UI with threaded `HelixAppState`, `ChatThread`, and `ChatMessage` models.
- Ollama-backed `LLMService` with streaming tokens and cancellation.
- Heuristic `ModelRouter` for local model selection per prompt.
- Menu-bar quick access (`MenuBarExtra`) and main window chat scaffold.
- Centralized `HelixError` for structured UI-safe error reporting.

## What We’re Reusing From AraUltra (Python)
- **AIEngine:** Ollama-first analysis with JSON enforcement, fallback heuristics, and killchain mapping.
- **Raw classifiers:** structured findings from tools (ports/tech stack/secret patterns/security headers).
- **ScannerEngine:** async tool runner with dynamic queueing, concurrency limits, and recon edge building.
- **Tool registry:** normalized targets, PATH bootstrapping, and rich command definitions for recon/scan/fuzz.
- **TaskRouter:** event bus linking tool output → AI → UI, emitting findings/next steps/live commentary.
- **Stores:** evidence/findings/issues/killchain stores for UI syncing and reporting.
- **ActionDispatcher:** safety net for autonomous AI actions (allowlist + dedupe).
- **ReasoningEngine:** attack-path construction and phase recommendations from findings/issues graph.
- **Recon/Fuzz hooks:** behavioral recon variants, parameter fuzz concepts, and payload mutation stubs to seed `core/recon` and `core/fuzz`.

## Phase Goals
- **Phase 1 – Foundation:** unified repo, core engine stubs, basic Swift ↔ Python IPC, one working module (Recon or ParamFuzzer), UI scaffold.
- **Phase 2 – Expansion:** fuzzing + vuln analysis modules, LLM agent reasoning, real-time logs, exportable reports, asset map visualizer.
- **Phase 3 – Full Platform:** exploit-chain engine, automated attack path builder, replay/teaching mode, custom payload designer, full bug-bounty workflow integration, historical scan comparisons, multi-model routing.

## Getting Started (Dev)
1) **Prereqs:** Python 3.11+, Swift toolchain for macOS, Ollama running locally, Homebrew tools for recon/scan (nmap, httpx, subfinder, etc.).
2) **Python env:** `python -m venv .venv && source .venv/bin/activate && pip install -r ../AraUltra/requirements.txt` (reuse AraUltra deps until Sentinel-specific ones are pinned).
3) **Swift UI:** open `sentinelforge/ui` in Xcode/SwiftPM (initial Swift files will be ported from Helix).
4) **VS Code:** open the repo folder; `.vscode/extensions.json` recommends Python + Swift tooling. Set your interpreter in Command Palette → Python: Select Interpreter.
5) **LLM router:** keep Ollama running on `127.0.0.1:11434`; models used today mirror Helix defaults (`llama3:latest`, `phi3:mini`, `deepseek-coder:6.7b`).

## IPC Contract (stub)
- Python exposes `core/api.py` with methods for `ping`, `start_scan(target, modules)`, `stream_logs()`, and `latest_results()`.
- SwiftUI side invokes via process/IPC, streams logs to UI, and parses JSON-only responses.
- All modules report findings/issues/evidence in normalized JSON to keep UI components deterministic.

## Next Steps
- Port Helix UI scaffolding (MainWindowView, MenuBarContentView, ModelRouter, LLMService) into `ui/`.
- Lift AraUltra orchestration (ScanOrchestrator, ScannerEngine, AIEngine, TaskRouter, raw_classifier) into `core/`, wiring them through `core/api.py`.
- Add a first working module (Recon or ParamFuzzer) to validate Swift ↔ Python IPC and log streaming.
- Document the IPC payloads in `docs/architecture.md` and track milestones in `docs/roadmap.md`.
