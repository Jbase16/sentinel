

Sentinel

An Autonomous Synthetic Analyst for Offensive Security

Sentinel is not a traditional vulnerability scanner.
It is a stateful reasoning system designed to model how an elite security researcher investigates, understands, and exploits complex targets.

Rather than firing static payloads at endpoints, Sentinel maintains memory, builds relationships, and adapts its behavior based on what it learns. Its goal is not volume—it is understanding.

⸻

Core Philosophy

Most security tools are stateless. Each request is isolated, every finding is flat, and the system forgets what it learned moments ago.

Sentinel is stateful and cognitive.

It incrementally constructs a model of the target—its infrastructure, interfaces, trust boundaries, and behaviors—and uses that evolving context to decide what to do next. Each action is informed by prior observations, not by a predefined script.

This enables classes of analysis that traditional scanners cannot perform:
	•	Business-logic reasoning
	•	Cross-surface correlation
	•	Multi-step exploit chaining
	•	Replayable forensic analysis

⸻

Architecture Overview: The Centaur Model

Sentinel is composed of three tightly integrated systems:
	•	Helix (SwiftUI)
A native macOS cockpit for orchestration, visualization, and real-time introspection.
	•	AraUltra (Python)
The execution engine responsible for reconnaissance, analysis, tool control, and AI-assisted reasoning.
	•	Cortex
A shared event and memory layer that synchronizes state across the system.

Each component is independently testable and loosely coupled, but all communication flows through Cortex to ensure consistency and traceability.

⸻

System Components

1. Cortex — Memory, State, and Forensics

Cortex functions as Sentinel’s nervous system.
	•	Event-Sourced Execution
Every meaningful action—tool invocation, discovery, decision, or failure—is recorded as an immutable event.
	•	Knowledge Graph
A continuously updated graph (NetworkX + SQLite) models relationships such as
Subdomain → IP → Port → Service → Credential → Identity.
	•	Run Replayability
Each execution is assigned a RUN_ID. Entire attack chains can be replayed, audited, or analyzed post-hoc without rerunning scans.

This architecture enables both real-time reasoning and post-incident forensics without state corruption.

⸻

2. Strategos — The Reasoning Layer

Strategos is the decision-making layer that sits above raw tooling.
	•	Policy-Driven Control Loop
Strategos consumes deltas from the Knowledge Graph and emits constrained action plans rather than linear scripts.
	•	AI Circuit Breaker
All LLM interactions pass through a hardened client that enforces rate limits, output validation, and failure isolation.
	•	Context Awareness
Decisions are made relative to discovered structure. For example, discovering an authentication boundary alters subsequent enumeration and testing strategy.

Strategos is designed to guide execution, not replace deterministic tooling.

⸻

3. ScannerEngine — Safe, Transactional Execution

AraUltra’s execution layer is built to be resilient under failure.
	•	Transactional Persistence
Scan state and events are committed atomically. Interrupted or failed runs leave the system in a consistent, replayable state.
	•	Resource Guardrails
Strict limits on memory, disk usage, and subprocess behavior prevent host degradation.
	•	Argument-Validated Subprocesses
All external tools execute with rigorous validation to eliminate command injection and unsafe invocation.

The engine prioritizes correctness and stability over raw speed.

⸻

Research Roadmap

Sentinel includes an active research track focused on vulnerability classes that evade pattern-based tooling.

CRONUS — Temporal Surface Mining

Status: In Development

Identifies latent attack surfaces by analyzing historical artifacts such as archived routes, deprecated APIs, and legacy client code that may still be reachable.

⸻

MIMIC — Grey-Box Structural Reconstruction

Status: In Design

Reconstructs client-side application structure by analyzing JavaScript bundles, source maps, and runtime artifacts to infer routing, privilege boundaries, and hidden functionality.

⸻

SENTIENT — Multi-Persona Logic Analysis

Status: Planned

Simulates multiple identities (e.g., unauthenticated user, standard user, administrator) to detect authorization inconsistencies such as IDOR and privilege leakage through comparative access modeling.

⸻

NEXUS — Exploit Chain Synthesis

Status: Planned

Transforms low-severity primitives into higher-impact findings by reasoning across relationships and attack paths (e.g., Open Redirect → Token Exposure → Account Takeover).

⸻

Project Maturity

Component	Status
Cortex	Implemented
Strategos	Implemented (iterating)
ScannerEngine	Implemented
Helix UI	Active Development
Research Modules	Prototyping / Planned


⸻

Developer Guide

Prerequisites
	•	Python 3.11+
	•	Ollama (local, port 11434)
	•	SQLite
	•	Optional: Redis (high-concurrency setups)
	•	External Tools: nmap, httpx, subfinder (Homebrew)

⸻

Setup

git clone https://github.com/your-org/sentinelforge.git
cd sentinelforge

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Database schema initialization and migrations occur automatically on first run.

⸻

Running SentinelForge

# Start the API server
python3 -m uvicorn core.server.api:app --reload --port 8000

# Run a scan via CLI
python3 -m core.cli scan --target example.com --mode fast


⸻

Legal & Ethical Use

SentinelForge is intended for authorized security testing only.

Use against systems without explicit permission is illegal and unethical.
Users are responsible for complying with all applicable laws and regulations.

⸻

Final note

SentinelForge is built to explore how machines can reason about security, not to replace human judgment. Its purpose is to extend analyst capability—not automate recklessness.

⸻
