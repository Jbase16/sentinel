# SentinelForge
> **The First Autonomous "Synthetic Analyst" for Offensive Security.**

SentinelForge is not a vulnerability scanner. It is a **Reasoning Engine** that models the behavior of an elite bug bounty hunter. It combines an ACID-compliant execution engine with an event-sourced knowledge graph to perform autonomous reconnaissance, vulnerability analysis, and exploit chaining.

---

## 🚀 The Core Philosophy

Traditional scanners are **stateless and dumb**. They fire patterns at URLs and report 404s or 200s.
SentinelForge is **stateful and cognitive**. It builds a `KnowledgeGraph` of the target, understands business logic, and uses AI (`Strategos`) to make decisions about *what* to do next based on *what* it just found.

### The "Centaur" Architecture
*   **Helix (SwiftUI)**: A high-performance, native macOS cockpit for visualization and control.
*   **AraUltra (Python)**: The heavy-lifting engine for recon, analysis, and AI reasoning.
*   **Cortex**: The event bus and memory layer that synchronizes them in real-time.

---

## 🧠 System Architecture

### 1. The Cortex (Memory & Nervous System)
The heart of SentinelForge is the **Cortex**, an event-sourced nervous system.
*   **Event Bus**: Every action (Tool Started, Finding Discovered, AI Decision) is an event.
*   **Knowledge Graph**: A real-time graph database (NetworkX + SQLite) that maps relationships (e.g., `Subdomain -> IP -> Port -> Service`).
*   **Forensics**: Every run is assigned a `RUN_ID`, allowing complete replayability of the attack chain.

### 2. Strategos (The Reasoning Engine)
Strategos is the "brain" that sits above the tools.
*   **AI Circuit Breaker**: A `ProtectedOllamaClient` ensures that AI calls are safe, vetted, and rate-limited.
*   **Decision Loop**: Instead of linear scripts, Strategos observes the `KnowledgeGraph` and chooses actions dynamically.
*   **Context-Aware**: It knows that if it finds a login page, it should look for default credentials *before* trying SQL injection.

### 3. ScannerEngine (The Execution Arm)
A robust, production-grade execution environment.
*   **ACID Transactionality**: Every scan is a **transaction**. If a scan crashes or is canceled, the database rolls back to a clean state. No more corrupted data.
*   **Resource Guards**: Strictly enforced memory and disk limits prevents the engine from crashing the host machine.
*   **Safe Execution**: All tools run in isolated subprocesses with rigorous argument validation to prevent injection.

---

## 🔮 Project OMEGA: The "God-Mode" Roadmap

We are currently implementing **Project OMEGA**, a set of "Illegal-tier" capabilities designed to bypass modern defenses.

### 1. CRONUS (Temporal Mining)
> *"The bug was patched in v2, but the route still exists."*
*   **Concept**: Scans the **past** to attack the **present**.
*   **Mechanism**: Queries Wayback Machine and CommonCrawl to find "Zombie APIs" (endpoints deleted from the UI but active on the backend).
*   **Status**: *In Development*.

### 2. MIMIC (Grey-Box Inverter)
> *"White-box visibility in a black-box world."*
*   **Concept**: Reconstructs the target's source code structure from the outside.
*   **Mechanism**: Downloads JS chunks and Source Maps to rebuild the directory tree (`src/components/AdminPanel.js`), creating a perfect map of client-side routes.
*   **Status**: *In Design*.

### 3. SENTIENT (The Cognitive Overlay)
> *"Solving the Business Logic Gap."*
*   **The Doppelgänger Protocol**: Spawns multiple "Personas" (User A, User B, Admin) to detect IDOR by comparing access rights to the same resource.
*   **The Darwinian Mutator**: An evolutionary genetic algorithm that uses the WAF's own error messages to train a bypass payload in real-time.
*   **Status**: *Planned*.

### 4. NEXUS (The Chain Reactor)
> *"Turning low-severity noise into high-severity signals."*
*   **Concept**: An **Exploit Compiler** that chains primitives.
*   **Mechanism**: "Use the Open Redirect (Low) to steal the OAuth Token (High) -> Account Takeover (Critical)."
*   **Status**: *Planned*.

---

## 🛠️ Developer Guide

### Prerequisites
*   **Python 3.11+**
*   **Ollama** (running locally on port 11434)
*   **Redis** (optional, for heavily concurrent setups)
*   **Core Tools**: `nmap`, `httpx`, `subfinder` (installed via Homebrew)

### Setup
```bash
# 1. Clone the repo
git clone https://github.com/your-org/sentinelforge.git

# 2. Setup Python Environment
cd sentinelforge
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Initialize Database
# The engine will auto-migrate SQLite on first run.
```

### Running the Engine
```bash
# Start the API Server
python3 -m uvicorn core.server.api:app --reload --port 8000

# Run a dedicated scan (CLI mode)
python3 -m core.cli scan --target example.com --mode fast
```

---

## 🛡️ License
SentinelForge is built for **authorized security testing only**.
Usage against targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws.
