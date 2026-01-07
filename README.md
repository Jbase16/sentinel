# Sentinel

## The Reasoning Engine for Offensive Security

**Sentinel is not a vulnerability scanner.** 
It is a strictly deterministic **Reasoning Virtual Machine** designed to model the cognition of an elite security researcher.

Traditional scanners are **Stateless**: independent requests, flat findings, and instant amnesia.
Sentinel is **Cognitive**: it maintains a cryptographic memory, builds a causal graph of the target, and makes evidence-backed decisions.

> *"The goal is not volume—it is understanding."*

## Capability Maturity

Some components described here are fully implemented, others are partial or under active development. This README describes Sentinel’s intended architecture; specific implementation status is documented in code and tracking artifacts.

---

## The "Time Machine" Architecture

Sentinel's core innovation is the **ScanCapsule**—a Merkle-DAG based flight recorder that captures not just *what* happened, but *why*.

### 1. Cryptographic Causality
Every observation, thought, and decision is a content-addressed block (`BlockID = SHA256(Content + ParentHashes)`). This forms an immutable chain of custody for every finding.

### 2. The Butterfly Effect (Verified)
Because the history is a Merkle DAG, Sentinel can perform **Counterfactual Analysis**.
* **Fork History**: Clone the memory state at any point in the past.
* **Inject Facts**: "What if Port 80 was closed?"
* **Observe Divergence**: The engine enforces causal integrity. If you remove the evidence, the downstream finding automatically evaporates.

### 3. Deterministic Replay
The **Hypervisor** can replay any session (`RUN_ID`) with bit-perfect fidelity, restoring the exact memory state of the AI at any moment in time. This enables forensic auditing of *reasoning failures*, not just code failures.

---

## Architecture: The Centaur Model

Sentinel fuses three distinct systems into a unified intelligence:

### 🧠 Cortex (The Mind)
* **Epistemic Ledger**: A double-entry accounting system for Truth. The AI cannot "hallucinate" a finding; it must *promote* a `FindingProposal` by citing specific, immutable `ObservationID`s from the Ledger. *Enforcement provided at the data model and promotion layer.*
* **Knowledge Graph**: A reactive breakdown of the target (`Subdomain -> IP -> Service -> vulnerability`).

### 🏛️ AraUltra (The Hand)
* **Merkle-Causal Hypervisor**: The runtime that executes the reasoning loop. *(Refers to logical control of reasoning state, not OS-level virtualization.)*
* **ScannerEngine**: A transactional, crash-proof execution layer. If the process dies, the **JSONL Flight Recorder** ensures zero data loss.
* **Command Validator**: A rigid security boundary that mathematically prevents command injection.

### 👁️ Helix (The Eye)
* **Native SwiftUI Cockpit**: Real-time visualization of the Knowledge Graph.
* **Bidirectional PTY**: A fully interactive terminal bridged directly into the engine's secure context.

---

## Research Roadmap

Sentinel drives the state of the art in automated reasoning. *These initiatives do not expand Sentinel’s core scope; they are explorations built atop existing principles.*

### CRONUS (Temporal Surface Mining)
* **State**: In Development
* **Goal**: Weaponizing the 4th Dimension. Finding vulnerabilities in "Zombie Routes" (deprecated APIs, historic endpoints) that modern scanners ignore.

### MIMIC (Grey-Box Reconstruction)
* **State**: In Design
* **Goal**: Inferring server-side logic from client-side artifacts (Sourcemaps, Webpack bundles) to construct a "Shadow Map" of the application.

### SENTIENT (Multi-Persona Logic)
* **State**: Planned
* **Goal**: Simulating authorized vs. unauthorized users to mathematically prove IDOR and Privilege Escalation flaws.

### NEXUS (Exploit Chain Synthesis)
* **State**: Planned
* **Goal**: Transforms low-severity primitives into higher-impact findings by reasoning across relationships and attack paths.

---

## Quick Start

### Prerequisites
* Python 3.11+
* Ollama (`localhost:11434`)
* specific tools (`nmap`, `httpx`, `subfinder`)

### Installation
```bash
git clone https://github.com/your-org/sentinelforge.git
cd sentinelforge

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running the Engine
```bash
# Start the API & Hypervisor
python3 -m uvicorn core.server.api:app --reload --port 8000

# Launch a Scan Session
python3 -m core.cli scan --target example.com --mode comprehensive
```

---

## Safety & Ethics

**Sentinel is a weapon of analysis.**
It is designed for authorized security testing only. The **Epistemic Ledger** creates an immutable audit trail of every action taken. You are responsible for your usage.

> *Built to extend human capability, not automate recklessness.*

