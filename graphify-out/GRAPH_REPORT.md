# Graphify Report: core + ui

Generated: 2026-07-01T05:43:37.631237+00:00

Merged graph built from `core` and `ui`.

- Nodes: 8172
- Edges: 16528
- Missing-endpoint edges: 0
- Self-loop edges: 0
- HTML view: `graphify-out/graph.html`

Note: Graphify's provider-based `cluster-only` report generation encountered a temporary Gemini 503 during community labeling. This compact report was generated deterministically from the merged `graph.json` plus the completed per-scope analysis files.

## God Nodes

- **Database** (`core`): degree 111; source `data/db.py:L41`
- **HelixAppState** (`ui`): degree 84; source `Sources/Models/HelixAppState.swift:L40`
- **GraphEvent** (`core`): degree 74; source `cortex/events.py:L90`
- **Strategos** (`core`): degree 69; source `scheduler/strategos.py:L363`
- **EventType** (`core`): degree 66; source `contracts/events.py:L62`
- **FlowStep** (`core`): degree 64; source `ghost/flow.py:L75`
- **WebMission** (`core`): degree 62; source `web/contracts/models.py:L28`
- **EventBus** (`core`): degree 62; source `cortex/events.py:L195`
- **WebContext** (`core`): degree 60; source `web/context.py:L13`
- **AIEngine** (`core`): degree 56; source `ai/ai_engine.py:L384`

## Surprising Connections

- **Three-Axis Priority Scoring Flag -> PressureGraphManager** (`core`): conceptually_related_to / INFERRED; inferred connection - not explicitly stated in source; crosses file types (code ↔ doc); connects across different repos/directories; peripheral node `Three-Axis Priority Scoring Flag` unexpectedly reaches hub `PressureGraphManager`; source `cortex/capability_model_config.yaml`, `data/pressure_graph/manager.py`
- **ChainExecutor -> ChainStep** (`core`): uses / INFERRED; inferred connection - not explicitly stated in source; connects across different repos/directories; bridges separate communities; source `aegis/nexus/chain.py`, `omega/nexus_phase.py`
- **ChainExecutor -> ExploitChain** (`core`): uses / INFERRED; inferred connection - not explicitly stated in source; connects across different repos/directories; bridges separate communities; source `aegis/nexus/chain.py`, `omega/nexus_phase.py`
- **ChainExecutor -> GoalState** (`core`): uses / INFERRED; inferred connection - not explicitly stated in source; connects across different repos/directories; bridges separate communities; source `aegis/nexus/chain.py`, `omega/nexus_phase.py`
- **PrimitiveType -> Database** (`core`): uses / INFERRED; inferred connection - not explicitly stated in source; connects across different repos/directories; bridges separate communities; source `aegis/nexus/primitives.py`, `data/db.py`
- **SentinelForge Swift Testing Strategy -> HelixAppState** (`ui`): cites / EXTRACTED; crosses file types (code ↔ doc); connects across different repos/directories; bridges separate communities; source `Tests/TESTING_STRATEGY.md`, `Sources/Models/HelixAppState.swift`
- **SentinelForge Swift Testing Strategy -> SentinelAPIClient** (`ui`): cites / EXTRACTED; crosses file types (code ↔ doc); connects across different repos/directories; bridges separate communities; source `Tests/TESTING_STRATEGY.md`, `Sources/Services/SentinelAPIClient.swift`
- **SentinelForge Swift Testing Strategy -> EventStreamClient** (`ui`): cites / EXTRACTED; crosses file types (code ↔ doc); connects across different repos/directories; source `Tests/TESTING_STRATEGY.md`, `Sources/Services/EventStreamClient.swift`

## Suggested Questions

- How does the capability-model configuration influence `PressureGraphManager`?
- Why does `ChainExecutor` bridge Aegis nexus code and Omega exploit-chain phases?
- How does `Database` depend on or influence `Strategos`?
- How do `EventType`, `GraphEvent`, and `EventBus` define event flow through core?
- How do `HelixAppState`, `SentinelAPIClient`, and `EventStreamClient` support the Swift testing strategy?
