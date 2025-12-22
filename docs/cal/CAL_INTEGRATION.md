# CAL Integration Guide
## Integrating the Collaborative Agent Language with Sentinel

---

## Overview

This document describes how CAL integrates with Sentinel's existing Python codebase. The integration is designed to be **gradual**—CAL runs alongside existing code, progressively replacing imperative orchestration logic.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                         Sentinel Application                            │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐        ┌────────────────────────────────────────┐│
│  │   Swift UI      │◀──────▶│            Python Backend              ││
│  │  (Existing)     │  IPC   │                                        ││
│  └─────────────────┘        │  ┌────────────────────────────────┐   ││
│                             │  │         CAL Runtime             │   ││
│                             │  │  ┌───────────┐ ┌────────────┐  │   ││
│                             │  │  │  Lexer/   │ │   Rule     │  │   ││
│                             │  │  │  Parser   │ │  Engine    │  │   ││
│                             │  │  └───────────┘ └────────────┘  │   ││
│                             │  │  ┌───────────┐ ┌────────────┐  │   ││
│                             │  │  │  Belief   │ │   Audit    │  │   ││
│                             │  │  │  State    │ │    Log     │  │   ││
│                             │  │  └─────┬─────┘ └────────────┘  │   ││
│                             │  └────────┼───────────────────────┘   ││
│                             │           │                            ││
│                             │  ┌────────▼───────────────────────┐   ││
│                             │  │      Agent Bindings (FFI)       │   ││
│                             │  │  ┌─────────┐ ┌────────┐ ┌────┐ │   ││
│                             │  │  │Nmap     │ │LLM     │ │Forg│ │   ││
│                             │  │  │Binding  │ │Binding │ │e   │ │   ││
│                             │  │  └────┬────┘ └───┬────┘ └─┬──┘ │   ││
│                             │  └───────┼─────────┼─────────┼────┘   ││
│                             │          │         │         │         ││
│                             │  ┌───────▼─────────▼─────────▼────┐   ││
│                             │  │    Existing Python Components   │   ││
│                             │  │  ┌─────────────┐ ┌───────────┐ │   ││
│                             │  │  │ScannerEngine│ │ AIEngine  │ │   ││
│                             │  │  └─────────────┘ └───────────┘ │   ││
│                             │  │  ┌─────────────┐ ┌───────────┐ │   ││
│                             │  │  │ KnowledgeGrp│ │  Stores   │ │   ││
│                             │  │  └─────────────┘ └───────────┘ │   ││
│                             │  └────────────────────────────────┘   ││
│                             └────────────────────────────────────────┘│
└────────────────────────────────────────────────────────────────────────┘
```

---

## Integration Points

### 1. Agent Bindings

CAL agents map to Python implementations through a binding layer.

**File: `core/cal/bindings/__init__.py`**

```python
"""
CAL Agent Binding System

This module provides the bridge between CAL agent declarations
and Sentinel's Python implementations.
"""

from typing import Dict, List, Any, Callable
from functools import wraps
import asyncio

# Registry of bound agents
_agent_registry: Dict[str, "AgentBinding"] = {}


def AgentBinding(cal_agent_name: str):
    """
    Decorator to bind a Python class to a CAL agent.
    
    Example:
        @AgentBinding("Scanner::Nmap")
        class NmapAgent:
            @capability("port_scan")
            async def port_scan(self, target: str) -> List[Observation]:
                ...
    """
    def decorator(cls):
        binding = AgentBindingWrapper(cal_agent_name, cls)
        _agent_registry[cal_agent_name] = binding
        return cls
    return decorator


def capability(cal_capability_name: str):
    """
    Decorator to mark a method as a CAL capability.
    """
    def decorator(method):
        method._cal_capability = cal_capability_name
        return method
    return decorator


class AgentBindingWrapper:
    """Wraps a Python class for CAL integration."""
    
    def __init__(self, name: str, cls):
        self.name = name
        self.cls = cls
        self.instance = None
        self.capabilities = self._discover_capabilities()
    
    def _discover_capabilities(self) -> Dict[str, Callable]:
        capabilities = {}
        for name in dir(self.cls):
            method = getattr(self.cls, name)
            if hasattr(method, '_cal_capability'):
                capabilities[method._cal_capability] = name
        return capabilities
    
    def get_instance(self):
        if self.instance is None:
            self.instance = self.cls()
        return self.instance
    
    async def invoke(self, capability_name: str, **kwargs) -> Any:
        instance = self.get_instance()
        method_name = self.capabilities.get(capability_name)
        if not method_name:
            raise ValueError(f"Unknown capability: {capability_name}")
        method = getattr(instance, method_name)
        return await method(**kwargs)


def get_agent(name: str) -> AgentBindingWrapper:
    """Get a bound agent by its CAL name."""
    if name not in _agent_registry:
        raise ValueError(f"No agent bound for: {name}")
    return _agent_registry[name]
```

### 2. Scanner Agent Binding

**File: `core/cal/bindings/scanner.py`**

```python
"""
CAL bindings for Sentinel's scanner agents.
"""

from typing import List
from core.cal.bindings import AgentBinding, capability
from core.cal.types import Observation, ObservationType
from core.engine.scanner_engine import ScannerEngine


@AgentBinding("Scanner::Nmap")
class NmapAgentBinding:
    """Binds Scanner::Nmap CAL agent to ScannerEngine."""
    
    def __init__(self):
        self.engine = ScannerEngine()
    
    @capability("port_scan")
    async def port_scan(self, target: str) -> List[Observation]:
        """
        Maps to CAL's Scanner::Nmap.port_scan()
        
        Returns observations for each open port found.
        """
        # Run nmap through the existing engine
        results = await self.engine.run_tool("nmap", ["-sV", target])
        
        # Convert to CAL observations
        observations = []
        for port_info in self._parse_nmap_output(results.stdout):
            observations.append(Observation(
                type=ObservationType.PORT_OPEN,
                data={
                    "host": target,
                    "port": port_info["port"],
                    "protocol": port_info["protocol"],
                    "service": port_info.get("service"),
                    "version": port_info.get("version")
                },
                observed_by="Scanner::Nmap"
            ))
        
        return observations
    
    @capability("service_detect")
    async def service_detect(self, target: str, port: int) -> List[Observation]:
        """Detailed service detection on a specific port."""
        results = await self.engine.run_tool("nmap", ["-sV", "-p", str(port), target])
        # ... parse and return observations
        pass
    
    def _parse_nmap_output(self, stdout: str) -> List[dict]:
        """Parse nmap output into structured port info."""
        # Reuse existing parsing logic from raw_classifier.py
        from core.toolkit.raw_classifier import parse_nmap_output
        return parse_nmap_output(stdout)


@AgentBinding("Scanner::Httpx")
class HttpxAgentBinding:
    """Binds Scanner::Httpx CAL agent to HTTP probing."""
    
    def __init__(self):
        self.engine = ScannerEngine()
    
    @capability("probe")
    async def probe(self, target: str) -> List[Observation]:
        """
        Maps to CAL's Scanner::Httpx.probe()
        
        Probes HTTP endpoints and returns observations.
        """
        results = await self.engine.run_tool("httpx", ["-u", target, "-json"])
        
        observations = []
        for response in self._parse_httpx_output(results.stdout):
            observations.append(Observation(
                type=ObservationType.HTTP_RESPONSE,
                data={
                    "url": response["url"],
                    "status": response["status_code"],
                    "headers": response.get("headers", {}),
                    "body_preview": response.get("body", "")[:1000],
                    "tech_stack": response.get("tech", [])
                },
                observed_by="Scanner::Httpx"
            ))
        
        return observations
    
    def _parse_httpx_output(self, stdout: str) -> List[dict]:
        import json
        results = []
        for line in stdout.strip().split('\n'):
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return results
```

### 3. LLM Reasoner Binding

**File: `core/cal/bindings/reasoner.py`**

```python
"""
CAL bindings for Sentinel's AI reasoning agents.
"""

from typing import List, Dict
from core.cal.bindings import AgentBinding, capability
from core.cal.types import Claim, Evidence, AnalysisResult
from core.ai.ai_engine import AIEngine
from core.cortex.synapse import Synapse


@AgentBinding("Reasoner::Sentinel")
class SentinelReasonerBinding:
    """Binds Reasoner::Sentinel CAL agent to AIEngine."""
    
    def __init__(self):
        self.ai = AIEngine.instance()
        self.synapse = Synapse.instance()
    
    @capability("analyze_sqli")
    async def analyze_sqli(
        self, 
        matches: List[dict], 
        context: dict
    ) -> AnalysisResult:
        """
        Analyze potential SQLi matches for true positives.
        
        Returns analysis with confidence boost/reduction recommendation.
        """
        # Build prompt for LLM
        prompt = self._build_sqli_analysis_prompt(matches, context)
        
        # Get LLM analysis
        response = self.ai.client.generate(
            prompt,
            system=self._get_sqli_system_prompt()
        )
        
        # Parse structured response
        return self._parse_sqli_analysis(response)
    
    @capability("review")
    async def review(self, claim: Claim) -> AnalysisResult:
        """
        General claim review capability.
        
        Analyzes a claim and returns confidence adjustment recommendation.
        """
        # Use Synapse for verification
        probability = self.synapse.verify_vulnerability(
            vulnerability_type=claim.type_name,
            context=self._build_claim_context(claim)
        )
        
        return AnalysisResult(
            likely_true_positive=probability > 0.5,
            confidence_boost=probability - 0.5 if probability > 0.5 else 0,
            confidence_reduction=0.5 - probability if probability < 0.5 else 0,
            reasoning=f"Synapse verification returned probability: {probability}"
        )
    
    @capability("correlate")
    async def correlate(self, claims: List[Claim]) -> List[dict]:
        """Correlate multiple claims to find attack paths."""
        # Use LLM to find connections between claims
        prompt = self._build_correlation_prompt(claims)
        response = self.ai.client.generate(prompt)
        return self._parse_correlation_response(response)
    
    @capability("explain")
    async def explain(self, claim: Claim) -> str:
        """Generate human-readable explanation of a claim."""
        prompt = f"""
        Generate a clear, professional explanation of this security finding.
        
        Claim Type: {claim.type_name}
        Target: {claim.target}
        Confidence: {claim.confidence}
        Status: {claim.status}
        
        Evidence:
        {self._format_evidence(claim.evidence)}
        
        History:
        {self._format_history(claim.history)}
        
        Explain:
        1. What was found
        2. How it was detected
        3. Why we believe it's valid
        4. What evidence supports this
        """
        
        return self.ai.client.generate(prompt)
    
    def _build_sqli_analysis_prompt(self, matches, context) -> str:
        # Build detailed analysis prompt
        return f"""
        Analyze these potential SQL injection indicators:
        
        Matches: {matches}
        HTTP Context: {context}
        
        Determine:
        1. Is this likely a true positive?
        2. What patterns indicate SQLi vs false positive?
        3. Confidence adjustment recommendation (-1.0 to 1.0)
        
        Return JSON: {{"likely_true_positive": bool, "confidence_adjustment": float, "reasoning": str}}
        """
    
    def _get_sqli_system_prompt(self) -> str:
        return """You are an expert SQL injection analyst. 
        Analyze patterns carefully, distinguishing true SQLi indicators from:
        - Normal error messages
        - Non-exploitable reflection
        - False positive patterns
        Return structured JSON analysis."""
```

### 4. Belief State Integration

**File: `core/cal/runtime/belief_state.py`**

```python
"""
CAL Belief State - integrates with Sentinel's findings_store
"""

import threading
from typing import List, Optional, Dict
from datetime import datetime
from uuid import uuid4

from core.data.findings_store import findings_store
from core.cortex.memory import KnowledgeGraph, NodeType, EdgeType
from core.cal.types import Claim, ClaimStatus, ClaimEvent


class BeliefState:
    """
    Manages the current set of claims (beliefs) in a CAL mission.
    
    Synchronizes with:
    - findings_store (for UI/persistence)
    - KnowledgeGraph (for relationship queries)
    """
    
    def __init__(self):
        self._claims: Dict[str, Claim] = {}
        self._lock = threading.RLock()
        self._graph = KnowledgeGraph.instance()
    
    def add_claim(self, claim: Claim) -> str:
        """Add a new claim to the belief state."""
        with self._lock:
            claim_id = str(uuid4())
            claim.id = claim_id
            claim.version = 1
            claim.created_at = datetime.utcnow()
            claim.history.append(ClaimEvent(
                action="asserted",
                agent=claim.asserted_by,
                before=None,
                after=claim.snapshot(),
                timestamp=datetime.utcnow()
            ))
            
            self._claims[claim_id] = claim
            
            # Sync to findings_store
            self._sync_to_findings_store(claim)
            
            # Sync to knowledge graph
            self._sync_to_graph(claim)
            
            return claim_id
    
    def update_claim(
        self, 
        claim_id: str, 
        agent: str,
        confidence_delta: float = 0,
        new_status: Optional[ClaimStatus] = None,
        new_evidence: Optional[List] = None,
        reason: str = ""
    ) -> Claim:
        """Update an existing claim."""
        with self._lock:
            if claim_id not in self._claims:
                raise ValueError(f"Unknown claim: {claim_id}")
            
            claim = self._claims[claim_id]
            before = claim.snapshot()
            
            # Apply updates
            if confidence_delta != 0:
                claim.confidence = max(0.0, min(1.0, claim.confidence + confidence_delta))
            
            if new_status:
                claim.status = new_status
            
            if new_evidence:
                claim.evidence.extend(new_evidence)
            
            claim.version += 1
            claim.updated_at = datetime.utcnow()
            
            # Record history
            action = self._infer_action(confidence_delta, new_status)
            claim.history.append(ClaimEvent(
                action=action,
                agent=agent,
                before=before,
                after=claim.snapshot(),
                reason=reason,
                timestamp=datetime.utcnow()
            ))
            
            # Sync
            self._sync_to_findings_store(claim)
            self._sync_to_graph(claim)
            
            return claim
    
    def query(
        self, 
        claim_type: Optional[str] = None,
        status: Optional[ClaimStatus] = None,
        min_confidence: Optional[float] = None,
        target: Optional[str] = None
    ) -> List[Claim]:
        """Query claims matching criteria."""
        with self._lock:
            results = list(self._claims.values())
            
            if claim_type:
                results = [c for c in results if c.type_name == claim_type]
            
            if status:
                results = [c for c in results if c.status == status]
            
            if min_confidence is not None:
                results = [c for c in results if c.confidence >= min_confidence]
            
            if target:
                results = [c for c in results if c.target == target]
            
            return results
    
    def get(self, claim_id: str) -> Optional[Claim]:
        """Get a specific claim by ID."""
        return self._claims.get(claim_id)
    
    def _sync_to_findings_store(self, claim: Claim):
        """Sync claim to Sentinel's findings_store."""
        finding = {
            "id": claim.id,
            "type": claim.type_name,
            "severity": claim.severity.value if claim.severity else "MEDIUM",
            "value": str(claim.target),
            "confidence": claim.confidence,
            "status": claim.status.value,
            "tool": claim.asserted_by,
            "proof": str(claim.evidence),
            "cal_managed": True  # Flag for CAL-managed findings
        }
        
        # Check if exists and update, or add new
        existing = next(
            (f for f in findings_store.get_all() if f.get("id") == claim.id), 
            None
        )
        if existing:
            # Update in place (findings_store would need this method)
            pass
        else:
            findings_store.add_finding(finding)
    
    def _sync_to_graph(self, claim: Claim):
        """Sync claim to KnowledgeGraph."""
        # Add claim as a FINDING node
        self._graph.add_node(
            node_id=claim.id,
            type=NodeType.FINDING,
            attributes={
                "claim_type": claim.type_name,
                "confidence": claim.confidence,
                "status": claim.status.value,
                "severity": claim.severity.value if claim.severity else None
            }
        )
        
        # Link to target
        if claim.target:
            self._graph.add_edge(
                source_id=str(claim.target),
                target_id=claim.id,
                type=EdgeType.EXPOSES
            )
    
    def _infer_action(self, confidence_delta: float, new_status: Optional[ClaimStatus]) -> str:
        """Infer the action type from the update."""
        if new_status == ClaimStatus.VALIDATED:
            return "validated"
        elif new_status == ClaimStatus.INVALIDATED:
            return "invalidated"
        elif new_status == ClaimStatus.CONFIRMED:
            return "confirmed"
        elif confidence_delta > 0:
            return "strengthened"
        elif confidence_delta < 0:
            return "weakened"
        else:
            return "updated"
```

### 5. API Integration

**File: `core/api.py` (additions)**

```python
# Add to existing core/api.py

from core.cal.runtime import CALRuntime
from core.cal.parser import parse_cal_source

# CAL Runtime instance
_cal_runtime: Optional[CALRuntime] = None

def get_cal_runtime() -> CALRuntime:
    global _cal_runtime
    if _cal_runtime is None:
        _cal_runtime = CALRuntime()
    return _cal_runtime


# New API endpoints for CAL

async def cal_load_mission(source: str) -> dict:
    """
    Load a CAL mission from source code.
    
    Args:
        source: CAL source code string
    
    Returns:
        {"mission_id": str, "agents": [...], "rules": [...]}
    """
    runtime = get_cal_runtime()
    ast = parse_cal_source(source)
    mission_id = runtime.load_mission(ast)
    
    return {
        "mission_id": mission_id,
        "agents": [a.name for a in ast.agents],
        "rules": [r.name for r in ast.rules],
        "phases": [p.name for p in ast.mission.phases]
    }


async def cal_run_mission(
    mission_id: str, 
    target: str, 
    scope: dict,
    mode: str = "execution"
) -> AsyncGenerator[dict, None]:
    """
    Run a loaded CAL mission.
    
    Yields status updates as the mission progresses.
    """
    runtime = get_cal_runtime()
    
    async for event in runtime.run_mission(mission_id, target, scope, mode):
        yield {
            "type": event.type,
            "phase": event.phase,
            "claims": [c.to_dict() for c in event.new_claims],
            "updates": [u.to_dict() for u in event.claim_updates],
            "timestamp": event.timestamp.isoformat()
        }


async def cal_get_claims(
    mission_id: Optional[str] = None,
    claim_type: Optional[str] = None,
    min_confidence: Optional[float] = None,
    status: Optional[str] = None
) -> List[dict]:
    """
    Query claims from the belief state.
    """
    runtime = get_cal_runtime()
    claims = runtime.belief_state.query(
        claim_type=claim_type,
        min_confidence=min_confidence,
        status=ClaimStatus[status] if status else None
    )
    
    return [c.to_dict() for c in claims]


async def cal_explain_claim(claim_id: str) -> dict:
    """
    Get full explanation of a claim including evidence lineage.
    """
    runtime = get_cal_runtime()
    claim = runtime.belief_state.get(claim_id)
    
    if not claim:
        return {"error": "Claim not found"}
    
    # Get LLM explanation
    explanation = await runtime.invoke_agent(
        "Reasoner::Sentinel",
        "explain",
        claim=claim
    )
    
    return {
        "claim_id": claim_id,
        "type": claim.type_name,
        "confidence": claim.confidence,
        "status": claim.status.value,
        "evidence": [e.to_dict() for e in claim.evidence],
        "history": [h.to_dict() for h in claim.history],
        "explanation": explanation
    }


async def cal_get_audit_log(
    claim_id: Optional[str] = None,
    agent: Optional[str] = None,
    since: Optional[str] = None
) -> List[dict]:
    """
    Query the audit log.
    """
    runtime = get_cal_runtime()
    entries = runtime.audit_log.query(
        claim_id=claim_id,
        agent=agent,
        since=datetime.fromisoformat(since) if since else None
    )
    
    return [e.to_dict() for e in entries]
```

---

## Migration Strategy

### Phase 1: Parallel Operation (Weeks 1-4)

CAL runs alongside existing orchestration:

```python
# In scan_orchestrator.py

class ScanOrchestrator:
    def __init__(self, use_cal: bool = False):
        self.use_cal = use_cal
        if use_cal:
            self.cal_runtime = CALRuntime()
    
    async def run(self, target: str, modules=None):
        if self.use_cal and self._has_cal_mission(modules):
            # Use CAL for orchestration
            return await self._run_cal_mission(target, modules)
        else:
            # Use existing Python orchestration
            return await self._run_legacy(target, modules)
```

### Phase 2: Gradual Rule Migration (Weeks 5-8)

Convert individual orchestration logic to CAL rules:

```python
# Before (Python)
def _handle_autonomous_actions(self, payload):
    next_steps = payload.get("next_steps", [])
    for step in next_steps:
        status = self.dispatcher.request_action(step, self.current_target)
        if status == "PENDING":
            self.log(f"Action paused: {step.get('tool')}")

# After (CAL rule)
"""
rule Handle_AI_Recommendations {
    when Reasoner::Sentinel suggests next_step(tool, args, reason) {
        if tool in safe_tools {
            Scanner may execute(tool, args)
        } else {
            emit authorization_request(tool, args, reason)
            await human_decision
        }
    }
}
"""
```

### Phase 3: Full CAL Operation (Weeks 9-12)

Orchestrator becomes a thin wrapper:

```python
class ScanOrchestrator:
    """Now primarily a CAL executor."""
    
    def __init__(self):
        self.cal_runtime = CALRuntime()
        self._load_default_rules()
    
    async def run(self, target: str, mission: str = "Standard"):
        async for event in self.cal_runtime.run_mission(
            mission_name=mission,
            target=target,
            scope=self._get_scope()
        ):
            yield self._format_event(event)
```

---

## UI Integration

### Claims View Component

The SwiftUI frontend can display CAL claims:

```swift
// In ui/Views/ClaimsView.swift

struct ClaimsView: View {
    @StateObject var viewModel = ClaimsViewModel()
    
    var body: some View {
        List(viewModel.claims) { claim in
            ClaimRow(claim: claim)
        }
        .task {
            await viewModel.loadClaims()
        }
    }
}

struct ClaimRow: View {
    let claim: CALClaim
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                SeverityBadge(severity: claim.severity)
                Text(claim.typeName)
                    .font(.headline)
                Spacer()
                ConfidenceIndicator(value: claim.confidence)
            }
            
            Text(claim.target)
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            StatusBadge(status: claim.status)
        }
        .contextMenu {
            Button("View Evidence") {
                // Show evidence lineage
            }
            Button("Explain") {
                // Get LLM explanation
            }
        }
    }
}
```

### Claim Timeline View

```swift
// Timeline showing claim evolution

struct ClaimTimelineView: View {
    let claim: CALClaim
    
    var body: some View {
        ScrollView {
            ForEach(claim.history) { event in
                TimelineEventRow(event: event)
            }
        }
    }
}

struct TimelineEventRow: View {
    let event: ClaimEvent
    
    var body: some View {
        HStack {
            // Timestamp
            Text(event.timestamp, style: .time)
                .font(.caption)
                .frame(width: 60)
            
            // Event indicator
            Circle()
                .fill(colorForAction(event.action))
                .frame(width: 12, height: 12)
            
            // Event details
            VStack(alignment: .leading) {
                Text("\(event.agent) \(event.action)")
                    .font(.subheadline)
                
                if let reason = event.reason {
                    Text(reason)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                if event.confidenceBefore != event.confidenceAfter {
                    HStack {
                        Text("\(event.confidenceBefore, specifier: "%.2f")")
                        Image(systemName: "arrow.right")
                        Text("\(event.confidenceAfter, specifier: "%.2f")")
                    }
                    .font(.caption)
                }
            }
        }
    }
}
```

---

## Testing CAL Integration

### Unit Tests

```python
# tests/cal/test_belief_state.py

import pytest
from core.cal.runtime.belief_state import BeliefState
from core.cal.types import Claim, ClaimStatus, Severity

@pytest.fixture
def belief_state():
    return BeliefState()

def test_add_claim(belief_state):
    claim = Claim(
        type_name="SQLInjection",
        target="/login",
        confidence=0.35,
        asserted_by="Detector::Regex"
    )
    
    claim_id = belief_state.add_claim(claim)
    
    assert claim_id is not None
    assert belief_state.get(claim_id).confidence == 0.35

def test_strengthen_claim(belief_state):
    claim = Claim(
        type_name="SQLInjection",
        target="/login",
        confidence=0.35,
        asserted_by="Detector::Regex"
    )
    claim_id = belief_state.add_claim(claim)
    
    belief_state.update_claim(
        claim_id,
        agent="Reasoner::Sentinel",
        confidence_delta=0.25,
        reason="LLM analysis indicates true positive"
    )
    
    updated = belief_state.get(claim_id)
    assert updated.confidence == 0.60
    assert len(updated.history) == 2
    assert updated.history[-1].action == "strengthened"

def test_validate_claim(belief_state):
    claim = Claim(
        type_name="SQLInjection",
        target="/login",
        confidence=0.75,
        asserted_by="Detector::Regex"
    )
    claim_id = belief_state.add_claim(claim)
    
    belief_state.update_claim(
        claim_id,
        agent="Validator::SQLMap",
        new_status=ClaimStatus.VALIDATED,
        confidence_delta=0.2,
        new_evidence=[{"type": "exploit_success", "payload": "..."}]
    )
    
    updated = belief_state.get(claim_id)
    assert updated.status == ClaimStatus.VALIDATED
    assert updated.confidence == 0.95
    assert len(updated.evidence) == 1
```

### Integration Tests

```python
# tests/cal/test_integration.py

import pytest
from core.cal.runtime import CALRuntime
from core.cal.parser import parse_cal_source

CAL_TEST_MISSION = """
agent Detector::Test {
    role: pattern_detector
    authority: [assert_hypothesis]
    trust: 0.5
}

claim_type TestClaim {
    target: String
    severity_range: [LOW, HIGH]
    requires_validation: false
}

mission TestMission(target: String) {
    phase Detect {
        Detector::Test may assert claim TestClaim {
            target: target,
            confidence: 0.5
        }
    }
}
"""

@pytest.fixture
async def runtime():
    runtime = CALRuntime()
    ast = parse_cal_source(CAL_TEST_MISSION)
    runtime.load_mission(ast)
    return runtime

async def test_mission_execution(runtime):
    events = []
    async for event in runtime.run_mission("TestMission", target="example.com"):
        events.append(event)
    
    assert any(e.type == "claim_asserted" for e in events)
    
    claims = runtime.belief_state.query(claim_type="TestClaim")
    assert len(claims) == 1
    assert claims[0].confidence == 0.5
```

---

## Summary

CAL integrates with Sentinel through:

1. **Agent Bindings**: Python decorators that map CAL agents to existing components
2. **Belief State**: Central claim management that syncs to findings_store and KnowledgeGraph  
3. **API Extensions**: New endpoints for CAL mission control and claim queries
4. **UI Integration**: SwiftUI views for claim visualization and explanation
5. **Gradual Migration**: Parallel operation allowing incremental adoption

The integration preserves all existing functionality while enabling the new epistemic model of claims, confidence, and evidence lineage.
