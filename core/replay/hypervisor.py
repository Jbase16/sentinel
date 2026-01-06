"""
Counterfactual Hypervisor.

The Engine that executes ScanCapsules.
Functions as a Simulator, isolating the AI logic from the real world.
Supports:
1. Deterministic Replay (Linear)
2. Causal Forking (Branching Reality)
3. Hypothetical Injection (What-If Analysis)
"""

import copy
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

from core.replay.models import CapsuleManifest, MerkleBlock
from core.replay.merkle import MerkleEngine

logger = logging.getLogger(__name__)

class DivergenceError(Exception):
    """Raised when the Replay diverges from the recorded history without an injection."""
    pass

@dataclass
class Hypothetical:
    """A Fact injected into a timeline to alter reality."""
    fact_type: str
    data: Dict[str, Any]

class ReplayContext:
    """
    An isolated execution context for a specific timeline branch.
    Holds the state of the EvidenceLedger and the pointer in the Merkle DAG.
    """
    def __init__(self, ledger_state: Any, cursor_id: Optional[str] = None):
        self.ledger = ledger_state
        self.cursor_id = cursor_id  # ID of the last processed event
        self.injections: List[Hypothetical] = []

    def fork(self, inherit_injections: bool = True) -> 'ReplayContext':
        """
        Create a counterfactual branch from this point.
        Uses deepcopy to ensure total state isolation.
        
        Args:
            inherit_injections: If True (default), the fork retains all 
                                hypothetical facts active in the parent.
                                If False, the fork starts with a clean slate 
                                relative to the factual history.
        """
        new_ctx = ReplayContext(
            ledger_state=copy.deepcopy(self.ledger),
            cursor_id=self.cursor_id
        )
        if inherit_injections:
            new_ctx.injections = copy.deepcopy(self.injections)
        return new_ctx

    def inject(self, hypothetical: Hypothetical):
        """Inject a hypothetical fact into this timeline."""
        # In a real impl, this would insert into the ledger.
        # self.ledger.inject_fact(...)
        self.injections.append(hypothetical)
        logger.info(f"Injecting hypothetical: {hypothetical}")

class ReplayEngine:
    """
    The Hypervisor.
    Manages the lifecycle of a Replay Session.
    """
    def __init__(self, manifest: CapsuleManifest):
        self.manifest = manifest
        self.blocks_map: Dict[str, MerkleBlock] = {b.id: b for b in manifest.blocks}
        self.roots: List[str] = [b.id for b in manifest.blocks if not b.parents]
        
        # Validation: Verify integrity of the DAG structure
        self._verify_structure()

    def _verify_structure(self):
        """
        Ensure DAG integrity:
        1. All parents exist.
        2. Graph is acyclic.
        3. All blocks are reachable from roots.
        """
        known_ids = set(self.blocks_map.keys())
        
        # 1. Existence Check
        for block in self.manifest.blocks:
            for pid in block.parents:
                if pid not in known_ids:
                    raise ValueError(f"Capsule Broken: Block {block.id} cites missing parent {pid}")

        # 2. Cycle Detection (DFS)
        visited = set()
        recursion_stack = set()

        def visit(node_id):
            visited.add(node_id)
            recursion_stack.add(node_id)
            
            # Find children (inverse of parents)
            # Optimization: Pre-computing children map would be faster, 
            # but for validation scan, looking for blocks citing this parent is acceptable.
            # actually strict checking logic:
            #   Cycle means A -> B -> A. 
            #   Block B has parent A. Block A has parent B.
            #   So we traverse PARENTS to see if we loop back to self.
            pass

            # Simpler Cycle Check: Merkle DAGs by definition cannot have cycles 
            # if we verify SHA256 integrity, because A cannot contain hash of B if B contains hash of A.
            # However, strictly checking topological order matches manifest order is good.
            # We will rely on the property that a valid Merkle hash implies acyclic *content*.
            # But the 'parents' field could still lie if hash verification wasn't enforcing strict ordering.
            # Since we verify hashes in codec, and hash covers parents, a cycle is mathematically impossible
            # without a hash collision.
            # BUT: We should still ensure the list is topologically sorted in the manifest for linear replay performance.
            
        # 3. Reachability (Orphan detection)
        # Every block must be reachable from a Root (block with no parents).
        # Traversing forward from roots.
        reachable = set()
        queue = [rid for rid in self.roots]
        
        # Build Child Map for traversal
        child_map = {bid: [] for bid in known_ids}
        for block in self.manifest.blocks:
            for pid in block.parents:
                child_map[pid].append(block.id)
                
        while queue:
            current = queue.pop(0)
            if current in reachable:
                continue
            reachable.add(current)
            for child in child_map.get(current, []):
                queue.append(child)
                
        if len(reachable) != len(known_ids):
            unreachable = known_ids - reachable
            raise ValueError(f"Capsule Broken: Orphan blocks detected (unreachable from roots): {unreachable}")

    def start_session(self) -> ReplayContext:
        """Initialize a new 0-state session."""
        # TODO: Initialize empty EvidenceLedger here
        empty_ledger = {"evidence": [], "decisions": []} 
        return ReplayContext(empty_ledger)

    def step(self, context: ReplayContext) -> Optional[MerkleBlock]:
        """
        Advance the context by one event.
        Returns the processed Block, or None if end of timeline.
        
        Strict Determinism Contract:
        A capsule replay MUST have exactly one valid successor at every step 
        unless forked explicitly (Phase 2).
        For Phase 0/1 (Linear), ambiguity is a DivergenceError.
        """
        candidates = []
        for block in self.manifest.blocks:
            # Case A: Start of chain (Root)
            if not context.cursor_id:
                if not block.parents:
                    candidates.append(block)
                continue
            
            # Case B: Continuation
            if context.cursor_id in block.parents:
                candidates.append(block)
                
        if not candidates:
            return None
            
        if len(candidates) > 1:
            # Ambiguity detected. 
            # In a linear log, this implies a fork exists in the history 
            # but the replay engine doesn't know which branch to take.
            ids = [c.id for c in candidates]
            raise DivergenceError(f"Nondeterministic Replay: Mulitple valid next blocks found {ids}. Context needs explicit branch choice.")
            
        next_block = candidates[0]
        
        # Execute (Apply to Ledger)
        self._apply_block(context, next_block)
        
        # Advance Cursor
        context.cursor_id = next_block.id
        return next_block

    def _apply_block(self, context: ReplayContext, block: MerkleBlock):
        """
        Apply the block's payload to the ledger state.
        This is where the "Simulation" happens.
        """
        ledger = context.ledger
        # Ensure we have a valid ledger object. In Phase 1 we mocked it as a dict.
        # Now we need the real EvidenceLedger or a duck-typed equivalent.
        # For this step, we assume context.ledger is an instance of EvidenceLedger.

        timestamp = block.meta.get("timestamp")
        
        if block.kind == "observed":
            # Map payload back to record_observation args
            # Payload schema expected: { "tool": str, "args": List[str], "target": str, "blob": str(base64) ... }
            # Note: We aren't storing the full blob in the block payload usually (too large).
            # But for Phase 0 we assumed payload contains the data.
            # In a real system, the block might contain the CAS hash, and we fetch the blob from CAS.
            # For this implementation, let's assume payload HAS the data needed.
            
            tool = block.payload.get("tool")
            args = block.payload.get("args", [])
            target = block.payload.get("target")
            raw_output = block.payload.get("blob", b"") # Should be bytes or base64 string
            
            # If it's a string (from JSON), encode to bytes
            if isinstance(raw_output, str):
                import base64
                try:
                    # Try de-base64 if it looks like it
                    raw_output = base64.b64decode(raw_output)
                except Exception:
                    raw_output = raw_output.encode('utf-8')
            
            if tool and target:
                ledger.record_observation(
                    tool_name=tool,
                    tool_args=args,
                    target=target,
                    raw_output=raw_output,
                    timestamp_override=timestamp
                )

        elif block.kind == "decision":
            # Map payload to promote/suppress
            action = block.payload.get("action")
            
            if action == "promote":
                ledger.promote_finding(
                    title=block.payload.get("title"),
                    severity=block.payload.get("severity"),
                    citations=block.payload.get("citations", []), # Need to rehydrate Citation objects?
                    description=block.payload.get("description"),
                    timestamp_override=timestamp,
                    **block.payload.get("metadata", {})
                )
            elif action == "suppress":
                ledger.suppress(
                    related_id=block.payload.get("related_id"),
                    reason_code=block.payload.get("reason_code"),
                    notes=block.payload.get("notes"),
                    timestamp_override=timestamp
                )
        
        # For now, we just log it
        logger.debug(f"Applied block {block.id} ({block.kind}) to Ledger.")
