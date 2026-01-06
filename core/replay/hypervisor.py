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

    def fork(self) -> 'ReplayContext':
        """
        Create a counterfactual branch from this point.
        Uses deepcopy to ensure total state isolation.
        """
        new_ctx = ReplayContext(
            ledger_state=copy.deepcopy(self.ledger),
            cursor_id=self.cursor_id
        )
        # Injections propagate to children? Usually yes.
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
        """Ensure all parents exist and DAG is causal."""
        known_ids = set(self.blocks_map.keys())
        for block in self.manifest.blocks:
            for pid in block.parents:
                if pid not in known_ids:
                    raise ValueError(f"Capsule Broken: Block {block.id} cites missing parent {pid}")

    def start_session(self) -> ReplayContext:
        """Initialize a new 0-state session."""
        # TODO: Initialize empty EvidenceLedger here
        empty_ledger = {"evidence": [], "decisions": []} 
        return ReplayContext(empty_ledger)

    def step(self, context: ReplayContext) -> Optional[MerkleBlock]:
        """
        Advance the context by one event.
        Returns the processed Block, or None if end of timeline.
        """
        # Linear Traversal for now (Phase 0)
        # We find the first block whose parent is the current cursor
        
        # Optimization: We could build an adjacency list in __init__
        # But for MVP linear, iterating is fine.
        
        candidates = []
        for block in self.manifest.blocks:
            # If start of chain (no parents) and no cursor
            if not context.cursor_id and not block.parents:
                candidates.append(block)
                continue
            
            # If cursor is one of the parents
            if context.cursor_id and context.cursor_id in block.parents:
                candidates.append(block)
                
        if not candidates:
            return None
            
        # Determinism Rule: If multiple candidates (fork in DAG), 
        # we must follow the one specified by the manifest order 
        # or some other deterministic rule.
        # For a Linear Log, there should be exactly one candidate.
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
        if block.kind == "observed":
            # context.ledger.record_observation(block.payload)
            pass
        elif block.kind == "decision":
            # context.ledger.record_decision(block.payload)
            pass
        
        # For now, we just log it
        logger.debug(f"Applied block {block.id} ({block.kind})")
