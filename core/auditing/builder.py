"""
Audit Builder
Stateless builder for SystemSelfAudit artifacts.
Aggregates data from immutable ledgers and graph snapshots.
"""

import time
from typing import Dict, List, Any
from core.contracts.audit import SystemSelfAudit, SubsystemStats
# Usage: builder.build(scan_id, ledger, graph_stats, tool_stats, policies)

class AuditBuilder:
    @staticmethod
    def build(
        scan_id: str,
        session_id: str,
        sequence_end: int,
        decision_ledger: List[Any], # List[DecisionPoint]
        graph_stats: Dict[str, int], # {nodes: x, edges: y}
        tool_stats: Dict[str, int], # {attempted: x, executed: y, failed: z}
        policy_stats: Dict[str, int] # {enforced: x, blocks: y}
    ) -> SystemSelfAudit:
        
        # 1. Strategos Stats
        decision_count = len(decision_ledger)
        assessments = sum(1 for d in decision_ledger if d.type.value == "assessment")
        suppressed = sum(len(d.suppressed or []) for d in decision_ledger)
        
        strategos_stats = SubsystemStats(
            exercised=decision_count > 0,
            counters={
                "decisions": decision_count,
                "assessments": assessments,
                "suppressed_actions": suppressed
            }
        )

        # 2. Graph Stats
        node_count = graph_stats.get("nodes", 0)
        edge_count = graph_stats.get("edges", 0)
        graph_subsystem = SubsystemStats(
            exercised=node_count > 0, # Assuming >0 means something was added, might start with 0
            counters={
                "nodes": node_count,
                "edges": edge_count
            }
        )
        
        # 3. Tool Stats
        tools_attempted = tool_stats.get("attempted", 0)
        tools_executed = tool_stats.get("executed", 0)
        tools_failed = tool_stats.get("failed", 0)
        tools_subsystem = SubsystemStats(
            exercised=tools_attempted > 0,
            counters={
                "attempted": tools_attempted,
                "executed": tools_executed,
                "failed": tools_failed
            }
        )

        # 4. Policy Stats
        policy_blocks = policy_stats.get("blocks", 0)
        policy_subsystem = SubsystemStats(
            exercised=policy_blocks > 0, # Or just check if engine was active? Blocks is a good proxy for "work"
            counters={
                "blocks": policy_blocks
            }
        )
        
        # Idle Detection
        subsystems = {
            "strategos": strategos_stats,
            "graph": graph_subsystem,
            "tools": tools_subsystem,
            "policies": policy_subsystem
        }
        
        idle = [name for name, stats in subsystems.items() if not stats.exercised]
        
        # Anomaly Detection (Simple heuristics)
        anomalies = []
        if decision_count > 0 and tools_executed == 0 and assessments > 5:
             # Strategos is thinking but not doing
             anomalies.append("high_decision_no_action_churn")
             
        if policy_blocks > (tools_attempted * 0.5) and tools_attempted > 0:
             anomalies.append("high_policy_block_rate")

        return SystemSelfAudit(
            scan_id=scan_id,
            completed_at=time.time(),
            event_sequence_end=sequence_end,
            source_epoch=session_id,
            subsystems=subsystems,
            idle_subsystems=idle,
            anomalies=anomalies,
            confidence=1.0 # Deterministic
        )
