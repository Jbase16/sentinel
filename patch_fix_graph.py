
import asyncio
import logging
from core.data.db import Database
from core.data.pressure_graph.manager import PressureGraphManager
from core.data.issues_store import issues_store

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def hydrate_graph():
    db = Database.instance()
    await db.init()
    
    # Target session with findings
    sid = "ab44b555-b394-45e8-ba10-fa339c5bdf8d"
    print(f"Hydrating Graph for Session: {sid}")

    # Fix timestamp format for correct sorting in API
    await db.execute(
        "UPDATE sessions SET start_time = datetime('now', '+1 minute') WHERE id = ?", 
        (sid,)
    )
    print("Updated session timestamp to be most recent.")
    
    # 2. Initialize Manager
    manager = PressureGraphManager(sid)
    await manager._load_state()  # Load whatever exists (probably nothing)
    
    # 3. Fetch Findings manually (referencing issues_store logic)
    # We can't easily use issues_store directly if it relies on "current session" context global
    # So we query DB directly.
    # 3. Fetch Findings manually
    # Schema: id, session_id, scan_sequence, tool, tool_version, type, severity, target, data, timestamp, confidence
    findings = await db.fetch_all(
        "SELECT id, type, severity, target, data, timestamp FROM findings WHERE session_id = ?", 
        (sid,)
    )
    print(f"Found {len(findings)} findings.")
    
    import json
    
    # 4. Convert to Nodes
    for f in findings:
        node_id = f[0]
        node_type = f[1]
        severity = f[2]
        target = f[3]
        data_json = f[4]
        timestamp = f[5]
        
        try:
            data = json.loads(data_json) if isinstance(data_json, str) else data_json
        except:
            data = {}
            
        f_dict = {
            "id": node_id,
            "type": node_type,
            "title": data.get("title", f"Finding {node_id}"),
            "severity": severity,
            "proof": data.get("proof", ""),
            "target": target,
            "cvss": data.get("cvss", {}),
            "created_at": timestamp
        }

        
        # Use Manager's logic to convert
        node = manager._issue_to_pressure_node(f_dict)
        manager.nodes[node.id] = node
        print(f" -> Added Node: {node.id} ({node.type})")
        
    # 5. Add Mock Killchain (Graph Structure)
    # If we have only nodes, they float. Let's link them to a central target node.
    target = "unknown_target"
    if findings:
        target = findings[0][3] # Use target from first finding as hub
        
    # Create Hub Node
    from core.data.pressure_graph.models import PressureNode, PressureEdge, EdgeType, PressureSource, RemediationState
    
    hub_node = PressureNode(
        id=target,
        type="asset",
        severity=10.0,
        exposure=1.0,
        exploitability=1.0,
        privilege_gain=1.0,
        asset_value=10.0,
        revision=1,
        pressure_source=PressureSource.ENGINE,
        remediation_state=RemediationState.NONE
    )
    manager.nodes[target] = hub_node
    
    # Link findings to Hub
    for f in findings:
        node_id = f[0]
        edge = PressureEdge(
            id=f"edge_{node_id}_to_{target}",
            source_id=node_id,
            target_id=target,
            type=EdgeType.ENABLES,
            transfer_factor=1.0,
            confidence=1.0
        )
        manager.edges[edge.id] = edge
        print(f" -> Linked {node_id} to {target}")

    # 6. Save Snapshot
    await manager.save_snapshot()
    print("Graph Snapshot Saved! ✅")

if __name__ == "__main__":
    asyncio.run(hydrate_graph())
