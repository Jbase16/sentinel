import networkx as nx
import hashlib
import json
import time
import logging
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ProcessPoolExecutor, TimeoutError
from core.cortex.models import TopologyRequest, TopologyResponse, PathResult, AnalysisCaps

# Configure module logger
logger = logging.getLogger(__name__)

def _serialize_graph_input(graph_data: Dict[str, Any]) -> str:
    """
    Creates a stable string representation of the graph for hashing.
    Sorts nodes and edges to ensure determinism.
    Include semantic attributes (type, criticality) in the hash.
    """
    # Normalized structure: {nodes: [{id, type, ...}], edges: [{source, target, ...}]}
    nodes = sorted(graph_data.get("nodes", []), key=lambda x: x.get("id", ""))
    edges = sorted(graph_data.get("edges", []), key=lambda x: (x.get("source", ""), x.get("target", "")))
    
    # We strip volatile fields (e.g., visual position) if necessary, 
    # but here we assume the input is already the semantic snapshot.
    payload = {
        "nodes": nodes,
        "edges": edges,
        "version": "1.0" # Schema version
    }
    return json.dumps(payload, sort_keys=True)

def _calculate_fingerprint(serialized_graph: str) -> str:
    return hashlib.sha256(serialized_graph.encode('utf-8')).hexdigest()

def _worker_analysis(graph_data: Dict[str, Any], entry_nodes: List[str], critical_assets: List[str], caps: Dict[str, Any]) -> Dict[str, Any]:
    """
    Isolated worker function. Reconstructs graph and runs algorithms.
    Returns a dict compatible with TopologyResponse structure.
    """
    try:
        # 1. Reconstruction
        G = nx.DiGraph()
        for n in graph_data.get("nodes", []):
            G.add_node(n["id"], **n)
        for e in graph_data.get("edges", []):
            G.add_edge(e["source"], e["target"], **e)
            
        node_count = G.number_of_nodes()
        limits_applied = {}
        
        # 2. Centrality
        # Use approx if > threshold
        threshold = caps.get("approximation_threshold", 500)
        if node_count > threshold:
            # k-samples approx
            k = min(int(node_count * 0.1) + 20, node_count) # 10% + 20 samples
            centrality = nx.betweenness_centrality(G, k=k, weight=None) # weight=None for topological centrality
            limits_applied["centrality_approx"] = True
        else:
            centrality = nx.betweenness_centrality(G, weight=None)
            limits_applied["centrality_approx"] = False

        # 3. Pathfinding
        critical_paths = []
        max_paths = caps.get("max_paths", 5)
        
        for source in entry_nodes:
            if source not in G: continue
            for target in critical_assets:
                if target not in G: continue
                if source == target: continue
                
                try:
                    # k-shortest paths
                    paths_gen = nx.shortest_simple_paths(G, source, target, weight=None) 
                    # We iterate manually to respect cap
                    count = 0
                    for path in paths_gen:
                        if count >= max_paths:
                            limits_applied["path_capped"] = True
                            break
                        
                        # Score: (length, accumulated_risk, bottleneck_sum)
                        # Placeholder risk/bottleneck logic for now (1.0)
                        score = (float(len(path)), 1.0, 1.0) 
                        
                        critical_paths.append({
                            "path": path,
                            "score": score,
                            "metadata": {"type": "attack_path"}
                        })
                        count += 1
                        
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        # 4. Communities
        # Label Propagation is fast O(m+n)
        communities_gen = nx.community.label_propagation_communities(G.to_undirected())
        community_map = {}
        for idx, comm in enumerate(communities_gen):
            for node in comm:
                community_map[str(node)] = idx

        return {
            "centrality": centrality,
            "communities": community_map,
            "critical_paths": critical_paths,
            "limits_applied": limits_applied
        }
        
    except Exception as e:
        # In worker, we must return exception info or re-raise
        # Returning dict with error to manage it gracefully in main process
        return {"error": str(e)}

class GraphAnalyzer:
    def __init__(self, max_workers: int = 2):
        self.executor = ProcessPoolExecutor(max_workers=max_workers)
        # Simple in-memory cache: fingerprint -> TopologyResponse
        # In prod this should be Redis or similar if scaling out.
        self._cache: Dict[str, TopologyResponse] = {} 

    async def analyze(self, request: TopologyRequest) -> TopologyResponse:
        """
        Main entry point. Asynchronous logic that offloads to process pool.
        Note: Centrality is computed on directed topology; results reflect flow-through importance, not degree.
        """
        # 1. Fingerprint
        serialized = _serialize_graph_input(request.graph_data)
        fingerprint = _calculate_fingerprint(serialized)
        
        # 2. Cache Check (Corrected to use composite key only)
        # We need to hash params too because entry_nodes/caps affect output.
        param_str = f"{sorted(request.entry_nodes)}-{sorted(request.critical_assets)}-{request.caps.model_dump_json()}"
        composite_key = f"{fingerprint}::{hashlib.md5(param_str.encode()).hexdigest()}"
        
        if composite_key in self._cache:
             logger.info(f"GraphAnalyzer cache hit for {composite_key[:16]}")
             return self._cache[composite_key]

        # 3. Enqueue
        logger.info(f"Starting graph analysis for {fingerprint[:8]}...")
        loop = asyncio.get_running_loop()
        start_time = time.time()
        
        try:
            # Run in executor with timeout enforcement
            result_dict = await asyncio.wait_for(
                loop.run_in_executor(
                    self.executor,
                    _worker_analysis,
                    request.graph_data,
                    request.entry_nodes,
                    request.critical_assets,
                    request.caps.model_dump()
                ),
                timeout=request.caps.timeout_seconds
            )
            
            if "error" in result_dict:
                raise RuntimeError(f"Analysis worker failed: {result_dict['error']}")
                
            # 4. Response Construction
            response = TopologyResponse(
                graph_hash=fingerprint,
                computed_at=time.time(),
                centrality=result_dict["centrality"],
                communities=result_dict["communities"],
                critical_paths=[PathResult(**p) for p in result_dict["critical_paths"]],
                limits_applied=result_dict["limits_applied"]
            )
            
            # 5. Cache
            self._cache[composite_key] = response
            logger.info(f"Analysis completed in {time.time() - start_time:.4f}s")
            return response
            
        except asyncio.TimeoutError:
            logger.warning(f"Analysis timed out for {fingerprint[:8]}")
            # We could return a partial response here if we improved the worker to support partials,
            # but for now, we raise or could return a "Timeout" response if the model supported it.
            # Given current constraints, raising is safer than lying.
            # Alternatively, we could catch this in the Router and return 504 / 408.
            raise
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise
            
        except TimeoutError:
            logger.error("Analysis timed out")
            raise
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise

import asyncio
