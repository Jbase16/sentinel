# ============================================================================
# core/cortex/__init__.py
# Cortex Package - The Neuro-Symbolic Brain
# ============================================================================
#
# PURPOSE:
# The "brain" of Sentinel - combines neural (AI) and symbolic (graph/rules) reasoning
# to understand security findings at a deeper level than either approach alone.
#
# NEURO-SYMBOLIC REASONING:
# - **Neural**: AI pattern recognition (finds unexpected vulnerabilities)
# - **Symbolic**: Graph reasoning (maps relationships, attack paths)
# - **Combined**: AI discovers, graph connects, rules validate
#
# WHAT CORTEX DOES:
# - Builds a knowledge graph of assets, findings, and relationships
# - Maps findings to kill chain phases (recon → exploit → persistence)
# - Discovers attack paths (how to chain vulns for maximum impact)
# - Provides reasoning explanations (why this finding matters)
#
# KEY MODULES:
# - **memory.py**: Knowledge graph (network of nodes and edges)
# - **reasoning.py**: Attack path discovery and impact analysis
# - **events.py**: Real-time graph update events
# - **synapse.py**: Inter-module communication
# - **parser.py**: Tool output parsers
# - **scanner_bridge.py**: Integration with scanning engine
#
# KEY CONCEPTS:
# - **Knowledge Graph**: Network of connected information (assets → findings → impacts)
# - **Kill Chain**: Attack progression model (Lockheed Martin Cyber Kill Chain)
# - **Attack Paths**: Sequences of exploits leading to objectives
# - **Neuro-Symbolic AI**: Hybrid of neural networks + symbolic reasoning
#
# ============================================================================

from .memory import KnowledgeGraph, NodeType, EdgeType
