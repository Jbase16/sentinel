# ============================================================================
# core/chat/__init__.py
# Chat Interface Package - Conversational Security Analysis
# ============================================================================
#
# PURPOSE:
# Provides a chat interface for interacting with the security analysis engine.
# Ask questions about findings, get explanations, and explore the knowledge graph
# through natural language.
#
# THE COMMAND DECK:
# Think of this like talking to an expert security analyst who has access to all
# your scan data. Instead of clicking through UIs, you can ask:
# - "What are the most critical findings for example.com?"
# - "Explain this SQL injection vulnerability"
# - "Show me the attack path to RCE"
#
# GRAPH-AWARE CHAT:
# The chat engine understands the knowledge graph (network of findings, assets,
# and relationships). It can traverse connections to answer complex questions.
#
# KEY MODULES:
# - **chat_engine.py**: Core conversational AI with graph awareness
#
# KEY CONCEPTS:
# - **Graph Awareness**: Chat understands relationships between findings
# - **Context Retention**: Remembers previous conversation turns
# - **Multi-Turn Dialogue**: Can answer follow-up questions
#
# ============================================================================

from .chat_engine import GraphAwareChat
