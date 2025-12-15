# ============================================================================
# core/toolkit/__init__.py
# Toolkit Package - Security Tool Integration Layer
# ============================================================================
#
# PURPOSE:
# Provides a unified interface for running security tools (nmap, httpx, nuclei, etc.)
# Abstracts away the differences between tools so the rest of the system doesn't
# need to know tool-specific details.
#
# THE TOOL REGISTRY:
# Think of this as a catalog of all available security tools with standardized
# interfaces. Each tool has:
# - Name and description
# - How to execute it (command-line arguments)
# - How to parse its output
# - What kind of findings it discovers
#
# WHAT THIS MODULE DOES:
# - **Registers** available security tools
# - **Executes** tools with proper arguments
# - **Parses** tool outputs into structured data
# - **Normalizes** findings into consistent format
# - **Classifies** raw output into vulnerability types
# - **Provides shims** for tools that need special handling
#
# KEY MODULES:
# - **tools.py**: Tool registry and execution interface
# - **tool_base.py**: Base class for tool wrappers
# - **tool_callbacks.py**: Event callbacks during tool execution
# - **raw_classifier.py**: Heuristic-based finding classification
# - **vuln_rules.py**: Vulnerability detection rules
# - **shims/**: Tool-specific adapters (nmap, httpx, subfinder, etc.)
#
# EXAMPLE TOOLS:
# - **nmap**: Port scanner (finds open ports and services)
# - **httpx**: HTTP prober (checks web server responses)
# - **subfinder**: Subdomain discovery (finds hidden subdomains)
# - **nuclei**: Vulnerability scanner (tests for known vulns)
# - **sqlmap**: SQL injection tester
# - **gobuster**: Directory/file brute-forcer
#
# KEY CONCEPTS:
# - **Tool Abstraction**: Unified interface despite different tool implementations
# - **Shims**: Adapters that translate between tool formats and our internal format
# - **Normalization**: Convert diverse outputs into consistent JSON structure
# - **Classification**: Categorize findings by vulnerability type
#
# ============================================================================
