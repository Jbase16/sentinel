# ============================================================================
# core/analyze/__init__.py
# Analysis Package - Vulnerability Analysis and Classification
# ============================================================================
#
# PURPOSE:
# Provides advanced analysis capabilities for discovered vulnerabilities.
# Goes beyond simple detection to classify, correlate, and prioritize findings.
#
# WHAT THIS MODULE DOES:
# - Classifies vulnerabilities by type (XSS, SQLi, IDOR, etc.)
# - Correlates related findings (same vuln across multiple endpoints)
# - Severity scoring based on exploitability and impact
# - Attack chain construction (how findings can be chained together)
#
# KEY CONCEPTS:
# - **Classification**: Categorizing what type of vulnerability was found
# - **Correlation**: Finding patterns across multiple discoveries
# - **Severity Analysis**: Determining how serious a vulnerability is
# - **Attack Chains**: Mapping how vulnerabilities enable attack progression
#
# ============================================================================
