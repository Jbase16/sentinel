"""
core/data/constants.py
Shared constants for the Attacker Capability Model.

Single source of truth for values used across multiple modules.
If you change a value here, it propagates to all consumers.

Consumers:
  - core/toolkit/vuln_rules.py (issue-level scoring)
  - core/data/risk.py (asset-level scoring)
  - core/cortex/causal_graph.py (enablement classification)
  - core/cortex/nexus_context.py (hypothesis confidence)
"""

from typing import Dict, List


# ---------------------------------------------------------------------------
# Confirmation Multipliers
# ---------------------------------------------------------------------------
# Applied at two independent levels:
#   1. ISSUE-LEVEL in VulnRule.apply() — which issue outranks which
#   2. ASSET-LEVEL in RiskEngine.recalculate() — which target needs attention first
# Do not remove one thinking the other covers it.
CONFIRMATION_MULTIPLIERS: Dict[str, float] = {
    "confirmed": 1.0,
    "probable": 0.7,
    "hypothesized": 0.4,
}


# ---------------------------------------------------------------------------
# Credential / Secret Indicators
# ---------------------------------------------------------------------------
# Substrings that, when found in evidence content, indicate credential or
# secret material. Used for:
#   - Content-aware escalation in vuln_rules._match_backup_rule()
#   - Enablement classification in causal_graph._classify_enablement()
#
# All matching is done against .lower() content — entries here must be lowercase.
CREDENTIAL_INDICATORS: List[str] = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "aws_access_key", "aws_secret", "private_key", "authorization",
    "database_url", "db_password", "smtp_password", "redis_url",
    "mongodb_uri", "connection_string", "client_secret",
    "jdbc:", "mysql://", "postgres://", "mongodb+srv://",
]


# ---------------------------------------------------------------------------
# Information Hypothesis Confidence
# ---------------------------------------------------------------------------
# Maps information finding types to hypothesis confidence for NexusContext Rule 3.
# Higher confidence = more certain that the finding enables follow-up exploitation.
INFORMATION_HYPOTHESIS_CONFIDENCE: Dict[str, float] = {
    "credential_exposure": 0.95,
    "source_code_secrets": 0.90,
    "internal_topology": 0.80,
    "backup_config": 0.70,
}
