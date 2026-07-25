# Layer 4 Hardening: Logic & Policy Integration
**Date:** 2025-12-16
**Status:** Completed

This document summarizes the changes made during the Layer 4 Hardening phase, which transformed the SentinelForge core from a script-runner into a policy-driven decision engine.

## Overview
The goal of Layer 4 was to formalize the "Brain" logic of the system. This involved three key initiatives:
1.  **Classifiers:** Standardizing how tool output is interpreted.
2.  **Rules:** Externalizing vulnerability detection logic to data (YAML).
3.  **Policies:** Implementing a final arbitration gatekeeper for strategic control.

---

## Phase 1: Classifier Documentation (Standardization)
**Objective:** Eliminate ambiguity in how findings are named and classified.

### key Changes
-   **Created Golden Record:** Established [`docs/classifiers.md`](classifiers.md) as the authoritative source for finding types and severity logic.
-   **Standardized Finding Types:** Unified disparate tool outputs (e.g., Gobuster, Feroxbuster, Dirsearch) to use consistent types like `Directory Enumeration` instead of variations like "Hidden Directory" or "Brute Forced Path".

### Files Modified
-   **[NEW]** `docs/classifiers.md`: Documentation of `RawFinding` schema and tool-specific classifiers.
-   **[MODIFIED]** `core/toolkit/raw_classifier.py`: Updated `_handle_gobuster`, `_handle_feroxbuster`, and `_handle_dirsearch` to align with the new standard.

---

## Phase 2: Vulnerability Rules (Externalization)
**Objective:** Move vulnerability detection logic out of hardcoded Python and into manageable configuration files.

### Key Changes
-   **Hybrid Rule Engine:** Upgraded the `vuln_rules` module to support loading rules from an external YAML file while maintaining backward compatibility with legacy Python-defined rules.
-   **Rule Overrides:** Implemented logic where YAML-defined rules take precedence over legacy hardcoded rules, allowing for easier updates.
-   **YAML Schema:** Defined a clean schema for rules including IDs, Matchers, Severity, and Remediation.

### Files Modified
-   **[NEW]** `core/cortex/rules.yaml`: Definitions for key rules like `OUTDATED_CMS`, `EXPOSED_ADMIN`, and `CLOUD_METADATA_LEAK`.
-   **[MODIFIED]** `core/toolkit/vuln_rules.py`:
    -   Added `load_rules_from_yaml()` function.
    -   Renamed `RULES` to `_LEGACY_RULES`.
    -   Implemented `_merge_rules()` to combine sources dynamically.

---

## Phase 3: Policy Arbitration (Governance)
**Objective:** Give the system a "Conscience" or "Safety Valve" to veto dangerous actions regardless of intent.

### Key Changes
-   **Arbitration Engine:** Integrated the `ArbitrationEngine` into the core `Strategos` loop.
-   **Concrete Policies:**
    -   **`ScopePolicy`**: Ensures actions target only authorized domains (placeholder logic implemented).
    -   **`RiskPolicy`**: Prevents high-risk tools from running in passive/low-risk modes.
-   **Decision Pipeline:** Injected a review step in `_select_tools`. If the Arbitrator vetoes a tool, it is removed from the candidate list with a structured `POLICY_VETO` reason.

### Files Modified
-   **[MODIFIED]** `core/cortex/policy.py`: Added `ScopePolicy` and `RiskPolicy` classes.
-   **[MODIFIED]** `core/scheduler/strategos.py`:
    -   Initialized `self.arbitrator = ArbitrationEngine()`.
    -   Registered default policies.
    -   Added `self.arbitrator.review()` call inside the tool selection loop.
    -   Fixed `ScanContext` attribute access bug (`target_uri` -> `target`).

---

## Summary of Impact
The system now adheres to a strict "Constitution + Policy" model:
1.  **Strategos** proposes a tool.
2.  **Constitution** checks hard laws (Safety).
3.  **Arbitration** checks flexible policies (Business Logic/Scope).
4.  **Narrator** explains the outcome (including Vetoes).

This structure allows for much safer and more adaptable autonomous operations.
