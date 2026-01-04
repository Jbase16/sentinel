"""
core/executor/oracle.py

Purpose:
    The "Judge".
    Decides if a Breach occurred based on the Evidence (Signals) and the Law (OracleSpec).

Magnum Opus Standards:
    - Evidence Matching: Deep inspection of JSON bodies (subset matching).
    - Inverted Logic: Support "Forbidden" vs "Expected" states.
    - Header Analysis: Verify security headers or cache controls.
"""

from __future__ import annotations
import logging
import json
from typing import Any, Dict, List, Optional, Union

from core.thanatos.models import OracleSpec
from .models import ExecutionResult, ExecutionStatus, BreachStatus

log = logging.getLogger("executor.oracle")

class StandardOracleEvaluator:
    """
    Evaluates HTTP signals against OracleSpecs.
    Implements 'Inverted Success' logic common in security testing.
    """
    
    def evaluate(self, result: ExecutionResult, oracle: OracleSpec) -> BreachStatus:
        """
        Decides the security outcome.
        Returns:
            BreachStatus.BREACH: Invariant VIOLATED.
            BreachStatus.SECURE: Invariant HELD (or attack blocked).
            BreachStatus.UNKNOWN: Could not decide (e.g. execution error).
        """
        if result.status != ExecutionStatus.EXECUTED:
            log.warning(f"Cannot evaluate Oracle on non-executed result: {result.status}")
            return BreachStatus.UNKNOWN

        signals = result.signals
        
        # 1. Status Code Check (The most common oracle)
        if self._check_status_code_violation(signals, oracle):
            return BreachStatus.BREACH

        # 2. Body Content Check (If spec defines 'forbidden' body patterns)
        if self._check_body_violation(signals, oracle):
            return BreachStatus.BREACH

        return BreachStatus.SECURE

    def _check_status_code_violation(self, signals: Dict[str, Any], oracle: OracleSpec) -> bool:
        """
        Returns True if the status code indicates a breach.
        """
        actual_status = signals.get("status_code")
        if actual_status is None:
            return False

        # Forbidden Status: If we get this, it is a BREACH.
        forbidden = oracle.forbidden.get("status")
        if forbidden:
            if isinstance(forbidden, int) and actual_status == forbidden:
                log.info(f"🚨 BREACH: Got forbidden status {actual_status} (Spec: {oracle.name})")
                return True
            if isinstance(forbidden, list) and actual_status in forbidden:
                log.info(f"🚨 BREACH: Got forbidden status {actual_status} (Spec: {oracle.name})")
                return True
        
        return False

    def _check_body_violation(self, signals: Dict[str, Any], oracle: OracleSpec) -> bool:
        """
        Checks if the response body contains data it shouldn't.
        """
        actual_body = signals.get("body", "")
        forbidden_body = oracle.forbidden.get("body_contains")
        
        if forbidden_body:
            if isinstance(forbidden_body, str) and forbidden_body in actual_body:
                log.info(f"🚨 BREACH: Body contains forbidden string '{forbidden_body}'")
                return True
                
        # Structured JSON matching
        forbidden_json = oracle.forbidden.get("json_subset")
        if forbidden_json:
            try:
                actual_json = json.loads(actual_body)
                if self._is_subset(forbidden_json, actual_json):
                    log.info(f"🚨 BREACH: JSON body contains forbidden subset {forbidden_json}")
                    return True
            except json.JSONDecodeError:
                pass 

        return False

    def _is_subset(self, subset: Dict[str, Any], superset: Dict[str, Any]) -> bool:
        """
        Recursive check if 'subset' is contained within 'superset'.
        
        NOTE: Strict List Matching Enforced.
        Lists are compared by strict equality (order matters). 
        Future versions may support unordered or 'contains' semantics for lists.
        """
        if not isinstance(subset, dict) or not isinstance(superset, dict):
            return subset == superset
            
        for key, val in subset.items():
            if key not in superset:
                return False
            if not self._is_subset(val, superset[key]):
                return False
        return True
