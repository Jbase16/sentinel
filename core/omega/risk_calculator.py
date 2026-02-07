"""
OMEGA Risk Calculator

Combines three pillar scores into a single risk metric with deliberate, static weights.

Architecture:
- CRONUS (20%): Exposure & posture (zombie endpoints, attack surface)
- MIMIC (30%): Code-level latent risk (API structure, secrets, routes)
- NEXUS (50%): Adversarial reality (exploit chains, goal reachability)

NEXUS dominates because exploitability > exposure. But if NEXUS doesn't fire
(no valid chains), the weight redistributes to CRONUS + MIMIC proportionally.

All weights are static constants. No magic numbers. No tuning for demos.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from core.cortex.events import GraphEvent, GraphEventType, get_event_bus

logger = logging.getLogger(__name__)


# Static pillar weights (non-negotiable)
# These are constants, not tunable parameters
WEIGHT_CRONUS = 0.20  # Exposure & attack surface
WEIGHT_MIMIC = 0.30   # Latent code-level risk
WEIGHT_NEXUS = 0.50   # Adversarial exploitability

# Sanity check: weights must sum to 1.0
assert abs(WEIGHT_CRONUS + WEIGHT_MIMIC + WEIGHT_NEXUS - 1.0) < 0.001, \
    "Pillar weights must sum to 1.0"


class RiskLevel(str, Enum):
    """Overall risk classification based on OMEGA score."""
    CRITICAL = "critical"    # 8.0-10.0
    HIGH = "high"            # 6.0-7.9
    MEDIUM = "medium"        # 4.0-5.9
    LOW = "low"              # 2.0-3.9
    MINIMAL = "minimal"      # 0.0-1.9


@dataclass
class PillarScore:
    """Score for a single pillar (0-10 scale)."""
    value: float  # 0.0-10.0
    confidence: float = 1.0  # 0.0-1.0 (measurement confidence)
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Clamp to valid ranges
        self.value = max(0.0, min(10.0, self.value))
        self.confidence = max(0.0, min(1.0, self.confidence))


@dataclass
class OMEGARiskScore:
    """Combined OMEGA risk score with pillar breakdown."""
    omega_score: float  # Final combined score (0-10)
    risk_level: RiskLevel
    cronus_score: PillarScore
    mimic_score: PillarScore
    nexus_score: PillarScore
    nexus_fired: bool  # Whether NEXUS had valid chains
    weights_used: Dict[str, float]  # Actual weights applied
    calculated_at: datetime = field(default_factory=lambda: datetime.utcnow())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "omega_score": round(self.omega_score, 2),
            "risk_level": self.risk_level.value,
            "pillars": {
                "cronus": {
                    "score": round(self.cronus_score.value, 2),
                    "confidence": round(self.cronus_score.confidence, 2),
                    "details": self.cronus_score.details,
                },
                "mimic": {
                    "score": round(self.mimic_score.value, 2),
                    "confidence": round(self.mimic_score.confidence, 2),
                    "details": self.mimic_score.details,
                },
                "nexus": {
                    "score": round(self.nexus_score.value, 2),
                    "confidence": round(self.nexus_score.confidence, 2),
                    "details": self.nexus_score.details,
                    "fired": self.nexus_fired,
                },
            },
            "weights": self.weights_used,
            "calculated_at": self.calculated_at.isoformat(),
        }


class OMEGARiskCalculator:
    """
    Calculates combined OMEGA risk score from pillar scores.

    Principles:
    1. Static weights (no tuning)
    2. Dynamic scores (evidence-based)
    3. NEXUS dominance (exploitability > exposure)
    4. Graceful degradation (redistribute if NEXUS doesn't fire)
    5. Audit trail (emit events for every calculation)
    """

    def __init__(self):
        self.event_bus = get_event_bus()

    def calculate(
        self,
        cronus_score: PillarScore,
        mimic_score: PillarScore,
        nexus_score: PillarScore,
        nexus_fired: bool,
    ) -> OMEGARiskScore:
        """
        Calculate combined OMEGA risk score.

        Args:
            cronus_score: CRONUS pillar score (exposure & posture)
            mimic_score: MIMIC pillar score (latent code risk)
            nexus_score: NEXUS pillar score (exploit chains)
            nexus_fired: Whether NEXUS discovered any valid chains

        Returns:
            OMEGARiskScore with combined score and breakdown
        """
        self.event_bus.emit(GraphEvent(
            type=GraphEventType.LOG,
            payload={
                "message": "[OMEGA] Calculating risk score",
                "cronus": cronus_score.value,
                "cronus_confidence": cronus_score.confidence,
                "mimic": mimic_score.value,
                "mimic_confidence": mimic_score.confidence,
                "nexus": nexus_score.value,
                "nexus_confidence": nexus_score.confidence,
                "nexus_fired": nexus_fired,
                "confidence_applied": True,
            },
        ))

        # Determine effective weights
        if nexus_fired:
            # NEXUS fired: use standard weights
            w_cronus = WEIGHT_CRONUS
            w_mimic = WEIGHT_MIMIC
            w_nexus = WEIGHT_NEXUS
        else:
            # NEXUS didn't fire: redistribute its weight proportionally
            # CRONUS gets 40% of total, MIMIC gets 60% of total
            # (maintains their relative 2:3 ratio)
            w_cronus = 0.40
            w_mimic = 0.60
            w_nexus = 0.0

            self.event_bus.emit(GraphEvent(
                type=GraphEventType.LOG,
                payload={
                    "message": "[OMEGA] NEXUS did not fire, redistributing weights",
                    "weights": {"cronus": w_cronus, "mimic": w_mimic, "nexus": w_nexus},
                },
            ))

        # Calculate weighted score
        # NOTE: Phase 1 does not modify pillar confidence values.
        # Confirmation weighting is handled at issue and asset levels only.
        omega_score = (
            w_cronus * cronus_score.value * cronus_score.confidence +
            w_mimic * mimic_score.value * mimic_score.confidence +
            w_nexus * nexus_score.value * nexus_score.confidence
        )

        # Classify risk level
        risk_level = self._classify_risk(omega_score)

        result = OMEGARiskScore(
            omega_score=omega_score,
            risk_level=risk_level,
            cronus_score=cronus_score,
            mimic_score=mimic_score,
            nexus_score=nexus_score,
            nexus_fired=nexus_fired,
            weights_used={
                "cronus": w_cronus,
                "mimic": w_mimic,
                "nexus": w_nexus,
            },
        )

        self.event_bus.emit(GraphEvent(
            type=GraphEventType.LOG,
            payload={
                "message": f"[OMEGA] Risk calculated: {omega_score:.2f} ({risk_level.value})",
                "omega_score": omega_score,
                "risk_level": risk_level.value,
            },
        ))

        return result

    def _classify_risk(self, score: float) -> RiskLevel:
        """Classify OMEGA score into risk level."""
        if score >= 8.0:
            return RiskLevel.CRITICAL
        elif score >= 6.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score >= 2.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def calculate_cronus_score(
        self,
        zombie_endpoints: int,
        exposed_routes: int,
        confidence: float = 1.0,
    ) -> PillarScore:
        """
        Calculate CRONUS pillar score from scan results.

        Args:
            zombie_endpoints: Number of historical endpoints found
            exposed_routes: Number of currently exposed routes
            confidence: Measurement confidence (0-1)

        Returns:
            PillarScore for CRONUS pillar
        """
        # Score formula:
        # - Base score from zombie count (10 zombies = 5.0 score)
        # - Bonus from exposure ratio (zombies / exposed ratio)
        # - Capped at 10.0

        zombie_score = min(5.0, zombie_endpoints / 2.0)

        exposure_ratio = 0.0
        if exposed_routes > 0:
            exposure_ratio = zombie_endpoints / exposed_routes

        exposure_bonus = min(5.0, exposure_ratio * 5.0)

        total_score = zombie_score + exposure_bonus

        return PillarScore(
            value=total_score,
            confidence=confidence,
            details={
                "zombie_endpoints": zombie_endpoints,
                "exposed_routes": exposed_routes,
                "zombie_score": round(zombie_score, 2),
                "exposure_bonus": round(exposure_bonus, 2),
            },
        )

    def calculate_mimic_score(
        self,
        routes_discovered: int,
        secrets_found: int,
        hidden_endpoints: int,
        confidence: float = 1.0,
    ) -> PillarScore:
        """
        Calculate MIMIC pillar score from asset analysis.

        Args:
            routes_discovered: Number of routes extracted from client code
            secrets_found: Number of secrets/keys found in bundles
            hidden_endpoints: Number of undocumented API endpoints
            confidence: Measurement confidence (0-1)

        Returns:
            PillarScore for MIMIC pillar
        """
        # Score formula:
        # - Routes: 3.0 max (1 point per 10 routes)
        # - Secrets: 4.0 max (2 points per secret)
        # - Hidden endpoints: 3.0 max (1 point per 5 endpoints)

        routes_score = min(3.0, routes_discovered / 10.0)
        secrets_score = min(4.0, secrets_found * 2.0)
        endpoints_score = min(3.0, hidden_endpoints / 5.0)

        total_score = routes_score + secrets_score + endpoints_score

        return PillarScore(
            value=total_score,
            confidence=confidence,
            details={
                "routes_discovered": routes_discovered,
                "secrets_found": secrets_found,
                "hidden_endpoints": hidden_endpoints,
                "routes_score": round(routes_score, 2),
                "secrets_score": round(secrets_score, 2),
                "endpoints_score": round(endpoints_score, 2),
            },
        )

    def calculate_nexus_score(
        self,
        top_chains: list,  # List[ExploitChain] from nexus_phase
        confidence: float = 1.0,
    ) -> PillarScore:
        """
        Calculate NEXUS pillar score from exploit chains.

        Args:
            top_chains: List of top exploit chains from NEXUS phase
            confidence: Measurement confidence (0-1)

        Returns:
            PillarScore for NEXUS pillar
        """
        if not top_chains:
            return PillarScore(
                value=0.0,
                confidence=confidence,
                details={"chain_count": 0, "max_impact": 0.0},
            )

        # Score formula:
        # - Take the highest impact chain as primary signal
        # - Add bonus for chain count (diversity of attack vectors)
        # - Capped at 10.0

        max_impact = max(chain.impact_score for chain in top_chains)
        chain_count_bonus = min(2.0, len(top_chains) * 0.5)

        total_score = min(10.0, max_impact + chain_count_bonus)

        return PillarScore(
            value=total_score,
            confidence=confidence,
            details={
                "chain_count": len(top_chains),
                "max_impact": round(max_impact, 2),
                "chain_count_bonus": round(chain_count_bonus, 2),
                "top_chain_goals": [chain.goal.value for chain in top_chains[:3]],
            },
        )
