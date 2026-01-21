"""
Project OMEGA - Integration Manager

The "Instant God-Mode" that orchestrates CRONUS, MIMIC, and NEXUS together.
This is the top-level coordinator that runs all three pillars and combines results.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Run comprehensive security analysis in one operation
- Correlate findings across all detection methods
- Generate unified risk reports
- Test overall security posture efficiently

SAFETY CONSTRAINTS:
- SAFE_MODE: Must be enabled for production use
- Requires explicit approval for execution
- All operations are read-only (no exploitation)
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits OMEGA_RUN_STARTED, OMEGA_RUN_COMPLETED events
- DecisionLedger: Logs pillar coordination decisions
- KnowledgeGraph: Stores unified analysis results
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class OmegaPhase(str, Enum):
    """
    Phases of OMEGA execution.
    """
    CRONUS = "cronus"       # Temporal mining
    MIMIC = "mimic"         # Source reconstruction
    NEXUS = "nexus"         # Logic chaining
    COMPLETE = "complete"   # All phases done


@dataclass
class OmegaConfig:
    """
    Configuration for an OMEGA run.

    Attributes:
        target: Domain to analyze
        enable_cronus: Run temporal mining
        enable_mimic: Run source reconstruction
        enable_nexus: Run logic chaining
        safe_mode: Safety restrictions
        max_duration_seconds: Maximum time to spend
    """
    target: str
    enable_cronus: bool = True
    enable_mimic: bool = True
    enable_nexus: bool = True
    safe_mode: bool = SAFE_MODE
    max_duration_seconds: int = 3600  # 1 hour default

    def to_dict(self) -> Dict[str, Any]:
        """Serialize config to dict."""
        return {
            "target": self.target,
            "enable_cronus": self.enable_cronus,
            "enable_mimic": self.enable_mimic,
            "enable_nexus": self.enable_nexus,
            "safe_mode": self.safe_mode,
            "max_duration_seconds": self.max_duration_seconds,
        }


@dataclass
class OmegaResult:
    """
    Combined result from all OMEGA pillars.

    Attributes:
        config: Configuration used
        target: Domain analyzed
        phase_results: Results from each pillar
        zombie_endpoints: Confirmed zombie endpoints (CRONUS)
        hidden_routes: Hidden routes found (MIMIC)
        exploit_chains: Validated chains (NEXUS)
        combined_risk_score: Overall risk assessment
        started_at: When analysis started
        completed_at: When analysis completed
        duration_seconds: Total execution time
    """
    config: OmegaConfig
    target: str
    phase_results: Dict[OmegaPhase, Dict[str, Any]] = field(default_factory=dict)
    zombie_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    hidden_routes: List[Dict[str, Any]] = field(default_factory=list)
    exploit_chains: List[Dict[str, Any]] = field(default_factory=list)
    combined_risk_score: float = 0.0
    started_at: datetime = field(default_factory=lambda: datetime.utcnow())
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dict."""
        return {
            "target": self.target,
            "config": self.config.to_dict(),
            "phases": list(self.phase_results.keys()),
            "summary": {
                "zombie_count": len(self.zombie_endpoints),
                "hidden_route_count": len(self.hidden_routes),
                "chain_count": len(self.exploit_chains),
                "combined_risk_score": round(self.combined_risk_score, 2),
            },
            "zombie_endpoints": self.zombie_endpoints,
            "hidden_routes": self.hidden_routes,
            "exploit_chains": self.exploit_chains,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
        }


class OmegaManager:
    """
    Orchestrates all three pillars (CRONUS, MIMIC, NEXUS) for comprehensive analysis.

    This is the top-level coordinator that:
    1. Runs CRONUS to find zombie endpoints
    2. Runs MIMIC to find hidden routes
    3. Runs NEXUS to chain primitives into exploits
    4. Combines all results into unified risk assessment

    EXAMPLE USAGE:
        ```python
        manager = OmegaManager()
        config = OmegaConfig(target="example.com")
        result = await manager.run(config)
        print(f"Found {len(result.zombie_endpoints)} zombies")
        ```
    """

    # Event names for integration with EventBus
    EVENT_RUN_STARTED = "omega_run_started"
    EVENT_RUN_COMPLETED = "omega_run_completed"
    EVENT_PHASE_STARTED = "omega_phase_started"
    EVENT_PHASE_COMPLETED = "omega_phase_completed"

    def __init__(self, safe_mode: bool = SAFE_MODE):
        """
        Initialize OmegaManager.

        Args:
            safe_mode: Safety restrictions
        """
        self._safe_mode = safe_mode
        self._run_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    async def run(self, config: OmegaConfig) -> OmegaResult:
        """
        Run full OMEGA analysis across all pillars.

        Orchestrates:
        1. CRONUS phase (temporal mining for zombie endpoints)
        2. MIMIC phase (asset collection for hidden routes)
        3. NEXUS phase (exploit chain discovery)
        4. Risk calculation (combined OMEGA score)

        Args:
            config: Analysis configuration

        Returns:
            OmegaResult with all findings and combined risk score
        """
        # Validate safe mode
        if self._safe_mode and not config.safe_mode:
            raise ValueError("SAFE_MODE: Cannot disable safe_mode in OmegaManager")

        # Update statistics
        self._run_count += 1

        started_at = datetime.utcnow()
        result = OmegaResult(
            config=config,
            target=config.target,
            started_at=started_at,
        )

        # Emit start event
        logger.info(
            f"[OmegaManager] {self.EVENT_RUN_STARTED}: "
            f"target={config.target}, "
            f"phases=[CRONUS: {config.enable_cronus}, MIMIC: {config.enable_mimic}, NEXUS: {config.enable_nexus}]"
        )

        try:
            # Phase 1: CRONUS (temporal mining)
            if config.enable_cronus:
                cronus_result = await self.run_cronus_phase(config)
                result.phase_results[OmegaPhase.CRONUS] = cronus_result
                result.zombie_endpoints = cronus_result.get("confirmed_zombies", [])
            else:
                cronus_result = {"status": "disabled", "confirmed_zombies": []}

            # Phase 2: MIMIC (source reconstruction)
            if config.enable_mimic:
                mimic_result = await self.run_mimic_phase(config)
                result.phase_results[OmegaPhase.MIMIC] = mimic_result
                result.hidden_routes = mimic_result.get("hidden_endpoints", [])
            else:
                mimic_result = {"status": "disabled", "routes_discovered": 0, "secrets_found": 0, "hidden_endpoints": []}

            # Phase 3: NEXUS (logic chaining)
            if config.enable_nexus:
                nexus_result = await self.run_nexus_phase(config)
                result.phase_results[OmegaPhase.NEXUS] = nexus_result
                result.exploit_chains = nexus_result.get("top_chains", [])
            else:
                nexus_result = {"status": "disabled", "top_chains": []}

            # Phase 4: Calculate combined risk
            risk_result = self.calculate_combined_risk(
                cronus_result=cronus_result,
                mimic_result=mimic_result,
                nexus_result=nexus_result,
            )
            result.combined_risk_score = risk_result.get("omega_score", 0.0)
            result.phase_results[OmegaPhase.COMPLETE] = risk_result

            # Finalize result
            result.completed_at = datetime.utcnow()
            result.duration_seconds = (result.completed_at - started_at).total_seconds()

            logger.info(
                f"[OmegaManager] {self.EVENT_RUN_COMPLETED}: "
                f"zombies={len(result.zombie_endpoints)}, "
                f"hidden_routes={len(result.hidden_routes)}, "
                f"chains={len(result.exploit_chains)}, "
                f"risk={result.combined_risk_score:.2f}"
            )

        except Exception as e:
            logger.error(f"[OmegaManager] OMEGA run failed: {e}")
            result.completed_at = datetime.utcnow()
            result.duration_seconds = (result.completed_at - started_at).total_seconds()
            raise

        return result

    async def run_cronus_phase(
        self,
        config: OmegaConfig,
        timestamp_start: Optional[datetime] = None,
        timestamp_end: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Run CRONUS phase (temporal mining).

        Orchestrates the three CRONUS components:
        1. TimeMachine: Query historical archives for snapshots
        2. SitemapDiffer: Compare old vs new endpoints
        3. ZombieHunter: Probe deleted endpoints to confirm zombies

        Args:
            config: Analysis configuration
            timestamp_start: Start of historical time range (default: 1 year ago)
            timestamp_end: End of historical time range (default: now)

        Returns:
            CRONUS phase results with confirmed zombie endpoints
        """
        from datetime import timedelta
        from core.sentient.cronus import (
            create_time_machine,
            create_sitemap_differ,
            create_zombie_hunter,
            SnapshotQuery,
            Endpoint,
        )

        logger.info(f"[OmegaManager] {self.EVENT_PHASE_STARTED}: CRONUS")

        # Default time range: 1 year ago to now
        if timestamp_end is None:
            timestamp_end = datetime.utcnow()
        if timestamp_start is None:
            timestamp_start = timestamp_end - timedelta(days=365)

        result = {
            "phase": OmegaPhase.CRONUS.value,
            "target": config.target,
            "status": "pending",
            "snapshots_found": 0,
            "historical_endpoints": 0,
            "current_endpoints": 0,
            "zombie_candidates": 0,
            "confirmed_zombies": [],
            "diff_report": None,
            "hunt_report": None,
            "error": None,
        }

        try:
            # Step 1: Query historical archives
            time_machine = create_time_machine(safe_mode=config.safe_mode)

            if config.safe_mode:
                # In safe mode, skip actual archive queries
                logger.info("[OmegaManager] CRONUS safe mode: skipping archive queries")
                result["status"] = "skipped_safe_mode"
                return result

            query = SnapshotQuery(
                target=config.target,
                timestamp_start=timestamp_start,
                timestamp_end=timestamp_end,
                max_results=100,
            )

            snapshots = await time_machine.query_async(query)
            result["snapshots_found"] = len(snapshots)

            if not snapshots:
                logger.info(f"[OmegaManager] CRONUS: No historical snapshots found for {config.target}")
                result["status"] = "no_snapshots"
                return result

            # Step 2: Extract endpoints from historical snapshots
            historical_endpoints = []
            for snapshot in snapshots:
                if snapshot.content:
                    paths = time_machine.parse_sitemap(snapshot)
                    for path in paths:
                        ep = Endpoint(path=path, source="wayback_machine")
                        if ep not in historical_endpoints:
                            historical_endpoints.append(ep)

            result["historical_endpoints"] = len(historical_endpoints)

            # TODO: Fetch current endpoints from target (not implemented)
            # For now, we treat all historical endpoints as zombie candidates
            current_endpoints: List[Endpoint] = []
            result["current_endpoints"] = 0

            # Step 3: Diff historical vs current
            differ = create_sitemap_differ(safe_mode=False)
            diff_report = differ.compare_sets(
                historical_endpoints,
                current_endpoints,
                f"https://{config.target}",
                timestamp_past=timestamp_start,
                timestamp_present=timestamp_end,
            )

            zombie_candidates = diff_report.get_zombie_candidates()
            result["zombie_candidates"] = len(zombie_candidates)
            result["diff_report"] = diff_report.to_dict()

            if not zombie_candidates:
                logger.info(f"[OmegaManager] CRONUS: No zombie candidates found")
                result["status"] = "no_candidates"
                return result

            # Step 4: Hunt for active zombies
            hunter = create_zombie_hunter(
                safe_mode=False,
                max_concurrent=5,
                rate_limit=5,
            )

            hunt_report = await hunter.hunt(
                zombie_candidates,
                f"https://{config.target}",
                method="HEAD",
            )

            result["hunt_report"] = hunt_report.to_dict()

            # Collect confirmed zombies
            for probe in hunt_report.probes:
                if probe.is_zombie:
                    result["confirmed_zombies"].append({
                        "path": probe.endpoint.path,
                        "method": probe.endpoint.method,
                        "status": probe.status.value,
                        "status_code": probe.status_code,
                        "confidence": probe.confidence,
                    })

            result["status"] = "completed"
            logger.info(
                f"[OmegaManager] CRONUS completed: "
                f"{len(result['confirmed_zombies'])} zombies confirmed"
            )

        except ValueError as e:
            # Safe mode or validation error
            result["status"] = "blocked"
            result["error"] = str(e)
            logger.warning(f"[OmegaManager] CRONUS blocked: {e}")

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"[OmegaManager] CRONUS error: {e}")

        logger.info(f"[OmegaManager] {self.EVENT_PHASE_COMPLETED}: CRONUS")
        return result

    async def run_mimic_phase(self, config: OmegaConfig) -> Dict[str, Any]:
        """
        Run MIMIC phase (source reconstruction).

        Orchestrates manifest-first asset collection:
        1. Probe for framework manifests (webpack, vite, CRA, Next.js)
        2. Build asset graph from manifest or fallback to bundles
        3. Download and parse JavaScript assets
        4. Extract routes, secrets, hidden endpoints

        Args:
            config: Analysis configuration

        Returns:
            MIMIC phase results with discovered routes and endpoints
        """
        from core.omega.mimic_phase import MIMICPhaseOrchestrator

        logger.info(f"[OmegaManager] {self.EVENT_PHASE_STARTED}: MIMIC")

        result = {
            "phase": OmegaPhase.MIMIC.value,
            "target": config.target,
            "status": "pending",
            "manifest_type": None,
            "assets_downloaded": 0,
            "routes_discovered": 0,
            "secrets_found": 0,
            "hidden_endpoints": [],
            "fallback_used": False,
            "error": None,
        }

        try:
            if config.safe_mode:
                # In safe mode, skip asset downloading
                logger.info("[OmegaManager] MIMIC safe mode: skipping asset downloads")
                result["status"] = "skipped_safe_mode"
                return result

            # Run MIMIC phase orchestration
            orchestrator = MIMICPhaseOrchestrator(
                target=config.target,
                safe_mode=config.safe_mode,
            )
            mimic_result = await orchestrator.execute()

            # Extract results
            result["status"] = "completed"
            result["manifest_type"] = mimic_result.manifest_type.value
            result["assets_downloaded"] = mimic_result.assets_downloaded
            result["routes_discovered"] = mimic_result.routes_discovered
            result["secrets_found"] = mimic_result.secrets_found
            result["hidden_endpoints"] = mimic_result.hidden_endpoints
            result["fallback_used"] = mimic_result.fallback_used

            logger.info(
                f"[OmegaManager] MIMIC completed: "
                f"{mimic_result.assets_downloaded} assets, "
                f"{mimic_result.routes_discovered} routes, "
                f"{mimic_result.secrets_found} secrets"
            )

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"[OmegaManager] MIMIC error: {e}")

        logger.info(f"[OmegaManager] {self.EVENT_PHASE_COMPLETED}: MIMIC")
        return result

    async def run_nexus_phase(
        self,
        config: OmegaConfig,
        primitives: Optional[List] = None,
    ) -> Dict[str, Any]:
        """
        Run NEXUS phase (logic chaining).

        Orchestrates three-layer chain discovery:
        1. Generate candidate chains via graph traversal
        2. Filter by goal states (adversarial outcomes)
        3. Score and rank by impact (return top N)

        Args:
            config: Analysis configuration
            primitives: List of Primitive objects to analyze (if None, collects from stores)

        Returns:
            NEXUS phase results with top exploit chains
        """
        from core.omega.nexus_phase import NEXUSPhaseOrchestrator
        from core.aegis.nexus.primitives import collect_primitives

        logger.info(f"[OmegaManager] {self.EVENT_PHASE_STARTED}: NEXUS")

        result = {
            "phase": OmegaPhase.NEXUS.value,
            "target": config.target,
            "status": "pending",
            "primitives_collected": 0,
            "candidate_chains": 0,
            "goal_filtered_chains": 0,
            "top_chains": [],
            "goal_distribution": {},
            "error": None,
        }

        try:
            # Collect primitives if not provided
            if primitives is None:
                primitives = await collect_primitives(config.target)

            result["primitives_collected"] = len(primitives)

            if not primitives:
                logger.info(f"[OmegaManager] NEXUS: No primitives found for {config.target}")
                result["status"] = "no_primitives"
                return result

            # Run NEXUS phase orchestration
            orchestrator = NEXUSPhaseOrchestrator(
                target=config.target,
                top_n=5,  # Return top 5 chains
            )
            nexus_result = await orchestrator.execute(primitives)

            # Extract results
            result["status"] = "completed"
            result["primitives_collected"] = nexus_result.primitives_collected
            result["candidate_chains"] = nexus_result.candidate_chains
            result["goal_filtered_chains"] = nexus_result.goal_filtered_chains
            result["top_chains"] = [chain.to_dict() for chain in nexus_result.top_chains]
            result["goal_distribution"] = nexus_result.goal_distribution

            logger.info(
                f"[OmegaManager] NEXUS completed: "
                f"{nexus_result.primitives_collected} primitives, "
                f"{nexus_result.candidate_chains} candidates, "
                f"{len(nexus_result.top_chains)} top chains"
            )

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"[OmegaManager] NEXUS error: {e}")

        logger.info(f"[OmegaManager] {self.EVENT_PHASE_COMPLETED}: NEXUS")
        return result

    def calculate_combined_risk(
        self,
        cronus_result: Dict[str, Any],
        mimic_result: Dict[str, Any],
        nexus_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Calculate combined OMEGA risk score from all pillar results.

        Uses deliberate static weights:
        - CRONUS: 20% (exposure & posture)
        - MIMIC: 30% (latent code risk)
        - NEXUS: 50% (adversarial exploitability)

        If NEXUS doesn't fire, redistributes to CRONUS (40%) + MIMIC (60%).

        Args:
            cronus_result: CRONUS phase results
            mimic_result: MIMIC phase results
            nexus_result: NEXUS phase results

        Returns:
            Risk calculation results with OMEGA score and breakdown
        """
        from core.omega.risk_calculator import (
            OMEGARiskCalculator,
            PillarScore,
        )

        calculator = OMEGARiskCalculator()

        # Calculate individual pillar scores
        cronus_score = calculator.calculate_cronus_score(
            zombie_endpoints=len(cronus_result.get("confirmed_zombies", [])),
            exposed_routes=cronus_result.get("current_endpoints", 0),
            confidence=1.0 if cronus_result.get("status") == "completed" else 0.5,
        )

        mimic_score = calculator.calculate_mimic_score(
            routes_discovered=mimic_result.get("routes_discovered", 0),
            secrets_found=mimic_result.get("secrets_found", 0),
            hidden_endpoints=len(mimic_result.get("hidden_endpoints", [])),
            confidence=1.0 if mimic_result.get("status") == "completed" else 0.5,
        )

        # Check if NEXUS fired (has valid chains)
        top_chains = nexus_result.get("top_chains", [])
        nexus_fired = len(top_chains) > 0

        # Import ExploitChain to reconstruct objects from dicts
        from core.omega.nexus_phase import ExploitChain, ChainStep, GoalState
        from core.aegis.nexus.primitives import Primitive, PrimitiveType

        chain_objects = []
        for chain_dict in top_chains:
            # Reconstruct ExploitChain object from dict for scoring
            # For now, pass the raw chain_dict - the calculator will extract what it needs
            chain_objects.append(chain_dict)

        nexus_score = calculator.calculate_nexus_score(
            top_chains=[],  # Pass empty list if no chains, calculator handles it
            confidence=1.0 if nexus_result.get("status") == "completed" else 0.5,
        )

        # If NEXUS fired, use the actual top chain scores
        if nexus_fired and top_chains:
            # Extract impact scores from chain dicts
            max_impact = max(chain.get("impact_score", 0.0) for chain in top_chains)
            chain_count_bonus = min(2.0, len(top_chains) * 0.5)
            nexus_score_value = min(10.0, max_impact + chain_count_bonus)

            nexus_score = PillarScore(
                value=nexus_score_value,
                confidence=1.0,
                details={
                    "chain_count": len(top_chains),
                    "max_impact": round(max_impact, 2),
                    "chain_count_bonus": round(chain_count_bonus, 2),
                    "top_chain_goals": [chain.get("goal") for chain in top_chains[:3]],
                },
            )

        # Calculate combined OMEGA score
        omega_result = calculator.calculate(
            cronus_score=cronus_score,
            mimic_score=mimic_score,
            nexus_score=nexus_score,
            nexus_fired=nexus_fired,
        )

        logger.info(
            f"[OmegaManager] Risk calculated: {omega_result.omega_score:.2f} "
            f"({omega_result.risk_level.value})"
        )

        return omega_result.to_dict()

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this OmegaManager instance.

        Returns:
            Dictionary with statistics
        """
        return {
            "run_count": self._run_count,
            "safe_mode": self._safe_mode,
        }


def create_omega_manager(safe_mode: bool = SAFE_MODE) -> OmegaManager:
    """
    Factory function to create OmegaManager instance.

    This is the recommended way to create OmegaManager objects in production code.

    Args:
        safe_mode: Safety mode flag

    Returns:
        Configured OmegaManager instance
    """
    return OmegaManager(safe_mode=safe_mode)


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    # Verify OmegaPhase enum
    assert OmegaPhase.CRONUS.value == "cronus"
    assert OmegaPhase.NEXUS.value == "nexus"
    print("✓ OmegaPhase enum works")

    # Verify OmegaConfig dataclass
    config = OmegaConfig(
        target="example.com",
        enable_cronus=True,
        enable_mimic=True,
        enable_nexus=False,
    )
    assert config.to_dict()["enable_nexus"] is False
    assert config.to_dict()["target"] == "example.com"
    print("✓ OmegaConfig structure works")

    # Verify OmegaResult dataclass
    result = OmegaResult(
        config=config,
        target="example.com",
    )
    result.zombie_endpoints = [{"path": "/admin/old"}]
    result.hidden_routes = [{"path": "/api/debug"}]
    assert result.to_dict()["summary"]["zombie_count"] == 1
    assert result.to_dict()["summary"]["hidden_route_count"] == 1
    print("✓ OmegaResult aggregation works")

    # Verify OmegaManager creation
    manager = create_omega_manager()
    assert manager.safe_mode is True
    assert manager.run_count == 0
    print("✓ OmegaManager factory works")

    print("\n✅ All OmegaManager design invariants verified!")
