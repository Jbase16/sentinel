"""
SentinelForge Feedback Loop Module

Implements a closed-loop feedback system that connects scan results back to
planning decisions in the Strategos scheduler. This module processes ActionOutcome
signals from the mutation engine, maintains intelligence on target/vulnerability
success rates, detects defensive mechanisms (WAF), and provides strategic
recommendations for capability escalation and resource allocation.

Key Responsibilities:
1. Aggregate outcome signals from executed actions
2. Maintain per-target and per-vulnerability success metrics
3. Track and alert on WAF/filter detections
4. Manage budget token tracking and allocation
5. Recommend next actions based on composite scoring
6. Advise on tier escalation and action abandonment

Architecture:
- FeedbackTracker: State machine for vulnerability intelligence
- ActionPriorityQueue: Heapq-based priority dispatch
- StrategyAdvisor: Decision recommendation engine
- Supporting dataclasses for structured data flow
"""

import dataclasses
import heapq
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

# ============================================================================
# Enums and Type Definitions
# ============================================================================


class ActionOutcome(str, Enum):
    """Possible outcomes from mutation engine execution."""
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    UNEXPECTED = "UNEXPECTED"
    PARTIAL = "PARTIAL"


class CapabilityTier(int, Enum):
    """Security testing capability tiers (T0=passive, T4=heavy)."""
    T0 = 0
    T1 = 1
    T2 = 2
    T3 = 3
    T4 = 4


class DecisionType(str, Enum):
    """Types of decisions made by Strategos scheduler."""
    INTENT_TRANSITION = "INTENT_TRANSITION"
    PHASE_TRANSITION = "PHASE_TRANSITION"
    TOOL_SELECTION = "TOOL_SELECTION"
    TOOL_REJECTION = "TOOL_REJECTION"
    ASSESSMENT = "ASSESSMENT"


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class ActionFeedback:
    """
    Structured feedback from a single executed action.
    
    Attributes:
        action_id: Unique identifier for the action execution
        target: Target system (URL, IP, hostname)
        tool_name: Name of the testing tool used (e.g., 'sqlmap', 'nikto')
        vuln_class: Vulnerability classification (e.g., 'SQL_INJECTION', 'XSS')
        tier: Capability tier used (0-4)
        outcome: Result of the action (SUCCESS, FAILURE, BLOCKED, etc.)
        evidence_count: Number of evidence artifacts recovered
        max_evidence_confidence: Highest confidence score (0.0-1.0)
        waf_detected: Name of detected WAF/filter if applicable
        elapsed_ms: Wall-clock execution time
        error_detail: Exception/error message if outcome is ERROR
        timestamp: Unix timestamp when feedback was generated
    """
    action_id: str
    target: str
    tool_name: str
    vuln_class: str
    tier: int
    outcome: ActionOutcome
    evidence_count: int
    max_evidence_confidence: float
    waf_detected: Optional[str]
    elapsed_ms: float
    error_detail: Optional[str]
    timestamp: float


@dataclass
class ProposedAction:
    """
    An action proposed for future execution based on feedback analysis.
    
    Attributes:
        target: Target system
        tool_name: Testing tool to employ
        vuln_class: Vulnerability class to target
        tier: Recommended capability tier
        priority: Composite priority score (higher = more urgent)
        rationale: Human-readable explanation for recommendation
        estimated_cost: Budget tokens required for execution
    """
    target: str
    tool_name: str
    vuln_class: str
    tier: int
    priority: float
    rationale: str
    estimated_cost: int

    def __eq__(self, other: object) -> bool:
        """Equality based on target, tool, vuln_class, and tier."""
        if not isinstance(other, ProposedAction):
            return NotImplemented
        return (
            self.target == other.target
            and self.tool_name == other.tool_name
            and self.vuln_class == other.vuln_class
            and self.tier == other.tier
        )

    def __hash__(self) -> int:
        """Hash for deduplication."""
        return hash((self.target, self.tool_name, self.vuln_class, self.tier))


@dataclass
class TargetIntelligence:
    """
    Aggregated intelligence about a single target.
    
    Attributes:
        target: Target identifier
        total_actions: Total actions executed against this target
        successful_actions: Count of successful outcomes
        failed_actions: Count of failed outcomes
        waf_detected: Name of WAF if detected
        waf_encounter_count: Number of times WAF was triggered
        vulnerability_hits: Dict mapping vuln_class → hit_count
        tool_effectiveness: Dict mapping tool_name → success_rate (0.0-1.0)
        last_activity: Unix timestamp of most recent action
        budget_consumed: Tokens spent so far
    """
    target: str
    total_actions: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    waf_detected: Optional[str] = None
    waf_encounter_count: int = 0
    vulnerability_hits: Dict[str, int] = field(default_factory=dict)
    tool_effectiveness: Dict[str, float] = field(default_factory=dict)
    last_activity: float = 0.0
    budget_consumed: int = 0

    @property
    def success_rate(self) -> float:
        """Overall success rate for this target."""
        if self.total_actions == 0:
            return 0.0
        return self.successful_actions / self.total_actions

    @property
    def failure_rate(self) -> float:
        """Overall failure rate for this target."""
        if self.total_actions == 0:
            return 0.0
        return self.failed_actions / self.total_actions


# ============================================================================
# Feedback Tracker
# ============================================================================


class FeedbackTracker:
    """
    Maintains aggregated intelligence from action execution outcomes.
    
    Tracks per-(target, vulnerability_class) success rates, per-tool effectiveness,
    WAF encounters, and provides methods for querying current intelligence state.
    Implements sliding window decay to deprioritize stale information.
    """

    # Configuration constants
    DECAY_WINDOW_SECONDS = 3600  # 1 hour decay window
    MIN_SAMPLES_FOR_STATS = 3  # Require at least 3 samples for meaningful stats
    CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence for high-priority actions

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the feedback tracker.
        
        Args:
            logger: Optional logger instance for diagnostics
        """
        self.logger = logger or logging.getLogger(__name__)

        # Per-target intelligence
        self._target_intelligence: Dict[str, TargetIntelligence] = defaultdict(
            lambda: TargetIntelligence(target="")
        )

        # Per-(target, vuln_class) metrics
        self._vuln_class_hits: Dict[Tuple[str, str], int] = defaultdict(int)
        self._vuln_class_attempts: Dict[Tuple[str, str], int] = defaultdict(int)

        # Per-tool effectiveness across all targets
        self._tool_success_counts: Dict[str, int] = defaultdict(int)
        self._tool_total_counts: Dict[str, int] = defaultdict(int)

        # WAF tracking
        self._waf_by_target: Dict[str, str] = {}
        self._waf_attempt_count: Dict[str, int] = defaultdict(int)

        # Time-series for decay calculations
        self._feedback_timestamps: List[float] = []

    def process_feedback(self, feedback: ActionFeedback) -> None:
        """
        Process a single action feedback signal and update internal state.
        
        Args:
            feedback: ActionFeedback object from mutation engine
        """
        target = feedback.target
        vuln_class = feedback.vuln_class
        tool_name = feedback.tool_name
        outcome = feedback.outcome

        # Initialize target intelligence if needed
        if target not in self._target_intelligence:
            self._target_intelligence[target] = TargetIntelligence(target=target)

        intel = self._target_intelligence[target]

        # Update global counts
        intel.total_actions += 1
        intel.last_activity = feedback.timestamp

        # Update outcome counts
        if outcome in (ActionOutcome.SUCCESS, ActionOutcome.PARTIAL):
            intel.successful_actions += 1
        elif outcome in (ActionOutcome.FAILURE, ActionOutcome.BLOCKED):
            intel.failed_actions += 1

        # Track vulnerability class hits
        key = (target, vuln_class)
        self._vuln_class_attempts[key] += 1
        if outcome in (ActionOutcome.SUCCESS, ActionOutcome.PARTIAL):
            self._vuln_class_hits[key] += 1
            intel.vulnerability_hits[vuln_class] = (
                intel.vulnerability_hits.get(vuln_class, 0) + 1
            )

        # Track tool effectiveness
        self._tool_total_counts[tool_name] += 1
        if outcome == ActionOutcome.SUCCESS:
            self._tool_success_counts[tool_name] += 1

        # Update tool-specific success rate for this target
        if tool_name not in intel.tool_effectiveness:
            intel.tool_effectiveness[tool_name] = 0.0
        tool_actions = [fb for fb in self._feedback_timestamps if tool_name in str(fb)]
        if len(tool_actions) > 0:
            intel.tool_effectiveness[tool_name] = (
                self._tool_success_counts[tool_name] / self._tool_total_counts[tool_name]
            )

        # Track WAF detections
        if feedback.waf_detected:
            self._waf_by_target[target] = feedback.waf_detected
            self._waf_attempt_count[feedback.waf_detected] += 1
            intel.waf_detected = feedback.waf_detected
            intel.waf_encounter_count += 1
            self.logger.warning(
                f"WAF detected on {target}: {feedback.waf_detected} "
                f"(encounter #{intel.waf_encounter_count})"
            )

        # Track budget consumption
        # Estimated: T0=1, T1=5, T2=10, T3=25, T4=50 tokens per action
        tier_costs = {0: 1, 1: 5, 2: 10, 3: 25, 4: 50}
        intel.budget_consumed += tier_costs.get(feedback.tier, 10)

        self._feedback_timestamps.append(feedback.timestamp)

        self.logger.debug(
            f"Processed feedback: {feedback.action_id} "
            f"{target}/{vuln_class} via {tool_name}: {outcome}"
        )

    def get_target_intelligence(self, target: str) -> TargetIntelligence:
        """
        Retrieve aggregated intelligence for a specific target.
        
        Args:
            target: Target identifier
            
        Returns:
            TargetIntelligence object with current metrics
        """
        if target not in self._target_intelligence:
            self._target_intelligence[target] = TargetIntelligence(target=target)
        return self._target_intelligence[target]

    def get_vuln_class_priority(self, target: str, vuln_class: str) -> float:
        """
        Calculate priority score for a specific vulnerability class on a target.
        
        Higher scores indicate more promising targets. Calculation factors in:
        - Historical success rate for this vuln_class on this target
        - Recency of information (newer is better)
        - Evidence confidence from successful hits
        
        Args:
            target: Target identifier
            vuln_class: Vulnerability classification
            
        Returns:
            Priority score (0.0-1.0, higher = more promising)
        """
        key = (target, vuln_class)
        attempts = self._vuln_class_attempts.get(key, 0)
        hits = self._vuln_class_hits.get(key, 0)

        if attempts == 0:
            return 0.5  # Unknown = neutral priority

        # Base success rate
        base_rate = hits / attempts

        # Reduce priority if too many failures
        if attempts >= self.MIN_SAMPLES_FOR_STATS and base_rate == 0.0:
            return 0.1  # Deprioritize repeatedly failing attempts

        # Apply confidence boost for recent attempts
        now = time.time()
        intel = self.get_target_intelligence(target)
        age_seconds = max(0, now - intel.last_activity)
        recency_factor = max(0.5, 1.0 - (age_seconds / self.DECAY_WINDOW_SECONDS))

        return min(1.0, base_rate * recency_factor)

    def get_tool_effectiveness(self, tool_name: str) -> float:
        """
        Retrieve effectiveness score for a specific tool across all targets.
        
        Args:
            tool_name: Name of the testing tool
            
        Returns:
            Success rate (0.0-1.0, higher = more effective)
        """
        total = self._tool_total_counts.get(tool_name, 0)
        if total == 0:
            return 0.5  # Unknown tool = neutral
        success = self._tool_success_counts.get(tool_name, 0)
        return success / total

    def get_waf_intelligence(self, target: str) -> Optional[str]:
        """
        Check if WAF has been detected on a target.
        
        Args:
            target: Target identifier
            
        Returns:
            WAF name if detected, None otherwise
        """
        return self._waf_by_target.get(target)

    def get_all_targets(self) -> List[str]:
        """Get list of all targets with recorded intelligence."""
        return list(self._target_intelligence.keys())

    def get_statistics(self) -> Dict[str, any]:
        """
        Get overall statistics across all targets and tools.
        
        Returns:
            Dictionary with aggregated metrics
        """
        total_actions = sum(
            intel.total_actions for intel in self._target_intelligence.values()
        )
        total_successes = sum(
            intel.successful_actions for intel in self._target_intelligence.values()
        )

        return {
            "total_targets": len(self._target_intelligence),
            "total_actions": total_actions,
            "total_successes": total_successes,
            "overall_success_rate": (
                total_successes / total_actions if total_actions > 0 else 0.0
            ),
            "tools_deployed": len(self._tool_total_counts),
            "waf_encounters": sum(self._waf_attempt_count.values()),
        }


# ============================================================================
# Action Priority Queue
# ============================================================================


class ActionPriorityQueue:
    """
    Heapq-based priority queue for proposed actions.
    
    Maintains a sorted queue of candidate actions ranked by:
    - Three-axis composite score (time_to_impact, uncertainty_reduction, effort_eliminated)
    - Historical success rate for similar actions
    - Inverse of failure count (deprioritizes repeated failures)
    
    Implements deduplication to prevent enqueueing duplicate actions.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the action priority queue.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self._heap: List[Tuple[float, str, ProposedAction]] = []
        self._seen: Set[Tuple[str, str, str, int]] = set()
        self._action_counter = 0  # For stable sorting

    def push(
        self,
        action: ProposedAction,
        three_axis_composite: float,
        success_rate: float = 0.5,
        failure_count: int = 0,
    ) -> bool:
        """
        Add an action to the priority queue.
        
        Priority calculation:
            priority = three_axis_composite * success_rate * (1 / (1 + failure_count))
        
        Args:
            action: ProposedAction to enqueue
            three_axis_composite: Composite score from three-axis analysis
            success_rate: Historical success rate for similar actions (0.0-1.0)
            failure_count: Number of previous failures (used as penalty)
            
        Returns:
            True if action was enqueued, False if already present
        """
        key = (action.target, action.tool_name, action.vuln_class, action.tier)

        if key in self._seen:
            self.logger.debug(f"Duplicate action skipped: {key}")
            return False

        # Calculate priority with three factors
        failure_penalty = 1.0 / (1.0 + failure_count)
        priority = three_axis_composite * success_rate * failure_penalty

        self._seen.add(key)
        self._action_counter += 1

        # Use negative priority for min-heap (we want max priority first)
        heapq.heappush(
            self._heap,
            (-priority, str(self._action_counter).zfill(10), action),
        )

        self.logger.debug(
            f"Enqueued action for {action.target}/{action.vuln_class} "
            f"(priority={priority:.3f})"
        )

        return True

    def pop(self) -> Optional[ProposedAction]:
        """
        Remove and return the highest-priority action.
        
        Returns:
            ProposedAction if queue is non-empty, None otherwise
        """
        while self._heap:
            _, _, action = heapq.heappop(self._heap)
            key = (action.target, action.tool_name, action.vuln_class, action.tier)
            self._seen.discard(key)
            return action
        return None

    def peek(self) -> Optional[ProposedAction]:
        """
        View the highest-priority action without removing it.
        
        Returns:
            ProposedAction if queue is non-empty, None otherwise
        """
        if self._heap:
            _, _, action = self._heap[0]
            return action
        return None

    def reprioritize(self, action: ProposedAction, new_priority: float) -> bool:
        """
        Update priority of an action already in queue.
        
        Note: This is expensive (O(n)) and should be used sparingly.
        Consider dequeuing and re-enqueueing instead.
        
        Args:
            action: ProposedAction to update
            new_priority: New priority value
            
        Returns:
            True if reprioritized, False if not found
        """
        key = (action.target, action.tool_name, action.vuln_class, action.tier)

        # Linear search through heap (expensive but necessary for arbitrary reprioritization)
        for i, (_, _, heap_action) in enumerate(self._heap):
            heap_key = (
                heap_action.target,
                heap_action.tool_name,
                heap_action.vuln_class,
                heap_action.tier,
            )
            if heap_key == key:
                self._heap[i] = (-new_priority, str(i).zfill(10), action)
                heapq.heapify(self._heap)
                self.logger.debug(
                    f"Reprioritized action for {action.target} "
                    f"(new priority={new_priority:.3f})"
                )
                return True

        return False

    @property
    def size(self) -> int:
        """Get current queue size."""
        return len(self._heap)

    def drain(self) -> List[ProposedAction]:
        """
        Remove and return all actions in priority order.
        
        Returns:
            List of ProposedAction ordered by priority
        """
        actions = []
        while self._heap:
            _, _, action = heapq.heappop(self._heap)
            actions.append(action)
        self._seen.clear()
        self.logger.debug(f"Drained {len(actions)} actions from queue")
        return actions

    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return len(self._heap) == 0


# ============================================================================
# Strategy Advisor
# ============================================================================


class StrategyAdvisor:
    """
    Decision recommendation engine that analyzes feedback state and proposes
    strategic actions.
    
    Provides recommendations for:
    - Next actions to execute
    - Capability tier escalation decisions
    - Action abandonment (when to stop trying)
    - Lessons learned summaries
    """

    # Configuration thresholds
    ESCALATION_SUCCESS_THRESHOLD = 0.6  # Escalate to T3 if success rate > 60%
    ABANDONMENT_THRESHOLD = 5  # Abandon after 5 consecutive failures
    ABANDONMENT_FAILURE_RATE = 0.8  # Abandon if failure rate > 80%
    RECOVERY_ATTEMPTS = 3  # Try this many times before abandoning

    def __init__(
        self,
        feedback_tracker: FeedbackTracker,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize the strategy advisor.
        
        Args:
            feedback_tracker: FeedbackTracker instance for intelligence queries
            logger: Optional logger instance
        """
        self.feedback_tracker = feedback_tracker
        self.logger = logger or logging.getLogger(__name__)
        self._abandoned_actions: Set[Tuple[str, str]] = set()

    def recommend_actions(
        self,
        target: str,
        available_tools: Optional[List[str]] = None,
        vuln_classes: Optional[List[str]] = None,
        max_count: int = 5,
    ) -> List[ProposedAction]:
        """
        Recommend next actions for a target based on feedback analysis.
        
        Recommendation logic:
        1. Score each (tool, vuln_class) combination by priority
        2. Filter out abandoned actions
        3. Rank by composite priority (vuln_class_priority * tool_effectiveness)
        4. Return top N actions with rationale
        
        Args:
            target: Target identifier
            available_tools: List of tools available for deployment (optional)
            vuln_classes: List of vulnerability classes to consider (optional)
            max_count: Maximum number of recommendations (default 5)
            
        Returns:
            List of ProposedAction objects ranked by priority
        """
        recommendations = []
        intel = self.feedback_tracker.get_target_intelligence(target)

        # Default to common tools if not specified
        if available_tools is None:
            available_tools = [
                "sqlmap",
                "nikto",
                "burpsuite",
                "nessus",
                "metasploit",
            ]

        # Default to common vuln classes if not specified
        if vuln_classes is None:
            vuln_classes = [
                "SQL_INJECTION",
                "XSS",
                "CSRF",
                "RFI",
                "XXE",
                "AUTHENTICATION",
            ]

        # Score each candidate action
        candidates = []
        for tool in available_tools:
            for vuln_class in vuln_classes:
                # Skip abandoned actions
                if (target, vuln_class) in self._abandoned_actions:
                    continue

                vuln_priority = self.feedback_tracker.get_vuln_class_priority(
                    target, vuln_class
                )
                tool_effectiveness = self.feedback_tracker.get_tool_effectiveness(
                    tool
                )

                # Skip low-priority combinations
                if vuln_priority < 0.2 or tool_effectiveness < 0.1:
                    continue

                composite_score = vuln_priority * tool_effectiveness

                # Determine recommended tier
                tier = self._recommend_tier(target, vuln_class)

                # Estimate cost based on tier
                tier_costs = {0: 1, 1: 5, 2: 10, 3: 25, 4: 50}
                estimated_cost = tier_costs.get(tier, 10)

                # Build rationale
                rationale = self._build_rationale(
                    target, tool, vuln_class, vuln_priority, tool_effectiveness
                )

                action = ProposedAction(
                    target=target,
                    tool_name=tool,
                    vuln_class=vuln_class,
                    tier=tier,
                    priority=composite_score,
                    rationale=rationale,
                    estimated_cost=estimated_cost,
                )

                candidates.append((composite_score, action))

        # Sort by priority and return top N
        candidates.sort(reverse=True, key=lambda x: x[0])
        for _, action in candidates[:max_count]:
            recommendations.append(action)

        self.logger.info(
            f"Recommended {len(recommendations)} actions for {target}"
        )
        return recommendations

    def should_escalate_tier(self, target: str, current_tier: int) -> bool:
        """
        Determine if capability tier should be escalated for a target.
        
        Escalation criteria:
        - Current tier < T4
        - AND overall success rate > ESCALATION_SUCCESS_THRESHOLD
        - AND no WAF detected (WAF escalation rarely helps)
        
        Args:
            target: Target identifier
            current_tier: Current capability tier (0-4)
            
        Returns:
            True if escalation is recommended
        """
        if current_tier >= CapabilityTier.T4:
            return False

        intel = self.feedback_tracker.get_target_intelligence(target)

        # Don't escalate if we've already tried plenty and haven't succeeded
        if (
            intel.total_actions >= 10
            and intel.success_rate < self.ESCALATION_SUCCESS_THRESHOLD
        ):
            return False

        # Don't escalate against detected WAF
        if intel.waf_detected:
            self.logger.debug(
                f"Skipping escalation for {target}: WAF detected ({intel.waf_detected})"
            )
            return False

        # Escalate if we're on a successful trajectory
        should_escalate = intel.success_rate >= self.ESCALATION_SUCCESS_THRESHOLD
        if should_escalate:
            self.logger.info(
                f"Recommending escalation for {target} "
                f"(success rate: {intel.success_rate:.2%})"
            )

        return should_escalate

    def should_abandon(self, target: str, vuln_class: str) -> bool:
        """
        Determine if attempts to exploit a vulnerability should be abandoned.
        
        Abandonment criteria:
        - Either: >= ABANDONMENT_THRESHOLD consecutive failures
        - OR: failure_rate > ABANDONMENT_FAILURE_RATE with >= MIN_SAMPLES_FOR_STATS attempts
        - AND: not a newly discovered vulnerability (give new vulns RECOVERY_ATTEMPTS)
        
        Args:
            target: Target identifier
            vuln_class: Vulnerability classification
            
        Returns:
            True if abandonment is recommended
        """
        key = (target, vuln_class)
        if key in self._abandoned_actions:
            return True  # Already abandoned

        intel = self.feedback_tracker.get_target_intelligence(target)
        attempts = self.feedback_tracker._vuln_class_attempts.get(key, 0)
        hits = self.feedback_tracker._vuln_class_hits.get(key, 0)

        # Too few attempts: give it more chances
        if attempts < self.RECOVERY_ATTEMPTS:
            return False

        # High failure rate after many attempts
        failure_rate = (attempts - hits) / attempts if attempts > 0 else 0.0
        if failure_rate > self.ABANDONMENT_FAILURE_RATE and attempts >= 5:
            self.logger.warning(
                f"Recommending abandonment of {target}/{vuln_class} "
                f"(failure rate: {failure_rate:.2%})"
            )
            self._abandoned_actions.add(key)
            return True

        return False

    def get_lesson_learned(self, target: str) -> str:
        """
        Generate a human-readable summary of what was learned about a target.
        
        Includes:
        - Success rate and action count
        - Most effective tools
        - Most vulnerable vuln classes
        - WAF detection if applicable
        - Budget consumption
        
        Args:
            target: Target identifier
            
        Returns:
            Formatted string with target assessment
        """
        intel = self.feedback_tracker.get_target_intelligence(target)

        lines = [
            f"Target Assessment: {target}",
            f"  Total actions: {intel.total_actions}",
            f"  Success rate: {intel.success_rate:.1%}",
            f"  Budget consumed: {intel.budget_consumed} tokens",
        ]

        if intel.tool_effectiveness:
            best_tool = max(
                intel.tool_effectiveness.items(), key=lambda x: x[1]
            )
            lines.append(f"  Most effective tool: {best_tool[0]} ({best_tool[1]:.1%})")

        if intel.vulnerability_hits:
            best_vuln = max(intel.vulnerability_hits.items(), key=lambda x: x[1])
            lines.append(
                f"  Most vulnerable class: {best_vuln[0]} ({best_vuln[1]} hits)"
            )

        if intel.waf_detected:
            lines.append(
                f"  WAF detected: {intel.waf_detected} "
                f"({intel.waf_encounter_count} encounters)"
            )

        return "\n".join(lines)

    # ========================================================================
    # Private Helper Methods
    # ========================================================================

    def _recommend_tier(self, target: str, vuln_class: str) -> int:
        """
        Recommend a capability tier for (target, vuln_class) pair.
        
        Logic:
        - Start with T1 (passive/light)
        - Escalate to T2 if success_rate > 40%
        - Escalate to T3 if success_rate > 60%
        - Escalate to T4 if success_rate > 80% and not WAF-blocked
        
        Args:
            target: Target identifier
            vuln_class: Vulnerability classification
            
        Returns:
            Recommended tier (0-4)
        """
        intel = self.feedback_tracker.get_target_intelligence(target)
        priority = self.feedback_tracker.get_vuln_class_priority(target, vuln_class)

        # Start conservative
        tier = CapabilityTier.T1

        # Escalate based on success trajectory
        if priority > 0.4:
            tier = CapabilityTier.T2
        if priority > 0.6 and not intel.waf_detected:
            tier = CapabilityTier.T3
        if priority > 0.8 and not intel.waf_detected and intel.total_actions >= 5:
            tier = CapabilityTier.T4

        return tier

    def _build_rationale(
        self,
        target: str,
        tool: str,
        vuln_class: str,
        vuln_priority: float,
        tool_effectiveness: float,
    ) -> str:
        """
        Build a human-readable explanation for an action recommendation.
        
        Args:
            target: Target identifier
            tool: Tool name
            vuln_class: Vulnerability class
            vuln_priority: Priority score for this vuln_class on this target
            tool_effectiveness: Effectiveness score for the tool
            
        Returns:
            Human-readable rationale string
        """
        intel = self.feedback_tracker.get_target_intelligence(target)

        reasons = []

        if vuln_priority > 0.7:
            reasons.append(f"High success probability ({vuln_priority:.1%})")
        elif vuln_priority > 0.5:
            reasons.append(f"Moderate promise ({vuln_priority:.1%})")

        if tool_effectiveness > 0.7:
            reasons.append(f"{tool} is highly effective")
        elif tool_effectiveness > 0.5:
            reasons.append(f"{tool} shows promise")

        if intel.waf_detected:
            reasons.append("(caution: WAF detected)")

        return " | ".join(reasons) if reasons else "Exploratory scan"


# ============================================================================
# Public API
# ============================================================================


def create_feedback_system(
    logger: Optional[logging.Logger] = None,
) -> Tuple[FeedbackTracker, ActionPriorityQueue, StrategyAdvisor]:
    """
    Factory function to create and wire together the feedback loop components.
    
    Args:
        logger: Optional logger instance (creates default if not provided)
        
    Returns:
        Tuple of (FeedbackTracker, ActionPriorityQueue, StrategyAdvisor)
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    tracker = FeedbackTracker(logger=logger)
    queue = ActionPriorityQueue(logger=logger)
    advisor = StrategyAdvisor(tracker, logger=logger)

    logger.info("Feedback loop system initialized")
    return tracker, queue, advisor
