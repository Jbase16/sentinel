"""
NEXUS Chain Executor - Proof Generation

PURPOSE:
Execute validated exploit chains to generate proof of concept demonstrations.
This turns theoretical chain plans into verifiable evidence.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Verify that theoretical chains actually work
- Generate proof for remediation prioritization
- Test defense-in-depth effectiveness
- Demonstrate risk to stakeholders safely

ASSUMPTIONS:
1. Chains have been pre-validated and approved
2. Execution is non-destructive (read-only where possible)
3. Proof is captured at each step
4. Execution can be aborted mid-chain

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, refuses to execute any steps
- Explicit approval required for execution
- Abort on any unexpected response
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_CHAIN_STARTED, NEXUS_CHAIN_STEP_COMPLETED events
- DecisionLedger: Logs execution decisions and aborts
- EvidenceStore: Stores proof artifacts

DEPENDENCIES (Future):
- asyncio: For sequential step execution
- aiohttp: For HTTP requests during execution
- json: For request/response handling
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class ExecutionStatus(str, Enum):
    """
    Status of a chain execution.
    """
    PENDING = "pending"           # Not yet started
    RUNNING = "running"           # Currently executing
    COMPLETED = "completed"       # All steps succeeded
    FAILED = "failed"             # Chain broken (step failed)
    ABORTED = "aborted"           # Manually stopped
    TIMEOUT = "timeout"           # Took too long


class StepStatus(str, Enum):
    """
    Status of an individual chain step.
    """
    PENDING = "pending"           # Not yet started
    RUNNING = "running"           # Currently executing
    SUCCESS = "success"           # Step completed successfully
    FAILED = "failed"             # Step failed (chain broken)
    SKIPPED = "skipped"           # Skipped due to prior failure


@dataclass
class StepResult:
    """
    Result of executing a single chain step.

    Attributes:
        step: The chain step that was executed
        status: What happened
        response: HTTP response data (if applicable)
        proof: Evidence of success/failure
        error_message: Any error details
        executed_at: When this step was executed
        duration_ms: How long the step took
    """
    step: "ChainStep"
    status: StepStatus
    response: Optional[Dict[str, Any]] = None
    proof: Optional[str] = None
    error_message: Optional[str] = None
    executed_at: datetime = field(default_factory=lambda: datetime.utcnow())
    duration_ms: Optional[int] = None

    @property
    def is_success(self) -> bool:
        """Check if step executed successfully."""
        return self.status == StepStatus.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dict."""
        return {
            "primitive_id": self.step.primitive_id,
            "primitive_type": self.step.primitive_type,
            "description": self.step.description,
            "status": self.status.value,
            "has_response": self.response is not None,
            "proof": self.proof,
            "error_message": self.error_message,
            "executed_at": self.executed_at.isoformat(),
            "duration_ms": self.duration_ms,
        }


@dataclass
class ExecutionProof:
    """
    Aggregated proof from a chain execution.

    This contains all evidence needed to demonstrate that
    the exploit chain works (or doesn't).

    Attributes:
        chain_id: Which chain this proves
        target: Domain this was executed against
        goal: Target goal state
        overall_status: Final execution status
        step_results: Results for each executed step
        completed_steps: How many steps succeeded
        total_steps: Total steps in chain
        started_at: When execution started
        completed_at: When execution completed
        duration_seconds: Total execution time
    """
    chain_id: str
    target: str
    goal: "GoalState"
    overall_status: ExecutionStatus
    step_results: List[StepResult] = field(default_factory=list)
    completed_steps: int = 0
    total_steps: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.utcnow())
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    @property
    def success_rate(self) -> float:
        """Get percentage of steps that succeeded."""
        if self.total_steps == 0:
            return 0.0
        return (self.completed_steps / self.total_steps) * 100

    @property
    def is_proven(self) -> bool:
        """Check if chain was successfully proven."""
        return self.overall_status == ExecutionStatus.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        """Serialize proof to dict."""
        return {
            "chain_id": self.chain_id,
            "target": self.target,
            "goal": self.goal.value,
            "overall_status": self.overall_status.value,
            "completed_steps": self.completed_steps,
            "total_steps": self.total_steps,
            "success_rate": round(self.success_rate, 2),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "step_results": [sr.to_dict() for sr in self.step_results],
        }


@dataclass
class ChainResult:
    """
    Result of a chain execution attempt.

    Attributes:
        proof: Execution proof with all step results
        error: Any execution error (if failed early)
    """
    proof: Optional[ExecutionProof] = None
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        """Check if chain executed successfully."""
        return self.proof is not None and self.proof.is_proven


class ChainExecutor:
    """
    Executes exploit chains to generate proof.

    This class takes a validated ChainPlan and attempts to execute
    it step-by-step, capturing evidence at each stage.

    EXECUTION STRATEGY:
    1. Validate chain is approved for execution
    2. Execute steps sequentially
    3. Verify each step succeeded before proceeding
    4. Capture proof (responses, screenshots, etc.)
    5. Abort on failure or timeout
    6. Return aggregated proof

    EXAMPLE USAGE:
        ```python
        executor = ChainExecutor()
        plan = ChainPlan(...)
        result = await executor.execute_chain(plan, approval_token="...")
        if result.succeeded:
            print("Chain proven!")
        ```
    """

    # Event names for integration with EventBus
    EVENT_EXECUTION_STARTED = "nexus_chain_started"
    EVENT_EXECUTION_COMPLETED = "nexus_chain_completed"
    EVENT_STEP_STARTED = "nexus_step_started"
    EVENT_STEP_COMPLETED = "nexus_step_completed"
    EVENT_CHAIN_ABORTED = "nexus_chain_aborted"

    # Timeouts
    DEFAULT_STEP_TIMEOUT = 30  # seconds
    DEFAULT_CHAIN_TIMEOUT = 300  # seconds (5 minutes)

    def __init__(
        self,
        safe_mode: bool = SAFE_MODE,
        step_timeout: int = DEFAULT_STEP_TIMEOUT,
        chain_timeout: int = DEFAULT_CHAIN_TIMEOUT,
    ):
        """
        Initialize ChainExecutor.

        Args:
            safe_mode: If True, refuses to execute any chains
            step_timeout: Max seconds per step
            chain_timeout: Max seconds for entire chain
        """
        self._safe_mode = safe_mode
        self._step_timeout = step_timeout
        self._chain_timeout = chain_timeout
        self._execution_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def execution_count(self) -> int:
        """Get number of executions performed."""
        return self._execution_count

    async def execute_chain(
        self,
        plan: "ChainPlan",
        approval_token: Optional[str] = None,
        target_override: Optional[str] = None,
    ) -> ChainResult:
        """
        Execute a chain plan to generate proof.

        TODO: Implement approval token validation.
        TODO: Execute steps sequentially with verification.
        TODO: Capture proof at each step (response, status, etc.).
        TODO: Abort chain on step failure.
        TODO: Handle timeouts gracefully.

        Args:
            plan: The chain plan to execute
            approval_token: Optional approval token
            target_override: Override target (for testing)

        Returns:
            ChainResult with proof or error

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Check safe mode
        if self._safe_mode:
            raise RuntimeError(
                "SAFE_MODE: Chain execution is disabled. "
                "Set safe_mode=False to enable execution."
            )

        # Validate approval
        if not self._validate_approval(approval_token):
            raise PermissionError("Invalid or missing approval token")

        # Update statistics
        self._execution_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[ChainExecutor] {self.EVENT_EXECUTION_STARTED}: "
            f"chain_id={plan.id}, goal={plan.goal.value}"
        )

        raise NotImplementedError(
            "Wrapper-only: Chain execution implementation deferred. "
            "Future implementation should execute steps sequentially."
        )

    async def execute_step(
        self,
        step: "ChainStep",
        target: str,
    ) -> StepResult:
        """
        Execute a single chain step.

        TODO: Implement step-specific execution logic.
        TODO: Handle different primitive types.
        TODO: Capture response data.
        TODO: Verify step success condition.

        Args:
            step: The step to execute
            target: Target domain

        Returns:
            StepResult with execution outcome

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Step execution implementation deferred. "
            "Future implementation should dispatch by primitive type."
        )

    def verify_step_success(
        self,
        step: "ChainStep",
        response: Dict[str, Any]
    ) -> bool:
        """
        Verify that a step achieved its objective.

        TODO: Implement success condition checking.
        TODO: Verify response status code.
        TODO: Check for expected response content.
        TODO: Validate side effects occurred.

        Args:
            step: The step that was executed
            response: HTTP response data

        Returns:
            True if step succeeded

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Step verification deferred. "
            "Future implementation should check response conditions."
        )

    def generate_proof_artifact(
        self,
        proof: ExecutionProof
    ) -> Dict[str, Any]:
        """
        Generate a shareable proof artifact from execution.

        TODO: Format proof for report generation.
        TODO: Include screenshots/images if available.
        TODO: Sanitize sensitive data from proof.
        TODO: Generate human-readable summary.

        Args:
            proof: Execution proof to format

        Returns:
            Formatted proof artifact

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Proof generation deferred. "
            "Future implementation should format for reports."
        )

    def _validate_approval(self, token: Optional[str]) -> bool:
        """
        Validate approval token for chain execution.

        TODO: Implement token validation logic.
        TODO: Check token signature/expiry.
        TODO: Verify token scope for this chain.

        Args:
            token: Approval token to validate

        Returns:
            True if token is valid

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Approval validation deferred. "
            "Future implementation should verify token signatures."
        )

    def replay(self, recorded_execution: Dict[str, Any]) -> ChainResult:
        """
        Replay a previously generated execution proof.

        Enables replayability without re-executing chains.

        Args:
            recorded_execution: Serialized ExecutionProof from to_dict()

        Returns:
            Reconstructed ChainResult

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Execution replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this ChainExecutor instance.

        Returns:
            Dictionary with execution statistics
        """
        return {
            "execution_count": self._execution_count,
            "safe_mode": self._safe_mode,
            "step_timeout": self._step_timeout,
            "chain_timeout": self._chain_timeout,
        }


def create_chain_executor(
    safe_mode: bool = SAFE_MODE,
    step_timeout: int = ChainExecutor.DEFAULT_STEP_TIMEOUT,
    chain_timeout: int = ChainExecutor.DEFAULT_CHAIN_TIMEOUT,
) -> ChainExecutor:
    """
    Factory function to create ChainExecutor instance.

    This is the recommended way to create ChainExecutor objects in production code.

    Args:
        safe_mode: Safety mode flag
        step_timeout: Max seconds per step
        chain_timeout: Max seconds for entire chain

    Returns:
        Configured ChainExecutor instance
    """
    return ChainExecutor(
        safe_mode=safe_mode,
        step_timeout=step_timeout,
        chain_timeout=chain_timeout,
    )


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    from core.nexus.solver import ChainStep, ChainPlan, GoalState

    # Verify enums
    assert ExecutionStatus.COMPLETED.value == "completed"
    assert StepStatus.SUCCESS.value == "success"
    print("✓ Enums work")

    # Verify StepResult dataclass
    step = ChainStep(
        primitive_id="prim_123",
        primitive_type="reflected_param",
        description="Test step",
    )
    step_result = StepResult(
        step=step,
        status=StepStatus.SUCCESS,
        proof="Worked!",
    )
    assert step_result.is_success is True
    assert step_result.to_dict()["status"] == "success"
    print("✓ StepResult structure works")

    # Verify ExecutionProof dataclass
    proof = ExecutionProof(
        chain_id="chain_123",
        target="example.com",
        goal=GoalState.ADMIN_ACCESS,
        overall_status=ExecutionStatus.COMPLETED,
        step_results=[step_result],
        completed_steps=1,
        total_steps=1,
    )
    assert proof.is_proven is True
    assert proof.success_rate == 100.0
    assert proof.to_dict()["success_rate"] == 100.0
    print("✓ ExecutionProof structure works")

    # Verify ChainExecutor creation
    executor = create_chain_executor()
    assert executor.safe_mode is True
    assert executor.execution_count == 0
    print("✓ ChainExecutor factory works")

    # Verify safe mode enforcement
    try:
        import asyncio
        plan = ChainPlan(
            id=str(uuid.uuid4()),
            goal=GoalState.ADMIN_ACCESS,
            start_primitive="prim_123",
        )
        asyncio.run(executor.execute_chain(plan))
        print("✗ Safe mode enforcement failed")
    except RuntimeError as e:
        if "SAFE_MODE" in str(e):
            print("✓ Safe mode enforcement works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All ChainExecutor design invariants verified!")
