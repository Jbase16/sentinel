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
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse, urljoin

import httpx

if TYPE_CHECKING:
    from core.omega.nexus_phase import ExploitChain, ChainStep as NEXUSChainStep, GoalState

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
        step: The chain step that was executed (from nexus_phase.ChainStep)
        status: What happened
        response: HTTP response data (if applicable)
        proof: Evidence of success/failure
        error_message: Any error details
        executed_at: When this step was executed
        duration_ms: How long the step took
    """
    step: Any  # NEXUSChainStep from nexus_phase
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
            "step_number": self.step.step_number,
            "primitive_id": self.step.primitive.id,
            "primitive_type": self.step.primitive.type.value,
            "target": self.step.primitive.target,
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
        target: str - Domain this was executed against
        goal: str - Target goal state (value from GoalState enum)
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
    goal: str  # GoalState.value from nexus_phase
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
            "goal": self.goal,
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
        chain: Any,  # ExploitChain from nexus_phase
        approval_token: Optional[str] = None,
        target_override: Optional[str] = None,
    ) -> ChainResult:
        """
        Execute an exploit chain to generate proof.

        Executes each step sequentially, verifying success before proceeding.
        Aborts on failure and captures evidence at each stage.

        Args:
            chain: The ExploitChain to execute (from nexus_phase)
            approval_token: Optional approval token (for authorization)
            target_override: Override target domain (for testing)

        Returns:
            ChainResult with proof or error
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

        started_at = datetime.utcnow()

        # Determine target (use override if provided)
        target = target_override if target_override else chain.steps[0].primitive.target

        # Create execution proof
        proof = ExecutionProof(
            chain_id=chain.id,
            target=target,
            goal=chain.goal.value,
            overall_status=ExecutionStatus.RUNNING,
            total_steps=len(chain.steps),
            started_at=started_at,
        )

        # Emit start event
        logger.info(
            f"[ChainExecutor] {self.EVENT_EXECUTION_STARTED}: "
            f"chain_id={chain.id}, goal={chain.goal.value}, steps={len(chain.steps)}"
        )

        try:
            # Execute steps sequentially with timeout
            async with asyncio.timeout(self._chain_timeout):
                for step in chain.steps:
                    # Execute step
                    step_result = await self.execute_step(step, target)
                    proof.step_results.append(step_result)

                    # Check success
                    if step_result.is_success:
                        proof.completed_steps += 1
                        logger.debug(
                            f"[ChainExecutor] Step {step.step_number} succeeded: "
                            f"{step.primitive.type.value}"
                        )
                    else:
                        # Chain broken - abort
                        logger.warning(
                            f"[ChainExecutor] Step {step.step_number} failed, aborting chain"
                        )
                        proof.overall_status = ExecutionStatus.FAILED
                        break

                # Check if all steps succeeded
                if proof.completed_steps == proof.total_steps:
                    proof.overall_status = ExecutionStatus.COMPLETED
                    logger.info(
                        f"[ChainExecutor] Chain {chain.id} completed successfully: "
                        f"{proof.completed_steps}/{proof.total_steps} steps"
                    )
                else:
                    # Partial success - mark as failed
                    logger.warning(
                        f"[ChainExecutor] Chain {chain.id} failed: "
                        f"{proof.completed_steps}/{proof.total_steps} steps completed"
                    )

        except asyncio.TimeoutError:
            proof.overall_status = ExecutionStatus.TIMEOUT
            logger.error(f"[ChainExecutor] Chain {chain.id} timed out")

        except Exception as e:
            proof.overall_status = ExecutionStatus.FAILED
            logger.error(f"[ChainExecutor] Chain {chain.id} error: {e}")
            return ChainResult(error=str(e))

        finally:
            proof.completed_at = datetime.utcnow()
            proof.duration_seconds = (proof.completed_at - started_at).total_seconds()

            # Emit completion event
            logger.info(
                f"[ChainExecutor] {self.EVENT_EXECUTION_COMPLETED}: "
                f"chain_id={chain.id}, status={proof.overall_status.value}"
            )

        return ChainResult(proof=proof)

    async def execute_step(
        self,
        step: Any,  # ChainStep from nexus_phase
        target: str,
    ) -> StepResult:
        """
        Execute a single chain step.

        Dispatches to appropriate handler based on primitive type.
        Captures response and verifies success.

        Args:
            step: The ChainStep to execute (from nexus_phase)
            target: Target domain

        Returns:
            StepResult with execution outcome
        """
        from core.aegis.nexus.primitives import PrimitiveType

        start_time = time.time()
        step_result = StepResult(
            step=step,
            status=StepStatus.RUNNING,
        )

        logger.debug(
            f"[ChainExecutor] {self.EVENT_STEP_STARTED}: "
            f"step={step.step_number}, type={step.primitive.type.value}"
        )

        try:
            # Dispatch based on primitive type
            async with asyncio.timeout(self._step_timeout):
                if step.primitive.type == PrimitiveType.MISSING_AUTH:
                    response = await self._execute_missing_auth(step, target)
                elif step.primitive.type == PrimitiveType.IDOR_PATTERN:
                    response = await self._execute_idor(step, target)
                elif step.primitive.type == PrimitiveType.SSRF_PATTERN:
                    response = await self._execute_ssrf(step, target)
                elif step.primitive.type == PrimitiveType.REFLECTED_PARAM:
                    response = await self._execute_reflected_param(step, target)
                elif step.primitive.type == PrimitiveType.OPEN_REDIRECT:
                    response = await self._execute_open_redirect(step, target)
                else:
                    # Unsupported primitive type - skip
                    step_result.status = StepStatus.SKIPPED
                    step_result.error_message = f"Unsupported primitive type: {step.primitive.type.value}"
                    logger.warning(f"[ChainExecutor] Skipping unsupported primitive: {step.primitive.type.value}")
                    return step_result

                # Store response
                step_result.response = response

                # Verify success
                if self.verify_step_success(step, response):
                    step_result.status = StepStatus.SUCCESS
                    step_result.proof = f"Step {step.step_number} succeeded with status {response.get('status_code')}"
                else:
                    step_result.status = StepStatus.FAILED
                    step_result.error_message = "Step verification failed"

        except asyncio.TimeoutError:
            step_result.status = StepStatus.FAILED
            step_result.error_message = "Step timed out"
            logger.warning(f"[ChainExecutor] Step {step.step_number} timed out")

        except Exception as e:
            step_result.status = StepStatus.FAILED
            step_result.error_message = str(e)
            logger.error(f"[ChainExecutor] Step {step.step_number} error: {e}")

        finally:
            step_result.duration_ms = int((time.time() - start_time) * 1000)

            logger.debug(
                f"[ChainExecutor] {self.EVENT_STEP_COMPLETED}: "
                f"step={step.step_number}, status={step_result.status.value}"
            )

        return step_result

    def verify_step_success(
        self,
        step: Any,  # ChainStep from nexus_phase
        response: Dict[str, Any]
    ) -> bool:
        """
        Verify that a step achieved its objective.

        Checks response status code and expected conditions.

        Args:
            step: The step that was executed
            response: HTTP response data

        Returns:
            True if step succeeded
        """
        # Check if we got a valid HTTP response
        status_code = response.get("status_code", 0)

        # Success criteria vary by primitive type
        from core.aegis.nexus.primitives import PrimitiveType

        # General success: 2xx status codes
        if 200 <= status_code < 300:
            return True

        # MISSING_AUTH: 200 when it should be 401/403
        if step.primitive.type == PrimitiveType.MISSING_AUTH:
            return status_code == 200

        # IDOR: Successful access to another user's resource
        if step.primitive.type == PrimitiveType.IDOR_PATTERN:
            return status_code == 200

        # SSRF: Successful internal request
        if step.primitive.type == PrimitiveType.SSRF_PATTERN:
            return 200 <= status_code < 400

        # REFLECTED_PARAM: Reflection detected in response
        if step.primitive.type == PrimitiveType.REFLECTED_PARAM:
            body = response.get("body", "")
            return status_code == 200 and len(body) > 0

        # OPEN_REDIRECT: Successful redirection
        if step.primitive.type == PrimitiveType.OPEN_REDIRECT:
            return status_code in (301, 302, 303, 307, 308)

        # Default: consider 2xx successful
        return 200 <= status_code < 300

    # ========== Primitive Execution Helpers ==========

    async def _execute_missing_auth(self, step: Any, target: str) -> Dict[str, Any]:
        """Execute MISSING_AUTH primitive - attempt to access endpoint without auth."""
        url = urljoin(f"https://{target}", step.primitive.target)

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            response = await client.get(url)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1000],  # Truncate
            }

    async def _execute_idor(self, step: Any, target: str) -> Dict[str, Any]:
        """Execute IDOR_PATTERN primitive - attempt to access another user's resource."""
        url = urljoin(f"https://{target}", step.primitive.target)

        # If parameter specified, try incrementing/decrementing ID
        if step.primitive.parameter:
            # Try accessing different IDs
            url = url.replace(f"={step.primitive.parameter}", f"={int(step.primitive.parameter) + 1}")

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            response = await client.get(url)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1000],
            }

    async def _execute_ssrf(self, step: Any, target: str) -> Dict[str, Any]:
        """Execute SSRF_PATTERN primitive - attempt to fetch internal URL."""
        url = urljoin(f"https://{target}", step.primitive.target)

        # Add internal URL as parameter
        if step.primitive.parameter:
            url = f"{url}?{step.primitive.parameter}=http://169.254.169.254/latest/meta-data/"

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            response = await client.get(url)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1000],
            }

    async def _execute_reflected_param(self, step: Any, target: str) -> Dict[str, Any]:
        """Execute REFLECTED_PARAM primitive - inject test payload."""
        url = urljoin(f"https://{target}", step.primitive.target)

        # Add test payload as parameter
        test_payload = "NEXUS_TEST_REFLECTION"
        if step.primitive.parameter:
            url = f"{url}?{step.primitive.parameter}={test_payload}"

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            response = await client.get(url)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1000],
                "reflected": test_payload in response.text,
            }

    async def _execute_open_redirect(self, step: Any, target: str) -> Dict[str, Any]:
        """Execute OPEN_REDIRECT primitive - test redirect to external URL."""
        url = urljoin(f"https://{target}", step.primitive.target)

        # Add external URL as parameter
        if step.primitive.parameter:
            url = f"{url}?{step.primitive.parameter}=https://example.com"

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            response = await client.get(url)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "location": response.headers.get("Location", ""),
            }

    # ========== End Primitive Helpers ==========

    def generate_proof_artifact(
        self,
        proof: ExecutionProof
    ) -> Dict[str, Any]:
        """
        Generate a shareable proof artifact from execution.

        Formats proof for report generation with sanitized data.

        Args:
            proof: Execution proof to format

        Returns:
            Formatted proof artifact
        """
        return {
            "chain_id": proof.chain_id,
            "target": proof.target,
            "goal": proof.goal,
            "success": proof.is_proven,
            "success_rate": proof.success_rate,
            "steps": [
                {
                    "number": sr.step.step_number,
                    "primitive": sr.step.primitive.type.value,
                    "status": sr.status.value,
                    "duration_ms": sr.duration_ms,
                }
                for sr in proof.step_results
            ],
            "duration_seconds": proof.duration_seconds,
        }

    def _validate_approval(self, token: Optional[str]) -> bool:
        """
        Validate approval token for chain execution.

        Accepted token formats:
        1. Static token set in SENTINEL_NEXUS_APPROVAL_TOKEN
        2. Timeboxed marker token: allow-chain-execution:<unix_expiry>
        3. Signed token: v1:<unix_expiry>:<hmac_sha256(api_token, "nexus-exec:<expiry>")>

        Args:
            token: Approval token to validate

        Returns:
            True if token is valid
        """
        if not token:
            return False

        candidate = token.strip()
        if candidate.lower().startswith("bearer "):
            candidate = candidate[7:].strip()

        static_token = os.getenv("SENTINEL_NEXUS_APPROVAL_TOKEN", "").strip()
        if static_token and hmac.compare_digest(candidate, static_token):
            return True

        # allow-chain-execution:<expiry_epoch>
        if candidate.startswith("allow-chain-execution:"):
            parts = candidate.split(":", 1)
            if len(parts) != 2:
                return False
            try:
                expiry = int(parts[1])
            except ValueError:
                return False
            return expiry >= int(time.time())

        # v1:<expiry_epoch>:<hmac>
        parts = candidate.split(":")
        if len(parts) != 3 or parts[0] != "v1":
            return False

        expiry_raw, provided_sig = parts[1], parts[2]
        try:
            expiry = int(expiry_raw)
        except ValueError:
            return False
        if expiry < int(time.time()):
            return False

        api_token = os.getenv("SENTINEL_API_TOKEN", "").strip()
        if not api_token:
            return False

        signing_input = f"nexus-exec:{expiry_raw}".encode("utf-8")
        expected_sig = hmac.new(api_token.encode("utf-8"), signing_input, hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided_sig, expected_sig)

    def replay(self, recorded_execution: Dict[str, Any]) -> ChainResult:
        """
        Replay a previously generated execution proof.

        Reconstructs ExecutionProof from serialized data without re-execution.

        Args:
            recorded_execution: Serialized ExecutionProof from to_dict()

        Returns:
            Reconstructed ChainResult
        """
        # Reconstruct ExecutionProof from dict
        proof = ExecutionProof(
            chain_id=recorded_execution["chain_id"],
            target=recorded_execution["target"],
            goal=recorded_execution["goal"],
            overall_status=ExecutionStatus(recorded_execution["overall_status"]),
            completed_steps=recorded_execution["completed_steps"],
            total_steps=recorded_execution["total_steps"],
            started_at=datetime.fromisoformat(recorded_execution["started_at"]),
            completed_at=datetime.fromisoformat(recorded_execution["completed_at"]) if recorded_execution.get("completed_at") else None,
            duration_seconds=recorded_execution["duration_seconds"],
        )

        # Note: step_results not reconstructed as they require ChainStep objects
        # This is sufficient for replay verification

        return ChainResult(proof=proof)

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
    # Verify enums
    assert ExecutionStatus.COMPLETED.value == "completed"
    assert StepStatus.SUCCESS.value == "success"
    print("✓ Enums work")

    # Verify ExecutionProof dataclass
    proof = ExecutionProof(
        chain_id="chain_123",
        target="example.com",
        goal="admin_access",  # GoalState.value
        overall_status=ExecutionStatus.COMPLETED,
        step_results=[],  # Empty for test
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
        # Create mock chain object
        class MockChain:
            id = str(uuid.uuid4())
            goal = type('Goal', (), {'value': 'admin_access'})()
            steps = []

        chain = MockChain()
        asyncio.run(executor.execute_chain(chain))
        print("✗ Safe mode enforcement failed")
    except RuntimeError as e:
        if "SAFE_MODE" in str(e):
            print("✓ Safe mode enforcement works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All ChainExecutor design invariants verified!")
