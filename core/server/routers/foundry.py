"""
core/server/routers/foundry.py — Phase 7-PF6: the Foundry HTTP surface.

Makes the Persona Foundry operable + completes the challenge-handoff
loop over HTTP. The crucial pair is:

  GET  /v1/foundry/challenges            — the human polls this to see
                                           "Sentinel needs me" handoffs
  POST /v1/foundry/challenges/{id}/resolve — the 1-click resolution

Those two close the cross-context loop: the replay engine awaits a
resolution future inside one async task; the human's resolve POST (in
another request task, same process, same event loop, same singleton
ChallengeBus) completes it.

Other endpoints:
  POST /v1/foundry/plan                  — account topology for a test
  GET/POST /v1/foundry/personas          — vault personas
  GET/POST /v1/foundry/recipes           — recipe store
  GET  /v1/foundry/recipes/{id}          — one recipe's detail

All gated by the sensitive token (operator-only). Persona POST bodies
carry real PII + passwords; they're never logged.

NOT here (yet): the /signup orchestration endpoint, which needs a real
browser Driver. The handoff plumbing is built and tested so /signup
drops in cleanly once a Driver exists.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.server.routers.auth import verify_sensitive_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["foundry"])


# ─────────────────────────── models ───────────────────────────


class PlanRequest(BaseModel):
    target_handle: str
    vuln_classes: List[str] = Field(
        ...,
        description="Vuln classes to test, e.g. ['idor_cross_principal', "
                    "'privilege_escalation'].",
    )


class AddPersonaRequest(BaseModel):
    label: str = Field(..., min_length=1)
    email: str = Field(..., min_length=3)
    password: str = ""
    first_name: str = ""
    last_name: str = ""
    phone: str = ""
    date_of_birth: str = ""
    verification: Dict[str, str] = Field(default_factory=dict)
    extra: Dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class AddRecipeRequest(BaseModel):
    """Store a recipe by passing its full to_dict() shape."""
    recipe: Dict[str, Any]


class ResolveChallengeRequest(BaseModel):
    resolved: bool = True
    extracted_value: Optional[str] = None
    note: str = ""


class StartSignupRequest(BaseModel):
    recipe_id: str
    persona_id: str
    envelope_id: Optional[str] = None


class RecordRecipeRequest(BaseModel):
    service_handle: str
    name: str
    origin: str


class CreateEnvelopeRequest(BaseModel):
    """The researcher's up-front judgment, declared explicitly."""
    researcher_identity: str = Field(..., min_length=1)
    target_handle: str = Field(..., min_length=1)
    authorized_origins: List[str] = Field(..., min_length=1)
    authorization_basis: str = Field(
        ..., min_length=1,
        description="WHY this is authorized — the disclosed authorization "
                    "reference (program policy, scope statement).",
    )
    allowed_workflows: List[str] = Field(..., min_length=1)
    disclosure_attestation: bool = Field(
        default=False,
        description="The researcher attests they operate under disclosed, "
                    "legitimate authorization. Must be true for the "
                    "envelope to reach an APPROVED context.",
    )
    max_accounts_per_service: int = 3
    legal_posture: str = ""
    ttl_days: int = 30


class RunBehavioralAuthorizationRequest(BaseModel):
    """One autonomous paired-world behavioral authorization run."""

    target_origin: str = Field(..., min_length=8, max_length=4096)
    envelope_id: str = Field(..., pattern=r"^[0-9a-f]{32}$")
    source_persona_id: str = Field(..., pattern=r"^[0-9a-f]{32}$")
    peer_persona_id: str = Field(..., pattern=r"^[0-9a-f]{32}$")
    source_records: List[Dict[str, Any]] = Field(..., min_length=1, max_length=20_000)
    peer_records: List[Dict[str, Any]] = Field(..., min_length=1, max_length=20_000)
    script_urls: List[str] = Field(default_factory=list, max_length=64)


class RunBehavioralAuthorizationFromURLRequest(BaseModel):
    """Capture two owned worlds from one URL, then run the primary planner."""

    target_url: str = Field(..., min_length=8, max_length=4096)
    envelope_id: str = Field(..., pattern=r"^[0-9a-f]{32}$")
    source_persona_id: str = Field(..., pattern=r"^[0-9a-f]{32}$")
    peer_persona_id: str = Field(..., pattern=r"^[0-9a-f]{32}$")


# ─────────────────────────── plan ───────────────────────────


@router.post("/plan")
async def plan_accounts_endpoint(
    req: PlanRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Compute the minimal account topology to test the given vuln
    classes. Pure analysis — no accounts created, nothing persisted."""
    from core.foundry.planner import plan_accounts

    if not req.vuln_classes:
        raise HTTPException(status_code=400, detail="vuln_classes must not be empty")
    plan = plan_accounts(req.target_handle, req.vuln_classes)
    return plan.to_dict()


# ─────────────────────────── personas ───────────────────────────


@router.get("/personas")
async def list_personas_endpoint(_: bool = Depends(verify_sensitive_token)):
    """List vault personas. Secrets (password) are EXCLUDED from the
    listing — the replay engine reads them from the vault directly, the
    API never returns them."""
    from core.foundry.vault import PersonaVault

    vault = PersonaVault()
    out = []
    for p in vault.list_personas():
        d = p.to_dict(include_secrets=False)
        d["has_password"] = bool(p.password)
        out.append(d)
    return out


@router.post("/personas")
async def add_persona_endpoint(
    req: AddPersonaRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Add a research persona to the vault. The password (if provided)
    is stored 0600 and never echoed back."""
    from core.foundry.vault import PersonaVault

    vault = PersonaVault()
    persona = vault.add_persona(
        label=req.label,
        email=req.email,
        password=req.password,
        first_name=req.first_name,
        last_name=req.last_name,
        phone=req.phone,
        date_of_birth=req.date_of_birth,
        verification=req.verification,
        extra=req.extra,
        notes=req.notes,
    )
    # Return WITHOUT the password.
    d = persona.to_dict(include_secrets=False)
    d["has_password"] = bool(persona.password)
    return d


@router.get("/personas/{persona_id}/audit")
async def persona_audit_endpoint(
    persona_id: str,
    _: bool = Depends(verify_sensitive_token),
):
    """The account-creation audit trail for one persona — every account
    it created, where, when, with what outcome."""
    from core.foundry.vault import PersonaVault

    vault = PersonaVault()
    records = vault.audit_records(persona_id=persona_id)
    return [r.to_dict() for r in records]


# ─────────────────────────── recipes ───────────────────────────


@router.get("/recipes")
async def list_recipes_endpoint(
    service_handle: Optional[str] = None,
    _: bool = Depends(verify_sensitive_token),
):
    """List stored recipes, optionally filtered by service."""
    from core.foundry.recipe_store import list_recipes

    return [
        {
            "recipe_id": r.recipe_id,
            "service_handle": r.service_handle,
            "name": r.name,
            "origin": r.origin,
            "version": r.version,
            "step_count": len(r.steps),
            "challenge_count": len(r.challenge_steps()),
            "required_persona_fields": r.required_persona_fields,
            "source": r.source,
        }
        for r in list_recipes(service_handle)
    ]


@router.post("/recipes")
async def add_recipe_endpoint(
    req: AddRecipeRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Store a recipe. The body is the recipe's to_dict() shape (from
    the recorder or hand-authored). Validation happens in save_recipe;
    a malformed recipe is rejected with 400."""
    from core.foundry.recipe import SignupRecipe
    from core.foundry.recipe_store import save_recipe

    try:
        recipe = SignupRecipe.from_dict(req.recipe)
        save_recipe(recipe)
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=400, detail=f"invalid recipe: {e}")
    return {
        "recipe_id": recipe.recipe_id,
        "service_handle": recipe.service_handle,
        "step_count": len(recipe.steps),
        "required_persona_fields": recipe.required_persona_fields,
    }


@router.get("/recipes/{recipe_id}")
async def get_recipe_endpoint(
    recipe_id: str,
    _: bool = Depends(verify_sensitive_token),
):
    from core.foundry.recipe_store import load_recipe

    recipe = load_recipe(recipe_id)
    if recipe is None:
        raise HTTPException(status_code=404, detail=f"recipe {recipe_id!r} not found")
    return recipe.to_dict()


@router.delete("/recipes/{recipe_id}")
async def delete_recipe_endpoint(
    recipe_id: str,
    _: bool = Depends(verify_sensitive_token),
):
    from core.foundry.recipe_store import delete_recipe
    deleted = delete_recipe(recipe_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Recipe not found")
    return {"status": "ok"}


@router.post("/record")
async def record_recipe_endpoint(
    req: RecordRecipeRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Launch a headful Playwright browser, record human actions, and
    save them as a SignupRecipe when the browser is closed."""
    from core.foundry.driver_native import GhostNativeDriver
    from core.foundry.recorder import RecordedAction, record_to_recipe
    from core.foundry.recipe_store import save_recipe
    from core.server.routers.driver import node_manager
    
    actions: List[RecordedAction] = []
    
    def on_event(event_type, data):
        if event_type == "recorded_action":
            try:
                actions.append(RecordedAction.from_dict(data.get("action", {})))
            except Exception as e:
                logger.warning("[recorder] invalid action payload: %s", e)
                
    node_manager.event_handlers.append(on_event)
            
    try:
        driver = await GhostNativeDriver.launch(headless=False)
        
        # Native recording logic: Swift injects the listener and bridges the events
        await driver.start_recording()
        
        actions.append(RecordedAction(action="navigate", url=req.origin))
        await driver.navigate(req.origin)
        
        # Wait for user to close the Native window
        try:
            await driver.wait_for_close()
        except Exception:
            pass # Timeout or other error during wait
            
        recipe = record_to_recipe(
            service_handle=req.service_handle,
            origin=req.origin,
            name=req.name,
            actions=actions,
        )
        save_recipe(recipe)
        return {
            "recipe_id": recipe.recipe_id,
            "service_handle": recipe.service_handle,
            "name": recipe.name,
            "step_count": len(recipe.steps),
            "challenge_count": len(recipe.challenge_steps()),
        }
    except Exception as e:
        logger.error("[recorder] recording failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if on_event in node_manager.event_handlers:
            node_manager.event_handlers.remove(on_event)
        if 'driver' in locals():
            await driver.close()


# ─────────────────────── challenges (the handoff loop) ───────────────────────


@router.get("/challenges")
async def list_challenges_endpoint(_: bool = Depends(verify_sensitive_token)):
    """The pending anti-bot challenges awaiting a human. The UI polls
    this; each entry is a 'Sentinel needs you' handoff with the kind,
    prompt, page URL, and a screenshot for context."""
    from core.foundry.challenges import get_challenge_bus

    bus = get_challenge_bus()
    return [c.to_dict() for c in bus.pending_challenges()]


@router.post("/challenges/{challenge_id}/resolve")
async def resolve_challenge_endpoint(
    challenge_id: str,
    req: ResolveChallengeRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """The 1-click handoff resolution. The human solved the CAPTCHA /
    clicked the email link / read the SMS code; this completes the
    awaiting replay's future and the automation resumes.

    For verification challenges, `extracted_value` carries the artifact
    (the link or code) the human supplied.
    """
    from core.foundry.challenges import get_challenge_bus

    bus = get_challenge_bus()
    # The challenge must still be pending (not timed out / already done).
    if bus.get_pending(challenge_id) is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"challenge {challenge_id!r} is not pending — it may have "
                f"timed out, already been resolved, or never existed."
            ),
        )
    ok = bus.resolve(
        challenge_id,
        resolved=req.resolved,
        extracted_value=req.extracted_value,
        note=req.note,
    )
    if not ok:
        raise HTTPException(
            status_code=409,
            detail=f"challenge {challenge_id!r} could not be resolved "
                   f"(already settled).",
        )
    return {"challenge_id": challenge_id, "resolved": req.resolved}


# ─────────────────────── signup orchestration ───────────────────────


@router.post("/envelopes")
async def create_envelope_endpoint(
    req: CreateEnvelopeRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Declare an authorization envelope — the researcher's up-front
    judgment (identity, target, scope, basis, allowed workflows, legal
    posture). Account creation runs strictly within it. The Foundry
    automates execution; the human makes THIS decision."""
    from core.foundry.authorization import create_envelope

    env = create_envelope(
        researcher_identity=req.researcher_identity,
        target_handle=req.target_handle,
        authorized_origins=req.authorized_origins,
        authorization_basis=req.authorization_basis,
        allowed_workflows=req.allowed_workflows,
        disclosure_attestation=req.disclosure_attestation,
        max_accounts_per_service=req.max_accounts_per_service,
        legal_posture=req.legal_posture,
        ttl_days=req.ttl_days,
    )
    return env.to_dict()


@router.get("/envelopes")
async def list_envelopes_endpoint(
    target_handle: Optional[str] = None,
    _: bool = Depends(verify_sensitive_token),
):
    """List authorization envelopes (with their approved/unapproved
    context), optionally filtered by target."""
    from core.foundry.authorization import list_envelopes

    return [e.to_dict() for e in list_envelopes(target_handle)]


@router.get("/envelopes/{envelope_id}/proof")
async def envelope_proof_endpoint(
    envelope_id: str,
    _: bool = Depends(verify_sensitive_token),
):
    """Emit the authorization proof for an APPROVED envelope — the
    disclosed-authorization + auditability + enforceable-controls
    artifact that SHOULD replace CAPTCHA for an authorized researcher-
    agent. 409 if the envelope is in an UNAPPROVED context (no proof to
    offer; the human checkpoint stands)."""
    from core.foundry.authorization import get_envelope

    env = get_envelope(envelope_id)
    if env is None:
        raise HTTPException(status_code=404, detail=f"envelope {envelope_id!r} not found")
    proof = env.authorization_proof(audit_reference=f"envelope:{envelope_id}")
    if proof is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "envelope is in an UNAPPROVED context — no authorization "
                "proof. Attest disclosure + ensure scope/basis/expiry are "
                "set to reach an APPROVED context."
            ),
        )
    return proof


# ───────────────── behavioral primary planner ─────────────────


_MAX_BEHAVIORAL_CAPTURE_BYTES = 16 * 1024 * 1024
_MAX_BEHAVIORAL_RESPONSE_CHARS = 2 * 1024 * 1024


def _behavioral_scope_filter(target_origin: str):
    parsed_target = urlsplit(target_origin)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.netloc:
        raise ValueError("target_origin must be an absolute HTTP(S) origin")
    origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

    def in_scope(url: str) -> bool:
        parsed = urlsplit(str(url or ""))
        if not parsed.scheme and not parsed.netloc:
            return str(url or "").startswith("/")
        return (
            parsed.scheme in {"http", "https"}
            and f"{parsed.scheme}://{parsed.netloc}" == origin
        )

    return origin, in_scope


def _bounded_in_scope_records(
    records: List[Dict[str, Any]], scope_filter
) -> List[Dict[str, Any]]:
    return [dict(record) for record in records if scope_filter(str(record.get("url") or ""))]


def _behavioral_capture_bytes(*record_sets: List[Dict[str, Any]]) -> int:
    return sum(
        len(
            json.dumps(
                record,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        )
        for records in record_sets
        for record in records
    )


def _bounded_script_urls(script_urls: List[str], scope_filter) -> List[str]:
    normalized = [str(url).strip() for url in script_urls]
    if any(len(url) > 16 * 1024 for url in normalized):
        raise ValueError("script URL exceeds the 16 KiB execution limit")
    in_scope = {url for url in normalized if url and scope_filter(url)}
    return sorted(in_scope)[:16]


@router.post("/behavioral-authorization")
async def run_behavioral_authorization_endpoint(
    req: RunBehavioralAuthorizationRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Resolve one frontier obligation and, when enabled, execute it once.

    ``SENTINELFORGE_BEHAVIOR_PRIMARY`` defaults off. In that state this endpoint
    returns the behavioral plan but cannot reach the SND replay transport.
    """
    from core.behavior.active import (
        BoundedResponseText,
        CONTROLLED_WORKFLOW,
        ControlledAuthorizationExecutor,
        ControlledExecutionDenied,
    )
    from core.behavior.scheduler import (
        BehavioralPrimaryScheduler,
        PrimaryPlannerConfig,
    )
    from core.behavior.resolver import (
        ClosedLoopResolverConfig,
        ClosedLoopResolverDenied,
        SingleStepObligationResolver,
    )
    from core.behavior.boundary import (
        FreshOwnedBoundaryConfig,
        FreshOwnedBoundaryDenied,
        FreshOwnedBoundaryExecutor,
    )
    from core.behavior.factory import (
        OwnedExperimentFactory,
        OwnedExperimentFactoryDenied,
    )
    from core.behavior.runtime import ControlledSequenceDenied
    from core.behavior.continuation import (
        BoundedContinuationConfig,
        BoundedContinuationController,
        BoundedContinuationDenied,
        ContinuationRound,
    )
    from core.behavior.explorer import BehavioralReadExplorer
    from core.behavior.graphql_catalog import PersistedOperationCatalog
    from core.behavior.receipts import (
        COMPLETED,
        BehavioralReceiptStore,
        ReceiptStoreError,
        redacted_outcome,
        redacted_receipt_context,
        request_fingerprint,
    )
    from core.behavior.orchestrator import (
        BehavioralShadowOrchestrator,
        OwnedExperimentShadowContext,
    )
    from core.behavior.feedback import ReceiptDispositionAdapter
    from core.behavior.affordances import ClientArtifact
    from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
    from core.foundry.authorization import get_envelope
    from core.foundry.vault import PersonaVault
    from core.safety.provenance import ProvenanceSink
    from core.safety.proof_budget import ProofBudget
    from core.safety.ownership_registry import OwnershipRegistry
    from core.safety.action_classifier import SAFE_READ
    from core.wraith.bola_replay import ReplayRequest, SNDReplayTransport

    try:
        target_origin, scope_filter = _behavioral_scope_filter(req.target_origin)
        if (
            _behavioral_capture_bytes(req.source_records, req.peer_records)
            > _MAX_BEHAVIORAL_CAPTURE_BYTES
        ):
            raise ValueError("paired capture exceeds the 16 MiB execution limit")
        source_records = _bounded_in_scope_records(req.source_records, scope_filter)
        peer_records = _bounded_in_scope_records(req.peer_records, scope_filter)
        script_urls = _bounded_script_urls(req.script_urls, scope_filter)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not source_records or not peer_records:
        raise HTTPException(status_code=400, detail="paired captures have no in-scope records")

    vault = PersonaVault()
    source_persona = vault.get_persona(req.source_persona_id)
    peer_persona = vault.get_persona(req.peer_persona_id)
    if source_persona is None or peer_persona is None:
        raise HTTPException(status_code=404, detail="one or both research personas were not found")
    envelope = get_envelope(req.envelope_id)
    if envelope is None:
        raise HTTPException(status_code=404, detail=f"envelope {req.envelope_id!r} not found")
    if CONTROLLED_WORKFLOW not in envelope.allowed_workflows:
        # Surface the missing up-front permission even while runtime activation
        # is disabled; otherwise enabling later would change a plan into a 403.
        raise HTTPException(
            status_code=409,
            detail=f"authorization envelope does not permit {CONTROLLED_WORKFLOW!r}",
        )

    resolver_config = ClosedLoopResolverConfig.from_environment()
    continuation_config = BoundedContinuationConfig.from_environment()
    try:
        continuation_config.authorize(envelope, target_origin=target_origin)
    except BoundedContinuationDenied as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    fresh_boundary_config = FreshOwnedBoundaryConfig.from_environment()
    config = PrimaryPlannerConfig(enabled=resolver_config.enabled)
    scheduler = BehavioralPrimaryScheduler(config)
    obligation_resolver = SingleStepObligationResolver(resolver_config)
    catalog = PersistedOperationCatalog()
    catalog.ingest_capture_records(source_records, source="source_capture")
    catalog.ingest_capture_records(peer_records, source="peer_capture")
    asset_resolution = {
        "attempted": 0,
        "fetched": 0,
        "failed": 0,
        "documents_added": 0,
    }
    shadow_artifacts = []
    controlled_executor = None
    fresh_boundary_executor = None
    executors = None
    boundary_executors = None
    receipt_store = None
    receipt_fingerprint = None
    receipt_reservation_token = None
    read_exploration = {
        "status": "disabled",
        "pairs_attempted": 0,
        "pairs_completed": 0,
        "requests_attempted": 0,
        "requests_sent": 0,
        "successful_responses": 0,
        "policy_denials": 0,
        "failed_requests": 0,
        "candidates_discovered": 0,
        "selected_after_pair": 0,
        "frontier_exhausted": False,
    }
    if config.enabled:
        transport = SNDReplayTransport()
        policy = ExecutionPolicy(
            "bounty_safe",
            scope_filter=scope_filter,
            budget=ProofBudget(
                max_total_requests=40,
                max_requests_per_endpoint=5,
                max_cross_object_reads=(
                    2 if continuation_config.enabled else 1
                ),
                max_privilege_mutations=0,
                max_creates=0,
                allow_delete=False,
                allow_real_user_data_access=False,
            ),
        )
        provenance = ProvenanceSink()
        provenance.record_context(
            target=target_origin,
            proof_mode="bounty_safe",
            policy_digest=policy.digest(),
        )

        def make_executor(
            persona_id: str,
            execution_policy: ExecutionPolicy,
            execution_provenance: ProvenanceSink,
        ) -> PolicyExecutor:
            async def raw_send(method, url, body=None, **kwargs):
                headers = kwargs.get("headers") or {}
                response_cap = kwargs.get("_max_response_chars")
                if (
                    isinstance(response_cap, bool)
                    or not isinstance(response_cap, int)
                    or response_cap <= 0
                ):
                    response_cap = _MAX_BEHAVIORAL_RESPONSE_CHARS
                response = await transport.send(
                    persona_id,
                    ReplayRequest(
                        method=str(method),
                        url=str(url),
                        body=(body if isinstance(body, str) or body is None else json.dumps(body)),
                        headers={str(key): str(value) for key, value in headers.items()},
                        max_response_chars=response_cap,
                    ),
                )
                return response.status, BoundedResponseText(
                    response.body,
                    body_truncated=response.body_truncated,
                )

            return PolicyExecutor(
                raw_send,
                execution_policy,
                provenance=execution_provenance,
            )

        executors = {
            source_persona.persona_id: make_executor(
                source_persona.persona_id,
                policy,
                provenance,
            ),
            peer_persona.persona_id: make_executor(
                peer_persona.persona_id,
                policy,
                provenance,
            ),
        }
        boundary_policy = ExecutionPolicy(
            "bounty_safe",
            scope_filter=scope_filter,
            budget=ProofBudget(
                max_total_requests=7,
                max_requests_per_endpoint=5,
                max_cross_object_reads=1,
                max_privilege_mutations=0,
                max_creates=2,
                allow_delete=False,
                allow_real_user_data_access=False,
            ),
            ownership_registry=OwnershipRegistry(),
        )
        boundary_provenance = ProvenanceSink()
        boundary_provenance.record_context(
            target=target_origin,
            proof_mode="bounty_safe",
            policy_digest=boundary_policy.digest(),
        )
        boundary_executors = {
            source_persona.persona_id: make_executor(
                source_persona.persona_id,
                boundary_policy,
                boundary_provenance,
            ),
            peer_persona.persona_id: make_executor(
                peer_persona.persona_id,
                boundary_policy,
                boundary_provenance,
            ),
        }
        controlled_executor = ControlledAuthorizationExecutor(
            target_origin=target_origin,
            authorization=envelope,
            source_persona=source_persona,
            peer_persona=peer_persona,
            executors=executors,
        )
        try:
            controlled_executor.validate_preflight()
        except ControlledExecutionDenied as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        receipt_store = BehavioralReceiptStore()
        try:
            receipt_fingerprint = request_fingerprint({
                "schema_version": 2,
                "execution_profile": {
                    "primary": resolver_config.enabled,
                    "fresh_owned_boundary": fresh_boundary_config.enabled,
                    "bounded_continuation": continuation_config.enabled,
                },
                "target_origin": target_origin,
                "envelope_id": req.envelope_id,
                "source_persona_id": source_persona.persona_id,
                "peer_persona_id": peer_persona.persona_id,
                "source_records": source_records,
                "peer_records": peer_records,
                "script_urls": script_urls,
            })
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail="behavioral request cannot be fingerprinted deterministically",
            ) from exc
        try:
            reservation = receipt_store.reserve(
                receipt_fingerprint,
                context=redacted_receipt_context(
                    target_origin=target_origin,
                    envelope_id=req.envelope_id,
                    source_persona_id=source_persona.persona_id,
                    peer_persona_id=peer_persona.persona_id,
                ),
            )
        except (OSError, ReceiptStoreError) as exc:
            raise HTTPException(
                status_code=503,
                detail="behavioral receipt store unavailable; execution refused",
            ) from exc
        if not reservation.created:
            if reservation.receipt.state == COMPLETED and reservation.receipt.outcome:
                cached = dict(reservation.receipt.outcome)
                cached["status"] = "already_executed"
                cached["receipt"] = {
                    "receipt_id": reservation.receipt.receipt_id,
                    "state": reservation.receipt.state,
                    "reused": True,
                }
                return cached
            raise HTTPException(
                status_code=409,
                detail=(
                    "identical behavioral execution is already reserved or terminal "
                    f"(receipt={reservation.receipt.receipt_id}, "
                    f"state={reservation.receipt.state})"
                ),
            )
        receipt_reservation_token = reservation.reservation_token
        if receipt_reservation_token is None:
            raise HTTPException(
                status_code=503,
                detail="behavioral receipt reservation token unavailable; execution refused",
            )

        source_executor = executors[source_persona.persona_id]
        for script_url in script_urls:
            asset_resolution["attempted"] += 1
            try:
                status, body = await source_executor.send(
                    "GET",
                    script_url,
                    None,
                    hint=SAFE_READ,
                    actor=source_persona.persona_id,
                    target_owner=source_persona.persona_id,
                    target_is_researcher_owned=True,
                    proof_goal="resolve_persisted_graphql_operation",
                    _max_response_chars=catalog.limits.max_artifact_bytes,
                )
            except Exception:
                asset_resolution["failed"] += 1
                continue
            if 200 <= int(status) < 300 and isinstance(body, str):
                asset_resolution["fetched"] += 1
                asset_resolution["documents_added"] += catalog.ingest_artifact(
                    script_url, body
                )
                try:
                    shadow_artifacts.append(ClientArtifact(script_url, body))
                except ValueError:
                    asset_resolution["shadow_artifacts_rejected"] = (
                        asset_resolution.get("shadow_artifacts_rejected", 0) + 1
                    )
                    logger.warning(
                        "fetched client artifact was rejected by shadow contract"
                    )
            else:
                asset_resolution["failed"] += 1

    source_resolution = catalog.resolve_records(source_records)
    peer_resolution = catalog.resolve_records(peer_records)
    source_records = list(source_resolution.records)
    peer_records = list(peer_resolution.records)

    if config.enabled and executors is not None:
        preliminary_plan = scheduler.plan(
            source_records,
            peer_records,
            source_persona=source_persona,
            peer_persona=peer_persona,
        )
        if preliminary_plan.selected is None:
            try:
                explorer = BehavioralReadExplorer(
                    target_origin=target_origin,
                    source_persona_id=source_persona.persona_id,
                    peer_persona_id=peer_persona.persona_id,
                    executors=executors,
                )
                exploration_result = await explorer.explore(
                    source_records,
                    peer_records,
                    stop_when=lambda current_source, current_peer: (
                        scheduler.plan(
                            current_source,
                            current_peer,
                            source_persona=source_persona,
                            peer_persona=peer_persona,
                        ).selected
                        is not None
                    ),
                )
            except Exception as exc:
                logger.exception("behavioral read exploration failed")
                if (
                    receipt_store is not None
                    and receipt_fingerprint is not None
                    and receipt_reservation_token is not None
                ):
                    try:
                        receipt_store.abort(
                            receipt_fingerprint,
                            reservation_token=receipt_reservation_token,
                            reason="read_exploration_error",
                        )
                    except (OSError, ReceiptStoreError):
                        logger.exception("failed to terminate exploration receipt")
                raise HTTPException(
                    status_code=500,
                    detail="behavioral read exploration failed",
                ) from exc
            else:
                source_records = list(exploration_result.source_records)
                peer_records = list(exploration_result.peer_records)
                read_exploration = {
                    "status": "completed",
                    **exploration_result.diagnostics,
                }
                source_resolution = catalog.resolve_records(source_records)
                peer_resolution = catalog.resolve_records(peer_records)
                source_records = list(source_resolution.records)
                peer_records = list(peer_resolution.records)
        else:
            read_exploration["status"] = "not_needed"

    # Build the full evidence frontier before the optional active run. This
    # compiler-only executor has no target transport, and factory admissions
    # remain default-off even when a proof-carrying experiment is prepared.
    async def _shadow_transport_forbidden(*_args, **_kwargs):
        raise RuntimeError("behavioral shadow transport is unavailable")

    shadow_policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=scope_filter,
        budget=ProofBudget(
            max_total_requests=7,
            max_requests_per_endpoint=5,
            max_cross_object_reads=1,
            max_privilege_mutations=0,
            max_creates=2,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
        ownership_registry=OwnershipRegistry(),
    )
    shadow_provenance = ProvenanceSink()
    shadow_provenance.record_context(
        target=target_origin,
        proof_mode="bounty_safe_shadow",
        policy_digest=shadow_policy.digest(),
    )
    shadow_executor = PolicyExecutor(
        _shadow_transport_forbidden,
        shadow_policy,
        provenance=shadow_provenance,
    )
    shadow_orchestrator = BehavioralShadowOrchestrator()
    shadow_context = OwnedExperimentShadowContext(
        authorization=envelope,
        actor_persona_id=source_persona.persona_id,
        executor=shadow_executor,
    )
    shadow_run = None
    try:
        shadow_run = shadow_orchestrator.run(
            source_records,
            target_origin=target_origin,
            world_id=source_persona.persona_id,
            peer_records=peer_records,
            peer_world_id=peer_persona.persona_id,
            artifacts=tuple(shadow_artifacts),
            experiment_context=shadow_context,
        )
        shadow_response = shadow_run.to_dict()
    except Exception:
        logger.exception("behavioral shadow orchestration failed")
        shadow_response = {
            "schema_version": 1,
            "mode": "behavioral_closed_loop_shadow_v1",
            "executable": False,
            "status": "error",
            "error_code": "shadow_orchestration_failed",
        }

    if shadow_run is None and resolver_config.enabled:
        if (
            receipt_store is not None
            and receipt_fingerprint is not None
            and receipt_reservation_token is not None
        ):
            try:
                receipt_store.abort(
                    receipt_fingerprint,
                    reservation_token=receipt_reservation_token,
                    reason="obligation_frontier_error",
                )
            except (OSError, ReceiptStoreError):
                logger.exception("failed to terminate frontier-error receipt")
        raise HTTPException(
            status_code=500,
            detail="behavioral obligation frontier failed; execution refused",
        )

    if (
        shadow_run is not None
        and fresh_boundary_config.enabled
        and boundary_executors is not None
        and shadow_run.experiment_stage.inventory is not None
    ):
        try:
            factory = OwnedExperimentFactory()
            source_inventory = factory.build(
                source_records,
                target_origin=target_origin,
                authorization=envelope,
                actor_persona_id=source_persona.persona_id,
                executor=boundary_executors[source_persona.persona_id],
            )
            peer_inventory = factory.build(
                peer_records,
                target_origin=target_origin,
                authorization=envelope,
                actor_persona_id=peer_persona.persona_id,
                executor=boundary_executors[peer_persona.persona_id],
            )
            candidate_boundary = FreshOwnedBoundaryExecutor(
                source_inventory=source_inventory,
                peer_inventory=peer_inventory,
                source_persona=source_persona,
                peer_persona=peer_persona,
                config=fresh_boundary_config,
            )
            if candidate_boundary.supported_experiment_ids():
                fresh_boundary_executor = candidate_boundary
        except (OwnedExperimentFactoryDenied, ControlledSequenceDenied) as exc:
            logger.warning("fresh owned boundary preflight unavailable: %s", exc)
        except Exception as exc:
            if (
                receipt_store is not None
                and receipt_fingerprint is not None
                and receipt_reservation_token is not None
            ):
                try:
                    receipt_store.abort(
                        receipt_fingerprint,
                        reservation_token=receipt_reservation_token,
                        reason="fresh_boundary_preflight_error",
                    )
                except (OSError, ReceiptStoreError):
                    logger.exception(
                        "failed to terminate fresh-boundary preflight receipt"
                    )
            logger.exception("fresh owned boundary preflight failed")
            raise HTTPException(
                status_code=500,
                detail="fresh owned boundary preflight failed; execution refused",
            ) from exc

    if continuation_config.enabled:
        if (
            shadow_run is None
            or receipt_store is None
            or receipt_fingerprint is None
            or receipt_reservation_token is None
            or executors is None
        ):
            raise HTTPException(
                status_code=500,
                detail="bounded continuation preflight is incomplete; execution refused",
            )

        continuation_controller = BoundedContinuationController(
            continuation_config
        )
        continuation_context = redacted_receipt_context(
            target_origin=target_origin,
            envelope_id=req.envelope_id,
            source_persona_id=source_persona.persona_id,
            peer_persona_id=peer_persona.persona_id,
        )
        graphql_summary = {
            "catalog": catalog.diagnostics(),
            "assets": asset_resolution,
            "source": source_resolution.diagnostics(),
            "peer": peer_resolution.diagnostics(),
        }
        initial_shadow = shadow_run
        current_shadow = shadow_run
        current_boundary = fresh_boundary_executor
        dispositions = []
        continuation_rounds = []
        response = None
        stop_reason = "no_executable_candidate"
        round_fingerprint = None
        round_token = None

        def abort_continuation_receipt(
            fingerprint: str,
            token: str,
            reason: str,
        ) -> None:
            try:
                receipt_store.abort(
                    fingerprint,
                    reservation_token=token,
                    reason=reason,
                )
            except (OSError, ReceiptStoreError):
                logger.exception("failed to terminate bounded continuation receipt")

        try:
            for round_index in range(1, continuation_config.max_rounds + 1):
                round_controlled_executor = ControlledAuthorizationExecutor(
                    target_origin=target_origin,
                    authorization=envelope,
                    source_persona=source_persona,
                    peer_persona=peer_persona,
                    executors=executors,
                )
                round_controlled_executor.validate_preflight()
                plan = obligation_resolver.plan(
                    current_shadow,
                    fresh_boundary_executor=current_boundary,
                )
                admission = continuation_controller.admit_plan(
                    continuation_rounds,
                    plan,
                )
                if not admission.continue_execution:
                    stop_reason = admission.reason
                    if response is None:
                        run = await obligation_resolver.run(
                            current_shadow,
                            source_records,
                            peer_records,
                            controlled_executor=round_controlled_executor,
                            fresh_boundary_executor=current_boundary,
                        )
                        response = run.to_dict()
                        response["behavioral_shadow"] = current_shadow.to_dict()
                        response["graphql_resolution"] = graphql_summary
                        response["read_exploration"] = read_exploration
                    break

                selected = plan.selected
                assert selected is not None
                round_fingerprint = request_fingerprint(
                    {
                        "schema_version": 1,
                        "mode": "behavioral_continuation_round",
                        "root_fingerprint": receipt_fingerprint,
                        "round_index": round_index,
                        "shadow_run_id": current_shadow.run_id,
                        "plan_id": plan.plan_id,
                        "obligation_id": selected.obligation_id,
                        "resolution_kind": selected.resolution_kind,
                        "resolution_ref": selected.resolution_ref,
                    }
                )
                round_reservation = receipt_store.reserve(
                    round_fingerprint,
                    context=continuation_context,
                )
                if not round_reservation.created:
                    raise BoundedContinuationDenied(
                        "continuation_round_is_already_reserved_or_terminal"
                    )
                round_token = round_reservation.reservation_token
                if round_token is None:
                    raise BoundedContinuationDenied(
                        "continuation_round_reservation_token_is_unavailable"
                    )

                before_shadow = current_shadow
                run = await obligation_resolver.run(
                    before_shadow,
                    source_records,
                    peer_records,
                    controlled_executor=round_controlled_executor,
                    fresh_boundary_executor=current_boundary,
                )
                response = run.to_dict()
                response["behavioral_shadow"] = before_shadow.to_dict()
                response["graphql_resolution"] = graphql_summary
                response["read_exploration"] = read_exploration
                completed_round_receipt = receipt_store.complete(
                    round_fingerprint,
                    reservation_token=round_token,
                    outcome=redacted_outcome(response),
                )
                round_token = None

                try:
                    feedback = ReceiptDispositionAdapter().adapt(
                        before_shadow.graph,
                        (completed_round_receipt,),
                        expected_context=continuation_context,
                    )
                    dispositions.extend(feedback.dispositions)
                    after_shadow = shadow_orchestrator.run(
                        source_records,
                        target_origin=target_origin,
                        world_id=source_persona.persona_id,
                        peer_records=peer_records,
                        peer_world_id=peer_persona.persona_id,
                        artifacts=tuple(shadow_artifacts),
                        experiment_context=shadow_context,
                        dispositions=tuple(dispositions),
                        previous_graph=before_shadow.graph,
                        derivation_round=round_index + 1,
                    )
                    after_shadow_response = after_shadow.to_dict()
                    after_shadow_response["receipt_feedback"] = feedback.to_dict()
                except Exception:
                    logger.exception("bounded continuation receipt feedback failed")
                    after_shadow = before_shadow
                    after_shadow_response = before_shadow.to_dict()
                    after_shadow_response["receipt_feedback"] = {
                        "schema_version": 1,
                        "mode": "behavioral_receipt_feedback_v1",
                        "executable": False,
                        "status": "error",
                        "error_code": "receipt_feedback_failed",
                    }

                response["behavioral_shadow"] = after_shadow_response
                continuation_round = ContinuationRound.create(
                    round_index=round_index,
                    receipt_fingerprint=round_fingerprint,
                    before=before_shadow,
                    after=after_shadow,
                    run=run,
                )
                continuation_rounds.append(continuation_round)
                if selected.resolution_kind == "owned_experiment":
                    current_boundary = None
                decision = continuation_controller.after_round(
                    continuation_rounds,
                    before=before_shadow,
                    after=after_shadow,
                )
                current_shadow = after_shadow
                if not decision.continue_execution:
                    stop_reason = decision.reason
                    break
            else:
                stop_reason = "round_limit_reached"
        except (
            ControlledExecutionDenied,
            ControlledSequenceDenied,
            FreshOwnedBoundaryDenied,
            BoundedContinuationDenied,
        ) as exc:
            if round_fingerprint is not None and round_token is not None:
                abort_continuation_receipt(
                    round_fingerprint,
                    round_token,
                    "continuation_execution_denied",
                )
            abort_continuation_receipt(
                receipt_fingerprint,
                receipt_reservation_token,
                "continuation_execution_denied",
            )
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ClosedLoopResolverDenied as exc:
            if round_fingerprint is not None and round_token is not None:
                abort_continuation_receipt(
                    round_fingerprint,
                    round_token,
                    "continuation_resolver_error",
                )
            abort_continuation_receipt(
                receipt_fingerprint,
                receipt_reservation_token,
                "continuation_resolver_error",
            )
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        except (OSError, ReceiptStoreError) as exc:
            if round_fingerprint is not None and round_token is not None:
                abort_continuation_receipt(
                    round_fingerprint,
                    round_token,
                    "continuation_receipt_error",
                )
            abort_continuation_receipt(
                receipt_fingerprint,
                receipt_reservation_token,
                "continuation_receipt_error",
            )
            raise HTTPException(
                status_code=503,
                detail="bounded continuation receipt store unavailable; execution stopped",
            ) from exc
        except Exception as exc:
            if round_fingerprint is not None and round_token is not None:
                abort_continuation_receipt(
                    round_fingerprint,
                    round_token,
                    "continuation_internal_error",
                )
            abort_continuation_receipt(
                receipt_fingerprint,
                receipt_reservation_token,
                "continuation_internal_error",
            )
            logger.exception("unexpected bounded continuation failure")
            raise HTTPException(
                status_code=500,
                detail="bounded continuation failed closed",
            ) from exc

        assert response is not None
        try:
            continuation_result = continuation_controller.finish(
                root_fingerprint=receipt_fingerprint,
                initial=initial_shadow,
                final=current_shadow,
                rounds=continuation_rounds,
                stop_reason=stop_reason,
            )
            response["continuation"] = continuation_result.to_dict()
            redacted_response = redacted_outcome(response)
        except (
            BoundedContinuationDenied,
            ReceiptStoreError,
            TypeError,
            ValueError,
        ) as exc:
            abort_continuation_receipt(
                receipt_fingerprint,
                receipt_reservation_token,
                "continuation_result_invalid",
            )
            logger.exception("bounded continuation result validation failed")
            raise HTTPException(
                status_code=500,
                detail="bounded continuation result was invalid and execution stopped",
            ) from exc
        try:
            completed_receipt = receipt_store.complete(
                receipt_fingerprint,
                reservation_token=receipt_reservation_token,
                outcome=redacted_response,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "bounded continuation completed but its root receipt could not "
                    "be finalized; identical retries remain blocked"
                ),
            ) from exc
        response["receipt"] = {
            "receipt_id": completed_receipt.receipt_id,
            "state": completed_receipt.state,
            "reused": False,
        }
        return response

    try:
        if shadow_run is None:
            # Disabled mode has no execution authority. Preserve its diagnostic
            # proposal response even if optional shadow analysis failed.
            run = await scheduler.run(
                source_records,
                peer_records,
                source_persona=source_persona,
                peer_persona=peer_persona,
            )
        else:
            run = await obligation_resolver.run(
                shadow_run,
                source_records,
                peer_records,
                controlled_executor=controlled_executor,
                fresh_boundary_executor=fresh_boundary_executor,
            )
    except (
        ControlledExecutionDenied,
        ControlledSequenceDenied,
        FreshOwnedBoundaryDenied,
    ) as exc:
        if (
            receipt_store is not None
            and receipt_fingerprint is not None
            and receipt_reservation_token is not None
        ):
            try:
                receipt_store.abort(
                    receipt_fingerprint,
                    reservation_token=receipt_reservation_token,
                    reason="controlled_execution_denied",
                )
            except (OSError, ReceiptStoreError):
                logger.exception("failed to terminate denied behavioral receipt")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ClosedLoopResolverDenied as exc:
        if (
            receipt_store is not None
            and receipt_fingerprint is not None
            and receipt_reservation_token is not None
        ):
            try:
                receipt_store.abort(
                    receipt_fingerprint,
                    reservation_token=receipt_reservation_token,
                    reason="closed_loop_resolver_error",
                )
            except (OSError, ReceiptStoreError):
                logger.exception("failed to terminate errored behavioral receipt")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    response = run.to_dict()
    response["behavioral_shadow"] = shadow_response
    response["graphql_resolution"] = {
        "catalog": catalog.diagnostics(),
        "assets": asset_resolution,
        "source": source_resolution.diagnostics(),
        "peer": peer_resolution.diagnostics(),
    }
    response["read_exploration"] = read_exploration
    if (
        receipt_store is not None
        and receipt_fingerprint is not None
        and receipt_reservation_token is not None
    ):
        try:
            completed_receipt = receipt_store.complete(
                receipt_fingerprint,
                reservation_token=receipt_reservation_token,
                outcome=redacted_outcome(response),
            )
        except (OSError, ReceiptStoreError) as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "behavioral execution completed but its durable receipt could not "
                    "be finalized; identical retries remain blocked"
                ),
            ) from exc
        response["receipt"] = {
            "receipt_id": completed_receipt.receipt_id,
            "state": completed_receipt.state,
            "reused": False,
        }
        if shadow_run is not None:
            try:
                feedback = ReceiptDispositionAdapter().adapt(
                    shadow_run.graph,
                    (completed_receipt,),
                    expected_context=redacted_receipt_context(
                        target_origin=target_origin,
                        envelope_id=req.envelope_id,
                        source_persona_id=source_persona.persona_id,
                        peer_persona_id=peer_persona.persona_id,
                    ),
                )
                feedback_run = shadow_orchestrator.run(
                    source_records,
                    target_origin=target_origin,
                    world_id=source_persona.persona_id,
                    peer_records=peer_records,
                    peer_world_id=peer_persona.persona_id,
                    artifacts=tuple(shadow_artifacts),
                    experiment_context=shadow_context,
                    dispositions=feedback.dispositions,
                    previous_graph=shadow_run.graph,
                    derivation_round=2,
                )
                shadow_response = feedback_run.to_dict()
                shadow_response["receipt_feedback"] = feedback.to_dict()
            except Exception:
                # A feedback failure cannot erase or falsify the already finalized
                # proof receipt.  Keep the pre-execution frontier and expose the
                # failed accounting step explicitly.
                logger.exception("behavioral receipt feedback failed")
                shadow_response["receipt_feedback"] = {
                    "schema_version": 1,
                    "mode": "behavioral_receipt_feedback_v1",
                    "executable": False,
                    "status": "error",
                    "error_code": "receipt_feedback_failed",
                }
            response["behavioral_shadow"] = shadow_response
    return response


@router.post("/behavioral-authorization-from-url")
async def run_behavioral_authorization_from_url_endpoint(
    req: RunBehavioralAuthorizationFromURLRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Capture both registered persona windows sequentially and execute one plan.

    Every authorization and native-window precondition is checked before an
    orchestration receipt is reserved and before either browser is navigated.
    Once capture begins, the durable receipt prevents an identical click from
    silently repeating target traffic after any terminal outcome.
    """
    from core.behavior.active import (
        ControlledExecutionDenied,
        validate_controlled_capture_context,
    )
    from core.behavior.receipts import (
        COMPLETED,
        BehavioralReceiptStore,
        ReceiptStoreError,
        redacted_outcome,
        redacted_receipt_context,
        request_fingerprint,
    )
    from core.behavior.boundary import FreshOwnedBoundaryConfig
    from core.behavior.continuation import (
        BoundedContinuationConfig,
        BoundedContinuationDenied,
    )
    from core.behavior.scheduler import PrimaryPlannerConfig
    from core.foundry.authorization import get_envelope
    from core.foundry.vault import PersonaVault
    from core.server.routers.driver import (
        CaptureConflict,
        DriverBridgeError,
        PersonaWindowUnavailable,
        capture_persona_pair,
        ensure_capture_available,
        validate_capture_url,
        validate_persona_windows,
    )

    try:
        target_url = validate_capture_url(req.target_url)
        target_origin, _scope_filter = _behavioral_scope_filter(target_url)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not PrimaryPlannerConfig.from_environment().enabled:
        raise HTTPException(
            status_code=409,
            detail=(
                "one-click behavioral execution requires "
                "SENTINELFORGE_BEHAVIOR_PRIMARY=1"
            ),
        )

    vault = PersonaVault()
    source_persona = vault.get_persona(req.source_persona_id)
    peer_persona = vault.get_persona(req.peer_persona_id)
    if source_persona is None or peer_persona is None:
        raise HTTPException(status_code=404, detail="one or both research personas were not found")
    envelope = get_envelope(req.envelope_id)
    if envelope is None:
        raise HTTPException(status_code=404, detail=f"envelope {req.envelope_id!r} not found")
    try:
        validate_controlled_capture_context(
            target_origin=target_origin,
            authorization=envelope,
            source_persona=source_persona,
            peer_persona=peer_persona,
        )
    except ControlledExecutionDenied as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    continuation_config = BoundedContinuationConfig.from_environment()
    try:
        continuation_config.authorize(envelope, target_origin=target_origin)
    except BoundedContinuationDenied as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    try:
        fingerprint = request_fingerprint({
            "schema_version": 2,
            "mode": "behavioral_url_capture_orchestration",
            "execution_profile": {
                "primary": True,
                "fresh_owned_boundary": (
                    FreshOwnedBoundaryConfig.from_environment().enabled
                ),
                "bounded_continuation": continuation_config.enabled,
            },
            "target_url": target_url,
            "envelope_id": req.envelope_id,
            "source_persona_id": source_persona.persona_id,
            "peer_persona_id": peer_persona.persona_id,
        })
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail="one-click request cannot be fingerprinted deterministically",
        ) from exc

    receipt_store = BehavioralReceiptStore()

    def duplicate_response(receipt):
        if receipt.state == COMPLETED and receipt.outcome:
            cached = dict(receipt.outcome)
            cached["status"] = "already_executed"
            cached["orchestration_receipt"] = {
                "receipt_id": receipt.receipt_id,
                "state": receipt.state,
                "reused": True,
            }
            return cached
        raise HTTPException(
            status_code=409,
            detail=(
                "identical one-click execution is already reserved or terminal "
                f"(receipt={receipt.receipt_id}, state={receipt.state})"
            ),
        )

    try:
        existing = receipt_store.load(fingerprint)
    except (OSError, ReceiptStoreError) as exc:
        raise HTTPException(
            status_code=503,
            detail="behavioral receipt store unavailable; capture refused",
        ) from exc
    if existing is not None:
        return duplicate_response(existing)

    try:
        ensure_capture_available()
        await validate_persona_windows(
            (source_persona.persona_id, peer_persona.persona_id)
        )
        ensure_capture_available()
    except CaptureConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PersonaWindowUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (DriverBridgeError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        reservation = receipt_store.reserve(
            fingerprint,
            context=redacted_receipt_context(
                target_origin=target_origin,
                envelope_id=req.envelope_id,
                source_persona_id=source_persona.persona_id,
                peer_persona_id=peer_persona.persona_id,
            ),
        )
    except (OSError, ReceiptStoreError) as exc:
        raise HTTPException(
            status_code=503,
            detail="behavioral receipt store unavailable; capture refused",
        ) from exc
    if not reservation.created:
        return duplicate_response(reservation.receipt)
    reservation_token = reservation.reservation_token
    if reservation_token is None:
        raise HTTPException(
            status_code=503,
            detail="behavioral receipt reservation token unavailable; capture refused",
        )

    def abort_receipt(reason: str) -> None:
        try:
            receipt_store.abort(
                fingerprint,
                reservation_token=reservation_token,
                reason=reason,
            )
        except (OSError, ReceiptStoreError):
            logger.exception("failed to terminate one-click behavioral receipt")

    try:
        source_capture, peer_capture, script_urls = await capture_persona_pair(
            target_url=target_url,
            source_persona_id=source_persona.persona_id,
            peer_persona_id=peer_persona.persona_id,
        )
        response = await run_behavioral_authorization_endpoint(
            RunBehavioralAuthorizationRequest(
                target_origin=target_origin,
                envelope_id=req.envelope_id,
                source_persona_id=source_persona.persona_id,
                peer_persona_id=peer_persona.persona_id,
                source_records=list(source_capture.records),
                peer_records=list(peer_capture.records),
                script_urls=list(script_urls),
            ),
            _=True,
        )
    except HTTPException:
        abort_receipt("behavioral_run_rejected")
        raise
    except (CaptureConflict, PersonaWindowUnavailable) as exc:
        abort_receipt("capture_unavailable")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (DriverBridgeError, OSError, RuntimeError) as exc:
        abort_receipt("capture_orchestration_failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        abort_receipt("capture_orchestration_failed")
        logger.exception("unexpected one-click behavioral orchestration failure")
        raise HTTPException(
            status_code=500,
            detail="one-click behavioral orchestration failed",
        ) from exc

    receiptable_response = dict(response)
    if receiptable_response.get("status") == "already_executed":
        execution = receiptable_response.get("execution")
        if isinstance(execution, dict) and execution.get("status") in {
            "completed",
            "aborted",
            "cleanup_failed",
        }:
            receiptable_response["status"] = execution["status"]
        elif execution is None:
            receiptable_response["status"] = "no_executable_candidate"
    try:
        completed_receipt = receipt_store.complete(
            fingerprint,
            reservation_token=reservation_token,
            outcome=redacted_outcome(receiptable_response),
        )
    except (OSError, ReceiptStoreError) as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "one-click execution completed but its durable receipt could not "
                "be finalized; identical retries remain blocked"
            ),
        ) from exc

    response["capture_pair"] = {
        "source": source_capture.summary(),
        "peer": peer_capture.summary(),
    }
    response["orchestration_receipt"] = {
        "receipt_id": completed_receipt.receipt_id,
        "state": completed_receipt.state,
        "reused": False,
    }
    return response


@router.post("/signup")
async def start_signup_endpoint(
    req: StartSignupRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Kick off a signup WITHIN an authorization envelope: launch a
    browser, replay the recipe with the persona, hand off anti-bot
    walls to the human via the challenge bus.

    The envelope is the precondition. If it doesn't authorize this
    target + workflow (or is missing / expired / unapproved), the
    request is refused (403) before any browser launches — judgment
    before execution.

    Returns immediately with a job id (the replay runs in the
    background). Poll /signup/{job_id}; challenges surface via
    GET /challenges and resolve via /challenges/{id}/resolve.
    """
    from core.foundry.authorization import AuthorizationDenied
    from core.foundry.signup import get_orchestrator

    orch = get_orchestrator()
    try:
        job = await orch.start(
            req.recipe_id, req.persona_id, envelope_id=req.envelope_id,
        )
    except AuthorizationDenied as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return job.to_dict()


@router.get("/signup")
async def list_signup_jobs_endpoint(_: bool = Depends(verify_sensitive_token)):
    """List signup jobs (extracted secrets redacted)."""
    from core.foundry.signup import get_orchestrator

    orch = get_orchestrator()
    return [j.to_dict() for j in orch.list_jobs()]


@router.get("/signup/{job_id}")
async def get_signup_job_endpoint(
    job_id: str,
    _: bool = Depends(verify_sensitive_token),
):
    """One signup job's status. Extracted secrets redacted to
    length-only — the operator reads the actual token from the vault /
    a dedicated secure path, never the status listing."""
    from core.foundry.signup import get_orchestrator

    orch = get_orchestrator()
    job = orch.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"signup job {job_id!r} not found")
    return job.to_dict()
