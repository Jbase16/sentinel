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

import logging
from typing import Any, Dict, List, Optional

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
    envelope_id: str = Field(
        ...,
        description="The authorization envelope this signup runs under. "
                    "Required — the Foundry refuses account creation "
                    "without the researcher's up-front authorization.",
    )


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
