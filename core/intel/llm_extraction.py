"""
LLM-driven extraction of structured ProgramScope data from policy text.

This is the bridge between unstructured bug-bounty policy pages and
Sentinel's typed data model. It runs in three stages:

  1. Pre-filter the page (strip HTML noise, focus on policy-relevant text)
  2. Call the local Ollama LLM with a strict JSON-output prompt
  3. Validate the response against ``ExtractedScope`` (Pydantic schema);
     on schema failure, retry once with the validation error appended
     to the prompt as a self-correction hint.

Why the LLM-facing schema is separate from ``ProgramScope``:
  Provenance fields (``raw_content_hash``, ``extractor_version``,
  ``extraction_confidence``) are not things a language model can
  legitimately produce — they're computed by the extractor that calls
  the model. The Pydantic schema below contains only the fields a
  model can derive *from policy text alone*. The extractor wraps that
  output with provenance to build the full ``ProgramScope``.

Why Pydantic for this schema (and not the main model):
  Untrusted input (LLM output) demands a hard validation boundary.
  Pydantic v2 gives type coercion, error reporting suitable for
  self-correction retries, and ``model_validate_json`` in one step.
"""
from __future__ import annotations

import json
import logging
from typing import List, Optional

from pydantic import BaseModel, Field, ValidationError

from core.intel.program_scope import (
    CredentialSource,
    LoginFlow,
    Persona,
    Platform,
    Restriction,
    RestrictionKind,
    ScopeRule,
    ScopeRuleType,
)

logger = logging.getLogger(__name__)


# Bumped any time the extraction prompt or output schema changes
# materially. Stored on the resulting ProgramScope.extractor_version
# so re-runs can detect prompt drift.
EXTRACTOR_VERSION = "llm_extraction@1.0"

# Cap input length to a reasonable model context. Most program pages
# fit comfortably under 30k chars after sanitization.
MAX_INPUT_CHARS = 30_000


# ─────────────────────────────────────────────────────────────────────────
# LLM-facing Pydantic schema
# ─────────────────────────────────────────────────────────────────────────

class ExtractedScopeRule(BaseModel):
    """A single in-scope or out-of-scope assertion as the LLM sees it."""
    pattern: str = Field(
        ...,
        description='Domain, URL, or CIDR pattern. Examples: "*.example.com", '
                    '"https://app.example.com/admin/*", "10.0.0.0/8".',
    )
    rule_type: str = Field(
        ...,
        description='One of: "domain", "url", "ip_cidr", "mobile_app", '
                    '"source_code", "other".',
    )
    in_scope: bool = Field(
        ...,
        description="true if this asset is in-scope for testing; false if "
                    "explicitly out-of-scope.",
    )
    notes: Optional[str] = Field(
        None,
        description="Any qualifiers from the policy text (e.g. 'production only').",
    )


class ExtractedLoginFlow(BaseModel):
    """How to authenticate, if the policy describes a login flow."""
    endpoint: str
    method: str = "POST"
    username_param: str = "email"
    password_param: str = "password"
    content_type: str = "application/json"


class ExtractedPersona(BaseModel):
    """A test credential pair as listed in the policy."""
    name: str = Field(..., description='Display name e.g. "test user", "admin".')
    persona_type: str = Field(
        ...,
        description='Role descriptor: "user", "admin", "merchant", "anonymous", etc.',
    )
    base_url: str = Field(
        ...,
        description="URL of the application this credential authenticates to.",
    )
    username: Optional[str] = Field(
        None,
        description="The email or username, exactly as listed in the policy. "
                    "Do NOT guess — if not present, return null.",
    )
    password: Optional[str] = Field(
        None,
        description="The password, exactly as listed. Do NOT guess.",
    )
    login_flow: Optional[ExtractedLoginFlow] = Field(
        None,
        description="Authentication endpoint info if described.",
    )
    role_hint: Optional[str] = None


class ExtractedRestriction(BaseModel):
    """A constraint the program imposes on testing."""
    kind: str = Field(
        ...,
        description='One of: "no_dos", "no_automated_scan", "no_social_engineering", '
                    '"no_data_destruction", "no_bruteforce", "no_third_party_services", '
                    '"rate_limited", "business_hours_only", "region_restricted", '
                    '"requires_prior_approval", "other".',
    )
    severity: str = Field(
        ...,
        description='"hard" if the policy says the action is prohibited or will '
                    'disqualify a submission; "soft" if the policy merely requests it.',
    )
    description: str = Field(
        ...,
        description="One-sentence description in your own words.",
    )
    raw_quote: Optional[str] = Field(
        None,
        description="Verbatim quote from the policy that supports this restriction. "
                    "Required for auditability — include whenever possible.",
    )
    applies_to: List[str] = Field(
        default_factory=lambda: ["all"],
        description=(
            'CRITICAL — the SCOPE of this rule: which category of testing it '
            'governs. Look at WHERE in the policy the rule appears.\n'
            '  ["all"]        = a global rule governing ALL testing on the program\n'
            '  ["dos"]        = the rule is in a DoS / load-testing section\n'
            '  ["bruteforce"] = the rule is about brute-force / enumeration only\n'
            '  ["social_eng"] = the rule is about social engineering only\n'
            '  ["automated"]  = the rule is specifically about automated/scanner traffic\n'
            'Example: "No automated tools or high-volume attacks" appearing under '
            'a "Denial of Service testing" heading is ["dos"], NOT ["all"] — it '
            'only restricts DoS testing. Do not mark a rule ["all"] unless it '
            'truly governs every kind of testing program-wide.'
        ),
    )


class ExtractedScope(BaseModel):
    """Top-level LLM extraction output. Matches the JSON the model must return."""
    name: str = Field(..., description="Program / organization name.")
    scope_rules: List[ExtractedScopeRule] = Field(default_factory=list)
    personas: List[ExtractedPersona] = Field(default_factory=list)
    signup_endpoint: Optional[str] = Field(
        None,
        description="If the policy says testers can create their own accounts, "
                    "the signup endpoint URL or path. null otherwise.",
    )
    restrictions: List[ExtractedRestriction] = Field(default_factory=list)
    rate_limit_rps: Optional[float] = Field(
        None,
        description='Numeric rate limit in requests-per-second if specified.',
    )
    payout_max_usd: Optional[int] = Field(
        None,
        description="Maximum bounty payout in USD if stated.",
    )
    extraction_confidence: float = Field(
        0.5,
        ge=0.0,
        le=1.0,
        description="0.0-1.0 self-assessed confidence that the extraction is "
                    "complete and accurate. Lower means the page was ambiguous "
                    "or partial.",
    )


# ─────────────────────────────────────────────────────────────────────────
# Prompt construction
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a security recon analyst. Your job is to read a bug bounty program's policy page and extract structured facts as strict JSON.

Rules — these are non-negotiable:

1. Return ONLY valid JSON conforming to the schema in the user message. No prose, no explanation, no markdown fences.
2. If a field is not present in the text, return null (for scalars) or [] (for arrays). Do NOT guess. Do NOT infer values that aren't explicitly stated.
3. Hallucinated credentials are the worst possible failure mode. If you didn't see a username/password pair written verbatim in the text, set them to null.
4. For scope_rules, include both in-scope (in_scope: true) and out-of-scope (in_scope: false) assertions. Programs often list both.
5. For restrictions, "hard" means the policy says testing this is prohibited or will disqualify a finding. "soft" means the policy expresses a preference but isn't blocking.
6. For extraction_confidence, score honestly: 0.9+ if the policy is clear and unambiguous, 0.5 if you're inferring structure from prose, 0.2 if the page is partial or contradictory.

Output: a single JSON object. Nothing else."""


def _build_user_prompt(policy_text: str, *, retry_hint: Optional[str] = None) -> str:
    """Construct the user message containing the schema + the page text.

    On retries (when validation failed last time), ``retry_hint`` is
    appended with the validation error so the model can self-correct.
    """
    schema_doc = ExtractedScope.model_json_schema()
    # Pretty-print but compactly — the model handles dense JSON better
    # than line-wrapped pretty JSON in practice.
    schema_str = json.dumps(schema_doc, separators=(",", ":"))

    parts = [
        "Extract structured facts from the policy text below. Return JSON "
        "matching this exact schema:",
        "",
        schema_str,
        "",
        "Policy text:",
        "─" * 60,
        policy_text[:MAX_INPUT_CHARS],
        "─" * 60,
    ]
    if retry_hint:
        parts.extend([
            "",
            "IMPORTANT — your previous response failed validation:",
            retry_hint,
            "Fix the schema violation and respond again with ONLY valid JSON.",
        ])
    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────
# Extraction entry point
# ─────────────────────────────────────────────────────────────────────────

# Policies longer than this (chars) are chunked before extraction. A 9B
# local model reading >~3k tokens AND emitting structured JSON in one shot
# routinely exceeds the request timeout (GitLab's 25KB policy timed out at
# 300s — Calibration Run #17). Chunking keeps each call small and fast.
CHUNK_THRESHOLD_CHARS = 12_000
CHUNK_SIZE_CHARS = 10_000


async def extract_scope_with_llm(
    policy_text: str,
    *,
    ai_engine=None,  # injectable for testing — defaults to AIEngine.instance()
    max_retries: int = 1,
) -> Optional[ExtractedScope]:
    """Run LLM extraction on policy text. Returns ``None`` if extraction
    fails after all retries or the LLM is unavailable.

    The contract: a non-None return is **always** a schema-valid
    ``ExtractedScope``. Schema-invalid model outputs are silently dropped
    by this function (after retries) — callers should treat None as
    "extraction failed, fall back to whatever else you have."

    ``max_retries`` is the count of *additional* attempts after the
    initial one — so default 1 means up to 2 total LLM calls.

    Large policies (> ``CHUNK_THRESHOLD_CHARS``) are split on paragraph
    boundaries, extracted chunk-by-chunk, and merged — each call stays
    small enough to avoid the request timeout that one-shot extraction of
    a 25KB policy hits.
    """
    if not policy_text or not policy_text.strip():
        logger.warning("[intel.llm] empty policy_text — nothing to extract")
        return None

    # Lazy import so this module can be imported without booting the AI
    # singleton (important for tests that mock the engine).
    if ai_engine is None:
        from core.ai.ai_engine import AIEngine
        ai_engine = AIEngine.instance()

    # Large policy → chunk + merge to avoid one-shot timeout.
    if len(policy_text) > CHUNK_THRESHOLD_CHARS:
        return await _extract_chunked(
            policy_text, ai_engine=ai_engine, max_retries=max_retries,
        )

    return await _extract_single(
        policy_text, ai_engine=ai_engine, max_retries=max_retries,
    )


async def _extract_single(
    policy_text: str,
    *,
    ai_engine,
    max_retries: int = 1,
) -> Optional[ExtractedScope]:
    """Single-shot extraction over one (already size-bounded) text."""
    retry_hint: Optional[str] = None
    last_validation_error: Optional[str] = None

    for attempt in range(max_retries + 1):
        user_prompt = _build_user_prompt(policy_text, retry_hint=retry_hint)

        raw = await ai_engine.safe_generate(
            prompt=user_prompt,
            system=SYSTEM_PROMPT,
            force_json=True,
        )
        if raw is None:
            logger.warning(
                "[intel.llm] LLM returned None on attempt %d (engine down or "
                "circuit breaker open)", attempt + 1
            )
            # If the engine is unreachable, retrying immediately won't
            # help — the circuit breaker is already managing back-off.
            return None

        # Extract JSON from possibly-fenced model output.
        from core.ai.ai_engine import _extract_json_payload
        payload = _extract_json_payload(raw)

        try:
            extracted = ExtractedScope.model_validate_json(payload)
            logger.info(
                "[intel.llm] extraction OK on attempt %d "
                "(personas=%d, scope_rules=%d, restrictions=%d, conf=%.2f)",
                attempt + 1, len(extracted.personas), len(extracted.scope_rules),
                len(extracted.restrictions), extracted.extraction_confidence,
            )
            return extracted
        except ValidationError as e:
            last_validation_error = str(e)
            logger.warning(
                "[intel.llm] schema validation failed on attempt %d: %s",
                attempt + 1, last_validation_error[:300],
            )
            retry_hint = last_validation_error
            # Loop continues to retry if we have attempts remaining.

    logger.error(
        "[intel.llm] extraction failed after %d attempts; last error: %s",
        max_retries + 1, last_validation_error,
    )
    return None


# ─────────────────────────────────────────────────────────────────────────
# Chunked extraction for large policies
# ─────────────────────────────────────────────────────────────────────────

def _chunk_policy(text: str, *, chunk_size: int = CHUNK_SIZE_CHARS) -> List[str]:
    """Split policy text into chunks on paragraph boundaries.

    Accumulates whole paragraphs (split on blank lines) until adding the
    next would exceed ``chunk_size``. Splitting on paragraph boundaries —
    not byte offsets — keeps each rule's surrounding context intact so the
    LLM can still determine its ``applies_to`` scope (a rule cut off from
    its "Denial of Service testing" heading would lose that signal).

    A single paragraph larger than chunk_size is emitted as its own chunk
    (hard-split as a last resort) rather than dropped.
    """
    paragraphs = text.split("\n\n")
    chunks: List[str] = []
    current: List[str] = []
    current_len = 0
    for para in paragraphs:
        para_len = len(para) + 2  # account for the "\n\n" join
        if current and current_len + para_len > chunk_size:
            chunks.append("\n\n".join(current))
            current = []
            current_len = 0
        if para_len > chunk_size and not current:
            # Single oversized paragraph — hard-split into chunk_size pieces.
            for i in range(0, len(para), chunk_size):
                chunks.append(para[i:i + chunk_size])
            continue
        current.append(para)
        current_len += para_len
    if current:
        chunks.append("\n\n".join(current))
    return [c for c in chunks if c.strip()]


async def _extract_chunked(
    policy_text: str,
    *,
    ai_engine,
    max_retries: int = 1,
) -> Optional[ExtractedScope]:
    """Extract from a large policy by chunking + merging.

    Each chunk is extracted independently (small enough to avoid timeout);
    results are merged. Returns None only if EVERY chunk failed — a single
    successful chunk still yields a usable (partial) ExtractedScope.
    """
    chunks = _chunk_policy(policy_text)
    logger.info(
        "[intel.llm] policy is %d chars — chunking into %d pieces for extraction",
        len(policy_text), len(chunks),
    )
    partials: List[ExtractedScope] = []
    for idx, chunk in enumerate(chunks):
        result = await _extract_single(
            chunk, ai_engine=ai_engine, max_retries=max_retries,
        )
        if result is not None:
            partials.append(result)
            logger.info(
                "[intel.llm] chunk %d/%d OK (restrictions=%d, personas=%d)",
                idx + 1, len(chunks), len(result.restrictions), len(result.personas),
            )
        else:
            logger.warning("[intel.llm] chunk %d/%d failed extraction", idx + 1, len(chunks))

    if not partials:
        logger.error("[intel.llm] all %d chunks failed extraction", len(chunks))
        return None

    return _merge_extracted_scopes(partials)


def _merge_extracted_scopes(scopes: List[ExtractedScope]) -> ExtractedScope:
    """Merge multiple per-chunk ExtractedScope objects into one.

    - name: first non-empty
    - scope_rules: union, dedup by (pattern, in_scope)
    - personas: union, dedup by name
    - restrictions: union, dedup by (kind, description)
    - signup_endpoint / rate_limit_rps: first non-null
    - extraction_confidence: minimum (a chain is only as confident as its
      least-confident chunk)
    """
    name = next((s.name for s in scopes if s.name and s.name.strip()), scopes[0].name)

    scope_rules: List[ExtractedScopeRule] = []
    seen_rules = set()
    for s in scopes:
        for r in s.scope_rules:
            key = (r.pattern, r.in_scope)
            if key not in seen_rules:
                seen_rules.add(key)
                scope_rules.append(r)

    personas: List[ExtractedPersona] = []
    seen_personas = set()
    for s in scopes:
        for p in s.personas:
            if p.name not in seen_personas:
                seen_personas.add(p.name)
                personas.append(p)

    restrictions: List[ExtractedRestriction] = []
    seen_restrictions = set()
    for s in scopes:
        for r in s.restrictions:
            key = (r.kind, r.description)
            if key not in seen_restrictions:
                seen_restrictions.add(key)
                restrictions.append(r)

    signup_endpoint = next((s.signup_endpoint for s in scopes if s.signup_endpoint), None)
    rate_limit_rps = next((s.rate_limit_rps for s in scopes if s.rate_limit_rps is not None), None)
    confidence = min((s.extraction_confidence for s in scopes), default=0.5)

    return ExtractedScope(
        name=name,
        scope_rules=scope_rules,
        personas=personas,
        signup_endpoint=signup_endpoint,
        restrictions=restrictions,
        rate_limit_rps=rate_limit_rps,
        extraction_confidence=confidence,
    )


# ─────────────────────────────────────────────────────────────────────────
# Translator: ExtractedScope → ProgramScope dataclasses
# ─────────────────────────────────────────────────────────────────────────

def to_scope_rule(extracted: ExtractedScopeRule) -> ScopeRule:
    """Translate one Pydantic rule to its dataclass equivalent.

    Unknown rule_type strings fall back to ``ScopeRuleType.OTHER`` rather
    than raising — the LLM may emit a label we haven't enumerated yet,
    and dropping the rule entirely is worse than tagging it.
    """
    try:
        rule_type = ScopeRuleType(extracted.rule_type)
    except ValueError:
        logger.info(
            "[intel.llm] unknown rule_type %r — coercing to OTHER",
            extracted.rule_type,
        )
        rule_type = ScopeRuleType.OTHER
    return ScopeRule(
        pattern=extracted.pattern,
        rule_type=rule_type,
        in_scope=extracted.in_scope,
        notes=extracted.notes,
    )


def to_persona(extracted: ExtractedPersona) -> Persona:
    """Translate one Pydantic persona to a Persona dataclass.

    The credential source is always ``POLICY_EXPLICIT`` — by the time
    we got here, the LLM saw the credential in the policy text. If
    later steps decide the LLM hallucinated (verification fails), the
    persona will be marked ``verified=FAILED`` but source stays
    ``POLICY_EXPLICIT`` since that's where it was *purportedly* found.
    """
    login_flow: Optional[LoginFlow] = None
    if extracted.login_flow is not None:
        lf = extracted.login_flow
        login_flow = LoginFlow(
            endpoint=lf.endpoint,
            method=lf.method,
            username_param=lf.username_param,
            password_param=lf.password_param,
            content_type=lf.content_type,
        )
    return Persona(
        name=extracted.name,
        persona_type=extracted.persona_type,
        base_url=extracted.base_url,
        login_flow=login_flow,
        username=extracted.username,
        password=extracted.password,
        role_hint=extracted.role_hint,
        source=CredentialSource.POLICY_EXPLICIT,
        # Verification status stays UNVERIFIED — the verifier sets this
        # to VERIFIED/FAILED after attempting a real login.
    )


def to_restriction(extracted: ExtractedRestriction) -> Restriction:
    """Translate one Pydantic restriction to its dataclass equivalent.

    Unknown ``kind`` strings coerce to ``RestrictionKind.OTHER``, same
    pattern as ``to_scope_rule``.
    """
    try:
        kind = RestrictionKind(extracted.kind)
    except ValueError:
        logger.info(
            "[intel.llm] unknown restriction kind %r — coercing to OTHER",
            extracted.kind,
        )
        kind = RestrictionKind.OTHER
    severity = extracted.severity if extracted.severity in ("hard", "soft") else "soft"
    # Normalize applies_to: lowercase, dedupe, default to ["all"] if empty.
    applies_to = [s.strip().lower() for s in (extracted.applies_to or []) if s and s.strip()]
    if not applies_to:
        applies_to = ["all"]
    return Restriction(
        kind=kind,
        severity=severity,
        description=extracted.description,
        raw_quote=extracted.raw_quote,
        applies_to=applies_to,
    )
