from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator

from core.server.state import get_state
from core.server.routers.auth import verify_sensitive_token, verify_token
from core.errors import SentinelError, ErrorCode
from core.data.db import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    modules: Optional[List[str]] = None
    force: bool = False
    mode: str = "standard"
    # Optional per-scan knowledge configuration used by internal verification tools.
    # These are intentionally kept minimal and opt-in; missing config simply disables
    # the corresponding internal tools (wraith_persona_diff / wraith_oob_probe).
    personas: Optional[List[Dict[str, Any]]] = None
    oob: Optional[Dict[str, Any]] = None
    # Bug bounty scope rules. List of scope strings:
    #   "*.example.com"          — wildcard domain (matches all subdomains)
    #   "example.com/api"        — domain + path prefix
    #   "!staging.example.com"   — explicit exclusion (prefix with !)
    #   "10.0.0.0/24"            — CIDR block
    #   "/regex/"                — regex pattern (surrounded by slashes)
    # If omitted, all targets are allowed (permissive mode).
    # Set strict=true to reject targets that don't match any inclusion rule.
    scope: Optional[List[str]] = None
    scope_strict: bool = False
    
    # Bounty Integration
    bounty_handle: Optional[str] = None
    bounty_json: Optional[Dict[str, Any]] = None

    # Phase 2H: program-policy enforcement.
    # ``restrictions`` is the parsed body of a ``<program>-restrictions.json``
    # file produced by ``sentinel-ingest``. When set, the engine applies the
    # corresponding ``PolicyEnforcement`` *before* scan execution — refusing
    # the scan entirely if any hard restriction has ``enforcement: block_scan``,
    # otherwise injecting banned_tools / rate limits / strict-scope into
    # ExecutionPolicy + ScopeContext.
    # Operators set this via ``pysentinel --restrictions <path>``; the CLI
    # reads the file and passes the parsed dict in the request body.
    restrictions: Optional[Dict[str, Any]] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            logger.warning("Scan start rejected: empty target")
            raise ValueError("Target cannot be empty")
        dangerous_patterns = [";", "&&", "||", "`", "$(", "\n", "\r", "|"]
        for pattern in dangerous_patterns:
            if pattern in v:
                logger.warning(f"Scan start rejected: dangerous character '{pattern}' in target: {v}")
                raise ValueError(f"Invalid character in target: {pattern}")
        
        # Validate URL format
        try:
            parsed = urlparse(v)
            if not parsed.scheme:
                logger.warning(f"Scan start rejected: missing URL scheme in target: {v}")
                raise ValueError("Invalid target URL: missing scheme (e.g., http:// or https://)")
            if parsed.scheme not in ("http", "https"):
                logger.warning(f"Scan start rejected: invalid scheme '{parsed.scheme}' in target: {v}")
                raise ValueError("Invalid target URL: scheme must be http or https")
            if not parsed.netloc:
                logger.warning(f"Scan start rejected: missing network location in target: {v}")
                raise ValueError("Invalid target URL: missing network location")
        except ValueError:
            raise
        except Exception as e:
            logger.warning(f"Scan start rejected: URL parsing error for target '{v}': {str(e)}")
            raise ValueError(f"Invalid target URL: {str(e)}")
        
        return v

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        from core.toolkit.tools import TOOLS
        valid_tools = set(TOOLS.keys())
        invalid = [tool for tool in v if tool not in valid_tools]
        if invalid:
            raise ValueError(f"Invalid tool names: {', '.join(invalid)}")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        raw = str(v or "").strip().lower()
        aliases = {
            "standard": "standard",
            "bug_bounty": "bug_bounty",
            "bug-bounty": "bug_bounty",
            "bugbounty": "bug_bounty",
            "stealth": "stealth",
            "passive": "passive",
        }
        normalized = aliases.get(raw)
        if not normalized:
            allowed = ", ".join(sorted({"standard", "bug_bounty", "stealth", "passive"}))
            raise ValueError(f"Invalid scan mode '{v}'. Allowed modes: {allowed}")
        return normalized

    @field_validator("personas")
    @classmethod
    def validate_personas(cls, v: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError("personas must be a list")
        if len(v) > 8:
            raise ValueError("personas list too large (max 8)")
        # Shallow validation: ensure each persona is a dict with a name field.
        for idx, item in enumerate(v):
            if not isinstance(item, dict):
                raise ValueError(f"personas[{idx}] must be an object")
            name = item.get("name")
            if name is not None and (not isinstance(name, str) or not name.strip()):
                raise ValueError(f"personas[{idx}].name must be a non-empty string")
        return v

    @field_validator("oob")
    @classmethod
    def validate_oob(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError("oob must be an object")
        base_domain = v.get("base_domain")
        if base_domain is not None and (not isinstance(base_domain, str) or not base_domain.strip()):
            raise ValueError("oob.base_domain must be a non-empty string when provided")
        provider = v.get("provider")
        if provider is not None and not isinstance(provider, str):
            raise ValueError("oob.provider must be a string when provided")
        return v

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError("scope must be a list of strings")
        if len(v) > 256:
            raise ValueError("scope list too large (max 256 entries)")
        cleaned: List[str] = []
        for idx, entry in enumerate(v):
            if not isinstance(entry, str):
                raise ValueError(f"scope[{idx}] must be a string")
            entry = entry.strip()
            if not entry or entry.startswith("#"):
                continue  # silently drop blank lines / comments
            cleaned.append(entry)
        return cleaned or None

def _log_sink_sync(msg: str) -> None:
    state = get_state()
    loop = None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = state.api_loop

    if loop is not None:
        try:
            if state.log_queue.full():
                logger.warning("Log queue overflow, dropping entry.")
            else:
                state.log_queue.put_nowait(msg)
        except Exception:
            pass


def _extract_graph_attack_paths_from_graph_dto(graph_dto: Dict[str, Any]) -> List[List[str]]:
    """
    Convert graph attack_chains payload to list-of-steps format.
    Never rebuild the graph here; empty or malformed chains degrade to [].
    """
    graph_attack_paths: List[List[str]] = []
    chains_from_dto = graph_dto.get("attack_chains", [])
    if not isinstance(chains_from_dto, list):
        logger.debug("[Results] attack_chains payload is not a list; returning empty graph_attack_paths")
        return graph_attack_paths

    for chain in chains_from_dto[:25]:
        if not isinstance(chain, dict):
            continue
        labels = chain.get("labels", [])
        if isinstance(labels, list) and labels:
            graph_attack_paths.append([str(label) for label in labels])
            continue
        node_ids = chain.get("node_ids", [])
        if isinstance(node_ids, list) and node_ids:
            graph_attack_paths.append([str(node_id) for node_id in node_ids])
    return graph_attack_paths


def _extract_attack_paths_from_graph_dto(graph_dto: Dict[str, Any]) -> List[List[str]]:
    """
    Backward-compat helper alias.
    Deprecated: use _extract_graph_attack_paths_from_graph_dto.
    """
    return _extract_graph_attack_paths_from_graph_dto(graph_dto)

async def begin_scan_logic(req: ScanRequest) -> str:
    state = get_state()
    
    from core.base.session import ScanSession
    from core.cortex.events import get_event_bus
    from core.engine.scanner_engine import ScannerEngine
    from core.toolkit.tools import get_installed_tools
    from core.cortex.reasoning import reasoning_engine
    from core.cortex.events import GraphEvent, GraphEventType

    async with state.scan_lock:
        if state.active_scan_task and not state.active_scan_task.done():
            if req.force:
                logger.info("Force-killing active scan...")
                state.cancel_requested.set()
                state.active_scan_task.cancel()
                try:
                    await state.active_scan_task
                except asyncio.CancelledError:
                    pass
                state.active_scan_task = None
            else:
                raise SentinelError(
                    ErrorCode.SCAN_ALREADY_RUNNING,
                    "Cannot start scan while another is active",
                    details={"active_target": state.scan_state.get("target")}
                )

        previous_session_id = state.scan_state.get("session_id")
        if previous_session_id:
            try:
                await state.unregister_session(previous_session_id)
            except Exception:
                pass

        state.cancel_requested.clear()

        session = ScanSession(req.target)
        # Seed per-scan knowledge used by internal tools. This is opt-in and
        # intentionally shallow-validated at the API boundary.
        if req.personas:
            session.knowledge["personas"] = req.personas
        if req.oob:
            session.knowledge["oob"] = req.oob

        # ─── Scope enforcement ────────────────────────────────────────────
        from core.base.scope import ScopeRegistry, ScopeRule, AssetType, ScopeDecision
        from core.base.context import ScopeContext
        from core.base.execution_policy import ExecutionPolicy
        from core.cortex.capability_tiers import ExecutionMode
        
        registry = ScopeRegistry()
        
        # 1. Parse manual scope lines
        if req.scope:
            for line in req.scope:
                # Strip inline comments emitted by sentinel-ingest's scope_compiler.
                # Lines may look like: "gitlab.com  # max_severity=critical"
                # We split on the two-space-hash marker so legitimate single-#
                # patterns (rare but possible) don't get truncated.
                if "  #" in line:
                    line = line.split("  #", 1)[0].strip()
                if not line:
                    continue
                decision = ScopeDecision.DENY if line.startswith("!") else ScopeDecision.ALLOW
                target_str = line.lstrip("!")
                # Rough inference for AssetType
                if target_str.startswith("*."):
                    asset_type = AssetType.WILDCARD
                elif "/" in target_str and target_str[0].isdigit():
                    asset_type = AssetType.CIDR
                elif "://" in target_str:
                    asset_type = AssetType.URL
                elif "/" in target_str:
                    asset_type = AssetType.PATH
                else:
                    asset_type = AssetType.DOMAIN
                    
                registry.add_rule(ScopeRule(asset_type=asset_type, target=target_str, decision=decision))
        
        # 2. Parse HackerOne integrations
        if req.bounty_json:
            from core.bounty.h1_client import HackerOneClient, parse_to_registry, H1ScopeDTO, H1ScopeElement
            # Convert dict to DTO
            dto = H1ScopeDTO(handle=req.bounty_json.get("handle", "unknown"))
            for item in req.bounty_json.get("in_scope", []):
                dto.in_scope.append(H1ScopeElement(
                    asset_identifier=item.get("asset_identifier", ""),
                    asset_type=item.get("asset_type", "URL"),
                    eligible_for_bounty=item.get("eligible_for_submission", True),
                    instruction=item.get("instruction", "")
                ))
            for item in req.bounty_json.get("out_of_scope", []):
                dto.out_of_scope.append(H1ScopeElement(
                    asset_identifier=item.get("asset_identifier", ""),
                    asset_type=item.get("asset_type", "URL"),
                    eligible_for_bounty=False,
                    instruction=item.get("instruction", "")
                ))
            parse_to_registry(dto, registry)
            
        elif req.bounty_handle:
            from core.bounty.h1_client import HackerOneClient, parse_to_registry
            client = HackerOneClient()
            dto = client.fetch_via_api(req.bounty_handle)
            parse_to_registry(dto, registry)

        # 3. Create Context
        # Map the validated scan-mode vocabulary (standard/bug_bounty/stealth/
        # passive) onto the two execution tiers (research/bounty). bug_bounty is
        # the ONLY mode that engages bounty-grade strict scope + the active
        # verification phase.
        #
        # BUG THIS FIXES: the old `ExecutionMode(req.mode)` silently fell back to
        # RESEARCH for *every* value except the literal "bounty" — and the
        # request validator never emits "bounty" (it emits "bug_bounty"). So
        # selecting bug_bounty produced ExecutionMode.RESEARCH, the
        # conservative-deny scope gate (is_bounty) never engaged, and
        # out-of-scope hosts (e.g. scanme.nmap.org) leaked into the scan.
        _MODE_TO_EXEC = {
            "bug_bounty": ExecutionMode.BOUNTY,
            "bounty": ExecutionMode.BOUNTY,
            "standard": ExecutionMode.RESEARCH,
            "stealth": ExecutionMode.RESEARCH,
            "passive": ExecutionMode.RESEARCH,
        }
        emode = _MODE_TO_EXEC.get(str(req.mode).strip().lower(), ExecutionMode.RESEARCH)

        # Phase 2H: Apply program-policy enforcement BEFORE constructing the
        # ScopeContext so banned_tools / rate limit / scope_strict are baked
        # into the ExecutionPolicy that ScopeContext holds. ``req.restrictions``
        # is the parsed body of a ``<program>-restrictions.json`` produced by
        # ``sentinel-ingest``; the policy_enforcer translates it into the
        # PolicyEnforcement struct, then we copy fields onto ExecutionPolicy.
        execution_policy = ExecutionPolicy()
        enforcement = None
        scope_strict_effective = req.scope_strict
        if req.restrictions:
            from core.intel.policy_enforcer import enforce as _enforce_restrictions
            enforcement = _enforce_restrictions(req.restrictions)

            # Hard block: if any restriction's enforcement is "block_scan"
            # with severity "hard", refuse the scan with a clear reason.
            if enforcement.scan_blocked:
                logger.warning(
                    "Scan request rejected by hard restriction: %s",
                    enforcement.scan_blocked_reason,
                )
                raise SentinelError(
                    ErrorCode.SCAN_TARGET_INVALID,
                    f"Scan blocked by program policy: {enforcement.scan_blocked_reason}",
                    details={
                        "blocked_reason": enforcement.scan_blocked_reason,
                        "warnings": enforcement.warnings,
                    },
                )

            # Soft enforcement: bake disabled tools + rate limit into the
            # ExecutionPolicy that ScopeContext holds.
            enforcement.apply_to_execution_policy(execution_policy)

            # Scope-strict: a NO_THIRD_PARTY restriction enforces strict scope
            # regardless of what the operator requested. Restrictions tighten,
            # never loosen.
            if enforcement.scope_strict:
                scope_strict_effective = True

            # Required attestations: log them. The CLI is responsible for
            # asking the operator BEFORE sending the request; if those got
            # bypassed, the engine logs but does not block (the operator may
            # have a legitimate non-CLI flow).
            for attestation in enforcement.required_attestations:
                logger.info("[policy] required attestation: %s", attestation)
            for warning in enforcement.warnings:
                logger.warning("[policy] %s", warning)

        scope_context = ScopeContext(
            registry=registry,
            policy=execution_policy,
            mode=emode.value,
            scan_id=session.id
        )

        # Fail-fast: the primary target itself must be in scope.
        check_decision = scope_context.registry.resolve(req.target)
        is_bounty = scope_context.mode == ExecutionMode.BOUNTY
        if check_decision.verdict == ScopeDecision.DENY or (check_decision.verdict == ScopeDecision.UNKNOWN and (is_bounty or scope_strict_effective)):
            raise SentinelError(
                ErrorCode.SCAN_TARGET_INVALID,
                f"Target is outside the declared scope: {check_decision.reason_code.value}",
                details={"target": req.target, "verdict": check_decision.verdict.value},
            )

        # Bind ScopeContext physically to the session
        session.scope_context = scope_context
        # ─────────────────────────────────────────────────────────────────

        session.set_external_log_sink(_log_sink_sync)
        await state.register_session(session.id, session)

        db = Database.instance()
        await db.init()
        await db.blackbox.enqueue(db._save_session_impl, session.to_dict())

        installed_tools = list(get_installed_tools().keys())
        requested_tools = list(dict.fromkeys(req.modules or []))
        allowed_tools = (
            [t for t in requested_tools if t in installed_tools]
            if requested_tools
            else installed_tools
        )
        # Phase 2H: subtract any banned_tools the policy enforcement set
        # (e.g. nuclei_mutating disabled by NO_DOS). banned_tools is a Set;
        # check for None defensively since older policies may not have it.
        banned = execution_policy.banned_tools or set()
        if banned:
            removed = [t for t in allowed_tools if t in banned]
            if removed:
                logger.info(
                    "[policy] removing %d tool(s) banned by program policy: %s",
                    len(removed), sorted(removed),
                )
            allowed_tools = [t for t in allowed_tools if t not in banned]
        
        state.scan_state = {
            "target": req.target,
            "modules": req.modules,
            "mode": req.mode,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "session_id": session.id,
            # Will hold dispatch_tool closure once scan runner starts
            "_dispatch_tool": None,
        }

        event_bus = get_event_bus()
        event_bus.emit_scan_started(req.target, allowed_tools, session.id)

        # ─── ActionDispatcher → tool execution bridge ───────────────────
        from core.base.action_dispatcher import ActionDispatcher
        _action_dispatcher = ActionDispatcher.instance()

        # Capture immutable identifiers (not mutable objects) so the closure
        # can safely verify liveness without holding stale references.
        _bound_session_id = session.id
        _bound_target = req.target

        def _on_action_approved(action: Dict) -> None:
            """Fire-and-forget: schedule approved tool execution on the event loop.

            Called from whatever thread emits the signal (may be AI thread).
            We only touch thread-safe primitives here and defer real work
            to the event loop via run_coroutine_threadsafe.
            """
            tool_name = action.get("tool", "")
            if not tool_name:
                return

            # Guard: verify the scan that wired us is still the active one.
            current_state = get_state()
            active_sid = (current_state.scan_state or {}).get("session_id")
            if active_sid != _bound_session_id:
                logger.warning(
                    "[ActionBridge] Stale callback: bound to session %s but active is %s — skipping",
                    _bound_session_id, active_sid,
                )
                return

            loop = current_state.api_loop
            if loop is None or loop.is_closed():
                logger.warning("[ActionBridge] No event loop for approved action %s", action.get("id"))
                return
            asyncio.run_coroutine_threadsafe(
                _dispatch_approved_action(action), loop,
            )

        async def _dispatch_approved_action(action: Dict) -> None:
            """Execute an AI-approved tool within the active scan session.

            Re-resolves session and event_bus from global state each time
            so we never operate on a stale/dead session object.
            """
            tool_name = action.get("tool", "")
            args = action.get("args", [])
            target_url = action.get("target") or _bound_target

            # Re-resolve session from the live state manager
            current_state = get_state()
            live_session = None
            for _sid, _sess in current_state.session_manager.items():
                if _sid == _bound_session_id:
                    live_session = _sess
                    break
            if live_session is None:
                logger.warning("[ActionBridge] Session %s no longer active — dropping action %s",
                               _bound_session_id, action.get("id"))
                return

            # Freshen event_bus from the module-level getter
            _event_bus = get_event_bus()

            live_session.log(f"[ActionDispatcher] Executing approved tool: {tool_name} {' '.join(args)}")

            engine = ScannerEngine(session=live_session)
            findings: List[Dict] = []
            exit_code = 0
            tool_error: Optional[Dict[str, Any]] = None
            try:
                _event_bus.emit_tool_invoked(tool=tool_name, target=target_url, args=args, scan_id=live_session.id)
                if current_state.cancel_requested.is_set():
                    return

                async for log_line in engine.scan(
                    target_url, selected_tools=[tool_name], cancel_flag=current_state.cancel_requested,
                ):
                    live_session.log(log_line)

                findings = engine.get_last_results() or []
                tool_error = engine.consume_last_tool_error()
                exit_code = 130 if current_state.cancel_requested.is_set() else 0
                if tool_error and "exit_code" in tool_error:
                    exit_code = int(tool_error["exit_code"])
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                live_session.log(f"[ActionDispatcher] Tool failed ({tool_name}): {exc}")
                logger.error("[ActionBridge] Approved action failed: %s", exc, exc_info=True)
            finally:
                _event_bus.emit_tool_completed(
                    tool=tool_name,
                    exit_code=exit_code,
                    findings_count=len(findings),
                    scan_id=live_session.id,
                    error=tool_error,
                )

        _action_dispatcher.action_approved.connect(_on_action_approved)
        logger.info("[ActionBridge] Wired action_approved → tool execution for session %s", session.id)

        async def _runner() -> None:
            start_time = time.time()
            try:
                async def dispatch_tool(tool: str) -> List[Dict]:
                    findings = []
                    exit_code = 0
                    tool_error: Optional[Dict[str, Any]] = None

                    if tool not in allowed_tools:
                        session.log(f"⚠️ [Security] Tool '{tool}' blocked")
                        return []

                    engine = ScannerEngine(session=session)
                    try:
                        event_bus.emit_tool_invoked(tool=tool, target=req.target, args=[], scan_id=session.id)
                        if state.cancel_requested.is_set():
                            return []

                        async for log_line in engine.scan(
                            req.target, selected_tools=[tool], cancel_flag=state.cancel_requested
                        ):
                            session.log(log_line)

                        findings = engine.get_last_results() or []
                        tool_error = engine.consume_last_tool_error()
                        exit_code = 130 if state.cancel_requested.is_set() else 0
                        if tool_error and "exit_code" in tool_error:
                            exit_code = int(tool_error["exit_code"])
                        return findings
                    except asyncio.CancelledError:
                        # Local task cancellation (e.g., from Strategos tool timeout)
                        # should NOT poison the global scan state.
                        raise
                    except Exception as exc:
                        session.log(f"[Strategos] Tool failed ({tool}): {exc}")
                        return []
                    finally:
                        event_bus.emit_tool_completed(
                            tool=tool,
                            exit_code=exit_code,
                            findings_count=len(findings),
                            scan_id=session.id,
                            error=tool_error,
                        )

                # Store dispatch_tool on state for external callers
                state.scan_state["_dispatch_tool"] = dispatch_tool

                mission = await reasoning_engine.start_scan(
                    target=req.target,
                    available_tools=allowed_tools,
                    mode=req.mode,
                    dispatch_tool=dispatch_tool,
                    log_fn=session.log,
                    knowledge=session.knowledge,
                )

                # --- Phase 3: active verification (Run #26 wiring) -----------
                # In bug_bounty mode, after recon, probe a curated set of
                # common parameterized endpoints on in-scope hosts using
                # VulnVerifier (boundary payloads, error/timing detection).
                # Confirmed verifications are added to the session as HIGH-
                # severity findings — they appear in the Findings tab, the AI
                # briefing, and reports, with zero extra plumbing.
                # Scope-strict mode hard-gates probes through the same scope
                # registry the scan uses for tools (single source of truth).
                if req.mode in ("bug_bounty", "bounty"):
                    try:
                        from core.wraith.verify_phase import run_verify_phase
                        # Build candidate target set: original + any hosts the
                        # recon already discovered (subdomain findings etc.).
                        target_set: set[str] = {req.target}
                        for _f in session.findings.get_all():
                            if not isinstance(_f, dict):
                                continue
                            _t = _f.get("target")
                            if isinstance(_t, str) and _t:
                                target_set.add(_t)
                            _meta = _f.get("metadata")
                            if isinstance(_meta, dict):
                                _h = _meta.get("host")
                                if isinstance(_h, str) and _h:
                                    target_set.add(_h)
                        # Scope filter: in scope_strict, only probe URLs the
                        # session's scope registry resolves as in-scope.
                        scope_filter = None
                        _sc = getattr(session, "scope_context", None)
                        if req.scope_strict and _sc is not None and getattr(_sc, "registry", None) is not None:
                            def scope_filter(_url: str, _reg=_sc.registry) -> bool:
                                try:
                                    decision = _reg.resolve(_url)
                                    return bool(getattr(decision, "in_scope", False))
                                except Exception:
                                    return False
                        # Pass personas through so the verify phase can run
                        # authenticated identity contexts (enables IDOR /
                        # authenticated-SQLi confirmation). Personas were
                        # already validated by the ScanRequest model.
                        confirmed_findings = await run_verify_phase(
                            session=session,
                            targets=list(target_set),
                            scope_filter=scope_filter,
                            personas=req.personas,
                        )
                        if confirmed_findings:
                            session.findings.bulk_add(confirmed_findings, persist=True)
                            session.log(
                                f"[verify_phase] added {len(confirmed_findings)} "
                                f"confirmed-vuln finding(s) to session"
                            )

                        # --- Phase 2: close the loop — verify omega chains ------
                        # Synthesize hypothesized exploit chains (omega/NEXUS) over
                        # this scan's findings, then live-test each chain's steps
                        # with the SAME VulnVerifier + scope discipline as the probe
                        # phase above. A chain whose steps confirm is PROMOTED to a
                        # verified, evidenced killchain and persisted as a HIGH
                        # issue; unconfirmed chains are never asserted. Best-effort,
                        # scope+host gated, budget-bounded — never kills the scan.
                        try:
                            from core.cortex.chain_arbiter import OmegaChainProposer, ChainContext
                            from core.cortex.chain_verifier import ChainVerifier
                            from core.web.contracts.enums import VulnerabilityClass
                            from core.wraith.mutation_engine import MutationEngine
                            from core.wraith.vuln_verifier import VulnVerifier
                            from urllib.parse import urlparse as _urlparse

                            # Use the just-confirmed findings DIRECTLY (not only
                            # session.findings.get_all(), whose in-memory view can
                            # lag the bulk_add above). Without this, the chain
                            # synthesis raced the persist and saw the SQLi but not
                            # its missing_auth companion → no enabling pair → 0
                            # chains. confirmed_findings is the guaranteed set.
                            _chain_findings = list(confirmed_findings or [])
                            _chain_findings.extend(session.findings.get_all())
                            from core.cortex.chain_hunter import ChainHunter
                            if _chain_findings:
                                _name_to_vc = {
                                    "idor": VulnerabilityClass.IDOR,
                                    "ssrf": VulnerabilityClass.SSRF,
                                    "open redirect": VulnerabilityClass.OPEN_REDIRECT,
                                    "reflected xss": VulnerabilityClass.XSS,
                                    "sqli": VulnerabilityClass.SQLI,
                                    "path traversal": VulnerabilityClass.PATH_TRAVERSAL,
                                }
                                # Hosts the scan actually discovered in-scope — chain
                                # steps may only be probed against these.
                                _inscope_hosts = set()
                                for _t in target_set:
                                    _u = _t if "://" in _t else f"https://{_t}"
                                    _net = _urlparse(_u).netloc
                                    if _net:
                                        _inscope_hosts.add(_net.lower())
                                # First persona enables authenticated IDOR; else anon.
                                _id_headers: Dict[str, str] = {}
                                _id_cookies: Dict[str, str] = {}
                                if req.personas:
                                    try:
                                        from core.wraith.persona_auth import authenticate_persona
                                        _id_headers, _id_cookies = await authenticate_persona(req.personas[0])
                                    except Exception:
                                        _id_headers, _id_cookies = {}, {}
                                _authed = bool(_id_headers or _id_cookies)
                                _cv_verifier = VulnVerifier(session)
                                _cv_engine = MutationEngine()
                                _cv_probes = {"n": 0}
                                _CV_CAP = 30  # hard cap on chain + escalation probes

                                async def _verify_step(vclass_name: str, url: str):
                                    if _cv_probes["n"] >= _CV_CAP:
                                        return None, "probe budget exhausted"
                                    if (_urlparse(url).netloc or "").lower() not in _inscope_hosts:
                                        return None, "host not in discovered scope"
                                    if scope_filter is not None and not scope_filter(url):
                                        return None, "out of scope"
                                    if vclass_name == "idor" and not (_id_headers or _id_cookies):
                                        return None, "idor needs an authenticated identity"
                                    vc = _name_to_vc.get(vclass_name, VulnerabilityClass.GENERIC)
                                    _cv_probes["n"] += 1
                                    results, _ = await _cv_verifier.verify_finding(
                                        engine=_cv_engine, finding={}, url=url, vuln_class=vc,
                                        headers=_id_headers, cookies=_id_cookies, budget=3,
                                    )
                                    if results:
                                        return True, f"confirmed (confidence={float(results[0][0]):.2f})"
                                    return None, "no signal"  # inconclusive — never a refutation

                                # ── Self-directing hunt (phase 3) ──────────────
                                # synthesize → verify → expand, iterated. A proven
                                # chain's terminal primitive unlocks follow-on vuln
                                # classes (omega enablement); we discover+verify
                                # THOSE specifically, fold confirmations back in,
                                # and re-synthesize — deepening toward higher goals
                                # until it converges. All within one probe budget.
                                async def _synthesize(_findings):
                                    return await OmegaChainProposer().propose(ChainContext(
                                        target=req.target, findings=_findings,
                                        issues=session.issues.get_all(),
                                    ))

                                async def _verify_chains(_chains):
                                    return (await ChainVerifier().verify(_chains, _verify_step))["verified"]

                                async def _expand(_fresh, _findings):
                                    from core.omega.nexus_phase import PRIMITIVE_ENABLEMENT
                                    from core.aegis.nexus.primitives import PrimitiveType
                                    from core.cortex.chain_verifier import PRIMITIVE_TO_VULN_CLASS
                                    from core.wraith.candidate_discovery import discover_candidates
                                    _want = set()
                                    for _v in _fresh:
                                        _raw = getattr(_v.proposal, "raw", {}) or {}
                                        _steps = _raw.get("steps", []) if isinstance(_raw, dict) else []
                                        if not _steps:
                                            continue
                                        try:
                                            _term = PrimitiveType(str(_steps[-1].get("primitive_type")))
                                        except Exception:
                                            continue
                                        for _nxt in PRIMITIVE_ENABLEMENT.get(_term, []):
                                            _vc = PRIMITIVE_TO_VULN_CLASS.get(_nxt.value)
                                            if _vc:
                                                _want.add(_vc)
                                    if not _want or _cv_probes["n"] >= _CV_CAP:
                                        return []
                                    _out: List[Dict[str, Any]] = []
                                    # Capability escalation (phase 4): if a follow-on
                                    # needs auth and we don't have it, PERFORM a login
                                    # SQLi to acquire a session, then probe
                                    # authenticated. This is what lets the hunt
                                    # breach the auth wall instead of converging.
                                    if ("idor" in _want) and not (_id_headers or _id_cookies):
                                        try:
                                            from core.wraith.capability import acquire_capability
                                            # The full library tries login-SQLi, then
                                            # default credentials. Forge-elevation
                                            # (alg:none / weak HMAC) fires only when a
                                            # token is already held + verifiable.
                                            _cap = await acquire_capability(req.target, scope_filter)
                                        except Exception as _cap_exc:
                                            logger.warning("[scan] capability acquire failed: %s", _cap_exc)
                                            _cap = None
                                        if _cap:
                                            _id_headers.update(_cap.headers or {})
                                            _id_cookies.update(_cap.cookies or {})
                                            session.log(f"[capability] session acquired ({_cap.acquirer}) — {_cap.provenance}")
                                            _out.append({
                                                "type": "Authentication Bypass (active verification)",
                                                "severity": "HIGH", "tool": "capability", "target": req.target,
                                                "message": f"session acquired via {_cap.provenance}",
                                                "tags": ["verified", "auth_bypass", "capability", _cap.acquirer],
                                                "families": ["confirmed_vuln"],
                                                "metadata": {"vuln_class": "missing_auth",
                                                             "acquirer": _cap.acquirer,
                                                             "provenance": _cap.provenance},
                                            })
                                    for _url, _label, _vc_name in await discover_candidates(
                                        req.target, scope_filter, max_candidates=60
                                    ):
                                        if _vc_name not in _want or _cv_probes["n"] >= _CV_CAP:
                                            continue
                                        _verdict, _ev = await _verify_step(_vc_name, _url)
                                        if _verdict is True:
                                            # Dynamic — a capability acquired above
                                            # may have authenticated us mid-expand.
                                            _now_authed = bool(_id_headers or _id_cookies)
                                            _out.append({
                                                "type": f"{_vc_name} (active verification)",
                                                "severity": "HIGH", "tool": "vuln_verifier", "target": _url,
                                                "message": f"{_vc_name} confirmed during chain escalation",
                                                "tags": ["verified", "escalation", _vc_name],
                                                "families": ["confirmed_vuln"],
                                                "metadata": {"vuln_class": _vc_name, "authenticated": _now_authed},
                                            })
                                            if not _now_authed:
                                                _out.append({
                                                    "type": "Missing Authentication (active verification)",
                                                    "severity": "MEDIUM", "tool": "vuln_verifier", "target": _url,
                                                    "message": f"unauthenticated {_vc_name} during escalation",
                                                    "tags": ["verified", "missing_auth", "escalation"],
                                                    "families": ["confirmed_vuln"],
                                                    "metadata": {"vuln_class": "missing_auth", "enabled_via": _vc_name},
                                                })
                                    return _out

                                try:
                                    _hunt = await ChainHunter(max_iterations=2).hunt(
                                        _chain_findings, synthesize=_synthesize,
                                        verify_chains=_verify_chains, expand=_expand,
                                    )
                                finally:
                                    _close = getattr(_cv_engine, "close", None)
                                    if callable(_close):
                                        try:
                                            _maybe = _close()
                                            if hasattr(_maybe, "__await__"):
                                                await _maybe
                                        except Exception:
                                            pass

                                for _vc_res in _hunt.verified:
                                    _chain = _vc_res.proposal
                                    session.issues.add_issue({
                                        "title": f"Verified Exploit Chain → {_chain.goal}",
                                        "severity": "HIGH",
                                        "target": req.target,
                                        "data": {
                                            "goal": _chain.goal,
                                            "steps": _chain.steps,
                                            "epistemic": "verified",
                                            "method": "omega-nexus synthesis + live step verification (self-directed)",
                                            "verification": _vc_res.to_dict().get("verification", {}),
                                        },
                                    }, persist=True)
                                # Surface the escalation evidence (auth bypass / IDOR
                                # confirmed mid-hunt) as findings, not just internal
                                # hunt state — they're real verified vulns.
                                if _hunt.findings_added:
                                    session.findings.bulk_add(_hunt.findings_added, persist=True)

                                # DEMONSTRATE data_exfiltration: a chain that *reaches*
                                # the goal proves the steps; here we actually PERFORM the
                                # exfil (bounded UNION dump on the chain's SQLi step) and
                                # attach the dumped rows as proof. Reaching → demonstrated.
                                _exfil_done: set = set()
                                for _vc_res in _hunt.verified:
                                    _chain = _vc_res.proposal
                                    if "exfil" not in str(_chain.goal or "").lower():
                                        continue
                                    _raw = getattr(_chain, "raw", {}) or {}
                                    _sqli_url = next(
                                        (s.get("url") for s in (_raw.get("steps", []) if isinstance(_raw, dict) else [])
                                         if isinstance(s, dict) and str(s.get("primitive_type")) == "sqli_pattern" and s.get("url")),
                                        None,
                                    )
                                    if not _sqli_url or _sqli_url in _exfil_done:
                                        continue
                                    _exfil_done.add(_sqli_url)
                                    if (scope_filter is not None and not scope_filter(_sqli_url)) or _cv_probes["n"] >= _CV_CAP:
                                        continue
                                    try:
                                        from core.wraith.exfiltration import exfiltrate_credentials, default_fetch
                                        from urllib.parse import parse_qsl as _parse_qsl
                                        _ex_param = next((k for k, _ in _parse_qsl(_urlparse(_sqli_url).query)), "q")
                                        _exfil = await exfiltrate_credentials(_sqli_url, _ex_param, default_fetch(), max_attempts=40)
                                    except Exception as _ex_exc:
                                        logger.warning("[scan] exfiltration failed: %s", _ex_exc)
                                        _exfil = None
                                    if _exfil:
                                        session.log(f"[exfil] dumped {_exfil.row_count} credential row(s) from {_exfil.table}")
                                        session.findings.bulk_add([{
                                            "type": "Data Exfiltration (active verification)",
                                            "severity": "CRITICAL", "tool": "exfiltration", "target": _sqli_url,
                                            "message": (f"Extracted {_exfil.row_count} credential rows from "
                                                        f"{_exfil.table} via UNION-based SQL injection"),
                                            "tags": ["verified", "data_exfiltration", "sqli", "critical"],
                                            "families": ["confirmed_vuln"],
                                            "metadata": {"vuln_class": "data_exfiltration",
                                                         "proof": _exfil.to_proof()},
                                        }], persist=True)
                                session.log(
                                    f"[chain_hunt] iterations={_hunt.iterations} "
                                    f"verified={len(_hunt.verified)} "
                                    f"escalation_unlocked={len(_hunt.findings_added)} "
                                    f"top_goal={_hunt.top_goal!r}; probes={_cv_probes['n']}"
                                )
                        except Exception as _cv_exc:
                            logger.error(
                                f"[scan] chain verification failed (nothing promoted): "
                                f"{type(_cv_exc).__name__}: {_cv_exc}",
                                exc_info=True,
                            )

                        # ── Business-logic probe (the UNDEFENDED class) ──────
                        # WAFs/signatures/token-allowlists key off payloads;
                        # business-logic flaws have none — a well-formed authed
                        # request that violates an invariant the server should
                        # enforce but instead trusts from the client. Register a
                        # LOW-priv account (so BFLA findings are real, not "admin
                        # can"), learn write-collection schemas, create throwaway
                        # objects we own, confirm invariant violations, clean up.
                        # Best-effort; never kills the scan.
                        try:
                            import httpx as _bl_httpx
                            import os as _bl_os
                            from core.wraith.logic_probe import (
                                acquire_low_priv_session, probe_business_logic,
                            )
                            from core.wraith.candidate_discovery import _mine_js_endpoints
                            _bl_p = _urlparse(req.target if "://" in req.target else "https://" + req.target)
                            _bl_origin = f"{_bl_p.scheme}://{_bl_p.netloc}"
                            _bl_hdrs = {"User-Agent": "SentinelForge-Logic"}
                            _bl_bb = _bl_os.getenv("SENTINEL_GHOST_BB_VALUE", "").strip()
                            if _bl_bb:
                                _bl_hdrs[_bl_os.getenv("SENTINEL_GHOST_BB_HEADER", "X-Bug-Bounty").strip()] = _bl_bb

                            async def _bl_send(method, url, body=None, _auth=None):
                                if scope_filter is not None and not scope_filter(url):
                                    return 599, {}
                                _h = dict(_bl_hdrs)
                                if _auth:
                                    _h["Authorization"] = f"Bearer {_auth}"
                                async with _bl_httpx.AsyncClient(timeout=10.0, follow_redirects=True) as _c:
                                    _r = await _c.request(method, url, json=body, headers=_h)
                                    try:
                                        _j = _r.json()
                                    except Exception:
                                        _j = {}
                                    return _r.status_code, _j

                            _bl_sess = await acquire_low_priv_session(_bl_origin, _bl_send)
                            if _bl_sess:
                                _bl_token, _bl_ctx = _bl_sess

                                async def _bl_authed(method, url, body=None):
                                    return await _bl_send(method, url, body, _auth=_bl_token)

                                _bl_colls = sorted({
                                    "/api/" + u.split("/api/", 1)[1].split("/")[0].split("?")[0]
                                    for u in _mine_js_endpoints(req.target, scope_filter) if "/api/" in u
                                })
                                _bl_findings = await probe_business_logic(
                                    req.target, _bl_authed, _bl_colls, context=_bl_ctx,
                                )
                                if _bl_findings:
                                    session.findings.bulk_add(_bl_findings, persist=True)
                                session.log(
                                    f"[logic] low-priv session acquired; "
                                    f"{len(_bl_findings)} business-logic flaw(s) across "
                                    f"{len(_bl_colls)} collection(s)"
                                )
                        except Exception as _bl_exc:
                            logger.error(
                                f"[scan] business-logic probe failed: "
                                f"{type(_bl_exc).__name__}: {_bl_exc}",
                                exc_info=True,
                            )
                    except Exception as _vp_exc:
                        # Verification-phase failures must NEVER kill the scan
                        # — recon results stand on their own. Log and move on.
                        logger.error(
                            f"[scan] verify phase failed: "
                            f"{type(_vp_exc).__name__}: {_vp_exc}",
                            exc_info=True,
                        )

                # ── Finding verification gate ───────────────────────────────
                # Before results are surfaced, re-test passive issues against
                # the live target and dedup. An issue the target itself
                # disproves (header actually present, verb blocked, cookie
                # secure, admin behind auth) is hidden rather than presented as
                # fact; dedup duplicates collapse to one. This is what stops
                # Sentinel emitting generic-scanner noise (a real run collapsed
                # 629 HIGH/MED issues to 1).
                #
                # /results reads from the DB, and an issue's primary key is a
                # content hash, so we can't mutate rows in place — instead we
                # compute which rows SURVIVE the gate (keep_ids) and flip the
                # non-destructive `suppressed` flag on every other row for this
                # session. Suppressed rows are preserved (recoverable), just
                # hidden. Active modes only (the gate issues live requests); a
                # gate failure never kills a scan and never suppresses anything.
                if req.mode in ("standard", "bug_bounty", "bounty"):
                    try:
                        from core.toolkit.finding_verifier import (
                            gate as _verify_gate,
                            finding_id as _finding_id,
                        )
                        # `db` is assigned later in _runner(), making it function-
                        # local; fetch the singleton here to avoid UnboundLocalError.
                        db = Database.instance()
                        _issues_before = session.issues.get_all()
                        if _issues_before:
                            _rep = await _verify_gate(_issues_before, drop_refuted=True)
                            _keep = _rep["keep_ids"]
                            # Suppress every original row whose id didn't survive
                            # (refuted findings + dedup-collapsed duplicates).
                            _suppress_ids = [
                                _id for _id in map(_finding_id, _issues_before)
                                if _id not in _keep
                            ]
                            _n = await db.suppress_issues(
                                session.id, _suppress_ids,
                                reason="verification-gate refuted/deduped",
                            )
                            # Keep the in-memory store consistent with what the
                            # operator now sees. persist=False: the DB is already
                            # authoritative here, and re-saving annotated dicts
                            # would mint new content-hash rows.
                            session.issues.replace_all(_rep["kept"], persist=False)
                            _c = _rep["counts"]
                            session.log(
                                f"[verify_gate] issues {_rep['input_count']} -> "
                                f"{_rep['kept_count']} surfaced; suppressed {_n} "
                                f"(deduped {_c.get('deduped')}, refuted {_c.get('refuted')}, "
                                f"confirmed {_c.get('confirmed')}, "
                                f"unverifiable {_c.get('unverifiable')})"
                            )
                    except Exception as _vg_exc:
                        logger.error(
                            f"[scan] verify gate failed (issues left unchanged): "
                            f"{type(_vg_exc).__name__}: {_vg_exc}",
                            exc_info=True,
                        )

                state.scan_state["status"] = "completed"
                state.scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()

                # Mirror engine-state into the ScanSession object so to_dict()
                # serializes the terminal state. Without this, session.status
                # stays "Created" and end_time stays None — see Bug #4.
                session.status = "completed"
                session.end_time = time.time()

                duration = time.time() - start_time
                event_bus.emit_scan_completed("completed", len(session.findings.get_all()), duration, scan_id=session.id)

                # Close per-scan log file
                session.close_log_file()

                # Persist final session state including logs
                db = Database.instance()
                await db.init()
                await db.blackbox.enqueue(db._save_session_impl, session.to_dict())
                await db.blackbox.flush()

            except asyncio.CancelledError:
                state.scan_state["status"] = "cancelled"
                session.status = "cancelled"
                session.end_time = time.time()
                duration = time.time() - start_time
                event_bus.emit_scan_completed("cancelled", len(session.findings.get_all()), duration, scan_id=session.id)

                # Close per-scan log file
                session.close_log_file()

                # Persist final session state including logs
                db = Database.instance()
                await db.init()
                await db.blackbox.enqueue(db._save_session_impl, session.to_dict())
                await db.blackbox.flush()

            except Exception as e:
                state.scan_state["status"] = "error"
                session.status = "error"
                session.end_time = time.time()
                logger.error(f"Scan error: {e}", exc_info=True)
                payload = {"error": str(e), "target": req.target, "scan_id": session.id}
                if isinstance(e, SentinelError):
                    payload["error_code"] = e.code.value
                    payload["error_details"] = e.details
                event_bus.emit(
                    GraphEvent(
                        type=GraphEventType.SCAN_FAILED,
                        payload=payload,
                        scan_id=session.id,
                    )
                )

                # Close per-scan log file
                session.close_log_file()

                # Persist final session state including logs
                db = Database.instance()
                await db.init()
                await db.blackbox.enqueue(db._save_session_impl, session.to_dict())
                await db.blackbox.flush()

            finally:
                # Disconnect ActionDispatcher subscriber so stale closures
                # don't fire on the next scan's session.
                try:
                    _action_dispatcher.action_approved.disconnect(_on_action_approved)
                    logger.info("[ActionBridge] Disconnected action_approved for session %s", session.id)
                except Exception:
                    pass
                # Clear the dispatch_tool reference
                if state.scan_state.get("_dispatch_tool"):
                    state.scan_state["_dispatch_tool"] = None

        state.active_scan_task = asyncio.create_task(_runner())
        return session.id

@router.post("/start", dependencies=[Depends(verify_sensitive_token)], status_code=202)
async def start_scan(req: ScanRequest):
    logger.info(f"Scan start request received for target: {req.target}")
    session_id = await begin_scan_logic(req)
    return {"session_id": session_id, "status": "started"}

@router.post("/cancel", dependencies=[Depends(verify_sensitive_token)])
async def cancel_scan():
    from fastapi.responses import Response

    state = get_state()
    async with state.scan_lock:
        if not state.active_scan_task or state.active_scan_task.done():
            return Response(status_code=409)

        state.cancel_requested.set()
        state.active_scan_task.cancel()
        return Response(status_code=202)

@router.get("/status", dependencies=[Depends(verify_token)])
async def get_scan_status():
    return get_state().scan_state

@router.get("/sessions/{session_id}/findings", dependencies=[Depends(verify_token)])
async def get_session_findings(session_id: str):
    """
    Retrieve all findings for a specific session.
    Fallback endpoint when WebSocket connection is lost.
    """
    db = Database.instance()
    findings = await db.get_findings(session_id)
    return {"session_id": session_id, "findings": findings, "count": len(findings)}

@router.get("/sessions/{session_id}/evidence", dependencies=[Depends(verify_token)])
async def get_session_evidence(session_id: str):
    """
    Retrieve all evidence for a specific session.
    """
    db = Database.instance()
    evidence = await db.get_evidence(session_id)
    return {"session_id": session_id, "evidence": evidence, "count": len(evidence)}

@router.get("/sessions/{session_id}/issues", dependencies=[Depends(verify_token)])
async def get_session_issues(session_id: str):
    """
    Retrieve all issues for a specific session.
    """
    db = Database.instance()
    issues = await db.get_issues(session_id)
    return {"session_id": session_id, "issues": issues, "count": len(issues)}

@router.get("/sessions/{session_id}/bounty-report", dependencies=[Depends(verify_token)])
async def get_session_bounty_report(
    session_id: str,
    min_severity: str = "LOW",
    format: str = "markdown",
    platform: str = "hackerone",
):
    """
    Generate a HackerOne-ready bug bounty report for a specific session.

    Query params:
      min_severity: Minimum severity to include (CRITICAL/HIGH/MEDIUM/LOW/INFO). Default: LOW
      format:       "markdown" (default) or "json"
      platform:     "hackerone" (default), "bugcrowd", "intigriti"

    Returns a complete Markdown document (or JSON array) with per-finding reports,
    CVSS 3.1 vectors, steps to reproduce, and impact statements.
    """
    from core.reporting.bounty_report import build_reports, render_summary_report
    from core.data.db import Database

    db = Database.instance()
    findings = await db.get_findings(session_id)
    issues = await db.get_issues(session_id)
    evidence = await db.get_evidence(session_id)

    # Merge issues and findings; prefer issues (higher confidence)
    all_findings = list(issues) + [
        f for f in findings
        if not any(
            (iss.get("type") == f.get("type") and iss.get("asset") == f.get("asset"))
            for iss in issues
        )
    ]

    if not all_findings:
        return {"session_id": session_id, "reports": [], "markdown": "No findings to report.", "count": 0}

    session_data = await db.get_session(session_id)
    target = (session_data or {}).get("target", session_id)

    reports = build_reports(
        all_findings,
        scan_id=session_id,
        evidence_items=evidence,
        min_severity=min_severity.upper(),
        platform=platform,
    )

    # Cross-scan duplicate annotations
    from core.data.dedup_store import DedupStore
    dedup_store = DedupStore.instance()
    try:
        await dedup_store.init()
        dedup_map: Dict[str, Any] = {}
        for finding in all_findings:
            fp = dedup_store.fingerprint(finding)
            result = await dedup_store.check_finding(finding)
            dedup_map[fp] = result
    except Exception as _dedup_err:
        logger.warning("[BountyReport] Dedup check failed (non-fatal): %s", _dedup_err)
        dedup_map = {}

    # Annotate each report dict with duplicate info
    report_dicts = []
    for rep in reports:
        d = rep.to_dict()
        # Find the corresponding finding to get its fingerprint
        for finding in all_findings:
            ftype = finding.get("type") or finding.get("title") or ""
            fasset = finding.get("asset") or finding.get("target") or ""
            if ftype.lower() in rep.title.lower() or fasset in rep.asset:
                fp = dedup_store.fingerprint(finding)
                dr = dedup_map.get(fp)
                if dr:
                    d["duplicate_info"] = {
                        "is_duplicate": dr.is_duplicate,
                        "first_seen_at": dr.first_seen_at,
                        "first_session": dr.first_session,
                        "seen_count": dr.seen_count,
                        "annotation": dr.annotation(),
                    }
                break
        report_dicts.append(d)

    if format.lower() == "json":
        return {
            "session_id": session_id,
            "target": target,
            "count": len(reports),
            "reports": report_dicts,
        }

    # Default: Markdown summary document
    md = render_summary_report(reports, target=target, scan_id=session_id)
    return {
        "session_id": session_id,
        "target": target,
        "count": len(reports),
        "markdown": md,
        "reports": report_dicts,
    }


@router.get("/bounty-report", dependencies=[Depends(verify_token)])
async def get_bounty_report(
    min_severity: str = "LOW",
    format: str = "markdown",
    platform: str = "hackerone",
):
    """
    Generate a HackerOne-ready bug bounty report for the active or most recent scan.

    Identical to /sessions/{session_id}/bounty-report but resolves the session
    automatically (same behaviour as /results).
    """
    state = get_state()
    scan_state = state.scan_state
    db = Database.instance()

    session_id = scan_state.get("session_id") if scan_state else None

    if not session_id:
        recent = await db.fetch_all(
            "SELECT id FROM sessions ORDER BY start_time DESC LIMIT 1", ()
        )
        if not recent:
            from fastapi.responses import Response
            return Response(status_code=204)
        session_id = recent[0][0]

    # Delegate to the per-session endpoint handler
    return await get_session_bounty_report(
        session_id=session_id,
        min_severity=min_severity,
        format=format,
        platform=platform,
    )


@router.get("/results", dependencies=[Depends(verify_token)])
async def get_scan_results():
    """
    Get complete scan results for the active or most recent scan session.
    This is the primary endpoint used by the Swift UI.
    Returns findings, issues, evidence, and scan metadata.
    """
    state = get_state()
    scan_state = state.scan_state
    db = Database.instance()

    # Get session_id from active scan, or fall back to most recent session
    session_id = scan_state.get("session_id") if scan_state else None

    if not session_id:
        # No active scan - try to get the most recent session from database
        # IMPORTANT: Query sessions table which persists beyond in-memory session destruction
        recent_sessions = await db.fetch_all(
            "SELECT id, target, status, start_time FROM sessions ORDER BY start_time DESC LIMIT 1",
            ()
        )
        if not recent_sessions or len(recent_sessions) == 0:
            from fastapi.responses import Response
            return Response(status_code=204)

        row = recent_sessions[0]
        session_id = row[0]
        # Build scan_state from database
        scan_state = {
            "target": row[1],
            "status": row[2],
            "started_at": row[3],
            "finished_at": None,
            "modules": []
        }
        logger.info(f"[Results] Using most recent session from DB: {session_id}")

    # Fetch from database
    logger.info(f"[Results] Fetching results for session_id={session_id}")
    findings = await db.get_findings(session_id)
    issues = await db.get_issues(session_id)
    evidence = await db.get_evidence(session_id)
    logger.info(f"[Results] Retrieved {len(findings)} findings, {len(issues)} issues, {len(evidence)} evidence")
    
    # Fetch logs from session record
    session_data = await db.get_session(session_id)
    logs = []
    if session_data and session_data.get("logs"):
        import json
        try:
            logs = json.loads(session_data["logs"])
        except Exception:
            logs = []

    # Build response matching Swift SentinelResults structure
    from core.cortex.causal_graph import get_graph_dto_for_session
    graph_dto = await get_graph_dto_for_session(
        session_id=session_id,
        findings=findings,
        issues=issues,
    )
    graph_attack_paths = _extract_graph_attack_paths_from_graph_dto(graph_dto)
    from core.cortex.attack_path_contract import build_attack_path_contract

    attack_path_contract = build_attack_path_contract(
        session_id=str(session_id),
        graph_dto=graph_dto,
    )

    # Multi-proposer chain ensemble (docs/CHAIN_ARBITER.md): cortex (observed)
    # + omega/NEXUS (hypothesized goal-synthesis), merged + ranked into one
    # canonical set. Additive and best-effort — any failure leaves the existing
    # cortex attack paths completely untouched. omega chains are labelled
    # `hypothesized` and never counted as confirmed; the closed loop promotes
    # them only after verification.
    arbitrated_chains: List[Dict[str, Any]] = []
    try:
        from core.cortex.chain_arbiter import ChainArbiter, ChainContext
        _chain_ctx = ChainContext(
            target=scan_state.get("target") or "",
            findings=findings,
            issues=issues,
            graph_dto=graph_dto,
            session_id=session_id,
        )
        arbitrated_chains = [
            c.to_dict() for c in await ChainArbiter.default().arbitrate(_chain_ctx)
        ]
    except Exception as _ca_exc:
        logger.warning(
            f"[Results] chain arbiter skipped (cortex paths unchanged): "
            f"{type(_ca_exc).__name__}: {_ca_exc}"
        )

    result = {
        "scan": {
            "target": scan_state.get("target"),
            "modules": scan_state.get("modules") or [],
            "status": scan_state.get("status"),
            "started_at": scan_state.get("started_at"),
            "finished_at": scan_state.get("finished_at"),
            "session_id": session_id,
        },
        "summary": {
            "counts": {
                "findings": len(findings),
                "issues": len(issues),
                "killchain_edges": graph_dto.get("count", {}).get("edges", 0),
                "logs": len(logs),
                "phase_results": {},
            }
        },
        "findings": findings,
        "issues": issues,
        "evidence": evidence,
        # Map the graph DTO to the 'killchain' field expected by UI
        # Note: UI expects 'edges' and 'attackPaths' in Killchain struct
        "killchain": {
            "edges": graph_dto.get("edges", []),
            # Canonical: graph-validated chains rendered as list-of-steps.
            "graph_attack_paths": graph_attack_paths,
            # Backward-compat alias (deprecated): use graph_attack_paths.
            "attack_paths": graph_attack_paths,
            # Multi-proposer ensemble: each entry carries source/method/epistemic
            # so observed (cortex) and hypothesized (omega) chains stay distinct.
            "arbitrated_chains": arbitrated_chains,
            "degraded_paths": [],
            "recommended_phases": [],
            "attack_path_contract": attack_path_contract,
        },
        "phase_results": {},
        "logs": logs
    }

    return result
