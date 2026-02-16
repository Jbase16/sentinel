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

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            logger.warning("Scan start rejected: empty target")
            raise ValueError("Target cannot be empty")
        dangerous_patterns = [";", "&&", "||", "`", "$(", "\n", "\r"]
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
            if not parsed.netloc:
                logger.warning(f"Scan start rejected: missing network location in target: {v}")
                raise ValueError("Invalid target URL: missing network location")
            if parsed.scheme not in ("http", "https"):
                logger.warning(f"Scan start rejected: invalid scheme '{parsed.scheme}' in target: {v}")
                raise ValueError("Invalid target URL: scheme must be http or https")
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


def _extract_attack_paths_from_graph_dto(graph_dto: Dict[str, Any]) -> List[List[str]]:
    """
    Convert attack_chains payload in graph DTO to legacy attack_paths format.
    Never rebuild the graph here; empty or malformed chains degrade to [].
    """
    attack_paths: List[List[str]] = []
    chains_from_dto = graph_dto.get("attack_chains", [])
    if not isinstance(chains_from_dto, list):
        logger.debug("[Results] attack_chains payload is not a list; returning empty attack_paths")
        return attack_paths

    for chain in chains_from_dto[:25]:
        if not isinstance(chain, dict):
            continue
        labels = chain.get("labels", [])
        if isinstance(labels, list) and labels:
            attack_paths.append([str(label) for label in labels])
            continue
        node_ids = chain.get("node_ids", [])
        if isinstance(node_ids, list) and node_ids:
            attack_paths.append([str(node_id) for node_id in node_ids])
    return attack_paths

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
                        state.cancel_requested.set()
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
                
                state.scan_state["status"] = "completed"
                state.scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()

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
    attack_paths = _extract_attack_paths_from_graph_dto(graph_dto)

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
            "attack_paths": attack_paths,
            "degraded_paths": [],
            "recommended_phases": []
        },
        "phase_results": {},
        "logs": logs
    }

    return result
