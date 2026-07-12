"""
core/server/routers/driver.py — Phase 7-PF11: Sentinel Native Driver (SND) Bridge.

Hosts the WebSocket bridge that connects the Python backend to the
Swift UI Execution Node. This severs the automation driver from the
JS execution environment by relying on physical macOS CGEvent
synthesis inside a pristine WKWebView.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect

from core.server.routers.auth import verify_sensitive_token
from core.server.routers.realtime import validate_websocket_connection

logger = logging.getLogger(__name__)

router = APIRouter(tags=["driver"])


class DriverBridgeError(RuntimeError):
    """The native driver is unavailable or rejected a bounded command."""


class DriverUnavailable(DriverBridgeError):
    """No healthy Swift execution node can accept commands."""


class DriverCommandError(DriverBridgeError):
    """The Swift node rejected a command after accepting the bridge request."""


class PersonaWindowUnavailable(DriverBridgeError):
    """One or more requested owned-persona windows are not authenticated."""


class CaptureConflict(DriverBridgeError):
    """A capture owner already holds the exclusive native capture seam."""


class NodeManager:
    """Manages connected Swift execution nodes and routes commands."""
    def __init__(self):
        # We only support one primary connected node for now (the operator's UI).
        self.active_node: Optional[WebSocket] = None
        # request_id -> future waiting for response
        self.pending_responses: Dict[str, asyncio.Future] = {}
        # List of callbacks for spontaneous events
        self.event_handlers = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_node = websocket
        logger.info("[snd-bridge] Swift execution node connected.")

    def disconnect(self, websocket: WebSocket):
        if self.active_node == websocket:
            self.active_node = None
            logger.info("[snd-bridge] Swift execution node disconnected.")
            # Cancel all pending requests
            for fut in self.pending_responses.values():
                if not fut.done():
                    fut.set_exception(DriverUnavailable("Swift node disconnected"))
            self.pending_responses.clear()

    async def send_command(self, payload: Dict[str, Any], timeout: float = 30.0) -> Any:
        """Send a command to the swift node and wait for its correlation reply."""
        if self.active_node is None:
            raise DriverUnavailable(
                "No Swift execution node connected to the SND bridge."
            )
        
        request_id = payload.get("request_id")
        if not request_id:
            raise ValueError("Payload must contain a request_id for correlation.")
            
        fut = asyncio.get_event_loop().create_future()
        self.pending_responses[request_id] = fut
        
        try:
            await self.active_node.send_text(json.dumps(payload))
            # Wait for response with timeout
            try:
                response = await asyncio.wait_for(fut, timeout=timeout)
            except TimeoutError as exc:
                raise DriverUnavailable("Swift node command timed out") from exc
            if response.get("error"):
                raise DriverCommandError(f"Node execution failed: {response['error']}")
            return response.get("result")
        finally:
            self.pending_responses.pop(request_id, None)

    async def handle_response(self, text: str):
        try:
            data = json.loads(text)
            req_id = data.get("request_id")
            if req_id and req_id in self.pending_responses:
                if not self.pending_responses[req_id].done():
                    self.pending_responses[req_id].set_result(data)
            else:
                # Could be a spontaneous event from the node (e.g., recording action)
                event_type = data.get("event")
                if event_type:
                    for handler in self.event_handlers:
                        try:
                            handler(event_type, data)
                        except Exception as ex:
                            logger.error("[snd-bridge] event handler error: %s", ex)
        except Exception as e:
            logger.error("[snd-bridge] failed to handle response: %s", e)

node_manager = NodeManager()

ACTIVE_CAPTURE_PATH: Optional[str] = None
ACTIVE_CAPTURE_PERSONA_ID: Optional[str] = None
ACTIVE_CAPTURE_BYTES = 0
ACTIVE_CAPTURE_RECORDS = 0
ACTIVE_CAPTURE_LIMIT_REACHED = False
ACTIVE_CAPTURE_LAST_EVENT_AT: Optional[float] = None
ACTIVE_CAPTURE_OWNER_ID: Optional[str] = None
ACTIVE_CAPTURE_SESSION_ID: Optional[str] = None
ACTIVE_CAPTURE_INFLIGHT = 0
ACTIVE_CAPTURE_WRITE_FAILED = False
_CAPTURE_STORE_ENV = "SENTINELFORGE_CAPTURE_STORE"
_MAX_CAPTURE_BYTES = 16 * 1024 * 1024
_MAX_CAPTURE_RECORDS = 20_000
_MAX_CAPTURE_REQUEST_CHARS = 256 * 1024
_MAX_CAPTURE_RESPONSE_CHARS = 2 * 1024 * 1024
_MAX_CAPTURE_HEADERS = 128
_MAX_CAPTURE_HEADER_CHARS = 256 * 1024
_CAPTURE_QUIET_SECONDS = 0.75
_CAPTURE_MIN_SETTLE_SECONDS = 0.5
_CAPTURE_MAX_SETTLE_SECONDS = 5.0
_MAX_CAPTURE_INFLIGHT = 10_000
_PAIR_CAPTURE_LOCK = asyncio.Lock()


@dataclass(frozen=True)
class PersonaCaptureArtifact:
    persona_id: str
    path: str
    records: Tuple[Dict[str, Any], ...]
    captured_bytes: int
    limit_reached: bool

    def summary(self) -> Dict[str, Any]:
        return {
            "records": len(self.records),
            "bytes": self.captured_bytes,
            "limit_reached": self.limit_reached,
        }


def _capture_store() -> Path:
    override = os.environ.get(_CAPTURE_STORE_ENV)
    if override:
        return Path(override)
    return Path.home() / ".sentinelforge" / "captures"


def _allocate_capture_file(persona_id: Optional[str]) -> str:
    root = _capture_store()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink():
        raise RuntimeError("capture store cannot be a symlink")
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError("capture store ownership is invalid")
    os.chmod(root, 0o700)

    persona_ref = hashlib.sha256((persona_id or "generic").encode()).hexdigest()[:16]
    path = root / f"capture-{persona_ref}-{uuid.uuid4().hex}.jsonl"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    os.close(descriptor)
    try:
        directory_descriptor = os.open(
            root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return str(path)


def _fsync_capture_file(path: Optional[str], *, expected_size: int) -> None:
    if path is None:
        return
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != expected_size
        ):
            raise RuntimeError("capture file changed before finalization")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_capture_url(value: Any) -> str:
    target_url = str(value or "").strip()
    parsed = urlsplit(target_url)
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("url contains an invalid network port") from exc
    if (
        len(target_url) > 4096
        or any(
            character.isspace()
            or ord(character) < 0x20
            or ord(character) == 0x7F
            or character == "\\"
            for character in target_url
        )
        or parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not hostname
        or port == 0
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("url must be an absolute HTTP(S) URL without credentials")
    return target_url


def _validated_persona_id(value: Any, *, optional: bool = False) -> Optional[str]:
    persona_id = str(value or "").strip() or None
    if persona_id is None and optional:
        return None
    if persona_id is None or re.fullmatch(r"[0-9a-f]{32}", persona_id) is None:
        raise ValueError("persona_id must be a lowercase UUID hex identifier")
    return persona_id


def _claim_capture_owner(owner_id: str) -> None:
    global ACTIVE_CAPTURE_OWNER_ID
    if ACTIVE_CAPTURE_OWNER_ID is not None:
        raise CaptureConflict("another persona capture is already active")
    ACTIVE_CAPTURE_OWNER_ID = owner_id


def _release_capture_owner(owner_id: str) -> None:
    global ACTIVE_CAPTURE_OWNER_ID
    if ACTIVE_CAPTURE_OWNER_ID == owner_id:
        ACTIVE_CAPTURE_OWNER_ID = None


def ensure_capture_available() -> None:
    """Refuse before reservation when another owner holds the capture seam."""
    if ACTIVE_CAPTURE_OWNER_ID is not None:
        raise CaptureConflict("another persona capture is already active")


def _load_capture_records(path: str, *, persona_id: str) -> Tuple[Dict[str, Any], ...]:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _MAX_CAPTURE_BYTES
        ):
            raise RuntimeError("capture file attributes are unsafe")
        handle = os.fdopen(descriptor, "r", encoding="utf-8")
        descriptor = -1
        records: List[Dict[str, Any]] = []
        with handle:
            for line in handle:
                if len(records) >= _MAX_CAPTURE_RECORDS:
                    raise RuntimeError("capture file exceeds the record limit")
                try:
                    record = json.loads(line)
                except (TypeError, ValueError) as exc:
                    raise RuntimeError("capture file contains malformed JSONL") from exc
                if not isinstance(record, dict):
                    raise RuntimeError("capture record must be a JSON object")
                if record.get("persona_id") != persona_id:
                    raise RuntimeError("capture record persona does not match its session")
                records.append(record)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not records:
        raise RuntimeError("persona capture produced no network records")
    return tuple(records)


def _append_capture_bytes(path: str, payload: bytes, *, expected_size: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_APPEND
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != expected_size
        ):
            raise RuntimeError("capture file changed during its active session")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("capture append made no progress")
            remaining = remaining[written:]
    finally:
        os.close(descriptor)


def _bounded_capture_text(value: Any, limit: int) -> tuple[str, bool]:
    if not isinstance(value, str):
        return "", value is not None and value != ""
    return value[:limit], len(value) > limit


def _bounded_capture_headers(value: Any) -> tuple[Dict[str, str], bool]:
    if not isinstance(value, dict):
        return {}, value is not None and value != ""
    output: Dict[str, str] = {}
    total_chars = 0
    truncated = False
    for index, (raw_key, raw_value) in enumerate(value.items()):
        if index >= _MAX_CAPTURE_HEADERS:
            truncated = True
            break
        key = str(raw_key)[:256]
        header_value = str(raw_value)[:8192]
        item_chars = len(key) + len(header_value)
        if total_chars + item_chars > _MAX_CAPTURE_HEADER_CHARS:
            truncated = True
            break
        truncated = truncated or len(str(raw_key)) > len(key) or len(str(raw_value)) > len(
            header_value
        )
        output[key] = header_value
        total_chars += item_chars
    return output, truncated


def _sanitized_capture_record(action: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(action, dict) or action.get("action") != "network_capture":
        return None
    url, url_truncated = _bounded_capture_text(action.get("url"), 16 * 1024)
    if not url:
        return None
    request_body, request_truncated = _bounded_capture_text(
        action.get("request_body"), _MAX_CAPTURE_REQUEST_CHARS
    )
    response_body, response_truncated = _bounded_capture_text(
        action.get("response_body"), _MAX_CAPTURE_RESPONSE_CHARS
    )
    request_headers, headers_truncated = _bounded_capture_headers(
        action.get("request_headers")
    )
    try:
        response_status = int(action.get("response_status") or 0)
    except (TypeError, ValueError):
        response_status = 0
    return {
        "action": "network_capture",
        "persona_id": str(action.get("persona_id") or "")[:256],
        "type": str(action.get("type") or "unknown")[:32],
        "url": url,
        "method": str(action.get("method") or "GET")[:32].upper(),
        "request_headers": request_headers,
        "request_body": request_body,
        "response_status": max(0, min(response_status, 999)),
        "response_body": response_body,
        "request_truncated": bool(action.get("request_truncated"))
        or request_truncated
        or headers_truncated
        or url_truncated,
        "response_truncated": bool(action.get("response_truncated"))
        or response_truncated,
    }


def _reset_capture_counters() -> None:
    global ACTIVE_CAPTURE_BYTES, ACTIVE_CAPTURE_RECORDS, ACTIVE_CAPTURE_LIMIT_REACHED
    global ACTIVE_CAPTURE_LAST_EVENT_AT, ACTIVE_CAPTURE_INFLIGHT
    global ACTIVE_CAPTURE_WRITE_FAILED
    ACTIVE_CAPTURE_BYTES = 0
    ACTIVE_CAPTURE_RECORDS = 0
    ACTIVE_CAPTURE_LIMIT_REACHED = False
    ACTIVE_CAPTURE_LAST_EVENT_AT = None
    ACTIVE_CAPTURE_INFLIGHT = 0
    ACTIVE_CAPTURE_WRITE_FAILED = False

# Set up spontaneous event handler for recording and network capture
def _handle_node_event(event_type: str, data: Dict[str, Any]):
    global ACTIVE_CAPTURE_BYTES, ACTIVE_CAPTURE_RECORDS, ACTIVE_CAPTURE_LIMIT_REACHED
    global ACTIVE_CAPTURE_LAST_EVENT_AT, ACTIVE_CAPTURE_INFLIGHT
    global ACTIVE_CAPTURE_WRITE_FAILED
    if event_type == "recorded_action":
        action = data.get("action", {})
        if isinstance(action, dict) and action.get("action") in {
            "network_activity",
            "network_capture",
        }:
            # Stale browser hooks must never recreate a repository-local capture.
            if ACTIVE_CAPTURE_PATH is None:
                return
            if (
                ACTIVE_CAPTURE_PERSONA_ID is not None
                and action.get("persona_id") != ACTIVE_CAPTURE_PERSONA_ID
            ):
                return
            if (
                ACTIVE_CAPTURE_SESSION_ID is not None
                and action.get("capture_session") != ACTIVE_CAPTURE_SESSION_ID
            ):
                return
            if action.get("action") == "network_activity":
                phase = action.get("phase")
                if phase == "start":
                    ACTIVE_CAPTURE_INFLIGHT = min(
                        _MAX_CAPTURE_INFLIGHT,
                        ACTIVE_CAPTURE_INFLIGHT + 1,
                    )
                elif phase == "end":
                    ACTIVE_CAPTURE_INFLIGHT = max(0, ACTIVE_CAPTURE_INFLIGHT - 1)
                else:
                    return
                ACTIVE_CAPTURE_LAST_EVENT_AT = time.monotonic()
                return
            if (
                ACTIVE_CAPTURE_LIMIT_REACHED
                or ACTIVE_CAPTURE_RECORDS >= _MAX_CAPTURE_RECORDS
            ):
                ACTIVE_CAPTURE_LIMIT_REACHED = True
                return
            record = _sanitized_capture_record(action)
            if record is None:
                return
            line = json.dumps(record, separators=(",", ":")) + "\n"
            encoded = line.encode("utf-8")
            encoded_size = len(encoded)
            if ACTIVE_CAPTURE_BYTES + encoded_size > _MAX_CAPTURE_BYTES:
                ACTIVE_CAPTURE_LIMIT_REACHED = True
                return
            try:
                _append_capture_bytes(
                    ACTIVE_CAPTURE_PATH,
                    encoded,
                    expected_size=ACTIVE_CAPTURE_BYTES,
                )
                ACTIVE_CAPTURE_BYTES += encoded_size
                ACTIVE_CAPTURE_RECORDS += 1
                ACTIVE_CAPTURE_LAST_EVENT_AT = time.monotonic()
            except Exception as e:
                ACTIVE_CAPTURE_WRITE_FAILED = True
                logger.error("[snd-bridge] failed to write network capture: %s", e)

node_manager.event_handlers.append(_handle_node_event)


@router.websocket("/bridge")
async def driver_bridge_endpoint(websocket: WebSocket):
    """The WebSocket upgrade endpoint for the Swift Native Driver node."""
    if not await validate_websocket_connection(websocket, "/v1/driver/bridge"):
        return
    await node_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await node_manager.handle_response(data)
    except WebSocketDisconnect:
        node_manager.disconnect(websocket)
    except Exception as e:
        logger.error("[snd-bridge] unexpected error: %s", e)
        node_manager.disconnect(websocket)

async def _wait_for_node(timeout: float = 10.0) -> None:
    elapsed = 0.0
    interval = 0.5
    while node_manager.active_node is None and elapsed < timeout:
        await asyncio.sleep(interval)
        elapsed += interval
    if node_manager.active_node is None:
        raise DriverUnavailable("Swift node not connected")


async def validate_persona_windows(persona_ids: Sequence[str]) -> None:
    validated = tuple(_validated_persona_id(value) for value in persona_ids)
    if len(validated) < 1 or len(set(validated)) != len(validated):
        raise ValueError("persona windows must be distinct")
    await _wait_for_node()
    try:
        await node_manager.send_command({
            "request_id": uuid.uuid4().hex,
            "command": "validate_persona_windows",
            "args": {"personas": list(validated)},
        }, timeout=5.0)
    except DriverCommandError as exc:
        raise PersonaWindowUnavailable(str(exc)) from exc


async def _begin_owned_capture(
    *, owner_id: str, target_url: str, persona_id: Optional[str]
) -> str:
    global ACTIVE_CAPTURE_PATH, ACTIVE_CAPTURE_PERSONA_ID, ACTIVE_CAPTURE_SESSION_ID
    if ACTIVE_CAPTURE_OWNER_ID != owner_id:
        raise RuntimeError("capture owner lost exclusive access")
    if ACTIVE_CAPTURE_PATH is not None:
        raise RuntimeError("capture owner already has an active persona")
    await _wait_for_node()
    if ACTIVE_CAPTURE_OWNER_ID != owner_id:
        raise RuntimeError("capture owner lost exclusive access")

    try:
        capture_file = _allocate_capture_file(persona_id)
    except (OSError, RuntimeError) as exc:
        logger.error("[snd-bridge] capture allocation failed: %s", exc)
        raise RuntimeError("capture store unavailable") from exc

    capture_hook_started = False
    capture_session_id = uuid.uuid4().hex
    try:
        if persona_id is None:
            browser_session_id = str(uuid.uuid4())
            await node_manager.send_command({
                "request_id": str(uuid.uuid4()),
                "command": "launch",
                "session_id": browser_session_id,
                "args": {"headless": False}
            }, timeout=5.0)
            await asyncio.sleep(2)

        _reset_capture_counters()
        ACTIVE_CAPTURE_PATH = capture_file
        ACTIVE_CAPTURE_PERSONA_ID = persona_id
        ACTIVE_CAPTURE_SESSION_ID = capture_session_id
        await node_manager.send_command({
            "command": "start_network_capture",
            "request_id": str(uuid.uuid4()),
            "args": {
                **({"persona": persona_id} if persona_id else {}),
                "capture_session": capture_session_id,
            },
        })
        capture_hook_started = True

        await node_manager.send_command({
            "command": "navigate",
            "request_id": str(uuid.uuid4()),
            "args": {"url": target_url, **({"persona": persona_id} if persona_id else {})}
        })
    except Exception as exc:
        ACTIVE_CAPTURE_PATH = None
        ACTIVE_CAPTURE_PERSONA_ID = None
        ACTIVE_CAPTURE_SESSION_ID = None
        _reset_capture_counters()
        if capture_hook_started and node_manager.active_node:
            try:
                await node_manager.send_command({
                    "request_id": str(uuid.uuid4()),
                    "command": "stop_network_capture" if persona_id else "close",
                    "args": {"persona": persona_id} if persona_id else {},
                })
            except Exception:
                logger.exception("[snd-bridge] failed to roll back capture hook")
        try:
            os.unlink(capture_file)
        except OSError:
            pass
        logger.error("[snd-bridge] persona capture start failed: %s", exc)
        raise RuntimeError(f"failed to start persona capture: {exc}") from exc
    return capture_file


async def _finish_owned_capture(
    *, owner_id: str, release_owner: bool
) -> Dict[str, Any]:
    global ACTIVE_CAPTURE_PATH, ACTIVE_CAPTURE_PERSONA_ID, ACTIVE_CAPTURE_SESSION_ID
    if ACTIVE_CAPTURE_OWNER_ID != owner_id:
        raise RuntimeError("capture owner lost exclusive access")
    persona_id = ACTIVE_CAPTURE_PERSONA_ID
    capture_path = ACTIVE_CAPTURE_PATH
    if capture_path is None:
        raise RuntimeError("capture owner has no active persona")
    stop_error: Optional[Exception] = None
    fsync_error: Optional[Exception] = None
    try:
        if node_manager.active_node:
            await node_manager.send_command({
                "request_id": uuid.uuid4().hex,
                "command": "stop_network_capture" if persona_id else "close",
                "args": {"persona": persona_id} if persona_id else {},
            })
    except Exception as exc:
        stop_error = exc
    finally:
        records = ACTIVE_CAPTURE_RECORDS
        captured_bytes = ACTIVE_CAPTURE_BYTES
        limit_reached = ACTIVE_CAPTURE_LIMIT_REACHED
        write_failed = ACTIVE_CAPTURE_WRITE_FAILED
        try:
            _fsync_capture_file(capture_path, expected_size=captured_bytes)
        except (OSError, RuntimeError) as exc:
            fsync_error = exc
            logger.exception("[snd-bridge] failed to fsync capture file")
        ACTIVE_CAPTURE_PATH = None
        ACTIVE_CAPTURE_PERSONA_ID = None
        ACTIVE_CAPTURE_SESSION_ID = None
        _reset_capture_counters()
        if release_owner:
            _release_capture_owner(owner_id)
    if stop_error is not None:
        raise RuntimeError(f"failed to stop persona capture: {stop_error}") from stop_error
    if fsync_error is not None:
        raise RuntimeError("failed to finalize capture persistence") from fsync_error
    if write_failed:
        raise RuntimeError("capture persistence failed")
    return {
        "status": "ok",
        "persona_id": persona_id,
        "capture_file": capture_path,
        "records": records,
        "bytes": captured_bytes,
        "limit_reached": limit_reached,
    }


async def _wait_for_capture_quiescence() -> None:
    started = time.monotonic()
    while True:
        await asyncio.sleep(0.1)
        if ACTIVE_CAPTURE_WRITE_FAILED:
            raise RuntimeError("capture persistence failed")
        now = time.monotonic()
        elapsed = now - started
        if ACTIVE_CAPTURE_LIMIT_REACHED:
            return
        if (
            ACTIVE_CAPTURE_LAST_EVENT_AT is not None
            and ACTIVE_CAPTURE_INFLIGHT == 0
            and elapsed >= _CAPTURE_MIN_SETTLE_SECONDS
            and now - ACTIVE_CAPTURE_LAST_EVENT_AT >= _CAPTURE_QUIET_SECONDS
        ):
            return
        if elapsed >= _CAPTURE_MAX_SETTLE_SECONDS:
            if ACTIVE_CAPTURE_RECORDS == 0:
                raise RuntimeError("persona capture produced no network records")
            return


async def _persona_script_urls(persona_id: str) -> Tuple[str, ...]:
    result = await node_manager.send_command({
        "request_id": uuid.uuid4().hex,
        "command": "script_resource_urls",
        "args": {"persona": persona_id},
    }, timeout=10.0)
    if not isinstance(result, list):
        return ()
    return tuple(str(value) for value in result[:64] if isinstance(value, str))


async def capture_persona_pair(
    *, target_url: str, source_persona_id: str, peer_persona_id: str
) -> Tuple[PersonaCaptureArtifact, PersonaCaptureArtifact, Tuple[str, ...]]:
    target_url = validate_capture_url(target_url)
    source_persona_id = _validated_persona_id(source_persona_id) or ""
    peer_persona_id = _validated_persona_id(peer_persona_id) or ""
    if source_persona_id == peer_persona_id:
        raise ValueError("two distinct persona windows are required")
    async with _PAIR_CAPTURE_LOCK:
        owner_id = f"pair:{uuid.uuid4().hex}"
        _claim_capture_owner(owner_id)
        artifacts: List[PersonaCaptureArtifact] = []
        try:
            await validate_persona_windows((source_persona_id, peer_persona_id))
            for persona_id in (source_persona_id, peer_persona_id):
                path = await _begin_owned_capture(
                    owner_id=owner_id,
                    target_url=target_url,
                    persona_id=persona_id,
                )
                await _wait_for_capture_quiescence()
                summary = await _finish_owned_capture(
                    owner_id=owner_id,
                    release_owner=False,
                )
                records = _load_capture_records(path, persona_id=persona_id)
                artifacts.append(PersonaCaptureArtifact(
                    persona_id=persona_id,
                    path=path,
                    records=records,
                    captured_bytes=int(summary["bytes"]),
                    limit_reached=bool(summary["limit_reached"]),
                ))
            script_urls = await _persona_script_urls(source_persona_id)
        finally:
            if ACTIVE_CAPTURE_OWNER_ID == owner_id and ACTIVE_CAPTURE_PATH is not None:
                try:
                    await _finish_owned_capture(owner_id=owner_id, release_owner=False)
                except Exception:
                    logger.exception("[snd-bridge] failed to finalize paired capture")
            _release_capture_owner(owner_id)
    if len(artifacts) != 2:
        raise RuntimeError("paired capture did not produce two isolated artifacts")
    return artifacts[0], artifacts[1], script_urls


@router.post("/start_capture")
async def start_capture(
    request: Request,
    _: bool = Depends(verify_sensitive_token),
):
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("request body must be a JSON object")
        target_url = validate_capture_url(body.get("url"))
        persona_id = _validated_persona_id(body.get("persona_id"), optional=True)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    owner_id = f"manual:{uuid.uuid4().hex}"
    try:
        _claim_capture_owner(owner_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        capture_file = await _begin_owned_capture(
            owner_id=owner_id,
            target_url=target_url,
            persona_id=persona_id,
        )
    except Exception as exc:
        _release_capture_owner(owner_id)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return {
        "status": "ok",
        "persona_id": persona_id,
        "capture_file": capture_file,
    }

@router.post("/stop_capture")
async def stop_capture(_: bool = Depends(verify_sensitive_token)):
    owner_id = ACTIVE_CAPTURE_OWNER_ID
    if owner_id is None:
        return {
            "status": "ok",
            "records": 0,
            "bytes": 0,
            "limit_reached": False,
        }
    if owner_id.startswith("pair:"):
        raise HTTPException(status_code=409, detail="paired capture is managed automatically")
    if ACTIVE_CAPTURE_PATH is None:
        raise HTTPException(status_code=409, detail="capture is still starting")
    try:
        summary = await _finish_owned_capture(owner_id=owner_id, release_owner=True)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "status": "ok",
        "records": summary["records"],
        "bytes": summary["bytes"],
        "limit_reached": summary["limit_reached"],
    }
