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
import hmac
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

from core.base.config import get_config
from core.safety.ownership_registry import NativeOwnedCreationWitness
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
_MAX_INTERACTION_CONTROLS = 256
_MAX_INTERACTION_LOCATOR_DEPTH = 12
_MAX_INTERACTION_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_INTERACTION_SCANNED_NODES = 4096
_INTERACTION_LOCATOR_TAG = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_INTERACTION_DESTINATION_REF = re.compile(
    r"^interaction_destination:[0-9a-f]{64}$"
)
_INTERACTION_CREATION_REF = re.compile(r"^interaction_creation:[0-9a-f]{64}$")
_NATIVE_OWNERSHIP_PROOF_REF = re.compile(
    r"^native_ownership_witness:[0-9a-f]{64}$"
)
_PAIR_CAPTURE_LOCK = asyncio.Lock()


@dataclass(frozen=True)
class PersonaCaptureArtifact:
    persona_id: str
    path: str
    records: Tuple[Dict[str, Any], ...]
    captured_bytes: int
    limit_reached: bool
    controls: Tuple[Dict[str, Any], ...] = ()
    page_url: str = ""

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
    data_dir = os.environ.get("SENTINEL_DATA_DIR")
    if data_dir:
        return Path(data_dir) / "captures"
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


async def _persona_current_url(persona_id: str) -> str:
    result = await node_manager.send_command(
        {
            "request_id": uuid.uuid4().hex,
            "command": "current_url",
            "args": {"persona": persona_id},
        },
        timeout=10.0,
    )
    return validate_capture_url(result)


def _sanitized_interaction_controls(value: Any) -> Tuple[Dict[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    controls = []
    string_fields = (
        "tag",
        "role",
        "input_type",
        "form_method",
        "destination",
    )
    boolean_fields = (
        "locator_truncated",
        "visible",
        "disabled",
        "content_editable",
        "aria_expanded",
        "aria_haspopup",
        "sensitive_form",
        "download",
        "scripted_handler",
        "submitter",
    )
    for raw in value[:_MAX_INTERACTION_CONTROLS]:
        if not isinstance(raw, dict) or any(
            not isinstance(raw.get(field), bool) for field in boolean_fields
        ):
            continue
        locator_value = raw.get("locator")
        if (
            not isinstance(locator_value, list)
            or not 1 <= len(locator_value) <= _MAX_INTERACTION_LOCATOR_DEPTH
        ):
            continue
        locator = []
        valid_locator = True
        for raw_segment in locator_value:
            if (
                not isinstance(raw_segment, dict)
                or not isinstance(raw_segment.get("tag"), str)
                or not isinstance(raw_segment.get("sibling_index"), int)
                or isinstance(raw_segment.get("sibling_index"), bool)
            ):
                valid_locator = False
                break
            locator.append({
                "tag": raw_segment["tag"][:32],
                "sibling_index": raw_segment["sibling_index"],
            })
        if not valid_locator:
            continue
        control = {
            field: str(raw.get(field) or "")[:64]
            for field in string_fields
        }
        control.update({field: raw[field] for field in boolean_fields})
        control["locator"] = locator
        destination_ref = raw.get("destination_ref")
        if (
            isinstance(destination_ref, str)
            and _INTERACTION_DESTINATION_REF.fullmatch(destination_ref)
        ):
            control["destination_ref"] = destination_ref
        controls.append(control)
    return tuple(controls)


def _verified_owned_creation_witness(
    value: Any,
    *,
    persona_id: str,
    destination_ref: str,
) -> Optional[NativeOwnedCreationWitness]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "persona_id",
        "create_ref",
        "destination_ref",
        "proof_ref",
    }:
        return None
    create_ref = value.get("create_ref")
    proof_ref = value.get("proof_ref")
    if (
        value.get("schema_version") != 1
        or value.get("persona_id") != persona_id
        or value.get("destination_ref") != destination_ref
        or not isinstance(create_ref, str)
        or _INTERACTION_CREATION_REF.fullmatch(create_ref) is None
        or not isinstance(proof_ref, str)
        or _NATIVE_OWNERSHIP_PROOF_REF.fullmatch(proof_ref) is None
    ):
        return None
    material = "\n".join(
        (
            "sentinelforge-native-owned-creation-v1",
            persona_id,
            create_ref,
            destination_ref,
        )
    )
    expected = hmac.new(
        get_config().security.api_token.encode("utf-8"),
        material.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    supplied = proof_ref[len("native_ownership_witness:") :]
    if not hmac.compare_digest(expected, supplied):
        return None
    try:
        return NativeOwnedCreationWitness(
            persona_id=persona_id,
            create_ref=create_ref,
            destination_ref=destination_ref,
            proof_ref=proof_ref,
        )
    except ValueError:
        return None


async def _persona_interaction_controls(
    persona_id: str,
) -> Tuple[Dict[str, Any], ...]:
    try:
        result = await node_manager.send_command({
            "request_id": uuid.uuid4().hex,
            "command": "interaction_controls",
            "args": {"persona": persona_id},
        }, timeout=10.0)
    except (DriverBridgeError, RuntimeError):
        logger.exception(
            "[snd-bridge] passive interaction snapshot unavailable for persona"
        )
        return ()
    return _sanitized_interaction_controls(result)


def _capture_url_identity(value: str) -> Tuple[str, str, int, str, str]:
    parsed = urlsplit(value)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
        parsed.path or "/",
        parsed.query,
    )


async def inspect_interaction_response(
    persona_id: str,
    *,
    base_url: str,
    html: str,
) -> Dict[str, Any]:
    """Inspect already-acquired HTML inertly without target navigation or I/O."""

    validated_persona = _validated_persona_id(persona_id) or ""
    validated_url = validate_capture_url(base_url)
    if not isinstance(html, str):
        raise ValueError("interaction response body must be text")
    encoded_bytes = len(html.encode("utf-8", errors="replace"))
    if encoded_bytes > _MAX_INTERACTION_RESPONSE_BYTES:
        raise ValueError("interaction response body exceeds the observation limit")
    await _wait_for_node()
    result = await node_manager.send_command(
        {
            "request_id": uuid.uuid4().hex,
            "command": "inspect_interaction_response",
            "args": {
                "persona": validated_persona,
                "base_url": validated_url,
                "html": html,
            },
        },
        timeout=15.0,
    )
    if not isinstance(result, dict) or set(result) != {
        "base_url",
        "controls",
        "scanned_nodes",
        "controls_truncated",
    }:
        raise DriverCommandError(
            "node returned an invalid interaction response observation"
        )
    observed_url = validate_capture_url(result.get("base_url"))
    if _capture_url_identity(observed_url) != _capture_url_identity(validated_url):
        raise DriverCommandError("interaction response observation changed its base URL")
    scanned_nodes = result.get("scanned_nodes")
    controls_truncated = result.get("controls_truncated")
    if (
        isinstance(scanned_nodes, bool)
        or not isinstance(scanned_nodes, int)
        or not 0 <= scanned_nodes <= _MAX_INTERACTION_SCANNED_NODES
        or not isinstance(controls_truncated, bool)
    ):
        raise DriverCommandError(
            "interaction response observation diagnostics are invalid"
        )
    raw_controls = result.get("controls")
    controls = _sanitized_interaction_controls(raw_controls)
    if (
        not isinstance(raw_controls, list)
        or len(raw_controls) > _MAX_INTERACTION_CONTROLS
        or len(controls) != len(raw_controls)
        or scanned_nodes < len(raw_controls)
    ):
        raise DriverCommandError(
            "interaction response observation controls are invalid"
        )
    return {
        "base_url": observed_url,
        "controls": controls,
        "scanned_nodes": scanned_nodes,
        "controls_truncated": controls_truncated,
        "bytes_inspected": encoded_bytes,
        "target_requests_sent": 0,
    }


def _normalized_interaction_locator(
    locator: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if (
        isinstance(locator, (str, bytes))
        or not 1 <= len(locator) <= _MAX_INTERACTION_LOCATOR_DEPTH
    ):
        raise ValueError("interaction locator is invalid")
    normalized_locator = []
    for segment in locator:
        if not isinstance(segment, dict) or set(segment) != {
            "tag",
            "sibling_index",
        }:
            raise ValueError("interaction locator segment fields are invalid")
        tag = segment.get("tag")
        sibling_index = segment.get("sibling_index")
        if (
            not isinstance(tag, str)
            or _INTERACTION_LOCATOR_TAG.fullmatch(tag) is None
            or isinstance(sibling_index, bool)
            or not isinstance(sibling_index, int)
            or not 1 <= sibling_index <= 4096
        ):
            raise ValueError("interaction locator segment is invalid")
        normalized_locator.append(
            {"tag": tag, "sibling_index": sibling_index}
        )
    return normalized_locator


async def resolve_interaction_response_navigation(
    persona_id: str,
    locator: Sequence[Dict[str, Any]],
    *,
    base_url: str,
    html: str,
) -> Dict[str, Any]:
    """Resolve one anchor from inert response bytes without target traffic."""

    validated_persona = _validated_persona_id(persona_id) or ""
    validated_url = validate_capture_url(base_url)
    if not isinstance(html, str):
        raise ValueError("interaction response body must be text")
    if len(html.encode("utf-8", errors="replace")) > _MAX_INTERACTION_RESPONSE_BYTES:
        raise ValueError("interaction response body exceeds the observation limit")
    normalized_locator = _normalized_interaction_locator(locator)
    await _wait_for_node()
    result = await node_manager.send_command(
        {
            "request_id": uuid.uuid4().hex,
            "command": "resolve_interaction_response_navigation",
            "args": {
                "persona": validated_persona,
                "base_url": validated_url,
                "html": html,
                "locator": normalized_locator,
            },
        },
        timeout=15.0,
    )
    if not isinstance(result, dict) or set(result) != {
        "base_url",
        "destination_url",
        "locator",
        "controls",
        "scanned_nodes",
        "controls_truncated",
    }:
        raise DriverCommandError(
            "node returned an invalid interaction response resolution"
        )
    observed_url = validate_capture_url(result.get("base_url"))
    destination_url = validate_capture_url(result.get("destination_url"))
    returned_locator = result.get("locator")
    scanned_nodes = result.get("scanned_nodes")
    raw_controls = result.get("controls")
    controls = _sanitized_interaction_controls(raw_controls)
    if (
        _capture_url_identity(observed_url) != _capture_url_identity(validated_url)
        or _capture_url_identity(destination_url)[:3]
        != _capture_url_identity(validated_url)[:3]
        or returned_locator != normalized_locator
        or isinstance(scanned_nodes, bool)
        or not isinstance(scanned_nodes, int)
        or not 0 <= scanned_nodes <= _MAX_INTERACTION_SCANNED_NODES
        or result.get("controls_truncated") is not False
        or not isinstance(raw_controls, list)
        or len(raw_controls) > _MAX_INTERACTION_CONTROLS
        or len(controls) != len(raw_controls)
        or scanned_nodes < len(raw_controls)
    ):
        raise DriverCommandError(
            "interaction response resolution binding is invalid"
        )
    matches = tuple(
        control
        for control in controls
        if control.get("locator") == normalized_locator
    )
    if len(matches) != 1:
        raise DriverCommandError(
            "interaction response resolution locator is not unique"
        )
    return {
        "current_url": observed_url,
        "destination_url": destination_url,
        "control": matches[0],
        "catalog_controls": controls,
        "peer_catalog_controls": (),
    }


async def resolve_interaction_navigation(
    persona_id: str,
    locator: Sequence[Dict[str, Any]],
    peer_persona_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve one structural anchor locally without activating page behavior."""

    validated_persona = _validated_persona_id(persona_id) or ""
    validated_peer = (
        _validated_persona_id(peer_persona_id)
        if peer_persona_id is not None
        else None
    )
    if validated_peer == validated_persona:
        raise ValueError("interaction peer persona must be distinct")
    normalized_locator = _normalized_interaction_locator(locator)

    await _wait_for_node()
    controls_value = await node_manager.send_command(
        {
            "request_id": uuid.uuid4().hex,
            "command": "interaction_controls",
            "args": {"persona": validated_persona},
        },
        timeout=10.0,
    )
    catalog_controls = _sanitized_interaction_controls(controls_value)
    if not catalog_controls:
        raise DriverCommandError("node returned no current interaction catalog")
    peer_controls: Tuple[Dict[str, Any], ...] = ()
    peer_url: Optional[str] = None
    if validated_peer is not None:
        peer_controls_value = await node_manager.send_command(
            {
                "request_id": uuid.uuid4().hex,
                "command": "interaction_controls",
                "args": {"persona": validated_peer},
            },
            timeout=10.0,
        )
        peer_controls = _sanitized_interaction_controls(peer_controls_value)
        if not peer_controls:
            raise DriverCommandError(
                "node returned no current peer interaction catalog"
            )
        peer_url_value = await node_manager.send_command(
            {
                "request_id": uuid.uuid4().hex,
                "command": "current_url",
                "args": {"persona": validated_peer},
            },
            timeout=10.0,
        )
        peer_url = validate_capture_url(peer_url_value)
    result = await node_manager.send_command(
        {
            "request_id": uuid.uuid4().hex,
            "command": "resolve_interaction_navigation",
            "args": {
                "persona": validated_persona,
                "locator": normalized_locator,
            },
        },
        timeout=10.0,
    )
    required_result_keys = {
        "current_url",
        "destination_url",
        "control",
    }
    result_keys = set(result) if isinstance(result, dict) else set()
    if (
        not isinstance(result, dict)
        or result_keys not in (
            required_result_keys,
            required_result_keys | {"owned_creation_witness"},
        )
    ):
        raise DriverCommandError("node returned an invalid interaction resolution")
    current_url = validate_capture_url(result.get("current_url"))
    destination_url = validate_capture_url(result.get("destination_url"))
    if peer_url is not None and urlsplit(peer_url)._replace(
        query="", fragment=""
    ) != urlsplit(current_url)._replace(query="", fragment=""):
        raise DriverCommandError("interaction persona pages no longer match")
    if urlsplit(current_url)._replace(path="", query="", fragment="") != urlsplit(
        destination_url
    )._replace(path="", query="", fragment=""):
        raise DriverCommandError("resolved navigation destination changed origin")
    resolved_controls = _sanitized_interaction_controls([result.get("control")])
    if (
        len(resolved_controls) != 1
        or list(resolved_controls[0]["locator"]) != normalized_locator
    ):
        raise DriverCommandError("resolved interaction control is invalid")
    control = resolved_controls[0]
    if (
        control["tag"] != "a"
        or control["destination"] != "same_origin"
        or not control["visible"]
        or control["disabled"]
        or control["download"]
        or control["scripted_handler"]
    ):
        raise DriverCommandError("resolved interaction is not an eligible navigation")
    resolved = {
        "current_url": current_url,
        "destination_url": destination_url,
        "control": control,
        "catalog_controls": catalog_controls,
        "peer_catalog_controls": peer_controls,
    }
    destination_ref = str(control.get("destination_ref") or "")
    witness = _verified_owned_creation_witness(
        result.get("owned_creation_witness"),
        persona_id=validated_persona,
        destination_ref=destination_ref,
    )
    if witness is not None:
        resolved["ownership_witness"] = witness
    return resolved


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
                controls = await _persona_interaction_controls(persona_id)
                page_url = await _persona_current_url(persona_id)
                target_parts = urlsplit(target_url)
                page_parts = urlsplit(page_url)
                if (
                    target_parts.scheme.lower(),
                    (target_parts.hostname or "").lower(),
                    target_parts.port,
                ) != (
                    page_parts.scheme.lower(),
                    (page_parts.hostname or "").lower(),
                    page_parts.port,
                ):
                    raise RuntimeError(
                        "persona capture redirected outside the target origin"
                    )
                artifacts.append(PersonaCaptureArtifact(
                    persona_id=persona_id,
                    path=path,
                    records=records,
                    captured_bytes=int(summary["bytes"]),
                    limit_reached=bool(summary["limit_reached"]),
                    controls=controls,
                    page_url=page_url,
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
    if urlsplit(artifacts[0].page_url)._replace(
        query="", fragment=""
    ) != urlsplit(artifacts[1].page_url)._replace(query="", fragment=""):
        raise RuntimeError("persona captures resolved to different pages")
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
