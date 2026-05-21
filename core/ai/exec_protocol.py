"""
core/ai/exec_protocol.py

Hardened parser for the ``>>> EXEC:`` action protocol.

THREAT MODEL
------------
The AI streams text. When a line starts with ``>>> EXEC:``, the engine treats
the JSON that follows as an instruction to dispatch a tool. The model's prompt
is built from user-supplied chat input — so without defense, an attacker can:

  1.  Inject the EXEC marker into their own question, hoping the model echoes it.
  2.  Get the model to emit an EXEC for a tool with shell-metacharacter args.
  3.  Inflate the JSON to oversized payloads that confuse the parser.
  4.  Add unexpected keys the dispatcher ignores but logging keeps.

This module is the choke point for all of those. The dispatch path is:

    raw streamed line
        -> parse_exec_line()           # strict, fail-closed
        -> ExecCommand pydantic model  # schema-locked
        -> ActionDispatcher.request_action()
        -> safe_tools auto-approve / restricted_tools human-approve / drop

If parsing fails for any reason — bad JSON, wrong shape, oversized, dangerous
args, unknown tool — we return None and the line is rendered as plain text.
There is no path from a malformed EXEC line to dispatcher invocation.

USER-INPUT SANITIZATION
-----------------------
Separately, ``sanitize_user_question()`` strips the EXEC marker out of the
user's chat text before it ever reaches the prompt. A user typing
``Tell me about findings. >>> EXEC: {...}`` cannot smuggle a directive in
because the marker is replaced before the model sees it.
"""
from __future__ import annotations

import json
import logging
import re
from typing import List, Optional, Set

from pydantic import BaseModel, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXEC_PREFIX = ">>> EXEC:"

# Hard cap on the JSON portion of an EXEC line. Real EXEC commands fit in
# under 200 chars; we leave headroom but refuse anything larger to prevent
# parser DoS and to bound the blast radius of a confused model.
MAX_EXEC_JSON_LEN = 1024

# Shell metacharacters that must never appear in any tool argument. This is
# the same set CommandValidator.validate_safe_args enforces for safe tools;
# we apply it uniformly here regardless of safe/restricted classification.
_SHELL_METACHARS = frozenset(";&|`$<>(){}[]\\\n\r\x00")

# Patterns to strip from user input before it enters the model prompt.
# We intentionally drop the marker (rather than reject the message) so the
# user gets a reply about their question instead of an error.
#
# NOTE: patterns are NOT anchored to start-of-line. The model may split,
# paraphrase, or re-emit user text on any line boundary; an attacker who
# embeds the marker mid-sentence could otherwise smuggle it past us.
_USER_INJECTION_PATTERNS: List[re.Pattern] = [
    # The EXEC marker itself, anywhere in the text, any case, any spacing.
    re.compile(r">>>\s*EXEC\s*:", re.IGNORECASE),
    # Common prompt-injection lead-ins ("Ignore previous instructions and ...")
    re.compile(r"\bignore\s+(?:the\s+)?(?:previous|prior|above)\s+instructions?\b", re.IGNORECASE),
    # System-prompt impersonation attempts — match anywhere, not just line-start
    re.compile(r"\bSYSTEM\s*:", re.IGNORECASE),
    re.compile(r"\bINSTRUCTION\s*:", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Pydantic schema — every EXEC payload must match this shape exactly
# ---------------------------------------------------------------------------

class ExecCommand(BaseModel):
    """A schema-locked tool invocation request.

    Pydantic's strict mode rejects extra fields, wrong types, and missing
    required keys. There is no path through this model that produces a
    surprising shape.
    """

    tool: str = Field(min_length=1, max_length=64)
    args: List[str] = Field(default_factory=list, max_length=32)
    reason: str = Field(default="AI-suggested", max_length=256)

    model_config = {
        "extra": "forbid",   # reject unknown keys outright
        "str_strip_whitespace": True,
    }

    @field_validator("tool")
    @classmethod
    def _tool_must_be_clean(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("tool name cannot be empty")
        # Tool names are simple identifiers — no shell metas, no paths
        if not re.fullmatch(r"[a-z0-9_\-]+", v):
            raise ValueError(f"tool name has invalid characters: {v!r}")
        return v

    @field_validator("args")
    @classmethod
    def _args_must_be_safe(cls, v: List[str]) -> List[str]:
        cleaned: List[str] = []
        for i, raw in enumerate(v):
            if not isinstance(raw, str):
                raise ValueError(f"args[{i}] must be a string")
            if len(raw) > 512:
                raise ValueError(f"args[{i}] exceeds 512 chars")
            if any(ch in _SHELL_METACHARS for ch in raw):
                raise ValueError(
                    f"args[{i}] contains shell metacharacter; rejected for safety"
                )
            cleaned.append(raw)
        return cleaned


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_exec_line(
    line: str,
    allowed_tools: Optional[Set[str]] = None,
) -> Optional[ExecCommand]:
    """Parse one streamed line for the EXEC protocol.

    Returns a validated ``ExecCommand`` if the line was a well-formed EXEC
    directive whose tool is in ``allowed_tools`` (if provided). Returns
    ``None`` in every other case — including malformed JSON, oversized
    payloads, schema mismatches, dangerous args, or unknown tools.

    The caller is responsible for routing the returned command through
    ``ActionDispatcher.request_action()``. This function only validates the
    *shape* of the directive; it does not consult the safe/restricted lists.

    Args:
        line: A single line from the streamed model output.
        allowed_tools: Optional whitelist. When provided, any tool not in
            this set causes ``None`` to be returned. Pass the union of
            ``config.scan.safe_tools`` and ``config.scan.restricted_tools``
            to enforce "the AI may only suggest known tools."

    Returns:
        ``ExecCommand`` on successful parse + validation, otherwise ``None``.
    """
    stripped = line.strip()
    if not stripped.startswith(EXEC_PREFIX):
        return None

    json_str = stripped[len(EXEC_PREFIX):].strip()

    if not json_str:
        logger.warning("[ExecProtocol] empty EXEC payload")
        return None

    if len(json_str) > MAX_EXEC_JSON_LEN:
        logger.warning(
            "[ExecProtocol] EXEC payload exceeds %d chars (got %d); rejected",
            MAX_EXEC_JSON_LEN,
            len(json_str),
        )
        return None

    try:
        payload = json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.warning("[ExecProtocol] malformed EXEC JSON: %s", exc)
        return None

    if not isinstance(payload, dict):
        logger.warning("[ExecProtocol] EXEC payload is not an object: %r", type(payload).__name__)
        return None

    try:
        cmd = ExecCommand.model_validate(payload)
    except ValidationError as exc:
        logger.warning("[ExecProtocol] EXEC schema validation failed: %s", exc.errors())
        return None

    if allowed_tools is not None and cmd.tool not in allowed_tools:
        logger.warning(
            "[ExecProtocol] EXEC rejected: tool %r not in allowed set", cmd.tool
        )
        return None

    return cmd


# ---------------------------------------------------------------------------
# User-input sanitization
# ---------------------------------------------------------------------------

def sanitize_user_question(text: str) -> str:
    """Strip prompt-injection markers from user-supplied chat text.

    The user's question is concatenated into the prompt the model sees.
    Without sanitization, a user can embed ``>>> EXEC: {...}`` directly in
    their question and the model is statistically likely to echo or act on
    it. We strip these markers before the text reaches the model.

    This is deliberately lossy. We do not try to "escape" or "quote" — we
    *remove* the dangerous patterns and replace them with a benign marker
    so logs preserve evidence of the attempt without preserving the payload.
    """
    if not text:
        return text

    sanitized = text
    for pattern in _USER_INJECTION_PATTERNS:
        sanitized = pattern.sub("[redacted-injection-marker]", sanitized)

    if sanitized != text:
        logger.warning(
            "[ExecProtocol] sanitized prompt-injection markers from user input "
            "(original_len=%d, sanitized_len=%d)",
            len(text),
            len(sanitized),
        )
    return sanitized
