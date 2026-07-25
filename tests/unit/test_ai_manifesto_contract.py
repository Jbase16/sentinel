"""
Calibration Run #23 — AI Assistant self-knowledge manifesto contract.

The chat system prompt (SENTINEL_IDENTITY_MANIFESTO) is a CONTRACT between
what the model is told it can do and what the chat code path can actually
invoke. It had drifted: it claimed "You can read the user's clipboard" (no
clipboard-read code exists in the chat path) and "suggest installing tools
via 'brew' or 'pip'" — which the same prompt's COMMAND PROTOCOL then forbids
("NEVER suggest installation commands").

Over-claiming capabilities makes an LLM confabulate: it will assert it did
something it cannot do. For a security assistant whose entire value is
trustworthy analysis, that is corrosive. These tests pin the contract:
  * no capability the chat path cannot back is claimed,
  * the prompt names its limits explicitly (anti-confabulation),
  * the genuine capabilities are NOT gutted in the process.
"""
from __future__ import annotations

import re

from core.ai.ai_engine import SENTINEL_IDENTITY_MANIFESTO as M


def _segments(text: str) -> list[str]:
    # Split into clause-sized segments so we can check the polarity of the
    # clause each keyword appears in (a denial vs. a claim).
    return [s.strip() for s in re.split(r"[\n.:]", text.lower()) if s.strip()]


class TestNoFalseCapabilityClaims:
    def test_clipboard_is_only_ever_denied(self):
        # "clipboard" may appear ONLY inside a negated clause (a stated limit),
        # never as a capability the model is told it has.
        for seg in _segments(M):
            if "clipboard" in seg:
                assert "cannot" in seg or "can not" in seg or "do not" in seg, (
                    f"manifesto claims clipboard access in: {seg!r}"
                )

    def test_no_brew_or_pip_install_suggestion(self):
        lower = M.lower()
        # The COMMAND PROTOCOL forbids installation commands; the manifesto
        # must not contradict it by advertising brew/pip installs.
        assert "brew" not in lower, "manifesto still advertises `brew` installs"
        assert "pip" not in lower, "manifesto still advertises `pip` installs"

    def test_no_arbitrary_shell_or_filesystem_claim(self):
        # These are not chat-path capabilities either; if mentioned, only as limits.
        for keyword in ("filesystem", "shell command", "arbitrary"):
            for seg in _segments(M):
                if keyword in seg:
                    assert "cannot" in seg or "can not" in seg or "do not" in seg, (
                        f"manifesto claims {keyword!r} access in: {seg!r}"
                    )


class TestStatesLimitsExplicitly:
    def test_declares_what_it_cannot_do(self):
        # Anti-confabulation: naming the boundary suppresses "sure, I'll do X".
        assert "cannot" in M.lower(), "manifesto must explicitly state its limits"

    def test_tells_model_to_refuse_out_of_scope_requests(self):
        lower = M.lower()
        assert "instead of pretending" in lower or "say so" in lower, (
            "manifesto should instruct the model to decline rather than fake actions"
        )


class TestRealCapabilitiesPreserved:
    """Removing false claims must not gut the genuine, code-backed ones."""

    def test_scan_orchestration_described(self):
        lower = M.lower()
        # The EXEC protocol + ActionDispatcher safety gate are real (see
        # AIEngine._try_dispatch_exec) and must remain described.
        assert "exec" in lower
        assert "action dispatcher" in lower

    def test_analysis_and_reporting_described(self):
        lower = M.lower()
        assert "finding" in lower          # reads session findings/issues
        assert "attack graph" in lower     # graph analysis
        assert "report composer" in lower  # reporting engine

    def test_identity_intact(self):
        assert "sentinel" in M.lower()
        assert "not a generic chatbot" in M.lower()


class TestManifestoIsWiredIntoChat:
    def test_stream_chat_uses_the_constant(self):
        # Guard against the inline copy creeping back: stream_chat must
        # reference the module constant, not re-inline its own manifesto.
        import inspect

        from core.ai.ai_engine import AIEngine

        src = inspect.getsource(AIEngine.stream_chat)
        assert "SENTINEL_IDENTITY_MANIFESTO" in src, (
            "stream_chat no longer references the shared manifesto constant"
        )
        # And it must not have re-inlined a second SYSTEM IDENTITY block.
        assert "You are Sentinel, the AI brain" not in src, (
            "stream_chat re-inlined the manifesto — keep it in the constant"
        )
