"""
Phase 4-G2 tests for core/ghost/flow.py.

Coverage:
  * FlowStep new fields (request_body, response_*, cookies_after_step).
  * FlowStep / UserFlow JSON round-trip — to_dict() then from_dict()
    must reproduce the same in-memory object (modulo class identity).
  * FlowMapper.record_request_to_all + finalize_step — the new
    request/response two-phase capture used by the addon.
  * Cookie jar accumulation from Set-Cookie headers (multi-step).
  * persist/load_persisted round-trip via env-isolated tempdir.
  * list_persisted enumerates correctly.

The persistence tests monkey-patch the SENTINELFORGE_FLOW_STORE env var
to a pytest tmp_path so they're hermetic — no touching the operator's
real ~/.sentinelforge.
"""
from __future__ import annotations

import json
import os

import pytest

from core.ghost.flow import (
    MAX_BODY_BYTES,
    FlowMapper,
    FlowStep,
    UserFlow,
    _flow_store_dir,
)


@pytest.fixture(autouse=True)
def _reset_flow_mapper(monkeypatch):
    """FlowMapper is a singleton; reset between tests so state doesn't
    leak. Also clear the step→flow reverse map."""
    FlowMapper._instance = None
    yield
    FlowMapper._instance = None


@pytest.fixture
def isolated_flow_store(monkeypatch, tmp_path):
    """Point the on-disk flow store at a pytest tmp_path so tests don't
    touch real ~/.sentinelforge data."""
    monkeypatch.setenv("SENTINELFORGE_FLOW_STORE", str(tmp_path))
    return tmp_path


# ───────────────────────── FlowStep shape ─────────────────────────


class TestFlowStepFields:
    def test_request_body_captured(self):
        step = FlowStep(
            method="POST",
            url="http://h/api",
            request_body='{"email": "a@b.com", "password": "p"}',
            request_content_type="application/json",
        )
        assert step.request_body == '{"email": "a@b.com", "password": "p"}'
        assert step.request_content_type == "application/json"
        assert step.request_body_truncated is False

    def test_headers_normalized_to_lowercase(self):
        step = FlowStep(
            method="GET",
            url="http://h/",
            headers={"Content-Type": "text/html", "X-Custom-Header": "yes"},
        )
        # Keys lowercased for case-insensitive replay-time lookup.
        assert "content-type" in step.headers
        assert "x-custom-header" in step.headers
        # Values preserved.
        assert step.headers["x-custom-header"] == "yes"

    def test_set_response_populates_all_fields(self):
        step = FlowStep(method="GET", url="http://h/")
        step.set_response(
            status=200,
            headers={"Content-Type": "application/json", "Set-Cookie": "sid=abc"},
            body='{"ok": true}',
            content_type="application/json",
            elapsed_ms=123.45,
            cookies_after_step={"sid": "abc"},
        )
        assert step.response_status == 200
        assert step.response_body == '{"ok": true}'
        # Response headers also lowercased.
        assert step.response_headers["content-type"] == "application/json"
        assert step.response_elapsed_ms == 123.45
        assert step.cookies_after_step == {"sid": "abc"}


class TestFlowStepSerialization:
    def test_round_trip_via_dict(self):
        original = FlowStep(
            method="POST",
            url="http://h/login",
            params={"redirect_to": "/dashboard"},
            headers={"Authorization": "Bearer token"},
            request_body='{"email": "a@b", "password": "p"}',
            request_content_type="application/json",
        )
        original.set_response(
            status=200,
            headers={"set-cookie": "session=xyz"},
            body='{"token": "jwt-here"}',
            content_type="application/json",
            elapsed_ms=89.0,
            cookies_after_step={"session": "xyz"},
        )

        restored = FlowStep.from_dict(original.to_dict())
        assert restored.id == original.id
        assert restored.method == original.method
        assert restored.url == original.url
        assert restored.params == original.params
        assert restored.headers == original.headers
        assert restored.request_body == original.request_body
        assert restored.request_content_type == original.request_content_type
        assert restored.response_status == original.response_status
        assert restored.response_headers == original.response_headers
        assert restored.response_body == original.response_body
        assert restored.response_elapsed_ms == original.response_elapsed_ms
        assert restored.cookies_after_step == original.cookies_after_step

    def test_empty_step_round_trips_safely(self):
        """A step with no response yet (request side only) must serialize
        and deserialize cleanly without raising."""
        step = FlowStep(method="GET", url="http://h/")
        restored = FlowStep.from_dict(step.to_dict())
        assert restored.method == "GET"
        assert restored.response_status == 0
        assert restored.response_body == ""


# ───────────────────────── UserFlow shape ─────────────────────────


class TestUserFlowSerialization:
    def test_user_flow_round_trip(self):
        flow = UserFlow(name="checkout-flow")
        s1 = FlowStep(method="GET", url="http://h/cart")
        s1.set_response(status=200, body="cart contents")
        s2 = FlowStep(method="POST", url="http://h/checkout",
                      headers={"Authorization": "Bearer X"},
                      request_body='{"items": [1, 2, 3]}')
        s2.set_response(status=201, body='{"order_id": 42}')
        flow.add_step(s1)
        flow.add_step(s2)
        flow.extract_tokens({"authorization": "Bearer X"})

        restored = UserFlow.from_dict(flow.to_dict())
        assert restored.id == flow.id
        assert restored.name == "checkout-flow"
        assert len(restored.steps) == 2
        assert restored.steps[0].response_body == "cart contents"
        assert restored.steps[1].response_status == 201
        assert restored.auth_tokens == flow.auth_tokens


class TestCookieJarAccumulation:
    def test_set_cookie_parsed_and_accumulated(self):
        flow = UserFlow(name="cookie-flow")
        # Simulate step 1: receive a session cookie.
        jar1 = flow.update_cookie_jar_from_response(
            {"set-cookie": "sid=abc123; Path=/; HttpOnly"}
        )
        assert jar1 == {"sid": "abc123"}

        # Step 2: receive an additional cookie. Jar should grow.
        jar2 = flow.update_cookie_jar_from_response(
            {"set-cookie": "csrf=xyz; Path=/"}
        )
        assert jar2 == {"sid": "abc123", "csrf": "xyz"}

        # Step 3: server updates existing cookie. Jar should reflect new value.
        jar3 = flow.update_cookie_jar_from_response(
            {"set-cookie": "sid=NEW; Path=/"}
        )
        assert jar3["sid"] == "NEW"
        assert jar3["csrf"] == "xyz"

    def test_no_set_cookie_means_unchanged_jar(self):
        flow = UserFlow(name="no-cookies")
        flow.update_cookie_jar_from_response({"set-cookie": "a=1"})
        jar = flow.update_cookie_jar_from_response({"content-type": "text/html"})
        # No new set-cookie → jar unchanged.
        assert jar == {"a": "1"}


# ───────────────────────── FlowMapper recording ─────────────────────────


class TestFlowMapperTwoPhaseCapture:
    def test_record_request_to_all_with_no_active_flows(self):
        fm = FlowMapper.instance()
        # No flows recording → fan-out is a no-op, returns empty.
        step_ids = fm.record_request_to_all(method="GET", url="http://h/")
        assert step_ids == []

    def test_record_request_to_all_populates_active_flows(self):
        fm = FlowMapper.instance()
        fid_a = fm.start_recording("flow-a")
        fid_b = fm.start_recording("flow-b")
        step_ids = fm.record_request_to_all(
            method="POST",
            url="http://h/login",
            headers={"content-type": "application/json"},
            request_body='{"email": "a"}',
        )
        # Both flows got the request.
        assert len(step_ids) == 2
        assert len(fm.active_flows[fid_a].steps) == 1
        assert len(fm.active_flows[fid_b].steps) == 1
        # Same request observed in both — same params/url/body.
        for f in (fm.active_flows[fid_a], fm.active_flows[fid_b]):
            assert f.steps[0].method == "POST"
            assert f.steps[0].url == "http://h/login"
            assert f.steps[0].request_body == '{"email": "a"}'

    def test_finalize_step_populates_response_and_updates_jar(self):
        fm = FlowMapper.instance()
        fid = fm.start_recording("login-flow")
        sid = fm.record_request(
            flow_id=fid,
            method="POST",
            url="http://h/login",
            request_body='{"email": "a@b.com"}',
        )
        assert sid is not None

        ok = fm.finalize_step(
            sid,
            status=200,
            headers={"set-cookie": "session=jwt-token; Path=/"},
            body='{"id": 42, "name": "alice"}',
            content_type="application/json",
            elapsed_ms=45.0,
        )
        assert ok is True

        flow = fm.active_flows[fid]
        step = flow.steps[0]
        assert step.response_status == 200
        assert step.response_body == '{"id": 42, "name": "alice"}'
        assert step.response_elapsed_ms == 45.0
        # Cookies-after-step reflects the Set-Cookie that just landed.
        assert step.cookies_after_step == {"session": "jwt-token"}

    def test_finalize_unknown_step_id_returns_false(self):
        fm = FlowMapper.instance()
        ok = fm.finalize_step("no-such-step", status=200)
        assert ok is False

    def test_cookie_jar_carries_across_steps(self):
        """Step 1 sets a cookie. Step 2's cookies_after_step must include
        that cookie. This is what the replayer uses to carry session
        state forward."""
        fm = FlowMapper.instance()
        fid = fm.start_recording("multi-step")

        sid1 = fm.record_request(fid, "POST", "http://h/login")
        fm.finalize_step(sid1, status=200,
                         headers={"set-cookie": "sid=abc"})

        sid2 = fm.record_request(fid, "GET", "http://h/profile")
        fm.finalize_step(sid2, status=200,
                         headers={"content-type": "text/html"})

        flow = fm.active_flows[fid]
        # Step 1 introduced sid=abc.
        assert flow.steps[0].cookies_after_step == {"sid": "abc"}
        # Step 2 didn't set new cookies but the jar still has sid=abc.
        assert flow.steps[1].cookies_after_step == {"sid": "abc"}


# ───────────────────────── persistence ─────────────────────────


class TestFlowPersistence:
    def test_persist_writes_json_file_atomically(self, isolated_flow_store):
        fm = FlowMapper.instance()
        fid = fm.start_recording("persist-test")
        fm.record_request(fid, "GET", "http://h/", headers={"x-test": "1"})

        path = fm.persist(fid)
        assert path is not None
        assert path.exists()
        # No leftover .tmp neighbor.
        assert not (isolated_flow_store / f"{fid}.json.tmp").exists()

        with path.open() as f:
            data = json.load(f)
        assert data["id"] == fid
        assert data["name"] == "persist-test"
        assert len(data["steps"]) == 1

    def test_persist_unknown_flow_returns_none(self, isolated_flow_store):
        fm = FlowMapper.instance()
        path = fm.persist("no-such-flow")
        assert path is None

    def test_load_persisted_round_trips(self, isolated_flow_store):
        # Record a flow, persist, drop the singleton, reload — flow
        # should come back from disk identical.
        fm = FlowMapper.instance()
        fid = fm.start_recording("round-trip")
        sid = fm.record_request(fid, "POST", "http://h/api",
                                request_body='{"x": 1}')
        fm.finalize_step(sid, status=201, body='{"ok": true}')
        fm.persist(fid)

        # Drop the singleton entirely (simulates process restart).
        FlowMapper._instance = None
        new_fm = FlowMapper.instance()
        assert fid not in new_fm.active_flows  # not loaded yet

        loaded = new_fm.load_persisted(fid)
        assert loaded is not None
        assert loaded.name == "round-trip"
        assert len(loaded.steps) == 1
        assert loaded.steps[0].request_body == '{"x": 1}'
        assert loaded.steps[0].response_body == '{"ok": true}'

    def test_load_persisted_returns_existing_if_already_in_memory(
        self, isolated_flow_store
    ):
        fm = FlowMapper.instance()
        fid = fm.start_recording("dup")
        original = fm.active_flows[fid]
        # load_persisted on an already-active flow returns the in-mem
        # copy without re-reading disk.
        loaded = fm.load_persisted(fid)
        assert loaded is original

    def test_load_persisted_nonexistent_returns_none(self, isolated_flow_store):
        fm = FlowMapper.instance()
        assert fm.load_persisted("never-existed") is None

    def test_list_persisted_enumerates_disk(self, isolated_flow_store):
        fm = FlowMapper.instance()
        a = fm.start_recording("alpha")
        b = fm.start_recording("beta")
        fm.record_request(a, "GET", "http://h/a")
        fm.record_request(b, "GET", "http://h/b1")
        fm.record_request(b, "POST", "http://h/b2")
        fm.persist(a)
        fm.persist(b)

        # Fresh FlowMapper — listing should find both on disk.
        FlowMapper._instance = None
        new_fm = FlowMapper.instance()
        listed = new_fm.list_persisted()
        names = {item["name"] for item in listed}
        assert names == {"alpha", "beta"}
        # alpha has 1 step, beta has 2.
        by_name = {item["name"]: item for item in listed}
        assert by_name["alpha"]["step_count"] == 1
        assert by_name["beta"]["step_count"] == 2

    def test_list_persisted_skips_unreadable_files(
        self, isolated_flow_store
    ):
        """Defensive: a corrupted JSON file in the store must not crash
        list_persisted — it should skip with a warning and surface the
        valid neighbors."""
        # Drop a valid + a corrupted file.
        fm = FlowMapper.instance()
        good_fid = fm.start_recording("good")
        fm.record_request(good_fid, "GET", "http://h/")
        fm.persist(good_fid)

        bad_path = isolated_flow_store / "corrupted-12345.json"
        bad_path.write_text("{ not valid json")

        FlowMapper._instance = None
        listed = FlowMapper.instance().list_persisted()
        names = {item["name"] for item in listed if item.get("name")}
        assert "good" in names
        # The corrupted entry should NOT crash enumeration.

    def test_persist_creates_store_dir_if_missing(
        self, monkeypatch, tmp_path
    ):
        """First-ever persist must auto-create the store directory."""
        nonexistent = tmp_path / "deep" / "nested" / "store"
        assert not nonexistent.exists()
        monkeypatch.setenv("SENTINELFORGE_FLOW_STORE", str(nonexistent))

        fm = FlowMapper.instance()
        fid = fm.start_recording("first")
        fm.record_request(fid, "GET", "http://h/")
        path = fm.persist(fid)
        assert path is not None
        assert nonexistent.exists()


# ───────────────────────── flow_store_dir resolution ─────────────────────────


def test_flow_store_dir_honors_env(monkeypatch, tmp_path):
    custom = tmp_path / "custom"
    monkeypatch.setenv("SENTINELFORGE_FLOW_STORE", str(custom))
    assert _flow_store_dir() == custom


def test_flow_store_dir_default_when_no_env(monkeypatch):
    monkeypatch.delenv("SENTINELFORGE_FLOW_STORE", raising=False)
    from pathlib import Path
    assert _flow_store_dir() == Path.home() / ".sentinelforge" / "ghost_flows"
