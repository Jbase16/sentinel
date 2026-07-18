from core.data.pressure_graph.manager import PressureGraphManager
from core.utils.observer import Signal


class _StubStore:
    def __init__(self, items):
        self._items = list(items)

    def get_all(self):
        return list(self._items)


class _RaisingStore:
    def get_all(self):
        raise AssertionError("global store should not be used")


class _SignalStore(_StubStore):
    def __init__(self, items, signal_name):
        super().__init__(items)
        setattr(self, signal_name, Signal())


class _Subscription:
    def __init__(self):
        self.unsubscribed = False

    def unsubscribe(self):
        self.unsubscribed = True


class _EventBus:
    def __init__(self):
        self.subscription = _Subscription()

    def subscribe(self, _callback):
        return self.subscription


def test_on_issues_changed_uses_injected_store(monkeypatch):
    issue = {
        "id": "issue-1",
        "type": "vulnerability",
        "severity": "HIGH",
        "target": "https://example.test",
        "description": "example",
    }
    mgr = PressureGraphManager(
        session_id="s1",
        issues_store=_StubStore([issue]),
        killchain_store=None,
        findings_store=None,
    )

    import core.data.pressure_graph.manager as pgm

    monkeypatch.setattr(pgm, "issues_store", _RaisingStore())

    mgr._on_issues_changed()

    assert "s1_issue-1" in mgr.nodes


def test_on_killchain_changed_uses_injected_store(monkeypatch):
    edge = {
        "id": "edge-1",
        "source": "source-node",
        "target": "target-node",
        "edge_type": "CAUSES",
        "severity": "HIGH",
        "tool": "nuclei",
    }
    mgr = PressureGraphManager(
        session_id="s1",
        issues_store=None,
        killchain_store=_StubStore([edge]),
        findings_store=None,
    )

    import core.data.pressure_graph.manager as pgm

    monkeypatch.setattr(pgm, "killchain_store", _RaisingStore())

    mgr._on_killchain_changed()

    assert "edge-1" in mgr.edges
    assert mgr.edges["edge-1"].source_id == "source-node"
    assert mgr.edges["edge-1"].target_id == "target-node"


def test_close_disconnects_store_and_event_subscriptions(monkeypatch):
    issues = _SignalStore([], "issues_changed")
    killchain = _SignalStore([], "edges_changed")
    findings = _SignalStore([], "findings_changed")
    event_bus = _EventBus()

    import core.data.pressure_graph.manager as pgm

    monkeypatch.setattr(pgm, "get_event_bus", lambda: event_bus)
    manager = PressureGraphManager(
        session_id="scan-1",
        issues_store=issues,
        killchain_store=killchain,
        findings_store=findings,
    )

    assert len(issues.issues_changed._observers) == 1
    assert len(killchain.edges_changed._observers) == 1
    assert len(findings.findings_changed._observers) == 1

    manager.close()
    manager.close()

    assert issues.issues_changed._observers == []
    assert killchain.edges_changed._observers == []
    assert findings.findings_changed._observers == []
    assert event_bus.subscription.unsubscribed is True
