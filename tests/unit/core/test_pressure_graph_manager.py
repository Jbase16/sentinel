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


def test_peer_issue_store_cannot_mutate_canonical_projection():
    mgr = PressureGraphManager(
        session_id="s1",
        issues_store=_RaisingStore(),
        killchain_store=None,
        findings_store=None,
    )

    mgr._on_issues_changed()

    assert mgr.nodes == {}


def test_peer_killchain_store_cannot_mutate_canonical_projection():
    mgr = PressureGraphManager(
        session_id="s1",
        issues_store=None,
        killchain_store=_RaisingStore(),
        findings_store=None,
    )

    mgr._on_killchain_changed()

    assert mgr.edges == {}


def test_manager_does_not_subscribe_to_peer_graph_sources(monkeypatch):
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

    assert issues.issues_changed._observers == []
    assert killchain.edges_changed._observers == []
    assert findings.findings_changed._observers == []

    manager.close()
    manager.close()

    assert issues.issues_changed._observers == []
    assert killchain.edges_changed._observers == []
    assert findings.findings_changed._observers == []
    assert event_bus.subscription.unsubscribed is False
