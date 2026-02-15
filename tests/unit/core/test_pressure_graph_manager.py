from core.data.pressure_graph.manager import PressureGraphManager


class _StubStore:
    def __init__(self, items):
        self._items = list(items)

    def get_all(self):
        return list(self._items)


class _RaisingStore:
    def get_all(self):
        raise AssertionError("global store should not be used")


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
