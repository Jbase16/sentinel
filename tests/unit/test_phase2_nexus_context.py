from core.cortex.nexus_context import NexusContext


class _StubBus:
    def __init__(self) -> None:
        self.events = []

    def subscribe_async(self, _handler) -> None:
        return None

    def emit(self, event) -> None:
        self.events.append(event)


def _build_context(monkeypatch):
    stub_bus = _StubBus()
    monkeypatch.setattr("core.cortex.nexus_context.get_event_bus", lambda: stub_bus)
    return NexusContext()


def test_rule3_emits_information_enablement_hypothesis(monkeypatch):
    context = _build_context(monkeypatch)
    emitted = []
    monkeypatch.setattr(
        context,
        "_emit_hypothesis_formed",
        lambda **kwargs: emitted.append(kwargs),
    )

    findings = [
        {
            "id": "f-cred",
            "type": "credential_dump",
            "target": "example.com",
            "severity": "HIGH",
            "confirmation_level": "confirmed",
            "capability_types": ["access", "information"],
            "base_score": 9.5,
            "tags": ["secret-leak"],
        },
        {
            "id": "f-noise",
            "type": "port_scan",
            "target": "example.com",
            "severity": "LOW",
            "confirmation_level": "confirmed",
            "capability_types": ["information"],
            "base_score": 3.0,
        },
    ]
    monkeypatch.setattr("core.cortex.nexus_context.findings_store.get_all", lambda: findings)

    paths = context.synthesize_attack_paths()

    assert any(path[0] == "Information Enablement" for path in paths)
    info_events = [event for event in emitted if event.get("rule_id") == "rule_information_enablement"]
    assert len(info_events) == 1
    assert info_events[0]["confidence"] == 0.95


def test_rule3_deduplicates_replayed_findings(monkeypatch):
    context = _build_context(monkeypatch)
    emitted = []
    monkeypatch.setattr(
        context,
        "_emit_hypothesis_formed",
        lambda **kwargs: emitted.append(kwargs),
    )

    findings = [
        {
            "id": "f1",
            "type": "git_exposure",
            "target": "example.com",
            "severity": "HIGH",
            "confirmation_level": "confirmed",
            "capability_types": ["information", "access"],
            "base_score": 9.0,
            "tags": ["backup-leak"],
        }
    ]
    monkeypatch.setattr("core.cortex.nexus_context.findings_store.get_all", lambda: findings)

    context.synthesize_attack_paths()
    context.synthesize_attack_paths()

    info_events = [event for event in emitted if event.get("rule_id") == "rule_information_enablement"]
    assert len(info_events) == 1


def test_rule3_skips_hypothesized_information_findings(monkeypatch):
    context = _build_context(monkeypatch)
    emitted = []
    monkeypatch.setattr(
        context,
        "_emit_hypothesis_formed",
        lambda **kwargs: emitted.append(kwargs),
    )

    findings = [
        {
            "id": "f-hyp",
            "type": "credential_dump",
            "target": "example.com",
            "severity": "MEDIUM",
            "confirmation_level": "hypothesized",
            "capability_types": ["access"],
            "base_score": 9.0,
            "tags": ["secret-leak"],
        }
    ]
    monkeypatch.setattr("core.cortex.nexus_context.findings_store.get_all", lambda: findings)

    context.synthesize_attack_paths()

    assert emitted == []


def test_analyze_context_exposes_hypothesized_attack_paths_alias(monkeypatch):
    context = _build_context(monkeypatch)
    monkeypatch.setattr(context, "synthesize_attack_paths", lambda: [["A", "B", "C"]])
    monkeypatch.setattr(context, "generate_recommendations", lambda: [{"phase": "Immediate Action"}])

    result = context.analyze_context()

    assert result["hypothesized_attack_paths"] == [["A", "B", "C"]]
    assert result["attack_paths"] == [["A", "B", "C"]]
