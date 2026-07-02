"""
Unit tests for the Finding Adversary (core/cortex/triage_adversary + evidence_bundle).

The adversary's whole job is DISTRUST. So the tests feed it liars: labels without
evidence, "bounty-safe" findings whose hops delete, and split scope/rules state —
and assert it never surfaces what a real triager would close. It also pins the two
signals the review flagged (cross_boundary, server_authz_delta) as evidence-based,
not label-based.
"""

from core.cortex.evidence_bundle import EvidenceBundle
from core.cortex.triage_adversary import (
    annotate, triage, TriageContext, BOUNTY, ENGINEERING, SURFACE, HOLD, SUPPRESS,
)


def _f(target="https://api.example.com/x", **metadata):
    return {"type": "T", "severity": "HIGH", "target": target,
            "families": ["confirmed_vuln"], "metadata": metadata}


def _ctx(route=BOUNTY, scope=True, rules=True):
    return TriageContext(route=route, scope_loaded=scope, program_rules_loaded=rules)


def _ideal(**over):
    m = dict(
        vuln_class="bola", subtype="two_persona_owned",
        owner_persona="researcher-B", accessor_persona="researcher-A",
        object_type="invoice", object_ref="https://api.example.com/api/invoices/inv_test_1",
        object_class_sensitivity="billing", real_data_accessed=False,
        ownership_markers={"planted": ["nonce123"]},
        novelty_claims=["leaked_ref_not_guessable_id", "cross_tenant_after_escalation"],
        intended_invariant="A user may read only invoices they own.",
        observed_violation="researcher-A read researcher-B's invoice object.",
        proof_mode="bounty_safe",
        restraint={"owned_test_accounts_only": True, "destructive_actions_sent": 0},
    )
    m.update(over)
    return _f(**m)


# ---------------------------------------------------------------- SURFACE / route

def test_ideal_owned_b_finding_surfaces():
    assert triage(EvidenceBundle.from_finding(_ideal()), _ctx()).decision == SURFACE


def test_local_target_is_suppressed_on_bounty_route():
    r = triage(EvidenceBundle.from_finding(_ideal(target="http://127.0.0.1:8000/x")), _ctx())
    assert r.decision == SUPPRESS and "LOCAL_TARGET_ONLY" in r.top_rejection_risks()


def test_local_target_can_surface_on_engineering_route():
    r = triage(EvidenceBundle.from_finding(_ideal(target="http://127.0.0.1:8000/x")),
               _ctx(route=ENGINEERING))
    assert r.decision == SURFACE


# ---------------------------------------------------------------- forged metadata

def test_bounty_safe_claim_with_delete_hop_is_suppressed():
    f = _ideal(hops=[{"label": "deleted the victim account", "evidence": "HTTP 200"}])
    r = triage(EvidenceBundle.from_finding(f), _ctx())
    assert r.decision == SUPPRESS and "DESTRUCTIVE_PROOF_USED" in r.top_rejection_risks()


def test_bola_label_without_evidence_never_surfaces():
    r = triage(EvidenceBundle.from_finding(_f(vuln_class="bola")), _ctx())
    assert r.decision != SURFACE
    assert "NO_CROSS_BOUNDARY_IMPACT" in r.top_rejection_risks()


# ---------------------------------------------------------------- scope vs rules

def test_scope_loaded_rules_missing_holds():
    r = triage(EvidenceBundle.from_finding(_ideal()), _ctx(scope=True, rules=False))
    assert r.decision == HOLD and "RULES_NOT_LOADED" in r.top_rejection_risks()


def test_rules_loaded_scope_missing_holds():
    r = triage(EvidenceBundle.from_finding(_ideal()), _ctx(scope=False, rules=True))
    assert r.decision == HOLD and "SCOPE_NOT_LOADED" in r.top_rejection_risks()


# ---------------------------------------------------------------- impact nuance

def test_self_escalation_high_holds_and_routes_to_manual_review():
    f = _f(vuln_class="mass_assignment", subtype="self_escalation", confidence="HIGH",
           field="role", baseline="viewer", escalated="admin",
           intended_invariant="A viewer may not self-elevate.",
           proof_mode="bounty_safe", restraint={"owned_test_accounts_only": True})
    r = triage(EvidenceBundle.from_finding(f), _ctx())
    assert r.decision == HOLD and "SELF_ESCALATION_NOT_WIELDED" in r.top_rejection_risks()
    assert "Manual review" in r.next_action
    assert any(e["safe_to_collect"] is False for e in r.evidence_needed())


def test_synthetic_low_object_holds_for_impact_framing():
    f = _ideal(object_type="note", object_ref="https://api.example.com/notes/n1")
    f["metadata"].pop("object_class_sensitivity")
    r = triage(EvidenceBundle.from_finding(f), _ctx())
    assert r.decision == HOLD and "SYNTHETIC_OBJECT_NO_SENSITIVITY" in r.top_rejection_risks()
    assert all(e["safe_to_collect"] for e in r.evidence_needed())


def test_missing_invariant_holds():
    f = _ideal()
    f["metadata"].pop("intended_invariant")
    r = triage(EvidenceBundle.from_finding(f), _ctx())
    assert r.decision == HOLD and "MISSING_INVARIANT" in r.top_rejection_risks()


# ---------------------------------------------------------- evidence-based signals

def test_cross_boundary_requires_evidence_not_label():
    assert not EvidenceBundle.from_finding(_f(vuln_class="bola")).cross_boundary
    assert EvidenceBundle.from_finding(_f(vuln_class="bola", accessor_persona="A", owner_persona="B")).cross_boundary
    assert EvidenceBundle.from_finding(_f(vuln_class="bola", ownership_markers={"planted": ["x"]})).cross_boundary
    assert EvidenceBundle.from_finding(_f(vuln_class="x", authorization_delta={"boundary": "tenant"})).cross_boundary


def test_server_authz_delta_requires_evidence_not_class():
    assert not EvidenceBundle.from_finding(_f(vuln_class="bola")).server_authz_delta
    assert EvidenceBundle.from_finding(_f(vuln_class="x", before_status=403, after_status=200)).server_authz_delta
    assert EvidenceBundle.from_finding(_f(subtype="self_escalation", confidence="HIGH")).server_authz_delta
    assert not EvidenceBundle.from_finding(_f(subtype="self_escalation", confidence="MEDIUM")).server_authz_delta


def test_used_destructive_detects_delete_method_hop():
    assert EvidenceBundle.from_finding(_f(hops=[{"method": "DELETE", "label": "x"}])).used_destructive
    assert not EvidenceBundle.from_finding(_f(hops=[{"method": "GET", "label": "read"}])).used_destructive


# ------------------------------------------------------------------- gate + volume

def test_annotate_attaches_block_and_returns_decision():
    f = _ideal()
    d = annotate(f, route=BOUNTY, scope=object(), program_rules=object())
    assert d == SURFACE
    blk = f["metadata"]["adversarial_triage"]
    assert blk["decision"] == SURFACE and blk["route"] == BOUNTY
    assert blk["payable_likelihood"] >= 0.9


def test_adversary_reduces_volume_over_mixed_findings():
    findings = [
        _ideal(),                                                    # SURFACE
        _f(vuln_class="bola"),                                       # SUPPRESS (no evidence)
        _ideal(target="http://127.0.0.1/x"),                        # SUPPRESS (local)
        _ideal(hops=[{"label": "delete user"}]),                    # SUPPRESS (destructive)
        _f(vuln_class="mass_assignment", subtype="self_escalation", confidence="HIGH",
           intended_invariant="x", proof_mode="bounty_safe",
           restraint={"owned_test_accounts_only": True}),           # HOLD
    ]
    decisions = [triage(EvidenceBundle.from_finding(f), _ctx()).decision for f in findings]
    assert decisions.count(SURFACE) == 1
    assert decisions.count(SUPPRESS) >= 3
