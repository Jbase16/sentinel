"""
Unit tests for the Finding Adversary (core/cortex/triage_adversary + evidence_bundle).

The adversary must be genuinely hostile: it SUPPRESSES destructive or impact-less
proofs, HOLDS the technically-real-but-weak ones (synthetic object, own-account
role change, local instance), and SURFACEs only a proof that survives every axis.
If it doesn't reduce volume it's decorative — one test pins that directly.
"""

from core.cortex.evidence_bundle import EvidenceBundle
from core.cortex.triage_adversary import triage, SURFACE, HOLD, SUPPRESS


def _triage(finding, **kw):
    return triage(EvidenceBundle.from_finding(finding, **kw))


# --------------------------------------------------------------------- SUPPRESS

def test_suppresses_destructive_lab_chain():
    f = {"target": "http://127.0.0.1:5002",
         "metadata": {"vuln_class": "exploit_chain", "kind": "privilege_escalation", "proof_mode": "lab",
                      "hops": [{"label": "Escalated principal can delete any user account (DELETE /users/v1/{v})",
                                "evidence": "normal 401, escalated 200"}]}}
    r = _triage(f)
    assert r.decision == SUPPRESS
    assert "proof_minimality_safety" in r.top_rejection_risks()


def test_suppresses_finding_with_no_impact_and_no_repro():
    f = {"target": "https://app.example.com",
         "metadata": {"vuln_class": "info", "proof_mode": "bounty_safe"}}
    r = _triage(f)
    assert r.decision == SUPPRESS
    assert r.payable_likelihood <= 0.1


# ------------------------------------------------------------------------- HOLD

def test_holds_two_persona_bola_on_synthetic_local_object():
    f = {"target": "http://127.0.0.1:5002/books/v1/x",
         "metadata": {"vuln_class": "bola", "subtype": "two_persona_owned", "object_type": "books",
                      "proof_mode": "bounty_safe", "object_ref": "http://127.0.0.1:5002/books/v1/x",
                      "ownership_markers": {"planted": ["sfsec_x"]},
                      "restraint": {"owned_test_accounts_only": True, "destructive_actions_sent": 0}}}
    r = _triage(f)
    assert r.decision == HOLD
    risks = r.top_rejection_risks()
    assert "impact_sufficiency" in risks and "environmental_artifact_risk" in risks
    assert r.challenges                        # carries the triager's predicted rejections


def test_holds_self_escalation_and_routes_impact_to_manual_review():
    f = {"target": "http://127.0.0.1:8000/api/users/me",
         "metadata": {"vuln_class": "mass_assignment", "subtype": "self_escalation", "field": "role",
                      "confidence": "HIGH", "proof_mode": "bounty_safe",
                      "evidence": "a fresh login still reflects role='member'",
                      "restraint": {"owned_test_accounts_only": True, "destructive_actions_sent": 0}}}
    r = _triage(f)
    assert r.decision == HOLD
    # strengthening impact would require wielding the role → manual review, not autonomy
    assert "Manual review required" in r.next_action


# ---------------------------------------------------------------------- SURFACE

def test_surfaces_a_proof_that_survives_every_axis():
    f = {"target": "https://app.realprogram.com", "steps": ["1. ...", "2. ..."],
         "metadata": {"vuln_class": "exploit_chain", "kind": "data_exposure", "proof_mode": "bounty_safe",
                      "hops": [{"label": "anon self-registration", "evidence": "200"},
                               {"label": "read other users' private records", "evidence": "200"}],
                      "restraint": {"owned_test_accounts_only": True, "destructive_actions_sent": 0}}}
    r = _triage(f, scope=object(), program_rules=object())
    assert r.decision == SURFACE
    assert not r.top_rejection_risks() and r.payable_likelihood > 0.9
    assert "Surface to researcher" in r.next_action


# ----------------------------------------------------------- it reduces volume

def test_adversary_actually_reduces_volume():
    batch = [
        {"target": "http://127.0.0.1/x", "metadata": {"vuln_class": "exploit_chain", "proof_mode": "lab",
            "hops": [{"label": "delete any user"}]}},                              # suppress
        {"target": "http://127.0.0.1:5002/books/v1/x", "metadata": {"vuln_class": "bola",
            "subtype": "two_persona_owned", "object_ref": "x", "ownership_markers": {"planted": ["m"]},
            "proof_mode": "bounty_safe", "restraint": {"owned_test_accounts_only": True}}},  # hold
        {"target": "http://127.0.0.1/me", "metadata": {"vuln_class": "mass_assignment",
            "subtype": "self_escalation", "confidence": "HIGH", "proof_mode": "bounty_safe",
            "restraint": {"owned_test_accounts_only": True}}},                    # hold
        {"target": "https://app.example.com", "metadata": {"vuln_class": "info", "proof_mode": "bounty_safe"}},  # suppress
    ]
    decisions = [_triage(f).decision for f in batch]
    assert decisions.count(SURFACE) == 0        # nothing this weak reaches the researcher
    assert SUPPRESS in decisions and HOLD in decisions


def test_to_metadata_shape():
    f = {"target": "http://127.0.0.1:5002/books/v1/x",
         "metadata": {"vuln_class": "bola", "subtype": "two_persona_owned", "object_ref": "x",
                      "ownership_markers": {"planted": ["m"]}, "proof_mode": "bounty_safe",
                      "restraint": {"owned_test_accounts_only": True}}}
    md = _triage(f).to_metadata()["adversarial_triage"]
    assert md["decision"] == HOLD
    assert set(md) >= {"decision", "payable_likelihood", "top_rejection_risks",
                       "survived_challenges", "predicted_rejections", "next_action"}
    assert md["predicted_rejections"]           # the triager's actual words
