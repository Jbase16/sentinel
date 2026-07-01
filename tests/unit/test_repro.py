"""
Unit tests for core/reporting/repro.py — turning confirmed findings' structured
metadata into real reproduction steps, evidence, and remediation, plus the
bounty_report integration that consumes them.

The point being pinned: a verified finding must render with its ACTUAL exploit
(the chain hops, the leaked markers, the injected value) — not the generic
"navigate to the homepage / no captured evidence" boilerplate.
"""

from core.reporting.repro import reproduction_for
from core.reporting.bounty_report import build_reports, _build_summary
from core.reporting.cvss_scorer import score_finding


def _chain_finding():
    return {
        "type": "Verified Exploit Chain (escalation-amplified BOLA)",
        "severity": "CRITICAL", "target": "http://h", "tool": "kill_chain",
        "families": ["confirmed_vuln"],
        "message": "Verified kill chain → viewer→admin expands access to 5 forbidden objects.",
        "metadata": {"vuln_class": "exploit_chain", "kind": "amplified_bola",
                     "goal": "viewer→admin expands access to 5 objects",
                     "hops": [
                         {"label": "Low-priv principal denied 9 objects", "verified": True,
                          "evidence": "baseline 401/403"},
                         {"label": "Escalation via PATCH /me {role: admin}", "verified": True,
                          "evidence": "confirmed by re-read"},
                         {"label": "Reads 5 previously-denied objects", "verified": True,
                          "evidence": "denied→allowed"}]}}


def test_chain_repro_uses_hops_as_steps_and_evidence():
    r = reproduction_for(_chain_finding())
    assert r is not None and r.confirmed is True
    # every hop label becomes a step, plus a Result line
    assert "Low-priv principal denied 9 objects" in r.steps[0]
    assert any("PATCH /me" in s for s in r.steps)
    assert any("Result:" in s for s in r.steps)
    # evidence carries the per-hop verification, not "no captured evidence"
    assert any("baseline 401/403" in e for e in r.evidence)
    assert "object/tenant scoping" in r.remediation      # amplified_bola remediation


def test_bola_oneobj_repro_names_the_ref_and_leak():
    f = {"type": "BOLA", "target": "http://h/rest/basket/7", "families": ["confirmed_vuln"],
         "metadata": {"vuln_class": "bola", "object_ref": "http://h/rest/basket/7",
                      "method": "GET", "leaked_markers": ['"UserId":39'], "victim": "victim's basket"}}
    r = reproduction_for(f)
    assert r and r.confirmed
    assert any("/rest/basket/7" in s for s in r.steps)
    assert any('"UserId":39' in s for s in r.steps)
    assert "object-level authorization" in r.remediation


def test_bola_scale_repro_describes_enumeration():
    f = {"type": "Horizontal BOLA", "target": "http://h", "families": ["confirmed_vuln"],
         "metadata": {"vuln_class": "bola", "subtype": "horizontal_enumeration",
                      "endpoint": "http://h/rest/basket/{id}", "accessed": 12,
                      "distinct_owners": 12, "owner_field": "UserId", "id_range": "1..16",
                      "sample_owners": ["1", "2", "3"]}}
    r = reproduction_for(f)
    assert r and any("12 objects" in s or "12 DISTINCT owners" in s or "12\n" in s or "12 " in s for s in r.steps)
    assert any("Enumerate" in s for s in r.steps)


def test_mass_assignment_repro_shows_injected_field():
    f = {"type": "Mass Assignment", "target": "http://h/api/Users", "families": ["confirmed_vuln"],
         "metadata": {"vuln_class": "mass_assignment", "field": "role", "klass": "privilege",
                      "injected": "admin", "baseline": "customer", "evidence": "persisted role=admin"}}
    r = reproduction_for(f)
    assert r and any('"role": "admin"' in s for s in r.steps)
    assert any("customer" in s for s in r.steps)          # baseline contrast
    assert "allowlist" in r.remediation


def test_business_logic_repro_shows_violation():
    f = {"type": "Business Logic Flaw", "target": "http://h/api/BasketItems/10",
         "families": ["confirmed_vuln"],
         "metadata": {"vuln_class": "business_logic", "field": "quantity",
                      "invariant": "'quantity' must be a positive quantity", "violation": -999,
                      "evidence": "server persisted quantity=-999"}}
    r = reproduction_for(f)
    assert r and any('"quantity": -999' in s for s in r.steps)
    assert "invariant" in r.remediation.lower()


def test_unknown_class_returns_none():
    assert reproduction_for({"metadata": {"vuln_class": "xss"}}) is None
    assert reproduction_for({"type": "Nikto Finding"}) is None


def test_build_summary_confirmed_is_assertive():
    f = _chain_finding()
    cvss = score_finding(f)
    confirmed = _build_summary(f, "Exploit Chain", "CRITICAL", cvss, confirmed=True)
    hedged = _build_summary(f, "Exploit Chain", "CRITICAL", cvss, confirmed=False)
    assert "CONFIRMED" in confirmed and "may be present" not in confirmed
    # the un-confirmed path keeps its hedging for low-confidence auto-scores
    assert "may be present" in hedged or "potential" in hedged.lower() or "exists" in hedged


def test_build_reports_wires_structured_repro():
    reports = build_reports([_chain_finding()], scan_id="s1")
    assert reports
    r = reports[0]
    assert "CONFIRMED" in r.summary
    assert any("PATCH /me" in s for s in r.steps_to_reproduce)   # real steps, not boilerplate
    assert r.evidence and any("baseline 401/403" in e for e in r.evidence)
    assert "Navigate to or send a request to" not in " ".join(r.steps_to_reproduce)
