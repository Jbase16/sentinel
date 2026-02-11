from core.toolkit.vuln_rules import apply_rules


def _messages(issue: dict) -> set[str]:
    evidence = issue.get("supporting_findings", []) if isinstance(issue, dict) else []
    return {
        str(item.get("message", "")).strip()
        for item in evidence
        if isinstance(item, dict)
    }


def test_auth_chain_evidence_is_not_all_findings_for_target():
    findings = [
        {
            "type": "directory_disclosure",
            "severity": "MEDIUM",
            "target": "localhost",
            "tool": "gobuster",
            "message": "auth signal",
            "tags": ["auth"],
            "families": [],
            "metadata": {},
        },
        {
            "type": "dev_surface",
            "severity": "MEDIUM",
            "target": "localhost",
            "tool": "httpx",
            "message": "dev signal",
            "tags": ["dev-surface"],
            "families": [],
            "metadata": {},
        },
        {
            "type": "missing_header",
            "severity": "LOW",
            "target": "localhost",
            "tool": "httpx",
            "message": "header signal",
            "tags": ["header-missing"],
            "families": [],
            "metadata": {"header": "x-frame-options"},
        },
        {
            "type": "tls_finding",
            "severity": "MEDIUM",
            "target": "localhost",
            "tool": "sslscan",
            "message": "crypto signal",
            "tags": ["crypto"],
            "families": [],
            "metadata": {},
        },
        {
            "type": "unrelated",
            "severity": "INFO",
            "target": "localhost",
            "tool": "nmap",
            "message": "unrelated signal",
            "tags": ["port-scan"],
            "families": [],
            "metadata": {},
        },
    ]

    issues, _, _ = apply_rules(findings)
    auth_issue = next((issue for issue in issues if issue.get("rule_id") == "AUTH_CHAIN"), None)
    assert auth_issue is not None

    evidence_messages = _messages(auth_issue)
    assert "auth signal" in evidence_messages
    assert "dev signal" in evidence_messages
    assert "header signal" in evidence_messages
    assert "crypto signal" in evidence_messages
    assert "unrelated signal" not in evidence_messages


def test_header_chain_evidence_is_limited_to_relevant_findings():
    findings = [
        {
            "type": "missing_header",
            "severity": "LOW",
            "target": "localhost",
            "tool": "httpx",
            "message": "missing csp",
            "tags": ["header-missing"],
            "families": [],
            "metadata": {"header": "content-security-policy"},
        },
        {
            "type": "upload_surface",
            "severity": "MEDIUM",
            "target": "localhost",
            "tool": "ffuf",
            "message": "upload endpoint",
            "tags": ["upload"],
            "families": [],
            "metadata": {},
        },
        {
            "type": "unrelated",
            "severity": "INFO",
            "target": "localhost",
            "tool": "nmap",
            "message": "unrelated target finding",
            "tags": ["port-scan"],
            "families": [],
            "metadata": {},
        },
    ]

    issues, _, _ = apply_rules(findings)
    header_issue = next((issue for issue in issues if issue.get("rule_id") == "HEADER_CHAIN"), None)
    assert header_issue is not None

    evidence_messages = _messages(header_issue)
    assert evidence_messages == {"missing csp", "upload endpoint"}


def test_timing_debug_chain_evidence_excludes_unrelated_findings():
    findings = [
        {
            "type": "timing",
            "severity": "MEDIUM",
            "target": "localhost",
            "tool": "httpx",
            "message": "timing variance seen",
            "tags": ["timing-variance"],
            "families": [],
            "metadata": {},
        },
        {
            "type": "debug",
            "severity": "MEDIUM",
            "target": "localhost",
            "tool": "httpx",
            "message": "debug endpoint leaked",
            "tags": ["debug-toggle"],
            "families": [],
            "metadata": {},
        },
        {
            "type": "unrelated",
            "severity": "INFO",
            "target": "localhost",
            "tool": "nmap",
            "message": "completely unrelated",
            "tags": ["port-scan"],
            "families": [],
            "metadata": {},
        },
    ]

    issues, _, _ = apply_rules(findings)
    timing_issue = next(
        (issue for issue in issues if issue.get("rule_id") == "TIMING_DEBUG_CHAIN"),
        None,
    )
    assert timing_issue is not None
    evidence_messages = _messages(timing_issue)
    assert evidence_messages == {"timing variance seen", "debug endpoint leaked"}
