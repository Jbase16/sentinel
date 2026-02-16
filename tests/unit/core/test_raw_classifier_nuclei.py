from core.toolkit.raw_classifier import classify


def test_nuclei_jsonl_parsing_emits_structured_finding() -> None:
    output = "\n".join(
        [
            # Non-JSON noise should be ignored.
            "[INF] some progress line",
            # Minimal nuclei JSONL example.
            (
                '{"templateID":"exposures/git-config","info":{"name":"Git Config Exposure","severity":"high","tags":"git,exposure"},'
                '"matched-at":"http://example.test/.git/config","type":"http","host":"example.test","timestamp":"2026-02-15T00:00:00Z"}'
            ),
        ]
    )

    findings = classify("nuclei_safe", "http://example.test", output)
    nuclei_findings = [f for f in findings if f.get("tool") == "nuclei_safe"]
    assert len(nuclei_findings) == 1

    f = nuclei_findings[0]
    assert f["tool"] == "nuclei_safe"
    assert f["severity"] == "HIGH"
    assert f["type"] == "Git Config Exposure"

    meta = f.get("metadata") or {}
    assert meta.get("url") == "http://example.test/.git/config"
    assert meta.get("template_id") == "exposures/git-config"

    tags = set(f.get("tags") or [])
    assert "nuclei" in tags
    assert "git" in tags
    assert "exposure" in tags
