from types import SimpleNamespace

from dvinesoul_security.security.assessment import assess_report


def test_assess_report_detects_sensitive_strings():
    report = SimpleNamespace(
        sections={
            "elf": {"is_elf": False},
            "strings": {
                "values": [
                    "normal text",
                    "API_KEY=example-secret",
                ]
            },
        }
    )

    findings = assess_report(report)

    assert len(findings) == 1
    assert findings[0].category == "strings"
    assert findings[0].severity == "medium"
    assert "API_KEY" in findings[0].detail


def test_assess_report_detects_yara_match():
    report = SimpleNamespace(
        sections={
            "elf": {"is_elf": True},
            "strings": {"values": []},
            "yara": {
                "matches": [
                    {"rule": "TestMalwareRule"},
                ]
            },
        }
    )

    findings = assess_report(report)

    assert any(
        finding.category == "yara"
        and finding.severity == "high"
        for finding in findings
    )

    assert any(
        finding.category == "binary"
        and finding.severity == "info"
        for finding in findings
    )
