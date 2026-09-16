from dvinesoul_security.security.assessment import Finding
from dvinesoul_security.security.system_assessment_text import (
    system_assessment_to_text,
)


def test_system_assessment_text_empty():
    text = system_assessment_to_text([])

    assert "=== SYSTEM ASSESSMENT ===" in text
    assert "Findings           : 0" in text
    assert "Risk score         : 0" in text
    assert "No assessment findings detected." in text


def test_system_assessment_text_orders_by_severity():
    findings = [
        Finding(
            category="network",
            severity="info",
            title="Established connection",
            detail="Connection observed.",
        ),
        Finding(
            category="service",
            severity="high",
            title="Failed service",
            detail="Service failed.",
        ),
        Finding(
            category="network",
            severity="low",
            title="Interface errors",
            detail="Errors detected.",
        ),
    ]

    text = system_assessment_to_text(findings)

    assert "Findings           : 3" in text
    assert "Risk score         : 7" in text

    high_position = text.index("[HIGH]")
    low_position = text.index("[LOW]")
    info_position = text.index("[INFO]")

    assert high_position < low_position < info_position
