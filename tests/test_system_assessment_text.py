from dvinesoul_security.security.assessment import Finding
from dvinesoul_security.security.system_assessment_text import (
    system_assessment_to_text,
)


def test_system_assessment_text_empty():
    text = system_assessment_to_text([])

    assert "=== SYSTEM ASSESSMENT ===" in text
    assert "Security findings : 0" in text
    assert "Observations      : 0" in text
    assert "Risk score        : 0" in text
    assert "No assessment findings or observations detected." in text


def test_system_assessment_text_separates_findings_and_observations():
    findings = [
        Finding(
            category="network",
            severity="info",
            title="Established connection",
            detail="Connection observed.",
            is_observation=True,
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

    assert "Security findings : 2" in text
    assert "Observations      : 1" in text
    assert "Risk score        : 7" in text

    assert "--- SECURITY FINDINGS ---" in text
    assert "--- OBSERVATIONS ---" in text

    security_section = text.split("--- SECURITY FINDINGS ---", 1)[1].split(
        "--- OBSERVATIONS ---", 1
    )[0]
    observation_section = text.split("--- OBSERVATIONS ---", 1)[1]

    assert "[HIGH] service: Failed service" in security_section
    assert "[LOW] network: Interface errors" in security_section
    assert "[INFO] network: Established connection" not in security_section

    assert "[INFO] network: Established connection" in observation_section


def test_system_assessment_text_orders_security_findings_by_severity():
    findings = [
        Finding(
            category="network",
            severity="low",
            title="Interface errors",
            detail="Errors detected.",
        ),
        Finding(
            category="service",
            severity="critical",
            title="Critical service",
            detail="Critical issue.",
        ),
        Finding(
            category="service",
            severity="high",
            title="Failed service",
            detail="Service failed.",
        ),
        Finding(
            category="file",
            severity="medium",
            title="Suspicious file",
            detail="Suspicious file detected.",
        ),
    ]

    text = system_assessment_to_text(findings)

    critical_position = text.index("[CRITICAL]")
    high_position = text.index("[HIGH]")
    medium_position = text.index("[MEDIUM]")
    low_position = text.index("[LOW]")

    assert critical_position < high_position
    assert high_position < medium_position
    assert medium_position < low_position


def test_system_assessment_text_orders_observations():
    findings = [
        Finding(
            category="network",
            severity="info",
            title="Z observation",
            detail="Z.",
            is_observation=True,
        ),
        Finding(
            category="network",
            severity="info",
            title="A observation",
            detail="A.",
            is_observation=True,
        ),
    ]

    text = system_assessment_to_text(findings)

    first = text.index("A observation")
    second = text.index("Z observation")

    assert first < second
