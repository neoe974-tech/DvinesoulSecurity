from dvinesoul_security.report.system_models import SystemAssessmentReport
from dvinesoul_security.security.assessment import Finding


def test_system_assessment_report_separates_findings_and_observations():
    report = SystemAssessmentReport(
        findings=[
            Finding(
                category="service",
                severity="high",
                title="Failed system service detected",
                detail="example.service is failed.",
            ),
            Finding(
                category="network",
                severity="info",
                title="Established network connection detected",
                detail="Connection observed.",
                is_observation=True,
            ),
        ]
    )

    assert len(report.security_findings) == 1
    assert len(report.observations) == 1
    assert report.risk_score == 6


def test_system_assessment_report_to_dict():
    report = SystemAssessmentReport(
        findings=[
            Finding(
                category="service",
                severity="low",
                title="Test finding",
                detail="Test detail.",
            ),
        ]
    )

    data = report.to_dict()

    assert data["risk_score"] == 1
    assert len(data["security_findings"]) == 1
    assert data["observations"] == []
    assert data["security_findings"][0]["category"] == "service"
    assert data["security_findings"][0]["severity"] == "low"
    assert data["security_findings"][0]["is_observation"] is False
