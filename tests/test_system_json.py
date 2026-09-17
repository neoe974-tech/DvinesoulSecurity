import json

from dvinesoul_security.report.system_json import system_report_to_json
from dvinesoul_security.report.system_models import SystemAssessmentReport
from dvinesoul_security.security.assessment import Finding


def test_system_report_to_json():
    report = SystemAssessmentReport(
        findings=[
            Finding(
                category="service",
                severity="high",
                title="Failed service",
                detail="example.service failed.",
            ),
        ]
    )

    output = system_report_to_json(report)

    data = json.loads(output)

    assert data["risk_score"] == 6
    assert len(data["security_findings"]) == 1
    assert data["observations"] == []
