from __future__ import annotations

from dvinesoul_security.security.assessment import (
    Finding,
    calculate_risk_score,
)


def system_assessment_to_text(findings: list[Finding]) -> str:
    risk_score = calculate_risk_score(findings)

    security_findings = [
        finding
        for finding in findings
        if not finding.is_observation
    ]

    observations = [
        finding
        for finding in findings
        if finding.is_observation
    ]

    lines: list[str] = [
        "=== SYSTEM ASSESSMENT ===",
        "",
        f"Security findings : {len(security_findings)}",
        f"Observations      : {len(observations)}",
        f"Risk score        : {risk_score}",
        "",
    ]

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    def sort_findings(items: list[Finding]) -> list[Finding]:
        return sorted(
            items,
            key=lambda finding: (
                severity_order.get(finding.severity.lower(), 99),
                finding.category,
                finding.title,
                finding.detail,
            ),
        )

    if security_findings:
        lines.extend(
            [
                "--- SECURITY FINDINGS ---",
                "",
            ]
        )

        for finding in sort_findings(security_findings):
            lines.extend(
                [
                    f"[{finding.severity.upper()}] "
                    f"{finding.category}: {finding.title}",
                    f"  {finding.detail}",
                    "",
                ]
            )

    if observations:
        lines.extend(
            [
                "--- OBSERVATIONS ---",
                "",
            ]
        )

        for finding in sort_findings(observations):
            lines.extend(
                [
                    f"[{finding.severity.upper()}] "
                    f"{finding.category}: {finding.title}",
                    f"  {finding.detail}",
                    "",
                ]
            )

    if not security_findings and not observations:
        lines.append("No assessment findings or observations detected.")

    return "\n".join(lines).rstrip()
