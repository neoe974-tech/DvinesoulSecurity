from __future__ import annotations

from dvinesoul_security.security.assessment import (
    Finding,
    calculate_risk_score,
)


def system_assessment_to_text(findings: list[Finding]) -> str:
    risk_score = calculate_risk_score(findings)

    lines: list[str] = [
        "=== SYSTEM ASSESSMENT ===",
        "",
        f"Findings           : {len(findings)}",
        f"Risk score         : {risk_score}",
        "",
    ]

    if not findings:
        lines.append("No assessment findings detected.")
        return "\n".join(lines)

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    ordered = sorted(
        findings,
        key=lambda finding: (
            severity_order.get(finding.severity.lower(), 99),
            finding.category,
            finding.title,
        ),
    )

    for finding in ordered:
        lines.extend(
            [
                f"[{finding.severity.upper()}] "
                f"{finding.category}: {finding.title}",
                f"  {finding.detail}",
                "",
            ]
        )

    return "\n".join(lines).rstrip()
