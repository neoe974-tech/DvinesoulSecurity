from __future__ import annotations

from dataclasses import asdict, dataclass

from dvinesoul_security.security.assessment import Finding


@dataclass(frozen=True)
class SystemAssessmentReport:
    findings: list[Finding]

    @property
    def security_findings(self) -> list[Finding]:
        return [
            finding
            for finding in self.findings
            if not finding.is_observation
        ]

    @property
    def observations(self) -> list[Finding]:
        return [
            finding
            for finding in self.findings
            if finding.is_observation
        ]

    @property
    def risk_score(self) -> int:
        from dvinesoul_security.security.assessment import (
            calculate_risk_score,
        )

        return calculate_risk_score(self.findings)

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "security_findings": [
                asdict(finding)
                for finding in self.security_findings
            ],
            "observations": [
                asdict(finding)
                for finding in self.observations
            ],
        }
