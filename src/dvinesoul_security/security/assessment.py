from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    title: str
    detail: str


def assess_report(report: Any) -> list[Finding]:
    findings: list[Finding] = []

    elf = report.sections.get("elf", {})
    if elf.get("is_elf"):
        findings.append(
            Finding(
                category="binary",
                severity="info",
                title="ELF executable detected",
                detail="The inspected file is an ELF binary.",
            )
        )

    strings = report.sections.get("strings", {})
    values = strings.get("values", [])

    suspicious_terms = (
        "password",
        "passwd",
        "credential",
        "secret",
        "private_key",
        "private key",
        "api_key",
        "apikey",
        "token",
        "cmd.exe",
        "powershell",
    )

    for value in values:
        lowered = value.lower()

        for term in suspicious_terms:
            if term in lowered:
                findings.append(
                    Finding(
                        category="strings",
                        severity="medium",
                        title="Potentially sensitive string detected",
                        detail=f"String matched indicator '{term}': {value}",
                    )
                )
                break

    yara = report.sections.get("yara", {})
    for match in yara.get("matches", []):
        rule = match.get("rule", "unknown")
        findings.append(
            Finding(
                category="yara",
                severity="high",
                title="YARA rule matched",
                detail=f"Rule '{rule}' matched the inspected file.",
            )
        )

    integrity = report.sections.get("integrity", {})
    if integrity.get("matches") is False:
        findings.append(
            Finding(
                category="integrity",
                severity="high",
                title="Integrity mismatch detected",
                detail="The inspected file does not match its supplied baseline.",
            )
        )

    return findings
