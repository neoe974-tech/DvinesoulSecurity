from __future__ import annotations

from pathlib import Path

from dvinesoul_security.security.assessment import Finding


SUSPICIOUS_WRITABLE_LOCATIONS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


def detect_suspicious_file_location(path: str) -> list[Finding]:
    findings: list[Finding] = []

    normalized = str(Path(path))

    if normalized.startswith(SUSPICIOUS_WRITABLE_LOCATIONS):
        findings.append(
            Finding(
                category="file",
                severity="medium",
                title="File located in unusual writable directory",
                detail=(
                    f"File '{path}' is located in a commonly writable "
                    "temporary directory."
                ),
            )
        )

    return findings
