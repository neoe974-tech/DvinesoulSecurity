from __future__ import annotations

from dvinesoul_security.core.files import FileInfo
from dvinesoul_security.security.assessment import Finding


def detect_integrity_changes(
    baseline: list[FileInfo],
    current: list[FileInfo],
) -> list[Finding]:
    findings: list[Finding] = []

    baseline_map = {item.path: item for item in baseline}
    current_map = {item.path: item for item in current}

    for path in sorted(current_map.keys() - baseline_map.keys()):
        findings.append(
            Finding(
                category="integrity",
                severity="medium",
                title="New file detected",
                detail=f"File '{path}' was not present in the baseline.",
            )
        )

    for path in sorted(baseline_map.keys() - current_map.keys()):
        findings.append(
            Finding(
                category="integrity",
                severity="high",
                title="Baseline file missing",
                detail=f"Baseline file '{path}' is no longer present.",
            )
        )

    for path in sorted(current_map.keys() & baseline_map.keys()):
        baseline_file = baseline_map[path]
        current_file = current_map[path]

        if baseline_file.sha256 != current_file.sha256:
            findings.append(
                Finding(
                    category="integrity",
                    severity="high",
                    title="File integrity change detected",
                    detail=f"File '{path}' has a different SHA-256 hash.",
                )
            )

    return findings
