from __future__ import annotations

import re

from dvinesoul_security.core.processes import ProcessInfo
from dvinesoul_security.security.assessment import Finding


SUSPICIOUS_COMMAND_PATTERNS = (
    re.compile(r"\bcurl\b.*\|\s*(?:sh|bash)\b", re.IGNORECASE),
    re.compile(r"\bwget\b.*\|\s*(?:sh|bash)\b", re.IGNORECASE),
    re.compile(r"\bpowershell\b.*-(?:enc|encodedcommand)\b", re.IGNORECASE),
)


def detect_suspicious_command_lines(
    processes: list[ProcessInfo],
) -> list[Finding]:
    findings: list[Finding] = []

    for process in processes:
        command = process.command.strip()

        if not command:
            continue

        for pattern in SUSPICIOUS_COMMAND_PATTERNS:
            if pattern.search(command):
                findings.append(
                    Finding(
                        category="process",
                        severity="high",
                        title="Suspicious process command line detected",
                        detail=(
                            f"Process '{process.name}' (PID {process.pid}) "
                            f"contains a suspicious execution pattern: "
                            f"{command}"
                        ),
                    )
                )
                break

    return findings
