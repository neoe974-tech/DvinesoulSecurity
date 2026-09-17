from __future__ import annotations

from pathlib import Path

from dvinesoul_security.core.processes import ProcessInfo
from dvinesoul_security.security.assessment import Finding


SUSPICIOUS_EXECUTABLE_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


def detect_suspicious_process_locations(
    processes: list[ProcessInfo],
) -> list[Finding]:
    findings: list[Finding] = []

    for process in processes:
        executable = process.executable

        if executable == "unavailable":
            continue

        normalized = str(Path(executable))

        if normalized.startswith(SUSPICIOUS_EXECUTABLE_PREFIXES):
            findings.append(
                Finding(
                    category="process",
                    severity="medium",
                    title="Process executable from unusual location",
                    detail=(
                        f"Process '{process.name}' (PID {process.pid}) "
                        f"is running from '{process.executable}'."
                    ),
                )
            )

    return findings
