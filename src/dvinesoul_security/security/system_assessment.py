from __future__ import annotations

from dvinesoul_security.core.snapshot import SystemSnapshot
from dvinesoul_security.security.assessment import Finding


def assess_system(snapshot: SystemSnapshot) -> list[Finding]:
    findings: list[Finding] = []

    failed_services = [
        service
        for service in snapshot.services
        if service.active == "failed"
    ]

    for service in failed_services:
        findings.append(
            Finding(
                category="service",
                severity="high",
                title="Failed system service detected",
                detail=(
                    f"Service '{service.name}' is in a failed state: "
                    f"{service.description}"
                ),
            )
        )

    listening = [
        connection
        for connection in snapshot.connections
        if connection.state == "LISTEN"
    ]

    for connection in listening:
        findings.append(
            Finding(
                category="network",
                severity="info",
                title="Listening network socket detected",
                detail=(
                    f"{connection.protocol.upper()} socket listening on "
                    f"{connection.local}"
                    f" (process: {connection.process})."
                ),
                is_observation=True,
            )
        )

    established = [
        connection
        for connection in snapshot.connections
        if connection.state == "ESTAB"
    ]

    for connection in established:
        findings.append(
            Finding(
                category="network",
                severity="info",
                title="Established network connection detected",
                detail=(
                    f"{connection.protocol.upper()} connection from "
                    f"{connection.local} to {connection.remote}"
                    f" (process: {connection.process})."
                ),
                is_observation=True,
            )
        )

    for interface in snapshot.interfaces:
        error_count = (
            interface.rx_errors
            + interface.tx_errors
            + interface.rx_dropped
            + interface.tx_dropped
        )

        if error_count:
            findings.append(
                Finding(
                    category="network",
                    severity="low",
                    title="Network interface errors detected",
                    detail=(
                        f"Interface '{interface.name}' reports "
                        f"{interface.rx_errors} RX errors, "
                        f"{interface.tx_errors} TX errors, "
                        f"{interface.rx_dropped} RX drops, and "
                        f"{interface.tx_dropped} TX drops."
                    ),
                )
            )

    return findings
