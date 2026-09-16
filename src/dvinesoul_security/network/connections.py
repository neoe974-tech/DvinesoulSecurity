from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass


@dataclass
class ConnectionInfo:
    protocol: str
    state: str
    local: str
    remote: str
    process: str


def _clean_process(value: str) -> str:
    value = value.strip()

    match = re.search(r'users:\(\("([^"]+)"', value)
    if match:
        return match.group(1)

    return value or "-"


def get_connections() -> list[ConnectionInfo]:
    command = [
        "ss",
        "-tunap",
        "--numeric",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []

    if result.returncode != 0:
        return []

    connections: list[ConnectionInfo] = []

    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        if line.startswith("Netid"):
            continue

        parts = line.split(None, 6)

        if len(parts) < 5:
            continue

        protocol = parts[0]
        state = parts[1]
        local = parts[4]
        remote = parts[5] if len(parts) > 5 else "-"
        process = _clean_process(parts[6]) if len(parts) > 6 else "-"

        connections.append(
            ConnectionInfo(
                protocol=protocol,
                state=state,
                local=local,
                remote=remote,
                process=process,
            )
        )

    return connections


def print_connections(limit: int = 40) -> None:
    connections = get_connections()

    established = [
        connection
        for connection in connections
        if connection.state == "ESTAB"
    ]

    listening = [
        connection
        for connection in connections
        if connection.state == "LISTEN"
    ]

    udp_unconnected = [
        connection
        for connection in connections
        if connection.protocol == "udp"
        and connection.state == "UNCONN"
    ]

    other = [
        connection
        for connection in connections
        if connection not in established
        and connection not in listening
        and connection not in udp_unconnected
    ]

    print("=== Dvinesoul Security / Network Connections ===")
    print()
    print(f"Total sockets : {len(connections)}")
    print(f"Established   : {len(established)}")
    print(f"Listening     : {len(listening)}")
    print(f"UDP/unconn    : {len(udp_unconnected)}")
    print(f"Other         : {len(other)}")
    print()

    print("[CONNECTIONS]")
    print(
        f"{'PROTO':<6} "
        f"{'STATE':<12} "
        f"{'LOCAL':<28} "
        f"{'REMOTE':<28} "
        f"PROCESS"
    )
    print("-" * 110)

    for connection in connections[:limit]:
        print(
            f"{connection.protocol:<6} "
            f"{connection.state:<12} "
            f"{connection.local:<28} "
            f"{connection.remote:<28} "
            f"{connection.process}"
        )
