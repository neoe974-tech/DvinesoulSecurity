from __future__ import annotations

from dvinesoul_security.core.snapshot import SystemSnapshot


def snapshot_to_text(snapshot: SystemSnapshot) -> str:
    lines: list[str] = []

    lines.append("=" * 60)
    lines.append("             DVINESOUL SECURITY SYSTEM")
    lines.append("=" * 60)
    lines.append("")

    system = snapshot.system

    lines.extend(
        [
            "=== SYSTEM ===",
            "",
            f"Hostname           : {system.get('hostname', 'Unknown')}",
            f"OS                 : {system.get('os', 'Unknown')}",
            f"Distribution       : {system.get('distribution', 'Unknown')}",
            f"Kernel             : {system.get('kernel', 'Unknown')}",
            f"Architecture       : {system.get('architecture', 'Unknown')}",
            f"Python             : {system.get('python', 'Unknown')}",
            "",
            "=== CPU ===",
            "",
            f"CPU                : {system.get('cpu', 'Unknown')}",
            f"CPU count          : {system.get('cpu_count', 'Unknown')}",
            f"Uptime             : {system.get('uptime', 'Unknown')}",
            "",
            "=== MEMORY ===",
            "",
            f"RAM total          : {system.get('ram_total', 'Unknown')}",
            f"RAM available      : {system.get('ram_available', 'Unknown')}",
            f"Swap total         : {system.get('swap_total', 'Unknown')}",
            f"Swap used          : {system.get('swap_used', 'Unknown')}",
            "",
            "=== STORAGE ===",
            "",
            f"Disk total         : {system.get('disk_total', 'Unknown')}",
            f"Disk used          : {system.get('disk_used', 'Unknown')}",
            f"Disk free          : {system.get('disk_free', 'Unknown')}",
            f"Disk used percent  : {system.get('disk_used_percent', 'Unknown')}",
            "",
        ]
    )

    processes = snapshot.processes

    lines.extend(
        [
            "=== PROCESSES ===",
            "",
            f"Total processes    : {len(processes)}",
            "",
            f"{'PID':>7} "
            f"{'USER':<12} "
            f"{'MEM':>10} "
            f"{'STATE':<18} "
            f"NAME",
            "-" * 75,
        ]
    )

    for process in processes[:15]:
        memory_mb = process.memory_kb / 1024

        lines.append(
            f"{process.pid:>7} "
            f"{process.user:<12.12} "
            f"{memory_mb:>8.1f} MB "
            f"{process.state:<18.18} "
            f"{process.name}"
        )

    lines.append("")

    services = snapshot.services

    running = [
        service
        for service in services
        if service.active == "active" and service.sub == "running"
    ]

    failed = [
        service
        for service in services
        if service.active == "failed"
    ]

    lines.extend(
        [
            "=== SERVICES ===",
            "",
            f"Total services     : {len(services)}",
            f"Running            : {len(running)}",
            f"Failed             : {len(failed)}",
            "",
        ]
    )

    if failed:
        lines.append("[FAILED]")

        for service in failed:
            lines.append(
                f"  {service.name:<45} "
                f"{service.description}"
            )

        lines.append("")

    lines.extend(
        [
            "[RUNNING]",
            f"{'SERVICE':<45} {'STATE':<12} DESCRIPTION",
            "-" * 100,
        ]
    )

    for service in running[:30]:
        lines.append(
            f"{service.name:<45} "
            f"{service.sub:<12} "
            f"{service.description}"
        )

    lines.append("")

    interfaces = snapshot.interfaces

    lines.extend(
        [
            "=== NETWORK INTERFACES ===",
            "",
            f"Total interfaces   : {len(interfaces)}",
            "",
        ]
    )

    for interface in interfaces:
        rx_mib = interface.rx_bytes / (1024 * 1024)
        tx_mib = interface.tx_bytes / (1024 * 1024)

        lines.extend(
            [
                f"[{interface.name}]",
                f"State              : {interface.state}",
                f"MAC                : {interface.mac}",
                f"IPv4               : {interface.ipv4 or 'none'}",
                f"IPv6               : {interface.ipv6 or 'none'}",
                f"RX                 : {rx_mib:.2f} MiB",
                f"TX                 : {tx_mib:.2f} MiB",
                f"RX packets         : {interface.rx_packets}",
                f"TX packets         : {interface.tx_packets}",
                f"RX errors          : {interface.rx_errors}",
                f"TX errors          : {interface.tx_errors}",
                f"RX dropped         : {interface.rx_dropped}",
                f"TX dropped         : {interface.tx_dropped}",
                "",
            ]
        )

    connections = snapshot.connections

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

    lines.extend(
        [
            "=== NETWORK CONNECTIONS ===",
            "",
            f"Total sockets      : {len(connections)}",
            f"Established        : {len(established)}",
            f"Listening          : {len(listening)}",
            f"UDP/unconnected    : {len(udp_unconnected)}",
            "",
            f"{'PROTO':<6} "
            f"{'STATE':<12} "
            f"{'LOCAL':<28} "
            f"{'REMOTE':<28} "
            f"PROCESS",
            "-" * 110,
        ]
    )

    for connection in connections[:40]:
        lines.append(
            f"{connection.protocol:<6} "
            f"{connection.state:<12} "
            f"{connection.local:<28} "
            f"{connection.remote:<28} "
            f"{connection.process}"
        )

    lines.append("")

    return "\n".join(lines)
