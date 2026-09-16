from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class ServiceInfo:
    name: str
    load: str
    active: str
    sub: str
    description: str


def get_services() -> list[ServiceInfo]:
    command = [
        "systemctl",
        "list-units",
        "--type=service",
        "--all",
        "--no-legend",
        "--no-pager",
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

    services: list[ServiceInfo] = []

    for line in result.stdout.splitlines():
        parts = line.split(None, 4)

        if len(parts) < 5:
            continue

        name, load, active, sub, description = parts

        services.append(
            ServiceInfo(
                name=name,
                load=load,
                active=active,
                sub=sub,
                description=description,
            )
        )

    return services


def print_services(limit: int = 30) -> None:
    services = get_services()

    running = [
        s for s in services
        if s.active == "active" and s.sub == "running"
    ]

    exited = [
        s for s in services
        if s.active == "active" and s.sub == "exited"
    ]

    failed = [
        s for s in services
        if s.active == "failed"
    ]

    inactive = [
        s for s in services
        if s.active == "inactive"
    ]

    print("=== Dvinesoul Security / Services ===")
    print()
    print(f"Total services : {len(services)}")
    print(f"Running        : {len(running)}")
    print(f"Exited         : {len(exited)}")
    print(f"Failed         : {len(failed)}")
    print(f"Inactive       : {len(inactive)}")
    print()

    if failed:
        print("[FAILED]")
        for service in failed:
            print(
                f"  {service.name:<45} "
                f"{service.description}"
            )
        print()

    print("[RUNNING]")
    print(f"{'SERVICE':<45} {'STATE':<12} DESCRIPTION")
    print("-" * 100)

    for service in running[:limit]:
        print(
            f"{service.name:<45} "
            f"{service.sub:<12} "
            f"{service.description}"
        )

    if exited:
        print()
        print("[EXITED / COMPLETED]")
        for service in exited[:10]:
            print(
                f"  {service.name:<45} "
                f"{service.description}"
            )
