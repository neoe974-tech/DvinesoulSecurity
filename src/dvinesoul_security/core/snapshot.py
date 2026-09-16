from __future__ import annotations

from dataclasses import dataclass

from dvinesoul_security.core.processes import ProcessInfo, get_processes
from dvinesoul_security.core.services import ServiceInfo, get_services
from dvinesoul_security.core.system import get_system_info
from dvinesoul_security.network.connections import (
    ConnectionInfo,
    get_connections,
)
from dvinesoul_security.network.interfaces import (
    InterfaceInfo,
    get_interfaces,
)


@dataclass
class SystemSnapshot:
    system: dict[str, str]
    processes: list[ProcessInfo]
    services: list[ServiceInfo]
    interfaces: list[InterfaceInfo]
    connections: list[ConnectionInfo]


def collect_system_snapshot() -> SystemSnapshot:
    return SystemSnapshot(
        system=get_system_info(),
        processes=get_processes(),
        services=get_services(),
        interfaces=get_interfaces(),
        connections=get_connections(),
    )
