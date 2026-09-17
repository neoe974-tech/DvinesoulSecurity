from __future__ import annotations

from dataclasses import dataclass

from dvinesoul_security.core.processes import ProcessInfo, get_processes
from dvinesoul_security.core.files import FileInfo, inventory_directory
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
    files: list[FileInfo]


def collect_system_snapshot(
    *,
    file_root: str | None = None,
    max_files: int = 1000,
) -> SystemSnapshot:
    files = (
        inventory_directory(file_root, max_files=max_files)
        if file_root
        else []
    )

    return SystemSnapshot(
        system=get_system_info(),
        processes=get_processes(),
        services=get_services(),
        interfaces=get_interfaces(),
        connections=get_connections(),
        files=files,
    )
