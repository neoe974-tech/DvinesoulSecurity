from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class InterfaceInfo:
    name: str
    state: str
    mac: str
    ipv4: str
    ipv6: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int
    tx_errors: int
    rx_dropped: int
    tx_dropped: int


def _read_stat(interface: str, stat: str) -> int:
    path = Path("/sys/class/net") / interface / "statistics" / stat

    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return 0


def _addresses() -> dict[str, tuple[str, str]]:
    addresses: dict[str, tuple[str, str]] = {}

    try:
        result = subprocess.run(
            ["ip", "-j", "address", "show"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return addresses

    if result.returncode != 0:
        return addresses

    import json

    try:
        interfaces = json.loads(result.stdout)
    except json.JSONDecodeError:
        return addresses

    for interface in interfaces:
        name = interface.get("ifname", "")
        ipv4 = ""
        ipv6 = ""

        for address in interface.get("addr_info", []):
            family = address.get("family")
            local = address.get("local", "")

            try:
                parsed = ipaddress.ip_address(local)
            except ValueError:
                continue

            if family == "inet" and not parsed.is_loopback:
                if not ipv4:
                    ipv4 = local

            elif family == "inet6" and not parsed.is_loopback:
                if not ipv6:
                    ipv6 = local

        addresses[name] = (ipv4, ipv6)

    return addresses


def get_interfaces() -> list[InterfaceInfo]:
    interfaces = []
    addresses = _addresses()

    net_path = Path("/sys/class/net")

    try:
        names = sorted(path.name for path in net_path.iterdir())
    except OSError:
        return []

    for name in names:
        interface_path = net_path / name

        try:
            state = (interface_path / "operstate").read_text().strip()
        except OSError:
            state = "unknown"

        try:
            mac = (interface_path / "address").read_text().strip()
        except OSError:
            mac = "unknown"

        ipv4, ipv6 = addresses.get(name, ("", ""))

        interfaces.append(
            InterfaceInfo(
                name=name,
                state=state,
                mac=mac,
                ipv4=ipv4,
                ipv6=ipv6,
                rx_bytes=_read_stat(name, "rx_bytes"),
                tx_bytes=_read_stat(name, "tx_bytes"),
                rx_packets=_read_stat(name, "rx_packets"),
                tx_packets=_read_stat(name, "tx_packets"),
                rx_errors=_read_stat(name, "rx_errors"),
                tx_errors=_read_stat(name, "tx_errors"),
                rx_dropped=_read_stat(name, "rx_dropped"),
                tx_dropped=_read_stat(name, "tx_dropped"),
            )
        )

    return interfaces


def _mib(value: int) -> float:
    return value / (1024 * 1024)


def print_interfaces() -> None:
    interfaces = get_interfaces()

    print("=== Dvinesoul Security / Network Interfaces ===")
    print()

    for interface in interfaces:
        print(f"[{interface.name}]")
        print(f"State             : {interface.state}")
        print(f"MAC               : {interface.mac}")
        print(f"IPv4              : {interface.ipv4 or 'none'}")
        print(f"IPv6              : {interface.ipv6 or 'none'}")
        print(f"RX                : {_mib(interface.rx_bytes):.2f} MiB")
        print(f"TX                : {_mib(interface.tx_bytes):.2f} MiB")
        print(f"RX packets        : {interface.rx_packets}")
        print(f"TX packets        : {interface.tx_packets}")
        print(f"RX errors         : {interface.rx_errors}")
        print(f"TX errors         : {interface.tx_errors}")
        print(f"RX dropped        : {interface.rx_dropped}")
        print(f"TX dropped        : {interface.tx_dropped}")
        print()
