from __future__ import annotations

import os
import platform
import re
import shutil
import time
from pathlib import Path


def _cpu_model() -> str:
    try:
        text = Path("/proc/cpuinfo").read_text()
        match = re.search(r"^model name\s*:\s*(.+)$", text, re.MULTILINE)
        return match.group(1).strip() if match else "Unknown"
    except OSError:
        return "Unknown"


def _memory_info() -> dict[str, str]:
    try:
        lines = Path("/proc/meminfo").read_text().splitlines()
        values: dict[str, int] = {}

        for line in lines:
            key, value = line.split(":", 1)
            parts = value.strip().split()
            if parts:
                values[key] = int(parts[0]) * 1024

        def gib(value: int) -> str:
            return f"{value / (1024 ** 3):.1f} GiB"

        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        swap_total = values.get("SwapTotal", 0)
        swap_free = values.get("SwapFree", 0)

        return {
            "ram_total": gib(total),
            "ram_available": gib(available),
            "swap_total": gib(swap_total),
            "swap_used": gib(swap_total - swap_free),
        }

    except (OSError, ValueError):
        return {
            "ram_total": "Unknown",
            "ram_available": "Unknown",
            "swap_total": "Unknown",
            "swap_used": "Unknown",
        }


def _uptime() -> str:
    try:
        seconds = float(Path("/proc/uptime").read_text().split()[0])

        days, remainder = divmod(int(seconds), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, _ = divmod(remainder, 60)

        parts = []

        if days:
            parts.append(f"{days}d")

        if hours:
            parts.append(f"{hours}h")

        if minutes or not parts:
            parts.append(f"{minutes}m")

        return " ".join(parts)

    except (OSError, ValueError, IndexError):
        return "Unknown"


def _disk_info() -> dict[str, str]:
    total, used, free = shutil.disk_usage("/")

    def gib(value: int) -> str:
        return f"{value / (1024 ** 3):.1f} GiB"

    return {
        "disk_total": gib(total),
        "disk_used": gib(used),
        "disk_free": gib(free),
        "disk_used_percent": f"{(used / total) * 100:.1f}%",
    }


def get_system_info() -> dict[str, str]:
    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "distribution": "Kali Linux",
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": _cpu_model(),
        "cpu_count": str(os.cpu_count() or 0),
        "uptime": _uptime(),
        "python": platform.python_version(),
    }

    info.update(_memory_info())
    info.update(_disk_info())

    return info


def print_system_info() -> None:
    info = get_system_info()

    print("=== Dvinesoul Security / System ===")
    print()

    sections = {
        "SYSTEM": [
            "hostname",
            "os",
            "distribution",
            "kernel",
            "architecture",
            "python",
        ],
        "CPU": [
            "cpu",
            "cpu_count",
            "uptime",
        ],
        "MEMORY": [
            "ram_total",
            "ram_available",
            "swap_total",
            "swap_used",
        ],
        "STORAGE": [
            "disk_total",
            "disk_used",
            "disk_free",
            "disk_used_percent",
        ],
    }

    for section, keys in sections.items():
        print(f"[{section}]")

        for key in keys:
            label = key.replace("_", " ").title()
            print(f"{label:18}: {info[key]}")

        print()
