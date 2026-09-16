from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProcessInfo:
    pid: int
    name: str
    state: str
    user: str
    memory_kb: int
    executable: str
    command: str


def _username_from_status(status: Path) -> str:
    try:
        for line in status.read_text().splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])

                try:
                    import pwd
                    return pwd.getpwuid(uid).pw_name
                except (KeyError, ImportError):
                    return str(uid)

    except (OSError, ValueError):
        pass

    return "unknown"


def _process_info(pid: int) -> ProcessInfo | None:
    proc = Path("/proc") / str(pid)

    try:
        status = proc / "status"

        name = "unknown"
        state = "unknown"
        memory_kb = 0

        for line in status.read_text().splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()

            elif line.startswith("State:"):
                state = line.split(":", 1)[1].strip()

            elif line.startswith("VmRSS:"):
                memory_kb = int(line.split()[1])

        user = _username_from_status(status)

        try:
            executable = os.readlink(proc / "exe")
        except OSError:
            executable = "unavailable"

        try:
            command = (proc / "cmdline").read_bytes().replace(
                b"\x00", b" "
            ).decode(errors="replace").strip()

        except OSError:
            command = ""

        return ProcessInfo(
            pid=pid,
            name=name,
            state=state,
            user=user,
            memory_kb=memory_kb,
            executable=executable,
            command=command,
        )

    except (OSError, ValueError):
        return None


def get_processes() -> list[ProcessInfo]:
    processes: list[ProcessInfo] = []

    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue

        process = _process_info(int(entry.name))

        if process is not None:
            processes.append(process)

    return sorted(processes, key=lambda p: p.memory_kb, reverse=True)


def print_processes(limit: int = 15) -> None:
    processes = get_processes()

    print("=== Dvinesoul Security / Processes ===")
    print()
    print(
        f"{'PID':>7} "
        f"{'USER':<12} "
        f"{'MEM':>10} "
        f"{'STATE':<18} "
        f"{'NAME'}"
    )
    print("-" * 75)

    for process in processes[:limit]:
        memory_mb = process.memory_kb / 1024

        print(
            f"{process.pid:>7} "
            f"{process.user:<12.12} "
            f"{memory_mb:>8.1f} MB "
            f"{process.state:<18.18} "
            f"{process.name}"
        )
