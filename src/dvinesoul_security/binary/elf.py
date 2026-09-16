from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ELFAnalysis:
    path: str
    is_elf: bool
    file_type: str
    architecture: str
    entry_point: str


def _run_readelf(path: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["readelf", *arguments, str(path)],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return ""

    return result.stdout


def analyze_elf(path: str | Path) -> ELFAnalysis:
    file_path = Path(path).resolve()

    file_result = subprocess.run(
        ["file", "-b", str(file_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    file_type = file_result.stdout.strip()

    is_elf = "ELF" in file_type

    architecture = "Unknown"
    entry_point = "Unknown"

    if is_elf:
        header = _run_readelf(file_path, "-h")

        for line in header.splitlines():
            line = line.strip()

            if line.startswith("Class:"):
                architecture = line.split(":", 1)[1].strip()

            elif line.startswith("Entry point address:"):
                entry_point = line.split(":", 1)[1].strip()

    return ELFAnalysis(
        path=str(file_path),
        is_elf=is_elf,
        file_type=file_type,
        architecture=architecture,
        entry_point=entry_point,
    )


def print_elf_analysis(path: str | Path) -> None:
    print("=== Dvinesoul Security / ELF Analysis ===")
    print()

    try:
        result = analyze_elf(path)
    except (OSError, PermissionError) as error:
        print(f"Error: {error}")
        return

    print(f"Path        : {result.path}")
    print(f"ELF         : {'yes' if result.is_elf else 'no'}")
    print(f"File type   : {result.file_type}")

    if result.is_elf:
        print(f"Class       : {result.architecture}")
        print(f"Entry point : {result.entry_point}")
