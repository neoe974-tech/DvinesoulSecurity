from __future__ import annotations

import subprocess
from pathlib import Path


def extract_strings(
    path: str | Path,
    minimum_length: int = 6,
    limit: int = 100,
) -> list[str]:
    file_path = Path(path).resolve()

    result = subprocess.run(
        ["strings", "-n", str(minimum_length), str(file_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return []

    return result.stdout.splitlines()[:limit]


def print_strings(
    path: str | Path,
    minimum_length: int = 6,
    limit: int = 30,
) -> None:
    print("=== Dvinesoul Security / Strings Analysis ===")
    print()
    print(f"File : {Path(path).resolve()}")
    print()

    try:
        strings = extract_strings(path, minimum_length, limit)
    except OSError as error:
        print(f"Error: {error}")
        return

    if not strings:
        print("No strings found.")
        return

    print(f"Showing {len(strings)} strings:")
    print()

    for index, value in enumerate(strings, start=1):
        print(f"{index:>3}: {value}")
