from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class YaraMatch:
    rule: str
    file: str


def scan_file(rule_file: str | Path, target_file: str | Path) -> list[YaraMatch]:
    rule_path = Path(rule_file)
    target_path = Path(target_file)

    result = subprocess.run(
        ["yara", str(rule_path), str(target_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(
            result.stderr.strip()
            or f"YARA exited with code {result.returncode}"
        )

    matches: list[YaraMatch] = []

    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue

        matches.append(
            YaraMatch(
                rule=parts[0],
                file=parts[1],
            )
        )

    return matches


def print_yara_scan(rule_file: str | Path, target_file: str | Path) -> None:
    print("=== Dvinesoul Security / YARA Scan ===")
    print()
    print(f"Rules : {Path(rule_file).resolve()}")
    print(f"Target: {Path(target_file).resolve()}")
    print()

    try:
        matches = scan_file(rule_file, target_file)
    except (OSError, RuntimeError) as error:
        print(f"Error : {error}")
        return

    if not matches:
        print("Result: No YARA matches")
        return

    print(f"Matches: {len(matches)}")
    print()

    for match in matches:
        print(f"  {match.rule:<30} {match.file}")
