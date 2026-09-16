from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class TraceResult:
    command: list[str]
    return_code: int
    output: list[str]


def trace_command(
    command: list[str],
    limit: int = 100,
) -> TraceResult:
    if not command:
        raise ValueError("Command cannot be empty")

    result = subprocess.run(
        ["strace", "-f", "-e", "trace=file,process,network", *command],
        capture_output=True,
        text=True,
        check=False,
    )

    output = (result.stderr + result.stdout).splitlines()

    return TraceResult(
        command=command,
        return_code=result.returncode,
        output=output[:limit],
    )


def print_trace(
    command: list[str],
    limit: int = 40,
) -> None:
    print("=== Dvinesoul Security / Process Trace ===")
    print()
    print(f"Command    : {' '.join(command)}")

    try:
        result = trace_command(command, limit)
    except (OSError, ValueError) as error:
        print(f"Error      : {error}")
        return

    print(f"Return code: {result.return_code}")
    print()
    print(f"Showing {len(result.output)} trace lines:")
    print()

    for line in result.output:
        print(line)
