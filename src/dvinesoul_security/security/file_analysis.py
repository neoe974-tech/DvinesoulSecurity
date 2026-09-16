from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from dvinesoul_security.security.hashes import hash_file


@dataclass
class FileAnalysis:
    path: str
    size: int
    mode: str
    owner_uid: int
    group_gid: int
    file_type: str
    sha256: str
    executable: bool


def _file_type(path: Path) -> str:
    try:
        result = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip() or "Unknown"
    except OSError:
        return "Unknown"


def analyze_file(path: str | Path) -> FileAnalysis:
    file_path = Path(path).resolve()
    metadata = file_path.stat()
    hashes = hash_file(file_path)

    return FileAnalysis(
        path=str(file_path),
        size=metadata.st_size,
        mode=stat.filemode(metadata.st_mode),
        owner_uid=metadata.st_uid,
        group_gid=metadata.st_gid,
        file_type=_file_type(file_path),
        sha256=hashes.sha256,
        executable=bool(metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
    )


def print_file_analysis(path: str | Path) -> None:
    print("=== Dvinesoul Security / File Analysis ===")
    print()

    try:
        result = analyze_file(path)
    except (OSError, PermissionError) as error:
        print(f"File : {path}")
        print(f"Error: {error}")
        return

    print(f"Path       : {result.path}")
    print(f"Size       : {result.size} bytes")
    print(f"Mode       : {result.mode}")
    print(f"Owner UID  : {result.owner_uid}")
    print(f"Group GID  : {result.group_gid}")
    print(f"Type       : {result.file_type}")
    print(f"SHA-256    : {result.sha256}")
    print(f"Executable : {'yes' if result.executable else 'no'}")
