from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FileHashes:
    path: str
    size: int
    md5: str
    sha1: str
    sha256: str


def hash_file(
    path: str | Path,
    chunk_size: int = 1024 * 1024,
) -> FileHashes:
    file_path = Path(path)

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while True:
            chunk = file.read(chunk_size)

            if not chunk:
                break

            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return FileHashes(
        path=str(file_path.resolve()),
        size=file_path.stat().st_size,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )


def print_file_hashes(path: str | Path) -> None:
    try:
        result = hash_file(path)
    except (OSError, PermissionError) as error:
        print("=== Dvinesoul Security / File Hash ===")
        print()
        print(f"File   : {path}")
        print(f"Error  : {error}")
        return

    print("=== Dvinesoul Security / File Hash ===")
    print()
    print(f"File   : {result.path}")
    print(f"Size   : {result.size} bytes")
    print(f"MD5    : {result.md5}")
    print(f"SHA-1  : {result.sha1}")
    print(f"SHA-256: {result.sha256}")
