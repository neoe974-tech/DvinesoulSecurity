from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileInfo:
    path: str
    file_type: str
    size: int
    modified_ns: int
    sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def inspect_file(path: str | Path) -> FileInfo | None:
    target = Path(path)

    try:
        stat = target.stat()

        if target.is_symlink():
            file_type = "symlink"
        elif target.is_file():
            file_type = "file"
        elif target.is_dir():
            file_type = "directory"
        else:
            file_type = "other"

        digest = _sha256(target) if target.is_file() else ""

        return FileInfo(
            path=str(target),
            file_type=file_type,
            size=stat.st_size,
            modified_ns=stat.st_mtime_ns,
            sha256=digest,
        )

    except (OSError, PermissionError):
        return None


def inventory_directory(
    path: str | Path,
    *,
    max_files: int = 1000,
) -> list[FileInfo]:
    root = Path(path)
    results: list[FileInfo] = []

    try:
        entries = root.rglob("*")
    except OSError:
        return results

    for entry in entries:
        if len(results) >= max_files:
            break

        if not entry.is_file():
            continue

        info = inspect_file(entry)

        if info is not None:
            results.append(info)

    return sorted(results, key=lambda item: item.path)
