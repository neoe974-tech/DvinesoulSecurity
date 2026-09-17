from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from dvinesoul_security.core.files import FileInfo


@dataclass
class IntegrityResult:
    path: str
    status: str
    expected_sha256: str | None
    actual_sha256: str | None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def create_baseline(path: str | Path, baseline_file: str | Path) -> str:
    target = Path(path).resolve()
    baseline = Path(baseline_file).resolve()

    digest = _sha256(target)

    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_text(digest + "\n")

    return digest


def check_integrity(
    path: str | Path,
    baseline_file: str | Path,
    actual_sha256: str | None = None,
) -> IntegrityResult:
    target = Path(path).resolve()
    baseline = Path(baseline_file).resolve()

    if not target.exists():
        return IntegrityResult(
            path=str(target),
            status="MISSING",
            expected_sha256=None,
            actual_sha256=None,
        )

    try:
        expected = baseline.read_text().strip()
    except OSError:
        expected = None

    if actual_sha256 is None:
        actual_sha256 = _sha256(target)

    actual = actual_sha256

    if expected is None:
        status = "NO_BASELINE"
    elif actual == expected:
        status = "OK"
    else:
        status = "MODIFIED"

    return IntegrityResult(
        path=str(target),
        status=status,
        expected_sha256=expected,
        actual_sha256=actual,
    )


def print_integrity_check(
    path: str | Path,
    baseline_file: str | Path,
) -> None:
    print("=== Dvinesoul Security / Integrity Check ===")
    print()

    try:
        result = check_integrity(path, baseline_file)
    except (OSError, PermissionError) as error:
        print(f"Error: {error}")
        return

    print(f"File     : {result.path}")
    print(f"Status   : {result.status}")

    if result.expected_sha256:
        print(f"Expected : {result.expected_sha256}")

    if result.actual_sha256:
        print(f"Actual   : {result.actual_sha256}")


def baseline_to_dict(files: list[FileInfo]) -> list[dict]:
    return [
        {
            "path": item.path,
            "file_type": item.file_type,
            "size": item.size,
            "modified_ns": item.modified_ns,
            "sha256": item.sha256,
        }
        for item in files
    ]


def save_baseline(
    files: list[FileInfo],
    path: str | Path,
) -> None:
    target = Path(path)

    target.write_text(
        json.dumps(
            baseline_to_dict(files),
            indent=2,
            sort_keys=True,
        )
    )


def load_baseline(
    path: str | Path,
) -> list[FileInfo]:
    target = Path(path)

    data = json.loads(target.read_text())

    return [
        FileInfo(
            path=item["path"],
            file_type=item["file_type"],
            size=item["size"],
            modified_ns=item["modified_ns"],
            sha256=item["sha256"],
        )
        for item in data
    ]
