from pathlib import Path

from dvinesoul_security.core.files import FileInfo
from dvinesoul_security.security.integrity import (
    load_baseline,
    save_baseline,
)


def test_baseline_round_trip(tmp_path: Path):
    baseline_path = tmp_path / "baseline.json"

    files = [
        FileInfo(
            path="/etc/example.conf",
            file_type="file",
            size=20,
            modified_ns=123456,
            sha256="a" * 64,
        )
    ]

    save_baseline(files, baseline_path)

    loaded = load_baseline(baseline_path)

    assert loaded == files
