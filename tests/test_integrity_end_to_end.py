from pathlib import Path

from dvinesoul_security.core.files import inventory_directory
from dvinesoul_security.security.detections.integrity import (
    detect_integrity_changes,
)
from dvinesoul_security.security.integrity import (
    load_baseline,
    save_baseline,
)


def test_real_file_change_is_detected(tmp_path: Path):
    target = tmp_path / "example.txt"
    baseline_path = tmp_path.parent / "baseline.json"

    target.write_text("original content")

    baseline_files = inventory_directory(tmp_path)

    save_baseline(baseline_files, baseline_path)

    target.write_text("changed content")

    current_files = inventory_directory(tmp_path)

    loaded_baseline = load_baseline(baseline_path)

    findings = detect_integrity_changes(
        loaded_baseline,
        current_files,
    )

    changed = [
        finding
        for finding in findings
        if finding.title == "File integrity change detected"
    ]

    assert len(changed) == 1
    assert str(target) in changed[0].detail
