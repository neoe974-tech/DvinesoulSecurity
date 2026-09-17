from dvinesoul_security.core.files import FileInfo
from dvinesoul_security.security.detections.integrity import (
    detect_integrity_changes,
)


def file_info(path: str, sha256: str) -> FileInfo:
    return FileInfo(
        path=path,
        file_type="file",
        size=10,
        modified_ns=100,
        sha256=sha256,
    )


def test_detects_new_file():
    baseline = [
        file_info("/etc/example.conf", "a" * 64),
    ]
    current = [
        file_info("/etc/example.conf", "a" * 64),
        file_info("/etc/new.conf", "b" * 64),
    ]

    findings = detect_integrity_changes(baseline, current)

    assert len(findings) == 1
    assert findings[0].title == "New file detected"
    assert findings[0].severity == "medium"


def test_detects_missing_file():
    baseline = [
        file_info("/etc/example.conf", "a" * 64),
    ]

    findings = detect_integrity_changes(
        baseline,
        [],
    )

    assert len(findings) == 1
    assert findings[0].title == "Baseline file missing"
    assert findings[0].severity == "high"


def test_detects_modified_file():
    baseline = [
        file_info("/etc/example.conf", "a" * 64),
    ]
    current = [
        file_info("/etc/example.conf", "b" * 64),
    ]

    findings = detect_integrity_changes(baseline, current)

    assert len(findings) == 1
    assert findings[0].title == "File integrity change detected"
    assert findings[0].severity == "high"


def test_unchanged_file_is_not_flagged():
    baseline = [
        file_info("/etc/example.conf", "a" * 64),
    ]
    current = [
        file_info("/etc/example.conf", "a" * 64),
    ]

    findings = detect_integrity_changes(baseline, current)

    assert findings == []
