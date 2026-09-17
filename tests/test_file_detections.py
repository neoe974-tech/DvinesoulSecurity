from dvinesoul_security.security.detections.files import (
    detect_suspicious_file_location,
)


def test_detects_file_in_tmp():
    findings = detect_suspicious_file_location("/tmp/example.bin")

    assert len(findings) == 1
    assert findings[0].category == "file"
    assert findings[0].severity == "medium"
    assert findings[0].is_observation is False


def test_normal_file_location_is_not_flagged():
    findings = detect_suspicious_file_location(
        "/usr/bin/example"
    )

    assert findings == []


def test_var_tmp_is_detected():
    findings = detect_suspicious_file_location(
        "/var/tmp/example.bin"
    )

    assert len(findings) == 1
