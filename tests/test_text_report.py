from pathlib import Path

from dvinesoul_security.report.inspection import inspect_file
from dvinesoul_security.report.text import report_to_text
from dvinesoul_security.security.integrity import create_baseline


def test_text_report_includes_assessment(tmp_path: Path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("API_KEY=example-secret\n")

    report = inspect_file(str(test_file))
    text = report_to_text(report)

    assert "=== ASSESSMENT ===" in text
    assert "Risk score : 3" in text
    assert "Findings   : 1" in text
    assert "[MEDIUM] [strings] Potentially sensitive string detected" in text
    assert "API_KEY=example-secret" in text


def test_text_report_includes_yara(tmp_path: Path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("DVINESOUL_YARA_TEST\n")

    yara_file = tmp_path / "test.yar"
    yara_file.write_text(
        """
rule DvinesoulTestRule
{
    strings:
        $marker = "DVINESOUL_YARA_TEST"

    condition:
        $marker
}
"""
    )

    report = inspect_file(
        str(test_file),
        yara_rules=str(yara_file),
    )

    text = report_to_text(report)

    assert "=== YARA ===" in text
    assert "Matches : 1" in text
    assert "DvinesoulTestRule" in text
    assert "Risk score : 6" in text
    assert "[HIGH] [yara] YARA rule matched" in text


def test_text_report_includes_integrity_mismatch(tmp_path: Path):
    test_file = tmp_path / "sample.txt"
    baseline_file = tmp_path / "sample.sha256"

    test_file.write_text("ORIGINAL_CONTENT\n")
    create_baseline(test_file, baseline_file)

    test_file.write_text("MODIFIED_CONTENT\n")

    report = inspect_file(
        str(test_file),
        baseline=str(baseline_file),
    )

    text = report_to_text(report)

    assert "=== INTEGRITY ===" in text
    assert "Status   : MODIFIED" in text
    assert "Expected :" in text
    assert "Actual   :" in text
    assert "Risk score : 6" in text
    assert "[HIGH] [integrity] Integrity mismatch detected" in text
