from pathlib import Path

from dvinesoul_security.report.inspection import inspect_file


def test_inspect_file_collects_file_and_strings(tmp_path: Path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("DVINESOUL_TEST_STRING\n")

    report = inspect_file(str(test_file))

    assert report.path == str(test_file.resolve())
    assert "file" in report.sections
    assert "elf" in report.sections
    assert "strings" in report.sections
    assert "assessment" in report.sections

    assert report.sections["file"]["size"] == len("DVINESOUL_TEST_STRING\n")
    assert report.sections["file"]["sha256"]
    assert report.sections["elf"]["is_elf"] is False
    assert "DVINESOUL_TEST_STRING" in report.sections["strings"]["values"]

    assessment = report.sections["assessment"]

    assert assessment["finding_count"] == 0
    assert assessment["risk_score"] == 0


def test_inspect_file_includes_assessment(tmp_path: Path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("API_KEY=example-secret\n")

    report = inspect_file(str(test_file))

    assert "assessment" in report.sections

    assessment = report.sections["assessment"]

    assert assessment["finding_count"] == 1
    assert assessment["risk_score"] == 3
    assert assessment["findings"][0]["category"] == "strings"
    assert assessment["findings"][0]["severity"] == "medium"


def test_inspect_file_includes_yara_assessment(tmp_path: Path):
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

    assert "yara" in report.sections

    yara = report.sections["yara"]

    assert yara["match_count"] == 1
    assert yara["matches"][0]["rule"] == "DvinesoulTestRule"

    assessment = report.sections["assessment"]

    assert assessment["finding_count"] == 1
    assert assessment["risk_score"] == 6
    assert assessment["findings"][0]["category"] == "yara"
    assert assessment["findings"][0]["severity"] == "high"
