from dvinesoul_security.report.models import InspectionReport
from dvinesoul_security.report.text import report_to_text


def test_report_to_text_renders_file_analysis():
    report = InspectionReport("/tmp/test.txt")

    report.add_section(
        "file",
        {
            "path": "/tmp/test.txt",
            "size": 24,
            "mode": "-rw-r--r--",
            "owner_uid": 1000,
            "group_gid": 1000,
            "file_type": "ASCII text",
            "sha256": "abc123",
            "executable": False,
        },
    )

    output = report_to_text(report)

    assert "DVINESOUL SECURITY INSPECT" in output
    assert "=== File Analysis ===" in output
    assert "Path       : /tmp/test.txt" in output
    assert "SHA-256    : abc123" in output
    assert "Executable : no" in output
