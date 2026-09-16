from dataclasses import asdict

from dvinesoul_security.report.models import InspectionReport
from dvinesoul_security.security.integrity import check_integrity


def add_integrity_analysis(
    report: InspectionReport,
    baseline_file: str,
) -> None:
    file_section = report.sections.get("file", {})
    actual_sha256 = file_section.get("sha256")

    result = check_integrity(
        report.path,
        baseline_file,
        actual_sha256=actual_sha256,
    )

    report.add_section(
        "integrity",
        asdict(result),
    )
