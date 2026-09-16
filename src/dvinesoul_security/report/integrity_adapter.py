from dataclasses import asdict

from dvinesoul_security.report.models import InspectionReport
from dvinesoul_security.security.integrity import check_integrity


def add_integrity_analysis(
    report: InspectionReport,
    baseline_file: str,
) -> None:
    result = check_integrity(report.path, baseline_file)

    report.add_section(
        "integrity",
        asdict(result),
    )
