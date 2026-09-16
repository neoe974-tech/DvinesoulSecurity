from dataclasses import asdict

from dvinesoul_security.report.models import InspectionReport
from dvinesoul_security.security.file_analysis import analyze_file


def add_file_analysis(report: InspectionReport) -> None:
    result = analyze_file(report.path)
    report.add_section("file", asdict(result))
