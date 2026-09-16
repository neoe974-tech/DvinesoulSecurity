from dataclasses import asdict

from dvinesoul_security.binary.elf import analyze_elf
from dvinesoul_security.report.models import InspectionReport


def add_elf_analysis(report: InspectionReport) -> None:
    result = analyze_elf(report.path)
    report.add_section("elf", asdict(result))
