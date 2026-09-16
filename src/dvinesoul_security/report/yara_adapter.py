from dataclasses import asdict

from dvinesoul_security.report.models import InspectionReport
from dvinesoul_security.security.yara_scan import scan_file


def add_yara_analysis(
    report: InspectionReport,
    rule_file: str,
) -> None:
    matches = scan_file(rule_file, report.path)

    report.add_section(
        "yara",
        {
            "rules": rule_file,
            "match_count": len(matches),
            "matches": [asdict(match) for match in matches],
        },
    )
