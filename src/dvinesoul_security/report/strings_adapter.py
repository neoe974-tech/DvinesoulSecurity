from dvinesoul_security.binary.strings import extract_strings
from dvinesoul_security.report.models import InspectionReport


def add_strings_analysis(
    report: InspectionReport,
    minimum_length: int = 6,
    limit: int = 100,
) -> None:
    strings = extract_strings(
        report.path,
        minimum_length=minimum_length,
        limit=limit,
    )

    report.add_section(
        "strings",
        {
            "count": len(strings),
            "values": strings,
        },
    )
