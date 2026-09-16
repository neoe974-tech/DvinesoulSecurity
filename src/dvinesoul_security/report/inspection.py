from dvinesoul_security.report.elf_adapter import add_elf_analysis
from dvinesoul_security.report.file_adapter import add_file_analysis
from dvinesoul_security.report.integrity_adapter import add_integrity_analysis
from dvinesoul_security.report.models import InspectionReport
from dvinesoul_security.report.strings_adapter import add_strings_analysis
from dvinesoul_security.report.yara_adapter import add_yara_analysis
from dvinesoul_security.security.assessment import assess_report


def inspect_file(
    path: str,
    *,
    yara_rules: str | None = None,
    baseline: str | None = None,
    strings_limit: int = 100,
) -> InspectionReport:
    report = InspectionReport(path)

    add_file_analysis(report)
    add_elf_analysis(report)
    add_strings_analysis(report, limit=strings_limit)

    if yara_rules:
        add_yara_analysis(report, yara_rules)

    if baseline:
        add_integrity_analysis(report, baseline)

    findings = assess_report(report)

    report.add_section(
        "assessment",
        {
            "finding_count": len(findings),
            "findings": [
                {
                    "category": finding.category,
                    "severity": finding.severity,
                    "title": finding.title,
                    "detail": finding.detail,
                }
                for finding in findings
            ],
        },
    )

    return report
