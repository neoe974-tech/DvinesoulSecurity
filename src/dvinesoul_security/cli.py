import argparse

from dvinesoul_security.report.inspection import inspect_file
from dvinesoul_security.report.json import report_to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dvinesoul-security",
        description="DvinesoulSecurity inspection and analysis tool.",
    )

    subparsers = parser.add_subparsers(dest="command")

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect a file.",
    )

    inspect_parser.add_argument(
        "path",
        help="Path to the file to inspect.",
    )

    inspect_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the complete inspection report as JSON.",
    )

    inspect_parser.add_argument(
        "--strings-limit",
        type=int,
        default=100,
        help="Maximum number of strings to extract.",
    )

    inspect_parser.add_argument(
        "--yara",
        dest="yara_rules",
        help="Path to a YARA rule file.",
    )

    inspect_parser.add_argument(
        "--baseline",
        help="Path to an integrity baseline file.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command != "inspect":
        parser.print_help()
        return 0

    report = inspect_file(
        args.path,
        yara_rules=args.yara_rules,
        baseline=args.baseline,
        strings_limit=args.strings_limit,
    )

    if args.json:
        print(report_to_json(report))
        return 0

    assessment = report.sections.get("assessment", {})
    findings = assessment.get("findings", [])

    print(f"File: {report.path}")
    print(f"Risk score: {assessment.get('risk_score', 0)}")
    print(f"Findings: {assessment.get('finding_count', 0)}")

    if findings:
        print("\nFindings:")
        for finding in findings:
            print(
                f"- [{finding['severity'].upper()}] "
                f"{finding['title']}: {finding['detail']}"
            )
    else:
        print("\nNo assessment findings.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
