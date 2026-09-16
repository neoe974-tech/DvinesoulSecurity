import argparse

from dvinesoul_security.core.snapshot import collect_system_snapshot
from dvinesoul_security.core.snapshot_text import snapshot_to_text
from dvinesoul_security.report.inspection import inspect_file
from dvinesoul_security.report.json import report_to_json
from dvinesoul_security.report.text import report_to_text


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

    subparsers.add_parser(
        "system",
        help="Show a read-only system snapshot.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "inspect":
        report = inspect_file(
            args.path,
            yara_rules=args.yara_rules,
            baseline=args.baseline,
            strings_limit=args.strings_limit,
        )

        if args.json:
            print(report_to_json(report))
        else:
            print(report_to_text(report))

        return 0

    if args.command == "system":
        snapshot = collect_system_snapshot()
        print(snapshot_to_text(snapshot))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
