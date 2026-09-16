from __future__ import annotations

import argparse

from dvinesoul_security.binary.elf import print_elf_analysis
from dvinesoul_security.binary.strings import print_strings
from dvinesoul_security.binary.tracing import print_trace
from dvinesoul_security.core.processes import print_processes
from dvinesoul_security.core.services import print_services
from dvinesoul_security.core.system import print_system_info
from dvinesoul_security.network.connections import print_connections
from dvinesoul_security.network.interfaces import print_interfaces
from dvinesoul_security.security.file_analysis import print_file_analysis
from dvinesoul_security.security.hashes import print_file_hashes
from dvinesoul_security.security.integrity import print_integrity_check
from dvinesoul_security.security.yara_scan import print_yara_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dvinesoul-security",
        description="Dvinesoul Security defensive analysis toolkit",
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("system", help="Show system information")
    subparsers.add_parser("processes", help="Show running processes")
    subparsers.add_parser("services", help="Show system services")
    subparsers.add_parser(
        "network",
        help="Show network interfaces and connections",
    )

    hash_parser = subparsers.add_parser(
        "hash",
        help="Calculate file hashes",
    )
    hash_parser.add_argument("file")

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a file",
    )
    analyze_parser.add_argument("file")

    yara_parser = subparsers.add_parser(
        "yara",
        help="Scan a file with YARA",
    )
    yara_parser.add_argument("rules")
    yara_parser.add_argument("file")

    integrity_parser = subparsers.add_parser(
        "integrity",
        help="Check file integrity",
    )
    integrity_parser.add_argument("file")
    integrity_parser.add_argument("baseline")

    elf_parser = subparsers.add_parser(
        "elf",
        help="Analyze an ELF file",
    )
    elf_parser.add_argument("file")

    strings_parser = subparsers.add_parser(
        "strings",
        help="Extract strings from a file",
    )
    strings_parser.add_argument("file")

    trace_parser = subparsers.add_parser(
        "trace",
        help="Trace an explicitly supplied command",
    )
    trace_parser.add_argument(
        "trace_command",
        nargs=argparse.REMAINDER,
    )

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Run a combined static file inspection",
    )
    inspect_parser.add_argument("file")
    inspect_parser.add_argument(
        "--yara-rules",
        help="Optional YARA rules file",
    )
    inspect_parser.add_argument(
        "--baseline",
        help="Optional integrity baseline file",
    )

    return parser


def inspect_file(
    file: str,
    yara_rules: str | None = None,
    baseline: str | None = None,
) -> None:
    from dvinesoul_security.report.inspection import inspect_file as build_report

    report = build_report(
        file,
        yara_rules=yara_rules,
        baseline=baseline,
    )

    print("=" * 60)
    print("              DVINESOUL SECURITY INSPECT")
    print("=" * 60)
    print()

    sections = report.sections

    file_result = sections.get("file")
    if file_result:
        print("=== File Analysis ===")
        print()
        print(f"Path       : {file_result['path']}")
        print(f"Size       : {file_result['size']} bytes")
        print(f"Mode       : {file_result['mode']}")
        print(f"Owner UID  : {file_result['owner_uid']}")
        print(f"Group GID  : {file_result['group_gid']}")
        print(f"Type       : {file_result['file_type']}")
        print(f"SHA-256    : {file_result['sha256']}")
        print(f"Executable : {'yes' if file_result['executable'] else 'no'}")
        print()

    elf_result = sections.get("elf")
    if elf_result:
        print("=== ELF ===")
        print()
        print(f"Path        : {elf_result['path']}")
        print(f"ELF         : {'yes' if elf_result['is_elf'] else 'no'}")
        print(f"File type   : {elf_result['file_type']}")
        if elf_result["is_elf"]:
            print(f"Class       : {elf_result['architecture']}")
            print(f"Entry point : {elf_result['entry_point']}")
        print()

    strings_result = sections.get("strings")
    if strings_result:
        print("=== STRINGS ===")
        print()
        values = strings_result["values"]
        print(f"Showing {len(values)} strings:")
        print()
        for index, value in enumerate(values[:30], start=1):
            print(f"{index:>3}: {value}")
        print()

    yara_result = sections.get("yara")
    if yara_result:
        print("=== YARA ===")
        print()
        print(f"Rules   : {yara_result['rules']}")
        print(f"Matches : {yara_result['match_count']}")
        print()
        for match in yara_result["matches"]:
            print(f"  {match['rule']:<30} {match['file']}")
        print()

    integrity_result = sections.get("integrity")
    if integrity_result:
        print("=== INTEGRITY ===")
        print()
        print(f"File     : {integrity_result['path']}")
        print(f"Status   : {integrity_result['status']}")
        if integrity_result["expected_sha256"]:
            print(f"Expected : {integrity_result['expected_sha256']}")
        if integrity_result["actual_sha256"]:
            print(f"Actual   : {integrity_result['actual_sha256']}")
        print()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "system":
        print_system_info()

    elif args.command == "processes":
        print_processes()

    elif args.command == "services":
        print_services()

    elif args.command == "network":
        print_interfaces()
        print_connections()

    elif args.command == "hash":
        print_file_hashes(args.file)

    elif args.command == "analyze":
        print_file_analysis(args.file)

    elif args.command == "yara":
        print_yara_scan(args.rules, args.file)

    elif args.command == "integrity":
        print_integrity_check(args.file, args.baseline)

    elif args.command == "elf":
        print_elf_analysis(args.file)

    elif args.command == "strings":
        print_strings(args.file)

    elif args.command == "trace":
        if not args.trace_command:
            parser.error("trace requires a command")
        print_trace(args.trace_command)

    elif args.command == "inspect":
        inspect_file(
            args.file,
            yara_rules=args.yara_rules,
            baseline=args.baseline,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
