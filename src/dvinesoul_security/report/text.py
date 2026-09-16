from __future__ import annotations

from dvinesoul_security.report.models import InspectionReport


def report_to_text(report: InspectionReport) -> str:
    lines: list[str] = []

    lines.append("=" * 60)
    lines.append("              DVINESOUL SECURITY INSPECT")
    lines.append("=" * 60)
    lines.append("")

    sections = report.sections

    file_result = sections.get("file")
    if file_result:
        lines.extend(
            [
                "=== File Analysis ===",
                "",
                f"Path       : {file_result['path']}",
                f"Size       : {file_result['size']} bytes",
                f"Mode       : {file_result['mode']}",
                f"Owner UID  : {file_result['owner_uid']}",
                f"Group GID  : {file_result['group_gid']}",
                f"Type       : {file_result['file_type']}",
                f"SHA-256    : {file_result['sha256']}",
                f"Executable : {'yes' if file_result['executable'] else 'no'}",
                "",
            ]
        )

    elf_result = sections.get("elf")
    if elf_result:
        lines.extend(
            [
                "=== ELF ===",
                "",
                f"Path        : {elf_result['path']}",
                f"ELF         : {'yes' if elf_result['is_elf'] else 'no'}",
                f"File type   : {elf_result['file_type']}",
            ]
        )

        if elf_result["is_elf"]:
            lines.append(f"Class       : {elf_result['architecture']}")
            lines.append(f"Entry point : {elf_result['entry_point']}")

        lines.append("")

    strings_result = sections.get("strings")
    if strings_result:
        values = strings_result["values"]

        lines.extend(
            [
                "=== STRINGS ===",
                "",
                f"Showing {len(values)} strings:",
                "",
            ]
        )

        for index, value in enumerate(values[:30], start=1):
            lines.append(f"{index:>3}: {value}")

        lines.append("")

    yara_result = sections.get("yara")
    if yara_result:
        lines.extend(
            [
                "=== YARA ===",
                "",
                f"Rules   : {yara_result['rules']}",
                f"Matches : {yara_result['match_count']}",
                "",
            ]
        )

        for match in yara_result["matches"]:
            lines.append(
                f"  {match['rule']:<30} {match['file']}"
            )

        lines.append("")

    integrity_result = sections.get("integrity")
    if integrity_result:
        lines.extend(
            [
                "=== INTEGRITY ===",
                "",
                f"File     : {integrity_result['path']}",
                f"Status   : {integrity_result['status']}",
            ]
        )

        if integrity_result["expected_sha256"]:
            lines.append(
                f"Expected : {integrity_result['expected_sha256']}"
            )

        if integrity_result["actual_sha256"]:
            lines.append(
                f"Actual   : {integrity_result['actual_sha256']}"
            )

        lines.append("")

    return "\n".join(lines)
