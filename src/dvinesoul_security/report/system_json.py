from __future__ import annotations

import json

from dvinesoul_security.report.system_models import SystemAssessmentReport


def system_report_to_json(
    report: SystemAssessmentReport,
    indent: int = 2,
) -> str:
    return json.dumps(
        report.to_dict(),
        indent=indent,
        sort_keys=True,
    )
