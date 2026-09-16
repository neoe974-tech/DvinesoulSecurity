import json
from typing import Any

from .models import InspectionReport


def report_to_json(report: InspectionReport, indent: int = 2) -> str:
    return json.dumps(
        report.to_dict(),
        indent=indent,
        sort_keys=True,
    )
