from dataclasses import dataclass, field
from typing import Any


@dataclass
class InspectionReport:
    path: str
    sections: dict[str, Any] = field(default_factory=dict)

    def add_section(self, name: str, data: Any) -> None:
        self.sections[name] = data

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sections": self.sections,
        }
