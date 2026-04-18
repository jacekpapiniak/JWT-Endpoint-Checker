from dataclasses import dataclass, field
from checker.src.common.severity import Severity


@dataclass
class Finding:
    title: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    recommendations: list[str] = field(default_factory=list)