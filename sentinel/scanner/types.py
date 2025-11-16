from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class CheckRule:
    id: str
    description: str
    key: str
    expected: Dict[str, str]
    default: Optional[str]
    weight: int

@dataclass
class Finding:
    id: str
    file: str
    description: str
    current_value: Optional[str]
    expected_value: str
    severity: str
    status: str
    can_fix: bool

