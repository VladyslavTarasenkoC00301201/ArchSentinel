from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

# ---- Severity constants (use these everywhere) ---- #
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"


@dataclass
class LogEvent:
    """
    Normalized log event.

    - source: logical source ("ssh", "sudo", etc.)
    - message: original log line
    - fields: structured info (status, user, ip, port, target_user, command, etc.)
    """
    timestamp: datetime
    source: str
    host: str
    pid: Optional[int]
    message: str
    fields: Dict[str, str]


@dataclass
class DetectionResult:
    """
    Output of a single detection rule.
    """
    id: str
    severity: str
    description: str
    evidence: str
    events: List[LogEvent]


@dataclass
class LogAnalysisResult:
    """
    Result of a complete log analysis run.
    """
    events: List[LogEvent]
    detections: List[DetectionResult]

