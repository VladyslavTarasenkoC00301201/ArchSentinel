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
    Normalised representation of a single log line.

    The parser is responsible for turning raw text into this structure so that
    detection rules and views never need to care about the original format.
    """
    timestamp: datetime
    # Logical source (e.g. "ssh", "sudo", "myapp"). This comes from the parser /
    # source config and is what rules.yaml will normally filter on.
    source: str
    # Raw syslog fields
    host: str
    program: Optional[str]
    pid: Optional[int]
    # Original full log line for reference / display
    message: str
    # Normalised fields extracted from the message (user, ip, status, command, ...)
    fields: Dict[str, str]


@dataclass
class DetectionResult:
    """
    One detection produced by a rule.

    A rule groups one or more LogEvent objects into a single finding with a
    severity and human readable description.
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

    Holds both the parsed events and all detections so that other parts of the
    application (CLI, future GUI, JSON exporter, etc.) can decide how to
    present them.
    """
    events: List[LogEvent]
    detections: List[DetectionResult]

