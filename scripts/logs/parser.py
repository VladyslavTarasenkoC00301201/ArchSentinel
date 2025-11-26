from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, List, Optional

from .results import LogEvent

# Timestamp like: "Nov 24 15:47:29"
TS_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)

# SSH auth patterns
FAILED_RE = re.compile(
    r"Failed password for (?P<invalid>invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

ACCEPT_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
)

# sudo command log, e.g.:
# Nov 24 16:02:13 HOST sudo[1234]:  arsen : TTY=pts/1 ; PWD=/home/arsen ; USER=root ; COMMAND=/usr/bin/bash
SUDO_CMD_RE = re.compile(
    r"sudo\[\d+\]:\s*(?P<user>\S+)\s*:\s*(?P<rest>.*)$"
)

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _parse_timestamp(line: str) -> datetime:
    m = TS_RE.match(line)
    if not m:
        return datetime.now()

    now = datetime.now()
    month = MONTHS.get(m.group("month"), now.month)
    day = int(m.group("day"))
    time_str = m.group("time")
    hour, minute, second = map(int, time_str.split(":"))

    # naive assumption: current year
    return datetime(
        year=now.year,
        month=month,
        day=day,
        hour=hour,
        minute=minute,
        second=second,
    )


def _extract_host_and_pid(line: str) -> tuple[Optional[str], Optional[int]]:
    """
    Best-effort extraction from lines like:
      Nov 24 15:47:29 HOST sshd[1234]: ...
      Nov 24 15:47:29 HOST sudo[1234]: ...
    """
    parts = line.split()
    if len(parts) < 5:
        return None, None

    host = parts[3]
    proc_token = parts[4]
    pid: Optional[int] = None

    lb = proc_token.find("[")
    rb = proc_token.find("]", lb + 1)
    if lb != -1 and rb != -1:
        pid_str = proc_token[lb + 1:rb]
        if pid_str.isdigit():
            pid = int(pid_str)

    return host, pid


def parse_ssh_events(lines: Iterable[str]) -> List[LogEvent]:
    """
    Parse SSH-related auth events into LogEvent(source="ssh").
    """
    events: List[LogEvent] = []

    for line in lines:
        if "sshd" not in line:
            continue

        ts = _parse_timestamp(line)
        host, pid = _extract_host_and_pid(line)

        # failed logins
        m_fail = FAILED_RE.search(line)
        if m_fail:
            fields = {
                "status": "failed",
                "user": m_fail.group("user"),
                "ip": m_fail.group("ip"),
                "port": m_fail.group("port"),
            }
            if m_fail.group("invalid"):
                fields["user_type"] = "invalid"

            events.append(
                LogEvent(
                    timestamp=ts,
                    source="ssh",
                    host=host or "",
                    pid=pid,
                    message=line,
                    fields=fields,
                )
            )
            continue

        # accepted logins
        m_acc = ACCEPT_RE.search(line)
        if m_acc:
            fields = {
                "status": "accepted",
                "user": m_acc.group("user"),
                "ip": m_acc.group("ip"),
            }
            method = m_acc.group("method")
            if method:
                fields["method"] = method
            port = m_acc.group("port")
            if port:
                fields["port"] = port

            events.append(
                LogEvent(
                    timestamp=ts,
                    source="ssh",
                    host=host or "",
                    pid=pid,
                    message=line,
                    fields=fields,
                )
            )
            continue

    return events


def parse_sudo_events(lines: Iterable[str]) -> List[LogEvent]:
    """
    Parse sudo command executions.

    Produces events with:
      - source="sudo"
      - fields: status="sudo_command", user, target_user, command
    """
    events: List[LogEvent] = []

    for line in lines:
        if "sudo[" not in line:
            continue

        m = SUDO_CMD_RE.search(line)
        if not m:
            continue

        ts = _parse_timestamp(line)
        host, pid = _extract_host_and_pid(line)

        user = m.group("user")
        rest = m.group("rest")

        target_user: Optional[str] = None
        command: Optional[str] = None

        m_target = re.search(r"USER=(?P<target>\S+)", rest)
        if m_target:
            target_user = m_target.group("target")

        m_cmd = re.search(r"COMMAND=(?P<cmd>.+)", rest)
        if m_cmd:
            command = m_cmd.group("cmd").strip()

        fields = {
            "status": "sudo_command",
            "user": user,
        }
        if target_user:
            fields["target_user"] = target_user
        if command:
            fields["command"] = command

        events.append(
            LogEvent(
                timestamp=ts,
                source="sudo",
                host=host or "",
                pid=pid,
                message=line,
                fields=fields,
            )
        )

    return events


def parse_all_events(lines: Iterable[str]) -> List[LogEvent]:
    """
    Orchestrator that calls all parsers.

    Currently:
      - SSH auth events
      - sudo command events
    """
    if not isinstance(lines, list):
        lines = list(lines)

    events: List[LogEvent] = []
    events.extend(parse_ssh_events(lines))
    events.extend(parse_sudo_events(lines))
    return events

