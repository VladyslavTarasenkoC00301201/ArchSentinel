from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

from results import LogEvent


# ---------------------------------------------------------------------------
# Syslog prefix parsing
# ---------------------------------------------------------------------------

# Example timestamp prefix: "Nov 24 15:47:29"
TS_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# After the timestamp we expect: "host program[pid]: message"
PROC_RE = re.compile(
    r"^(?P<host>\S+)\s+"
    r"(?P<proc>[^:]+):\s*"
)


def _parse_syslog_prefix(
    line: str,
) -> Tuple[Optional[datetime], Optional[str], Optional[str], Optional[int], str]:
    """
    Parse a classic syslog-style line:

        'Nov 24 15:47:29 host sshd[1234]: the rest of the message'

    Returns:
        (timestamp, host, program, pid, message_without_prefix)

    If parsing fails, timestamp may be None and the other fields are best-effort.
    """
    m = TS_RE.match(line)
    if not m:
        # No timestamp at all; treat whole line as message
        return None, None, None, None, line

    month_str = m.group("month")
    day = int(m.group("day"))
    time_str = m.group("time")

    month = MONTHS.get(month_str)
    if not month:
        return None, None, None, None, line

    now = datetime.now()
    try:
        timestamp = datetime.strptime(
            f"{now.year} {month} {day} {time_str}",
            "%Y %m %d %H:%M:%S",
        )
    except ValueError:
        timestamp = None

    rest = line[m.end():].lstrip()
    m2 = PROC_RE.match(rest)
    if not m2:
        # We have a timestamp but no clear host/program prefix
        return timestamp, None, None, None, rest

    host = m2.group("host")
    proc_token = m2.group("proc")  # e.g. "sshd[1234]" or "sudo" or "sshd-session[42]"

    program: Optional[str] = None
    pid: Optional[int] = None

    token = proc_token.strip()

    # program can be "name[pid]" or just "name"
    if "[" in token and token.endswith("]"):
        prog_part, pid_part = token.split("[", 1)
        program = prog_part
        pid_str = pid_part.rstrip("]")
        if pid_str.isdigit():
            pid = int(pid_str)
    else:
        program = token

    message = rest[m2.end():].lstrip()
    return timestamp, host, program, pid, message


# ---------------------------------------------------------------------------
# SSH parsing
# ---------------------------------------------------------------------------

FAILED_RE = re.compile(
    r"Failed password for (?P<invalid>invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

ACCEPT_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
)


def parse_ssh_events(lines: Iterable[str]) -> List[LogEvent]:
    """
    Parse SSH authentication events from generic syslog lines.

    Produces LogEvent objects with:
        source = "ssh"
        fields:
          - status: "failed" or "accepted"
          - user
          - ip
          - port (optional)
          - user_type = "invalid" (for invalid user failures)
          - method (for accepted logins)
    """
    events: List[LogEvent] = []

    for line in lines:
        ts, host, program, pid, msg = _parse_syslog_prefix(line)
        # We treat any "sshd*" program as SSH server logs (sshd, sshd-session, ...)
        if not program or not program.startswith("sshd"):
            continue

        m_fail = FAILED_RE.search(msg)
        m_acc = ACCEPT_RE.search(msg)

        if not (m_fail or m_acc):
            continue

        fields: dict[str, str] = {}
        if m_fail:
            gd = m_fail.groupdict()
            fields["status"] = "failed"
            fields["user"] = gd.get("user", "") or ""
            fields["ip"] = gd.get("ip", "") or ""
            fields["port"] = gd.get("port", "") or ""
            if gd.get("invalid"):
                fields["user_type"] = "invalid"
        elif m_acc:
            gd = m_acc.groupdict()
            fields["status"] = "accepted"
            fields["user"] = gd.get("user", "") or ""
            fields["ip"] = gd.get("ip", "") or ""
            if gd.get("port"):
                fields["port"] = gd.get("port", "") or ""
            if gd.get("method"):
                fields["method"] = gd.get("method", "") or ""

        events.append(
            LogEvent(
                timestamp=ts or datetime.now(),
                source="ssh",
                host=host or "",
                program=program,
                pid=pid,
                message=line,
                fields=fields,
            )
        )

    return events


# ---------------------------------------------------------------------------
# sudo parsing
# ---------------------------------------------------------------------------

# After _parse_syslog_prefix(), msg for sudo lines looks like:
#   "USER : TTY=pts/0 ; PWD=/... ; USER=root ; COMMAND=/usr/bin/id"
#
# So we only match "USER : rest", not "sudo[PID]: USER : rest".
SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?P<rest>.*)$"
)

KV_RE = re.compile(r"(?P<key>\w+)=([^;]+)")


def parse_sudo_events(lines: Iterable[str]) -> List[LogEvent]:
    """
    Parse sudo command events from generic syslog lines.

    Produces LogEvent objects with:
        source = "sudo"
        fields:
          - status = "sudo_command"
          - user        (the invoking user)
          - target_user (from USER=..., usually 'root')
          - command     (from COMMAND=...)
    """
    events: List[LogEvent] = []

    for line in lines:
        ts, host, program, pid, msg = _parse_syslog_prefix(line)
        if program != "sudo":
            continue

        m = SUDO_RE.search(msg)
        if not m:
            continue

        user = m.group("user")
        rest = m.group("rest")

        fields: dict[str, str] = {
            "status": "sudo_command",
            "user": user,
        }

        # Parse key=value pairs inside the sudo message
        kvs = {
            m_kv.group("key"): m_kv.group(0).split("=", 1)[1].strip()
            for m_kv in KV_RE.finditer(rest)
        }

        if "USER" in kvs:
            fields["target_user"] = kvs["USER"]
        if "COMMAND" in kvs:
            fields["command"] = kvs["COMMAND"]

        events.append(
            LogEvent(
                timestamp=ts or datetime.now(),
                source="sudo",
                host=host or "",
                program=program,
                pid=pid,
                message=line,
                fields=fields,
            )
        )

    return events


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def parse_all_events(lines: Iterable[str]) -> List[LogEvent]:
    """
    Orchestrator that calls all parsers.

    Currently:
      - SSH auth events
      - sudo command events

    In the future this function can be extended to also use a YAML-driven
    sources configuration to plug in custom parsers / sources, but the public
    interface (lines -> List[LogEvent]) will remain the same.
    """
    if not isinstance(lines, list):
        lines = list(lines)

    events: List[LogEvent] = []
    events.extend(parse_ssh_events(lines))
    events.extend(parse_sudo_events(lines))
    return events

