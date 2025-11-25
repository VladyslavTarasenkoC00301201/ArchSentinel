from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, List, Optional, Dict, Any, Set

from results import LogEvent
from config_loader import load_yaml_dict


# ---------------------------------------------------------------------------
# Syslog prefix parsing
# ---------------------------------------------------------------------------

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

PROC_RE = re.compile(
    r"^(?P<host>\S+)\s+"
    r"(?P<proc>[^:]+):\s*"
)


def _parse_syslog_prefix(
    line: str,
) -> (Optional[datetime], Optional[str], Optional[str], Optional[int], str):
    """
    Parse a classic syslog-style line:

        'Nov 24 15:47:29 host sshd[1234]: the rest of the message'

    Returns:
        (timestamp, host, program, pid, message_without_prefix)
    """
    m = TS_RE.match(line)
    if not m:
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
        return timestamp, None, None, None, rest

    host = m2.group("host")
    proc_token = m2.group("proc")

    program: Optional[str] = None
    pid: Optional[int] = None

    token = proc_token.strip()
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
# SSH parsing (built-in)
# ---------------------------------------------------------------------------

FAILED_RE = re.compile(
    r"Failed password for (?P<invalid>invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

ACCEPT_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
)


def parse_ssh_events(
    lines: Iterable[str],
    source: str = "ssh",
    programs: Optional[Set[str]] = None,
) -> List[LogEvent]:
    """
    Parse SSH authentication events into LogEvent objects.

    Produces:
        source = <source> (default 'ssh')
        fields:
          - status: 'failed' or 'accepted'
          - user
          - ip
          - port (optional)
          - user_type = 'invalid' (for invalid user failures)
          - method (for accepted logins)
    """
    events: List[LogEvent] = []

    for line in lines:
        ts, host, program, pid, msg = _parse_syslog_prefix(line)
        if not program:
            continue

        if programs is not None:
            if program not in programs:
                continue
        else:
            if not program.startswith("sshd"):
                continue

        m_fail = FAILED_RE.search(msg)
        m_acc = ACCEPT_RE.search(msg)
        if not (m_fail or m_acc):
            continue

        fields: Dict[str, str] = {}

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
                source=source,
                host=host or "",
                program=program,
                pid=pid,
                message=line,
                fields=fields,
            )
        )

    return events


# ---------------------------------------------------------------------------
# sudo parsing (built-in)
# ---------------------------------------------------------------------------

SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?P<rest>.*)$"
)

KV_RE = re.compile(r"(?P<key>\w+)=([^;]+)")


def parse_sudo_events(
    lines: Iterable[str],
    source: str = "sudo",
    programs: Optional[Set[str]] = None,
) -> List[LogEvent]:
    """
    Parse sudo command events from generic syslog lines.

    Produces:
        source = <source> (default 'sudo')
        fields:
          - status = 'sudo_command'
          - user        (invoking user)
          - target_user (USER=...)
          - command     (COMMAND=...)
          - binary      (first token of command basename)
    """
    events: List[LogEvent] = []

    for line in lines:
        ts, host, program, pid, msg = _parse_syslog_prefix(line)
        if not program:
            continue

        if programs is not None:
            if program not in programs:
                continue
        else:
            if program != "sudo":
                continue

        m = SUDO_RE.search(msg)
        if not m:
            continue

        user = m.group("user")
        rest = m.group("rest")

        fields: Dict[str, str] = {
            "status": "sudo_command",
            "user": user,
        }

        kvs = {
            m_kv.group("key"): m_kv.group(0).split("=", 1)[1].strip()
            for m_kv in KV_RE.finditer(rest)
        }

        target_user = kvs.get("USER")
        command = kvs.get("COMMAND")

        if target_user:
            fields["target_user"] = target_user
        if command:
            fields["command"] = command
            # derive binary name for easier YAML rules, e.g. 'docker', 'bash'
            first_token = command.split()[0]
            binary = first_token.split("/")[-1]
            fields["binary"] = binary

        events.append(
            LogEvent(
                timestamp=ts or datetime.now(),
                source=source,
                host=host or "",
                program=program,
                pid=pid,
                message=line,
                fields=fields,
            )
        )

    return events


# ---------------------------------------------------------------------------
# Generic YAML-driven parser
# ---------------------------------------------------------------------------


def parse_generic_events(
    lines: Iterable[str],
    source: str,
    programs: Optional[Set[str]],
    patterns: List[Dict[str, Any]],
) -> List[LogEvent]:
    """
    Generic parser that uses regex patterns from sources.yaml.

    Each pattern has the form:

        - id: myapp_login_success
          regex: "User (?P<user>\\S+) logged in from (?P<ip>\\S+)"
          status: login_success
          fields:
            user: "{user}"
            ip: "{ip}"
    """
    events: List[LogEvent] = []

    compiled: List[tuple[Dict[str, Any], re.Pattern[str]]] = []
    for p in patterns:
        if not isinstance(p, dict):
            continue
        regex = p.get("regex")
        if not isinstance(regex, str):
            continue
        try:
            cre = re.compile(regex)
        except re.error as e:
            print(f"WARNING: bad regex in sources.yaml for source '{source}': {e}")
            continue
        compiled.append((p, cre))

    if not compiled:
        return events

    for line in lines:
        ts, host, program, pid, msg = _parse_syslog_prefix(line)
        if not program:
            continue

        if programs is not None and program not in programs:
            continue

        for patt, cre in compiled:
            m = cre.search(msg)
            if not m:
                continue

            gd = m.groupdict()
            fields: Dict[str, str] = {}

            status = patt.get("status")
            if status is not None:
                fields["status"] = str(status)

            field_defs = patt.get("fields") or {}
            if isinstance(field_defs, dict):
                for fname, template in field_defs.items():
                    if isinstance(template, str):
                        try:
                            fields[fname] = template.format(**gd)
                        except Exception:
                            fields[fname] = template
                    else:
                        fields[fname] = str(template)

            events.append(
                LogEvent(
                    timestamp=ts or datetime.now(),
                    source=source,
                    host=host or "",
                    program=program,
                    pid=pid,
                    message=line,
                    fields=fields,
                )
            )
            break  # only first matching pattern per line

    return events


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def parse_all_events(lines: Iterable[str]) -> List[LogEvent]:
    """
    Decide which parsers to run based on sources.yaml.

    - If sources.yaml is missing/invalid:
        * run built-in SSH + sudo parsers (old behaviour).
    - If sources.yaml exists:
        * for each 'source' entry:
            - parser: 'ssh'     -> built-in SSH parser
            - parser: 'sudo'    -> built-in sudo parser
            - parser: 'generic' -> regex-based generic parser
        * if 'ssh' or 'sudo' are NOT mentioned at all in sources.yaml,
          still run their built-in parsers as a fallback.
    """
    if not isinstance(lines, list):
        lines = list(lines)

    events: List[LogEvent] = []

    cfg = load_yaml_dict("sources.yaml")
    sources_cfg = cfg.get("sources") if isinstance(cfg, dict) else None

    if not isinstance(sources_cfg, dict) or not sources_cfg:
        # No YAML -> behave exactly like previous version
        events.extend(parse_ssh_events(lines))
        events.extend(parse_sudo_events(lines))
        return events

    ssh_defined = False
    sudo_defined = False

    for source_id, scfg in sources_cfg.items():
        if not isinstance(scfg, dict):
            continue

        parser_name = scfg.get("parser", "generic")
        programs_cfg = scfg.get("programs")
        programs_set: Optional[Set[str]] = None
        if isinstance(programs_cfg, list):
            programs_set = {str(p) for p in programs_cfg}

        if parser_name == "ssh":
            ssh_defined = True
            events.extend(
                parse_ssh_events(
                    lines,
                    source=source_id,
                    programs=programs_set,
                )
            )
        elif parser_name == "sudo":
            sudo_defined = True
            events.extend(
                parse_sudo_events(
                    lines,
                    source=source_id,
                    programs=programs_set,
                )
            )
        elif parser_name == "generic":
            patterns = scfg.get("patterns") or []
            if not isinstance(patterns, list):
                patterns = []
            events.extend(
                parse_generic_events(
                    lines,
                    source=source_id,
                    programs=programs_set,
                    patterns=patterns,
                )
            )
        else:
            print(
                f"WARNING: unknown parser '{parser_name}' for source '{source_id}' "
                "in sources.yaml; skipping this source."
            )

    # Built-in fallback if user didn't mention ssh/sudo at all in YAML
    if not ssh_defined and "ssh" not in sources_cfg:
        events.extend(parse_ssh_events(lines))
    if not sudo_defined and "sudo" not in sources_cfg:
        events.extend(parse_sudo_events(lines))

    return events

