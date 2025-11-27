from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple, Optional

from .results import (
    LogEvent,
    DetectionResult,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
from config_loader import load_yaml_dict


DetectionFn = Callable[[List[LogEvent], Dict[str, Any]], List[DetectionResult]]


# ---------------------------------------------------------------------------
# Built-in detection rules
# ---------------------------------------------------------------------------


def detect_ssh_bruteforce(events: List[LogEvent], config: Dict[str, Any]) -> List[DetectionResult]:
    """
    Many failed SSH logins from the same IP within a time window.
    """
    window_minutes = int(config.get("window_minutes", 5))
    threshold = int(config.get("threshold", 5))

    failures_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in events:
        if ev.source != "ssh":
            continue
        if ev.fields.get("status") != "failed":
            continue
        ip = ev.fields.get("ip")
        if not ip:
            continue
        failures_by_ip[ip].append(ev)

    results: List[DetectionResult] = []
    window = timedelta(minutes=window_minutes)

    for ip, evs in failures_by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        start = 0
        n = len(evs)

        while start < n:
            end = start
            while end < n and evs[end].timestamp - evs[start].timestamp <= window:
                end += 1

            count = end - start
            if count >= threshold:
                window_events = evs[start:end]

                local_ips = {"127.0.0.1", "::1"}
                if ip in local_ips:
                    severity = SEVERITY_LOW
                else:
                    severity = SEVERITY_HIGH

                evidence = f"{count} failed SSH logins from {ip} within {window_minutes} minute(s)"

                results.append(
                    DetectionResult(
                        id="ssh_bruteforce",
                        severity=severity,
                        description="Possible SSH brute-force attack",
                        evidence=evidence,
                        events=window_events,
                    )
                )

                # Move window past this burst
                start = end
            else:
                start += 1

    return results


def detect_ssh_root_login(events: List[LogEvent], config: Dict[str, Any]) -> List[DetectionResult]:
    """
    Any successful SSH login as root.
    """
    base_severity = config.get("base_severity", SEVERITY_MEDIUM)
    remote_severity = config.get("remote_severity", SEVERITY_HIGH)

    root_events: List[LogEvent] = []
    for ev in events:
        if ev.source != "ssh":
            continue
        if ev.fields.get("status") != "accepted":
            continue
        if ev.fields.get("user") != "root":
            continue
        root_events.append(ev)

    if not root_events:
        return []

    ips = {ev.fields.get("ip") for ev in root_events if ev.fields.get("ip")}
    local_ips = {"127.0.0.1", "::1"}
    remote_present = any(ip not in local_ips for ip in ips)

    severity = remote_severity if remote_present else base_severity
    evidence = f"{len(root_events)} successful root SSH login(s)"

    return [
        DetectionResult(
            id="ssh_root_login",
            severity=severity,
            description="Root SSH login detected",
            evidence=evidence,
            events=root_events,
        )
    ]


def detect_ssh_many_success(events: List[LogEvent], config: Dict[str, Any]) -> List[DetectionResult]:
    """
    Many successful SSH logins from the same IP within a time window.
    """
    window_minutes = int(config.get("window_minutes", 10))
    threshold = int(config.get("threshold", 10))
    severity = config.get("severity", SEVERITY_MEDIUM)

    success_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in events:
        if ev.source != "ssh":
            continue
        if ev.fields.get("status") != "accepted":
            continue
        ip = ev.fields.get("ip")
        if not ip:
            continue
        success_by_ip[ip].append(ev)

    results: List[DetectionResult] = []
    window = timedelta(minutes=window_minutes)

    for ip, evs in success_by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        start = 0
        n = len(evs)

        while start < n:
            end = start
            while end < n and evs[end].timestamp - evs[start].timestamp <= window:
                end += 1

            count = end - start
            if count >= threshold:
                window_events = evs[start:end]
                evidence = f"{count} successful SSH logins from {ip} within {window_minutes} minute(s)"

                results.append(
                    DetectionResult(
                        id="ssh_many_success",
                        severity=severity,
                        description="Unusually many successful SSH logins from single IP",
                        evidence=evidence,
                        events=window_events,
                    )
                )

                start = end
            else:
                start += 1

    return results


def _is_shell_command(cmd: str, shell_binaries: List[str]) -> bool:
    cmd = (cmd or "").strip()
    if not cmd:
        return False
    prog = cmd.split()[0]
    binary = prog.split("/")[-1]
    return binary in shell_binaries


def detect_sudo_root_shell(events: List[LogEvent], config: Dict[str, Any]) -> List[DetectionResult]:
    """
    sudo commands that spawn a root shell (sudo bash/sh/zsh/fish/su).
    """
    shell_binaries = list(config.get("shell_binaries", ["bash", "sh", "zsh", "fish", "su"]))
    severity = config.get("severity", SEVERITY_MEDIUM)

    matches: List[LogEvent] = []
    for ev in events:
        if ev.source != "sudo":
            continue
        if ev.fields.get("status") != "sudo_command":
            continue
        if ev.fields.get("target_user") != "root":
            continue
        cmd = ev.fields.get("command", "")
        if not _is_shell_command(cmd, shell_binaries):
            continue
        matches.append(ev)

    if not matches:
        return []

    users = sorted({ev.fields.get("user", "?") for ev in matches})
    evidence = (
        f"{len(matches)} sudo command(s) spawning a root shell by user(s): "
        + ", ".join(users)
    )

    return [
        DetectionResult(
            id="sudo_root_shell",
            severity=severity,
            description="Root shell spawned via sudo",
            evidence=evidence,
            events=matches,
        )
    ]


def detect_ssh_sudo_root_chain(events: List[LogEvent], config: Dict[str, Any]) -> List[DetectionResult]:
    """
    Correlate SSH logins with sudo root shells for the same user within a window.
    """
    window_minutes = int(config.get("window_minutes", 10))
    shell_binaries = list(config.get("shell_binaries", ["bash", "sh", "zsh", "fish", "su"]))
    severity = config.get("severity", SEVERITY_HIGH)

    window = timedelta(minutes=window_minutes)

    ssh_success: List[LogEvent] = [
        ev for ev in events
        if ev.source == "ssh" and ev.fields.get("status") == "accepted"
    ]

    sudo_shell: List[LogEvent] = []
    for ev in events:
        if ev.source != "sudo":
            continue
        if ev.fields.get("status") != "sudo_command":
            continue
        if ev.fields.get("target_user") != "root":
            continue
        if not _is_shell_command(ev.fields.get("command", ""), shell_binaries):
            continue
        sudo_shell.append(ev)

    ssh_success.sort(key=lambda e: e.timestamp)
    sudo_shell.sort(key=lambda e: e.timestamp)

    chains: List[List[LogEvent]] = []
    used_pairs: set[Tuple[str, str, str]] = set()

    for ssh_ev in ssh_success:
        user = ssh_ev.fields.get("user")
        if not user:
            continue
        for sudo_ev in sudo_shell:
            if sudo_ev.timestamp < ssh_ev.timestamp:
                continue
            if sudo_ev.timestamp - ssh_ev.timestamp > window:
                break
            if sudo_ev.fields.get("user") != user:
                continue

            key = (ssh_ev.timestamp.isoformat(), sudo_ev.timestamp.isoformat(), user)
            if key in used_pairs:
                continue
            used_pairs.add(key)
            chains.append([ssh_ev, sudo_ev])

    if not chains:
        return []

    all_events: List[LogEvent] = []
    users = set()
    for chain in chains:
        all_events.extend(chain)
        for ev in chain:
            if ev.fields.get("user"):
                users.add(ev.fields["user"])

    evidence = (
        f"{len(chains)} SSH login → sudo root shell chain(s) within "
        f"{window_minutes} minute(s) for user(s): {', '.join(sorted(users))}"
    )

    return [
        DetectionResult(
            id="ssh_sudo_root_chain",
            severity=severity,
            description="SSH login followed by sudo root shell",
            evidence=evidence,
            events=all_events,
        )
    ]


# ---------------------------------------------------------------------------
# User-defined rules from YAML
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "low": SEVERITY_LOW,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "critical": SEVERITY_CRITICAL,
}


def _match_event(ev: LogEvent, match_def: Dict[str, Any]) -> bool:
    """
    Return True if a LogEvent matches a simple match definition:

        match:
          source: ssh
          fields:
            status: accepted
            user: root
    """
    if not match_def:
        return False

    expected_source = match_def.get("source")
    if expected_source and ev.source != expected_source:
        return False

    expected_fields = match_def.get("fields") or {}
    for key, expected in expected_fields.items():
        actual = ev.fields.get(key)
        if actual is None or str(actual) != str(expected):
            return False

    return True


def _load_user_rules(
    filename: str = "user_rules.yaml",
) -> Tuple[Dict[str, DetectionFn], Dict[str, Dict[str, Any]]]:
    """
    Load user-defined rules from a YAML file and convert them into DetectionFn
    functions.

    The YAML schema is:

        rules:
          - id: my_rule
            description: "optional description"
            severity: medium|high|...
            match:
              source: ssh
              fields:
                status: accepted
                user: root
            evidence: "optional evidence override"

    Returns (registry, default_configs). If file is missing or invalid,
    returns ({}, {}).
    """
    data = load_yaml_dict(filename)
    if not data:
        return {}, {}

    rules_def = data.get("rules")
    if not isinstance(rules_def, list):
        return {}, {}

    registry: Dict[str, DetectionFn] = {}
    default_configs: Dict[str, Dict[str, Any]] = {}

    for raw_rule in rules_def:
        if not isinstance(raw_rule, dict):
            continue

        rule_id = raw_rule.get("id")
        if not rule_id or not isinstance(rule_id, str):
            continue

        if rule_id in registry:
            print(f"WARNING: duplicate user rule id '{rule_id}', skipping")
            continue

        description = raw_rule.get("description") or rule_id
        severity_str = str(raw_rule.get("severity", "medium")).lower()
        severity = SEVERITY_MAP.get(severity_str, SEVERITY_MEDIUM)
        match_def = raw_rule.get("match") or {}
        evidence_override = raw_rule.get("evidence")

        def make_rule(
            rid: str,
            desc: str,
            sev: str,
            match_local: Dict[str, Any],
            evidence_local: Optional[str],
        ) -> DetectionFn:
            def rule(events: List[LogEvent], config: Dict[str, Any]) -> List[DetectionResult]:
                matched = [ev for ev in events if _match_event(ev, match_local)]
                if not matched:
                    return []

                evidence = evidence_local or f"{len(matched)} event(s) matched user rule '{rid}'"
                return [
                    DetectionResult(
                        id=rid,
                        severity=sev,
                        description=desc,
                        evidence=evidence,
                        events=matched,
                    )
                ]

            return rule

        registry[rule_id] = make_rule(rule_id, description, severity, match_def, evidence_override)
        default_configs[rule_id] = {}

    return registry, default_configs


# ---------------------------------------------------------------------------
# Registry & default configs
# ---------------------------------------------------------------------------

DETECTION_REGISTRY: Dict[str, DetectionFn] = {
    "ssh_bruteforce": detect_ssh_bruteforce,
    "ssh_root_login": detect_ssh_root_login,
    "ssh_many_success": detect_ssh_many_success,
    "sudo_root_shell": detect_sudo_root_shell,
    "ssh_sudo_root_chain": detect_ssh_sudo_root_chain,
}

DEFAULT_DETECTION_CONFIG: Dict[str, Dict[str, Any]] = {
    "ssh_bruteforce": {
        "window_minutes": 5,
        "threshold": 5,
    },
    "ssh_root_login": {
        "base_severity": SEVERITY_MEDIUM,
        "remote_severity": SEVERITY_HIGH,
    },
    "ssh_many_success": {
        "window_minutes": 10,
        "threshold": 10,
        "severity": SEVERITY_MEDIUM,
    },
    "sudo_root_shell": {
        "shell_binaries": ["bash", "sh", "zsh", "fish", "su"],
        "severity": SEVERITY_MEDIUM,
    },
    "ssh_sudo_root_chain": {
        "window_minutes": 10,
        "shell_binaries": ["bash", "sh", "zsh", "fish", "su"],
        "severity": SEVERITY_HIGH,
    },
}


# Load user-defined rules on import, if present
try:
    _user_registry, _user_default_cfg = _load_user_rules("user_rules.yaml")
    if _user_registry:
        print(f"Loaded {len(_user_registry)} user-defined log detection rule(s).")
        for rid, fn in _user_registry.items():
            if rid in DETECTION_REGISTRY:
                print(f"WARNING: user rule '{rid}' conflicts with built-in rule and will be ignored")
                continue
            DETECTION_REGISTRY[rid] = fn
        for rid, cfg in _user_default_cfg.items():
            if rid not in DEFAULT_DETECTION_CONFIG:
                DEFAULT_DETECTION_CONFIG[rid] = cfg
except Exception as e:
    print(f"WARNING: failed to load user-defined rules: {e}")

