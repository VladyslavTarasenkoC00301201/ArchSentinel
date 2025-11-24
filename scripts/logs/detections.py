from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Callable, Dict, List

from results import (
    LogEvent,
    DetectionResult,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
)

DetectionFn = Callable[[List[LogEvent], Dict], List[DetectionResult]]


def detect_ssh_bruteforce(
    events: List[LogEvent],
    config: Dict,
) -> List[DetectionResult]:
    """
    Detect many failed SSH logins from the same IP in a short time window.

    Config keys:
      - window_minutes (int)
      - threshold (int): minimum failures in window to trigger
    """
    window_minutes = int(config.get("window_minutes", 5))
    threshold = int(config.get("threshold", 5))

    results: List[DetectionResult] = []
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

    window_delta = timedelta(minutes=window_minutes)

    for ip, evs in failures_by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        start = 0

        for end in range(len(evs)):
            while evs[end].timestamp - evs[start].timestamp > window_delta:
                start += 1

            count = end - start + 1
            if count >= threshold:
                window_events = evs[start : end + 1]

                severity = SEVERITY_HIGH
                if ip in ("127.0.0.1", "::1"):
                    severity = SEVERITY_LOW

                results.append(
                    DetectionResult(
                        id="ssh_bruteforce",
                        severity=severity,
                        description=f"Possible SSH brute-force from {ip}",
                        evidence=f"{count} failed logins within {window_minutes} minutes",
                        events=window_events,
                    )
                )

                start = end + 1

    return results


def detect_ssh_root_login(
    events: List[LogEvent],
    config: Dict,
) -> List[DetectionResult]:
    """
    Detect successful SSH logins as root.

    Config keys:
      - base_severity: used when all logins are from localhost
      - remote_severity: used when any login is from non-localhost IP
    """
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
    remote_present = any(ip not in local_ips for ip in ips if ip is not None)

    base_severity = config.get("base_severity", SEVERITY_MEDIUM)
    remote_severity = config.get("remote_severity", SEVERITY_HIGH)

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


def detect_ssh_many_success(
    events: List[LogEvent],
    config: Dict,
) -> List[DetectionResult]:
    """
    Detect many successful SSH logins from the same IP in a short window.

    Config keys:
      - window_minutes (int)
      - threshold (int)
      - severity (str)
    """
    window_minutes = int(config.get("window_minutes", 10))
    threshold = int(config.get("threshold", 10))
    severity = config.get("severity", SEVERITY_MEDIUM)

    results: List[DetectionResult] = []
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

    window_delta = timedelta(minutes=window_minutes)

    for ip, evs in success_by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        start = 0

        for end in range(len(evs)):
            while evs[end].timestamp - evs[start].timestamp > window_delta:
                start += 1

            count = end - start + 1
            if count >= threshold:
                window_events = evs[start : end + 1]

                results.append(
                    DetectionResult(
                        id="ssh_many_success",
                        severity=severity,
                        description=f"Many successful SSH logins from {ip}",
                        evidence=f"{count} successful logins within {window_minutes} minutes",
                        events=window_events,
                    )
                )

                start = end + 1

    return results


def detect_sudo_root_shell(
    events: List[LogEvent],
    config: Dict,
) -> List[DetectionResult]:
    """
    Detect sudo commands that spawn an interactive root shell.

    Looks for:
      - source == "sudo"
      - status == "sudo_command"
      - target_user == "root"
      - command binary in shell_binaries
    """
    shell_binaries = set(config.get("shell_binaries", ["bash", "sh", "zsh", "fish", "su"]))
    severity = config.get("severity", SEVERITY_MEDIUM)

    suspicious: List[LogEvent] = []

    for ev in events:
        if ev.source != "sudo":
            continue
        if ev.fields.get("status") != "sudo_command":
            continue
        if ev.fields.get("target_user") != "root":
            continue

        cmd = (ev.fields.get("command") or "").strip()
        if not cmd:
            continue

        prog = cmd.split()[0]
        binary = prog.split("/")[-1]

        if binary in shell_binaries:
            suspicious.append(ev)

    if not suspicious:
        return []

    users = sorted({ev.fields.get("user", "?") for ev in suspicious})
    evidence = (
        f"{len(suspicious)} sudo command(s) spawning a root shell "
        f"by user(s): {', '.join(users)}"
    )

    return [
        DetectionResult(
            id="sudo_root_shell",
            severity=severity,
            description="Root shell spawned via sudo",
            evidence=evidence,
            events=suspicious,
        )
    ]


def detect_ssh_sudo_root_chain(
    events: List[LogEvent],
    config: Dict,
) -> List[DetectionResult]:
    """
    Correlate SSH logins with sudo root shells.

    Pattern:
      1) SSH accepted login for user U
      2) Within `window_minutes`, sudo root shell by the same user U
    """
    window_minutes = int(config.get("window_minutes", 10))
    severity = config.get("severity", SEVERITY_HIGH)
    shell_binaries = set(config.get("shell_binaries", ["bash", "sh", "zsh", "fish", "su"]))

    ssh_success: List[LogEvent] = []
    sudo_cmds: List[LogEvent] = []

    for ev in events:
        if ev.source == "ssh" and ev.fields.get("status") == "accepted":
            ssh_success.append(ev)
        elif ev.source == "sudo" and ev.fields.get("status") == "sudo_command":
            if ev.fields.get("target_user") != "root":
                continue
            cmd = (ev.fields.get("command") or "").strip()
            if not cmd:
                continue
            prog = cmd.split()[0]
            binary = prog.split("/")[-1]
            if binary not in shell_binaries:
                continue
            sudo_cmds.append(ev)

    if not ssh_success or not sudo_cmds:
        return []

    ssh_success.sort(key=lambda e: e.timestamp)
    sudo_cmds.sort(key=lambda e: e.timestamp)

    chains: List[List[LogEvent]] = []
    used_pairs = set()
    window_delta = timedelta(minutes=window_minutes)

    for ssh_ev in ssh_success:
        user = ssh_ev.fields.get("user")
        if not user:
            continue

        for sudo_ev in sudo_cmds:
            if sudo_ev.timestamp < ssh_ev.timestamp:
                continue
            if sudo_ev.timestamp - ssh_ev.timestamp > window_delta:
                break

            if sudo_ev.fields.get("user") != user:
                continue

            key = (ssh_ev.timestamp, sudo_ev.timestamp, user)
            if key in used_pairs:
                continue
            used_pairs.add(key)
            chains.append([ssh_ev, sudo_ev])

    if not chains:
        return []

    users = sorted({ev.fields.get("user", "?") for chain in chains for ev in chain})
    evidence = (
        f"{len(chains)} SSH login → sudo root shell chain(s) within "
        f"{window_minutes} minutes for user(s): {', '.join(users)}"
    )
    correlated_events: List[LogEvent] = [ev for chain in chains for ev in chain]

    return [
        DetectionResult(
            id="ssh_sudo_root_chain",
            severity=severity,
            description="SSH login followed by sudo root shell",
            evidence=evidence,
            events=correlated_events,
        )
    ]


DETECTION_REGISTRY: Dict[str, DetectionFn] = {
    "ssh_bruteforce": detect_ssh_bruteforce,
    "ssh_root_login": detect_ssh_root_login,
    "ssh_many_success": detect_ssh_many_success,
    "sudo_root_shell": detect_sudo_root_shell,
    "ssh_sudo_root_chain": detect_ssh_sudo_root_chain,
}

DEFAULT_DETECTION_CONFIG: Dict[str, Dict] = {
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

