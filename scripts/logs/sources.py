from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from .config_loader import load_yaml_dict


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Common auth log locations (for "auto" mode)
AUTH_LOG_CANDIDATES: Sequence[str] = (
    "/var/log/auth.log",
    "/var/log/secure",
)

# Default journal reading behaviour if not overridden by YAML.
DEFAULT_JOURNAL_UNITS: Sequence[str] = ("sshd", "sshd-session", "sudo")
DEFAULT_JOURNAL_LIMIT: int = 1000

# Base directory for config files (kept for symmetry with other modules).
BASE_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_file_lines(path: str) -> List[str]:
    """Read all lines from a text file, safely."""
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except FileNotFoundError:
        print(f"WARNING: log file '{p}' not found.")
    except PermissionError:
        print(f"WARNING: permission denied reading log file '{p}'.")
    except OSError as e:
        print(f"WARNING: error reading log file '{p}': {e}")
    return []


def _read_journal_tail(
    limit: int = DEFAULT_JOURNAL_LIMIT,
    units: Optional[Iterable[str]] = None,
    since: Optional[str] = None,
    grep_pattern: Optional[str] = None,
) -> List[str]:
    """
    Read from systemd journal.

    Parameters
    ----------
    limit:
        Maximum number of lines to request from journalctl. If limit <= 0,
        no ``-n`` argument is passed and journalctl will return all available
        entries (subject to other filters).
    units:
        Optional iterable of systemd units to filter with ``-u``. If this is
        an empty iterable or ``None``, no unit filter is applied.
    since:
        Optional value forwarded to ``journalctl --since`` (for example
        ``"-1h"`` or ``"2025-11-27 00:00:00"``).
    grep_pattern:
        Optional Python regular expression applied *after* reading the journal.
        If provided and valid, only lines matching the pattern are kept.
    """
    cmd: List[str] = ["journalctl", "--no-pager"]

    # Limit: if positive, pass -n; else request full journal.
    if limit is not None and limit > 0:
        cmd.extend(["-n", str(limit)])

    # Optional unit filtering.
    if units:
        for u in units:
            if u:
                cmd.extend(["-u", str(u)])

    # Optional --since filter.
    if since:
        cmd.extend(["--since", str(since)])

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError:
        print("WARNING: journalctl not found; cannot read journal logs.")
        return []

    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if stderr:
            print(f"WARNING: journalctl exited with status {proc.returncode}: {stderr}")
        else:
            print(f"WARNING: journalctl exited with status {proc.returncode}.")
        return []

    lines = proc.stdout.splitlines()

    # Optional regex filter on the full line.
    if grep_pattern:
        try:
            cre = re.compile(grep_pattern)
        except re.error as e:
            print(f"WARNING: invalid journal grep regex {grep_pattern!r}: {e}")
            return lines
        lines = [ln for ln in lines if cre.search(ln)]

    return lines


def find_auth_log() -> Optional[str]:
    """Return the first existing auth log file from common candidates."""
    for path in AUTH_LOG_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def _load_log_input_config() -> dict:
    """
    Load log input configuration from sources.yaml, if present.

    Expected structure:

        log_input:
          mode: auto | file | journal
          file: /var/log/auth.log
          journal:
            units: [sshd, sudo]   # optional; [] => no unit filter
            max_lines: 5000       # optional; 0 => no -n (full journal)
            since: "-24h"         # optional; forwarded to journalctl --since
            grep: "regex"         # optional; Python regex applied to lines
    """
    cfg = load_yaml_dict("sources.yaml")
    if not cfg:
        return {}

    li = cfg.get("log_input")
    if not isinstance(li, dict):
        return {}

    return li


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def read_auth_log(path: Optional[str] = None) -> List[str]:
    """
    Return raw log lines for authentication-related events.

    Precedence:
      1) If ``path`` argument is provided and exists -> use that file.
      2) Else, if sources.yaml has ``log_input.mode == "file"`` and ``file`` exists -> use it.
      3) Else, if mode == "journal" -> use journal with configured options
         (units, max_lines, since, grep).
      4) Else (mode "auto" or missing):
           - try ``log_input.file`` if present,
           - else try common AUTH_LOG_CANDIDATES,
           - else fall back to journal with defaults / configured overrides.
    """
    # 1) explicit path argument wins
    if path:
        p = Path(path)
        if p.exists():
            return _read_file_lines(str(p))
        else:
            print(
                f"WARNING: specified log file '{path}' does not exist; "
                "falling back to config / auto detection."
            )

    li = _load_log_input_config()

    mode = str(li.get("mode", "auto")).lower() if li else "auto"
    cfg_file = li.get("file") if li else None
    j_cfg = li.get("journal") if li else {}

    if not isinstance(j_cfg, dict):
        j_cfg = {}

    # ---- decode journal options from YAML ----
    # units:
    #   - if key missing => fallback to DEFAULT_JOURNAL_UNITS
    #   - if key present but empty list/None => no unit filter
    if "units" in j_cfg:
        j_units = j_cfg.get("units") or []
    else:
        j_units = list(DEFAULT_JOURNAL_UNITS)

    max_lines_raw = j_cfg.get("max_lines", DEFAULT_JOURNAL_LIMIT)
    try:
        max_lines = int(max_lines_raw)
    except (TypeError, ValueError):
        print(
            f"WARNING: invalid journal.max_lines={max_lines_raw!r}; "
            f"using default {DEFAULT_JOURNAL_LIMIT}"
        )
        max_lines = DEFAULT_JOURNAL_LIMIT

    j_since = j_cfg.get("since")
    j_grep = j_cfg.get("grep")

    def _journal() -> List[str]:
        return _read_journal_tail(
            limit=max_lines,
            units=j_units,
            since=j_since,
            grep_pattern=j_grep,
        )

    # 2) explicit "file" mode in YAML
    if mode == "file":
        if cfg_file:
            p = Path(cfg_file)
            if p.exists():
                return _read_file_lines(str(p))
            print(
                f"WARNING: log_input.file '{cfg_file}' does not exist; "
                "falling back to auto / journal."
            )
        # fall through to auto behaviour with journal fallback
        mode = "auto"

    # 3) explicit "journal" mode in YAML
    if mode == "journal":
        return _journal()

    # 4) auto mode: prefer real files, else journal
    # 4a) try configured file if set
    if cfg_file:
        p = Path(cfg_file)
        if p.exists():
            return _read_file_lines(str(p))

    # 4b) try known distro auth logs
    detected = find_auth_log()
    if detected:
        return _read_file_lines(detected)

    # 4c) final fallback: journal
    return _journal()

