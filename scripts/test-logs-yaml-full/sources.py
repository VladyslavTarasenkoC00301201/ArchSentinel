from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from config_loader import load_yaml_dict


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Common auth log locations (for "auto" mode)
AUTH_LOG_CANDIDATES: Sequence[str] = (
    "/var/log/auth.log",   # Debian/Ubuntu
    "/var/log/secure",     # RHEL/Fedora
)

BASE_DIR = Path(__file__).resolve().parent

DEFAULT_JOURNAL_UNITS: Sequence[str] = ("sshd", "sshd-session", "sudo")
DEFAULT_JOURNAL_LIMIT: int = 1000


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
) -> List[str]:
    """
    Read the last N lines from systemd journal.

    If units is provided, it will add '-u UNIT' for each one.
    """
    cmd = ["journalctl", "--no-pager", "-n", str(limit)]
    if units:
        for u in units:
            if u:
                cmd.extend(["-u", str(u)])

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
        print(
            "WARNING: journalctl exited with non-zero status "
            f"({proc.returncode}): {proc.stderr.strip()}"
        )
        return []

    return proc.stdout.splitlines()


def find_auth_log() -> Optional[str]:
    """Return the first existing auth log file from common candidates."""
    for path in AUTH_LOG_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


# ---------------------------------------------------------------------------
# YAML-driven config
# ---------------------------------------------------------------------------


def _load_log_input_config() -> dict:
    """
    Load log input configuration from sources.yaml, if present.

    Expected structure:

        log_input:
          mode: auto | file | journal
          file: /var/log/auth.log
          journal:
            units: [sshd, sudo]
            max_lines: 5000
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
      1) If 'path' argument is provided and exists -> use that file.
      2) Else, if sources.yaml has log_input.mode == 'file' and 'file' exists -> use it.
      3) Else, if mode == 'journal' -> use journal with configured units/max_lines.
      4) Else (mode 'auto' or missing):
           - try log_input.file if present,
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
    j_cfg = li.get("journal") if li else None
    if not isinstance(j_cfg, dict):
        j_cfg = {}

    units = j_cfg.get("units", DEFAULT_JOURNAL_UNITS)
    if isinstance(units, str):
        units = [units]
    try:
        max_lines = int(j_cfg.get("max_lines", DEFAULT_JOURNAL_LIMIT))
    except (TypeError, ValueError):
        max_lines = DEFAULT_JOURNAL_LIMIT

    # Helper for journal fallback
    def _journal() -> List[str]:
        return _read_journal_tail(limit=max_lines, units=units)

    # 2) explicit 'file' mode in YAML
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

    # 3) explicit 'journal' mode in YAML
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

