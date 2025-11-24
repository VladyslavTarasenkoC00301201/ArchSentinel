from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterable, Optional

# Common auth log locations
AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",   # Debian/Ubuntu
    "/var/log/secure",     # RHEL/Fedora
]

BASE_DIR = Path(__file__).resolve().parent  # scripts/logs/


def find_auth_log() -> Optional[str]:
    for path in AUTH_LOG_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def _read_file_lines(path: str) -> Iterable[str]:
    def _gen() -> Iterable[str]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line.rstrip("\n")
    return _gen()


def _read_journal_tail(limit: int = 1000) -> Iterable[str]:
    """
    Tail the systemd journal. Parser will filter relevant lines.
    """
    cmd = [
        "journalctl",
        "--no-pager",
        "-o",
        "short",
        "-n",
        str(limit),
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []

    if proc.returncode != 0 or not proc.stdout:
        return []

    def _gen() -> Iterable[str]:
        for line in proc.stdout.splitlines():
            yield line.rstrip("\n")

    return _gen()


def read_auth_log(path: Optional[str] = None, journal_limit: int = 1000) -> Iterable[str]:
    """
    Get raw auth-related log lines.

    Priority:
      1) explicit path, if provided and exists (absolute or relative to scripts/logs)
      2) known auth log files
      3) journald tail
    """
    if path is not None:
        p = Path(path)

        # try as given
        if not p.is_absolute() and not p.exists():
            # try relative to this module (scripts/logs/)
            p = BASE_DIR / path

        if p.exists():
            return _read_file_lines(str(p))

        print(
            f"WARNING: specified log file '{path}' does not exist; "
            "falling back to system auth logs / journal."
        )

    detected = find_auth_log()
    if detected is not None:
        return _read_file_lines(detected)

    return _read_journal_tail(limit=journal_limit)

