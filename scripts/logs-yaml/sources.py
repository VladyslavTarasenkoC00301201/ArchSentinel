from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterable, Iterator, Optional


# Common auth log locations. We prefer real files over journalctl when possible
# because they are cheap to read and easy to reason about.
AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",   # Debian / Ubuntu
    "/var/log/secure",     # RHEL / Fedora
]

BASE_DIR = Path(__file__).resolve().parent


def _read_file_lines(path: str) -> Iterator[str]:
    """
    Yield lines from a text file, stripping trailing newlines.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n")


def _read_journal_tail(limit: int = 1000) -> Iterator[str]:
    """
    Fallback: read the tail of the systemd journal using journalctl.

    We keep this deliberately simple: short output format, no paging, last N
    lines. If journalctl is not available or fails, we return an empty
    iterator.
    """
    try:
        proc = subprocess.run(
            ["journalctl", "-n", str(limit), "--no-pager", "-o", "short"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return iter(())

    if proc.returncode != 0:
        return iter(())

    return (line.rstrip("\n") for line in proc.stdout.splitlines())


def find_auth_log() -> Optional[str]:
    """
    Try to locate a suitable auth log file.

    Returns the first existing path from AUTH_LOG_CANDIDATES, or None if none
    are present.
    """
    for candidate in AUTH_LOG_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    return None


def read_auth_log(
    path: Optional[str] = None,
    journal_limit: int = 1000,
) -> Iterable[str]:
    """
    Main log source for the analyzer.

    The behaviour is:

      1. If *path* is given and exists, read that file.
      2. Else, if a known auth log file exists, read that.
      3. Else, fall back to `journalctl -n <journal_limit>`.

    It always yields plain text lines (without trailing newlines).
    """
    if path:
        p = Path(path)
        if p.exists():
            return _read_file_lines(str(p))

        print(
            f"WARNING: specified log file '{path}' does not exist; "
            "falling back to system auth logs / journal."
        )

    detected = find_auth_log()
    if detected is not None:
        return _read_file_lines(detected)

    # Last resort: journal tail
    return _read_journal_tail(limit=journal_limit)

