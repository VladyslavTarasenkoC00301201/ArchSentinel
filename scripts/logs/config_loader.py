from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml  # type: ignore[import]


BASE_DIR = Path(__file__).resolve().parent


def load_yaml_dict(filename: str) -> Dict[str, Any]:
    """
    Load a YAML file as a top-level dict with common error handling.

    - Paths are resolved relative to this directory if not absolute.
    - On missing file or error, returns {}.
    - Ensures the top-level object is a mapping.
    """
    path = Path(filename)
    if not path.is_absolute():
        path = BASE_DIR / filename

    if not path.exists():
        # Silent: caller can decide if missing file is OK.
        return {}

    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"WARNING: failed to read YAML file '{path}': {e}")
        return {}

    try:
        data = yaml.safe_load(text)
    except Exception as e:
        print(f"WARNING: failed to parse YAML file '{path}': {e}")
        return {}

    if not isinstance(data, dict):
        print(f"WARNING: YAML file '{path}' does not contain a mapping at top level.")
        return {}

    return data

