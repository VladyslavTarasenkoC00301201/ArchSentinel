from dataclasses import dataclass
from typing import Optional





@dataclass
class ScanResult:
    key: str    # key represents the setting name in the config (e.g. "PermitRootLogin")
    current: Optional[str]  # current value in config (or None)
    expected: Optional[str] # the value that we want there to be ( the secure setting e.g for the PermitRootLogin key, we expeting "no" as the setting)
    status: str     # "OK" - if secure setting is set, "BAD" - insecure setting, "MISSING" - not set
    description: str    # human-readable explanation




