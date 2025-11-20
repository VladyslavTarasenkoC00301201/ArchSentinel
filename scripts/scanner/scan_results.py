from dataclasses import dataclass
from typing import Optional
import score




@dataclass
class ScanResult:
    key: str    # key represents the setting name in the config (e.g. "PermitRootLogin")
    current: Optional[str]  # current value in config (or None)
    expected: Optional[str] # the value that we want there to be ( the secure setting e.g for the PermitRootLogin key, we expeting "no" as the setting)
    status: str     # "OK" - if secure setting is set, "BAD" - insecure setting, "MISSING" - not set
    description: str    # human-readable explanation



class ScanResults:
    def __init__(self):
        self.results: Optional[ScanResult] = None
        self.score = Score()


    def run_checks(self):
        results: list[ScanResult] = []


        for key, rule in self.rules.items():
            expected = rule["expected"]
            description = rule["description"]

            current = self.config.get(key)

            if current is None:
                status = "MISSING"
            elif current.lower() == expected.lower():
                status = "OK"
            else:
                status = "BAD"

        results.append(
                ScanResult(
                    key=key,
                    current=current,
                    expected=expected,
                    status=status,
                    description=description,
                )
        )
        return results
