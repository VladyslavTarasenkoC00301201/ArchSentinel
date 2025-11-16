import yaml
from .types import CheckRule

def load_rules(path: str):
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    file_path = data["file"]
    checks = []

    for c in data["checks"]:
        checks.append(CheckRule(
            id=c["id"],
            description=c["description"],
            key=c["key"],
            expected=c["expected"],
            default=c.get("default"),
            weight=c["weight"],
        ))

    return file_path, checks

