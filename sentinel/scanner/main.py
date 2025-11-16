from .loader import load_rules
from .files import parse_kv_config
from .scoring import compute_score
from .types import Finding

import glob
import os

def evaluate(file_path, rules, mode):
    config = parse_kv_config(file_path)
    findings = []

    for rule in rules:
        current = config.get(rule.key)
        expected = rule.expected.get(mode)

        status = "pass" if current == expected else "fail"

        severity = (
            "critical" if rule.weight >= 5 else
            "high" if rule.weight >= 3 else
            "medium"
        )

        findings.append(Finding(
            id=rule.id,
            file=file_path,
            description=rule.description,
            current_value=current,
            expected_value=expected,
            severity=severity,
            status=status,
            can_fix=True
        ))

    return findings


def run_scanner(mode, auto_fix):
    rule_files = glob.glob("sentinel/rules/*.yml")
    all_findings = []
    all_rules = []

    for rule_path in rule_files:
        file_path, rules = load_rules(rule_path)
        findings = evaluate(file_path, rules, mode)

        all_findings.extend(findings)
        all_rules.extend(rules)

    score = compute_score(all_findings, all_rules)

    # Print security bar
    bar_len = 30
    filled = int(score / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)

    print(f"\nSecurity Score: {score}%")
    print(f"[{bar}]")

    for f in all_findings:
        print(f"\n[{f.severity.upper()}] {f.description}")
        print(f"  File:     {f.file}")
        print(f"  Current:  {f.current_value}")
        print(f"  Expected: {f.expected_value}")
        print(f"  Status:   {f.status}")

