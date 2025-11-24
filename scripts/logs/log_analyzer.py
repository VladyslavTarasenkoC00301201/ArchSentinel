from __future__ import annotations

import argparse
from typing import Dict, List, Optional

from results import DetectionResult, LogAnalysisResult
from sources import read_auth_log
from parser import parse_all_events
from detections import DETECTION_REGISTRY, DEFAULT_DETECTION_CONFIG, DetectionFn


def analyze_logs(
    enabled_rules: Optional[List[str]] = None,
    rule_config_overrides: Optional[Dict[str, Dict]] = None,
) -> LogAnalysisResult:
    """
    Core API: read system auth logs, parse events, run detection rules.

    - enabled_rules: list of rule IDs from DETECTION_REGISTRY to execute.
                     If None, all registered rules are run.
    - rule_config_overrides: per-rule config overrides merged onto defaults.
    """
    lines = list(read_auth_log())
    events = parse_all_events(lines)

    if enabled_rules is None:
        enabled_rules = list(DETECTION_REGISTRY.keys())

    # merge default config + overrides
    rule_configs: Dict[str, Dict] = {}
    rule_configs.update(DEFAULT_DETECTION_CONFIG)
    if rule_config_overrides:
        for rid, cfg in rule_config_overrides.items():
            base = rule_configs.get(rid, {})
            merged = {**base, **cfg}
            rule_configs[rid] = merged

    detections: List[DetectionResult] = []

    for rule_id in enabled_rules:
        # NOTE: no explicit type here; .get() can return None
        rule_fn = DETECTION_REGISTRY.get(rule_id)
        if rule_fn is None:
            continue
        cfg = rule_configs.get(rule_id, {})
        detections.extend(rule_fn(events, cfg))

    return LogAnalysisResult(events=events, detections=detections)


def print_debug_stats(result: LogAnalysisResult) -> None:
    print(f"DEBUG: parsed {len(result.events)} events")
    print(f"DEBUG: produced {len(result.detections)} detections")


def print_detections(detections: List[DetectionResult]) -> None:
    if not detections:
        print("No suspicious activity detected in logs.")
        return

    print("=== Log Detections ===\n")

    for det in detections:
        print(f"[{det.severity.upper()}] {det.id} - {det.description}")
        print(f"  Evidence: {det.evidence}")
        for ev in det.events[:5]:
            src = ev.source
            ip = ev.fields.get("ip", "?")
            user = ev.fields.get("user", "?")
            print(f"    {ev.timestamp} source={src} ip={ip} user={user}")
            print(f"      {ev.message}")
        if len(det.events) > 5:
            print(f"    ... and {len(det.events) - 5} more related events")
        print()


def _parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel log analyzer (SSH + sudo, system logs only).",
    )
    parser.add_argument(
        "--rules",
        help=(
            "Comma-separated list of rule IDs to run "
            f"(available: {', '.join(sorted(DETECTION_REGISTRY.keys()))})"
        ),
        default=None,
    )
    parser.add_argument(
        "--no-debug",
        help="Hide debug statistics (event / detection counts).",
        action="store_true",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_cli_args()

    enabled_rules: Optional[List[str]] = None
    if args.rules:
        enabled_rules = [
            r.strip()
            for r in args.rules.split(",")
            if r.strip() in DETECTION_REGISTRY
        ]
        if not enabled_rules:
            print("No valid rules specified, running all.")
            enabled_rules = None

    result = analyze_logs(enabled_rules=enabled_rules)

    if not args.no_debug:
        print_debug_stats(result)
    print_detections(result.detections)


if __name__ == "__main__":
    main()

