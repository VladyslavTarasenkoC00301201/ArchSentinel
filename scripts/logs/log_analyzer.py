from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any

from .results import DetectionResult, LogAnalysisResult
from .sources import read_auth_log
from .parser import parse_all_events
from .detections import DETECTION_REGISTRY, DEFAULT_DETECTION_CONFIG
from .config_loader import load_yaml_dict


# ---------------------------------------------------------------------------
# View config loading (views.yaml)
# ---------------------------------------------------------------------------


def load_views(filename: str = "views.yaml") -> Dict[str, Dict[str, Any]]:
    """
    Load view definitions from a YAML file.

    Schema:

        views:
          default:
            sort:
              by: timestamp | none
              order: asc | desc
            max_events_per_detection: 0   # 0 or missing = unlimited
            per_source:
              ssh:
                show_fields: [timestamp, user, ip, status]
              sudo:
                show_fields: [timestamp, user, target_user, command]

    Returns:
        dict[view_name] -> view_config
    """
    data = load_yaml_dict(filename)
    if not data:
        return {}

    raw_views = data.get("views") or {}
    if not isinstance(raw_views, dict):
        return {}

    views: Dict[str, Dict[str, Any]] = {}

    for name, cfg in raw_views.items():
        if not isinstance(cfg, dict):
            continue
        sort_cfg = cfg.get("sort") or {}
        if not isinstance(sort_cfg, dict):
            sort_cfg = {}
        by = str(sort_cfg.get("by", "timestamp"))
        order = str(sort_cfg.get("order", "asc")).lower()
        if by not in ("timestamp", "none"):
            by = "timestamp"
        if order not in ("asc", "desc"):
            order = "asc"

        max_ev = cfg.get("max_events_per_detection", 0)
        try:
            max_ev_int = int(max_ev)
        except Exception:
            max_ev_int = 0

        per_source = cfg.get("per_source") or {}
        if not isinstance(per_source, dict):
            per_source = {}

        views[name] = {
            "sort": {"by": by, "order": order},
            "max_events_per_detection": max_ev_int,
            "per_source": per_source,
        }

    return views


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze_logs(
    enabled_rules: Optional[List[str]] = None,
    rule_config_overrides: Optional[Dict[str, Dict]] = None,
) -> LogAnalysisResult:
    """
    High-level API: read auth logs, parse them into LogEvent objects, and run
    all enabled detection rules.

    This function is intentionally free of any CLI / printing logic so it can
    be reused by other frontends (tests, future GUI, JSON exporter, etc.).
    """
    lines = list(read_auth_log())
    events = parse_all_events(lines)

    # Decide which rules to run
    if enabled_rules is None:
        rule_ids = list(DETECTION_REGISTRY.keys())
    else:
        rule_ids = [rid for rid in enabled_rules if rid in DETECTION_REGISTRY]

    # Merge default configs with overrides
    rule_configs: Dict[str, Dict] = dict(DEFAULT_DETECTION_CONFIG)
    if rule_config_overrides:
        for rid, override in rule_config_overrides.items():
            base = rule_configs.get(rid, {})
            merged = {**base, **override}
            rule_configs[rid] = merged

    detections: List[DetectionResult] = []

    for rid in rule_ids:
        rule_fn = DETECTION_REGISTRY.get(rid)
        if not rule_fn:
            continue
        cfg = rule_configs.get(rid, {})
        detections.extend(rule_fn(events, cfg))

    return LogAnalysisResult(events=events, detections=detections)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def print_debug_stats(result: LogAnalysisResult) -> None:
    """
    Print some quick stats about parsed events. Useful when tuning rules.
    """
    total = len(result.events)
    by_source: Dict[str, int] = {}
    for ev in result.events:
        by_source[ev.source] = by_source.get(ev.source, 0) + 1

    print("=== Debug stats ===")
    print(f"Total parsed events: {total}")
    if not by_source:
        print("No events parsed.")
    else:
        print("Events by source:")
        for src, count in sorted(by_source.items()):
            print(f"  {src}: {count}")
    print()


def _format_event_line(ev, show_fields: List[str]) -> str:
    """
    Build a single human-readable line for an event according to show_fields.
    'timestamp' is rendered as ISO, everything else as key=value.
    """
    parts: List[str] = []

    # If timestamp is requested, show it first
    if "timestamp" in show_fields:
        ts = ev.timestamp.isoformat(sep=" ", timespec="seconds")
        parts.append(ts)

    for field in show_fields:
        if field == "timestamp":
            continue
        if field == "host":
            value = ev.host
        elif field == "source":
            value = ev.source
        elif field == "program":
            value = ev.program or ""
        elif field == "pid":
            value = str(ev.pid) if ev.pid is not None else ""
        else:
            # Look into the normalised fields dictionary
            value = ev.fields.get(field, "")
        if value is None:
            value = ""
        parts.append(f"{field}={value}")

    return " ".join(parts)


def print_detections(
    detections: List[DetectionResult],
    view_cfg: Dict[str, Any],
    cli_max_events_per_detection: int = 0,
) -> None:
    """
    Human-readable output for detections using a view configuration.

    Priority for max events:
      - if cli_max_events_per_detection > 0 -> use that
      - else if view_cfg[max_events_per_detection] > 0 -> use that
      - else -> unlimited
    """
    if not detections:
        print("No detections.")
        return

    sort_cfg = view_cfg.get("sort", {}) or {}
    sort_by = sort_cfg.get("by", "timestamp")
    sort_order = sort_cfg.get("order", "asc")
    per_source = view_cfg.get("per_source", {}) or {}

    # Decide max events per detection
    if cli_max_events_per_detection and cli_max_events_per_detection > 0:
        max_events = cli_max_events_per_detection
    else:
        max_events = int(view_cfg.get("max_events_per_detection", 0))

    print("=== Detections ===")
    for det in detections:
        print(f"[{det.severity.upper()}] {det.id} - {det.description}")
        print(f"  Evidence: {det.evidence}")
        print(f"  Related events: {len(det.events)}")

        events = det.events

        # Sort events inside detection according to view
        if sort_by == "timestamp":
            reverse = sort_order == "desc"
            events = sorted(events, key=lambda e: e.timestamp, reverse=reverse)

        # Determine how many to show
        if max_events and max_events > 0 and len(events) > max_events:
            to_show = events[:max_events]
            remaining = len(events) - max_events
        else:
            to_show = events
            remaining = 0

        for ev in to_show:
            # Pick show_fields for this source, or a sensible default
            src_cfg = per_source.get(ev.source, {})
            show_fields = src_cfg.get("show_fields")
            if not show_fields:
                show_fields = ["timestamp", "host", "user", "ip", "source"]
            line = _format_event_line(ev, show_fields)
            print(f"    {line}")

        if remaining > 0:
            print(
                f"    ... {remaining} more event(s) omitted "
                f"(use --max-events-per-detection 0 and/or adjust view to see all)"
            )

        print()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Config-driven log analyzer for SSH/sudo auth events.",
    )
    parser.add_argument(
        "--rules",
        help=(
            "Comma-separated list of rule IDs to run. "
            "If omitted, all available rules (built-in + YAML) are executed."
        ),
    )
    parser.add_argument(
        "--no-debug",
        action="store_true",
        help="Do not print debug stats about parsed events.",
    )
    parser.add_argument(
        "--view",
        default="default",
        help=(
            "Named view from views.yaml to control how detections/events are shown. "
            "If views.yaml is missing or the view is not found, a built-in default is used."
        ),
    )
    parser.add_argument(
        "--max-events-per-detection",
        type=int,
        default=0,
        help=(
            "Override view's max events per detection. "
            "0 = use view.yaml setting (or unlimited if not set)."
        ),
    )
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # Load views from YAML
    views = load_views()
    view_cfg: Dict[str, Any]

    if not views:
        # Built-in fallback view if views.yaml is missing or invalid
        view_cfg = {
            "sort": {"by": "timestamp", "order": "asc"},
            "max_events_per_detection": 0,
            "per_source": {},
        }
    else:
        requested = args.view or "default"
        print(requested)
        if requested not in views:
            print(
                f"WARNING: view '{requested}' not found in views.yaml; "
                f"using first available view instead."
            )
            # Pick an arbitrary but stable view (first key)
            first_name = sorted(views.keys())[0]
            view_cfg = views[first_name]
        else:
            view_cfg = views[requested]

    enabled_rules: Optional[List[str]] = None
    if args.rules:
        enabled_rules = [rid.strip() for rid in args.rules.split(",") if rid.strip()]
        unknown = [rid for rid in enabled_rules if rid not in DETECTION_REGISTRY]
        if unknown:
            print(
                "WARNING: unknown rule id(s): "
                + ", ".join(sorted(unknown))
            )
            enabled_rules = [rid for rid in enabled_rules if rid in DETECTION_REGISTRY]
        if not enabled_rules:
            print("No valid rules specified, running all.")
            enabled_rules = None

    result = analyze_logs(enabled_rules=enabled_rules)

    if not args.no_debug:
        print_debug_stats(result)

    print_detections(
        result.detections,
        view_cfg=view_cfg,
        cli_max_events_per_detection=args.max_events_per_detection,
    )


if __name__ == "__main__":
    main()

