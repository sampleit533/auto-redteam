#!/usr/bin/env python3
"""
Multi-run trend dashboard — reads all evaluation.json files in
artifacts/history/ and renders an HTML page showing detection-coverage
trend over time, per-scenario history, and recent regressions.

Usage:
    python reporting/generate_trends.py \
        --history artifacts/history \
        --template reporting/templates/trends.html.j2 \
        --out artifacts/trends.html
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def load_history(history_dir: Path) -> list:
    """Load all evaluation JSONs in the history dir, oldest first."""
    runs = []
    for path in sorted(history_dir.glob("*.json")):
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        # Normalize fields used by the template
        evaluated_at = data.get("evaluated_at")
        try:
            ts = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00")) if evaluated_at else None
        except (TypeError, ValueError):
            ts = None
        runs.append({
            "run_id": data.get("run_id") or path.stem,
            "evaluated_at": evaluated_at or "",
            "ts": ts,
            "summary": data.get("summary", {}),
            "scenarios": data.get("scenarios", []),
            "history_file": path.name,
        })
    runs.sort(key=lambda r: r["ts"] or datetime.min.replace(tzinfo=timezone.utc))
    return runs


def build_per_scenario(runs: list) -> dict:
    """Map scenario_id -> ordered list of {run_id, coverage_pct, passed, total}."""
    per_scenario: dict = {}
    for run in runs:
        for s in run["scenarios"]:
            sid = s["scenario_id"]
            per_scenario.setdefault(sid, []).append({
                "run_id": run["run_id"],
                "coverage_pct": s.get("detection_coverage_pct", 0.0),
                "passed": s.get("passed", 0),
                "total": s.get("total", 0),
                "mitre_ttp": s.get("mitre_ttp", ""),
                "ts": run["ts"],
            })
    return per_scenario


def build_overall_series(runs: list) -> list:
    return [
        {
            "run_id": r["run_id"],
            "coverage_pct": r["summary"].get("overall_coverage_pct", 0.0),
            "passed": r["summary"].get("passed", 0),
            "total": r["summary"].get("total_detection_checks", 0),
            "ts": r["ts"],
        }
        for r in runs
    ]


def detect_regressions(per_scenario: dict, recent: int = 5) -> list:
    """Find scenarios whose coverage dropped between any two adjacent recent runs."""
    regressions = []
    for sid, hist in per_scenario.items():
        recent_hist = hist[-recent:] if len(hist) >= 2 else hist
        for prev, curr in zip(recent_hist, recent_hist[1:]):
            if curr["coverage_pct"] < prev["coverage_pct"]:
                regressions.append({
                    "scenario_id": sid,
                    "from_run": prev["run_id"],
                    "to_run": curr["run_id"],
                    "from_pct": prev["coverage_pct"],
                    "to_pct": curr["coverage_pct"],
                })
    return regressions


def main():
    parser = argparse.ArgumentParser(description="auto-redteam trend report")
    parser.add_argument("--history", default="artifacts/history")
    parser.add_argument("--template", default="reporting/templates/trends.html.j2")
    parser.add_argument("--out", default="artifacts/trends.html")
    args = parser.parse_args()

    history_dir = Path(args.history)
    if not history_dir.exists():
        print(f"[TRENDS] No history at {history_dir}; nothing to render.")
        return

    runs = load_history(history_dir)
    if not runs:
        print(f"[TRENDS] History dir is empty; nothing to render.")
        return

    per_scenario = build_per_scenario(runs)
    overall_series = build_overall_series(runs)
    regressions = detect_regressions(per_scenario)

    template_path = Path(args.template)
    env = Environment(loader=FileSystemLoader(str(template_path.parent)))
    template = env.get_template(template_path.name)

    html = template.render(
        runs=runs,
        per_scenario=per_scenario,
        overall_series=overall_series,
        regressions=regressions,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        n_runs=len(runs),
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    print(f"[TRENDS] Rendered {len(runs)} runs ({len(per_scenario)} scenarios) → {out_path}")


if __name__ == "__main__":
    main()
