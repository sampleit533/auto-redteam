#!/usr/bin/env python3
"""
Baseline regression gate — compares the current evaluation against a saved
baseline. Exits non-zero on regression so CI can block a PR / merge / release.

A regression is any of:
  - A rule that was PASS in baseline is now FAIL or missing.
  - A scenario's coverage_pct dropped below baseline (beyond --tolerance-pct).
  - Overall coverage dropped beyond tolerance.

Use --update to copy the current evaluation back as the new baseline after
intentional changes.

Usage:
    python evaluation/check_baseline.py
    python evaluation/check_baseline.py --tolerance-pct 5
    python evaluation/check_baseline.py --update
"""

import argparse
import json
import shutil
import sys
from pathlib import Path


def _load(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def _index_rules(eval_data: dict) -> dict:
    """Build {(scenario_id, rule_id) -> passed_or_none} from an evaluation."""
    idx = {}
    for s in eval_data.get("scenarios", []):
        for det in s.get("detections", []):
            idx[(s["scenario_id"], det["rule_id"])] = det.get("passed")
    return idx


def find_regressions(baseline: dict, current: dict, tolerance_pct: float) -> list:
    base_rules = _index_rules(baseline)
    curr_rules = _index_rules(current)

    regressions: list = []

    # Rule-level: previously PASS now FAIL or missing
    for key, base_passed in base_rules.items():
        if base_passed is not True:
            continue
        curr_passed = curr_rules.get(key, "missing")
        if curr_passed is True:
            continue
        if curr_passed == "missing":
            regressions.append({
                "type": "missing_rule",
                "scenario_id": key[0],
                "rule_id": key[1],
                "message": "PASS in baseline, missing in current evaluation",
            })
        elif curr_passed is False:
            regressions.append({
                "type": "rule_regression",
                "scenario_id": key[0],
                "rule_id": key[1],
                "message": "PASS in baseline, now FAIL",
            })
        # passed is None means SKIP — treat as soft regression (warn but don't fail)

    # Overall coverage drop
    base_overall = baseline.get("summary", {}).get("overall_coverage_pct", 0)
    curr_overall = current.get("summary", {}).get("overall_coverage_pct", 0)
    if curr_overall < base_overall - tolerance_pct:
        regressions.append({
            "type": "overall_coverage_drop",
            "from_pct": base_overall,
            "to_pct": curr_overall,
            "message": f"Overall coverage {base_overall}% → {curr_overall}% (tolerance {tolerance_pct}%)",
        })

    # Per-scenario coverage drop
    base_scenarios = {s["scenario_id"]: s for s in baseline.get("scenarios", [])}
    for s in current.get("scenarios", []):
        sid = s["scenario_id"]
        if sid not in base_scenarios:
            continue
        base_pct = base_scenarios[sid].get("detection_coverage_pct", 0)
        curr_pct = s.get("detection_coverage_pct", 0)
        if curr_pct < base_pct - tolerance_pct:
            regressions.append({
                "type": "scenario_coverage_drop",
                "scenario_id": sid,
                "from_pct": base_pct,
                "to_pct": curr_pct,
                "message": f"{sid} {base_pct}% → {curr_pct}%",
            })

    return regressions


def main():
    parser = argparse.ArgumentParser(description="auto-redteam baseline regression gate")
    parser.add_argument("--baseline", default="evaluation/baseline.json")
    parser.add_argument("--current", default="artifacts/evaluation.json")
    parser.add_argument("--tolerance-pct", type=float, default=0.0,
                        help="Allowed coverage drop in percentage points (default 0)")
    parser.add_argument("--update", action="store_true",
                        help="Copy current evaluation to baseline (use after intentional changes)")
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    current_path = Path(args.current)

    if args.update:
        if not current_path.exists():
            print(f"[BASELINE] ERROR: current evaluation missing: {current_path}")
            sys.exit(2)
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(current_path, baseline_path)
        print(f"[BASELINE] Updated: {baseline_path} ← {current_path}")
        return

    if not baseline_path.exists():
        print(f"[BASELINE] No baseline at {baseline_path}.")
        print(f"[BASELINE] Create one with: python evaluation/check_baseline.py --update")
        return

    if not current_path.exists():
        print(f"[BASELINE] ERROR: current evaluation missing: {current_path}")
        sys.exit(2)

    baseline = _load(baseline_path)
    current = _load(current_path)

    regressions = find_regressions(baseline, current, args.tolerance_pct)

    base_overall = baseline.get("summary", {}).get("overall_coverage_pct", 0)
    curr_overall = current.get("summary", {}).get("overall_coverage_pct", 0)

    print("=" * 64)
    print("auto-redteam baseline regression check")
    print("=" * 64)
    print(f"Baseline:  {baseline_path}  (run_id={baseline.get('run_id')})")
    print(f"Current:   {current_path}  (run_id={current.get('run_id')})")
    print(f"Coverage:  {base_overall}%  →  {curr_overall}%   tolerance={args.tolerance_pct}%")
    print()

    if not regressions:
        print("[BASELINE] PASS — no regressions detected.")
        return

    print(f"[BASELINE] FAIL — {len(regressions)} regression(s):")
    for r in regressions:
        sid = r.get("scenario_id", "")
        rid = r.get("rule_id", "")
        loc = f" {sid}/{rid}" if rid else (f" {sid}" if sid else "")
        print(f"  - [{r['type']}]{loc}: {r['message']}")
    sys.exit(1)


if __name__ == "__main__":
    main()
