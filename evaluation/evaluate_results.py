#!/usr/bin/env python3
"""
Detection evaluator.

Computes coverage by matching the observables recorded in results.json
against the expected checks in expected_mappings.yaml.
No external Elasticsearch required — works entirely from simulation output.

Usage:
    python evaluate_results.py \
        --results artifacts/results.json \
        --mappings evaluation/expected_mappings.yaml \
        --out artifacts/evaluation.json
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml


def load_mappings(path: str) -> dict:
    with open(path) as f:
        data = yaml.safe_load(f)
    return {m["scenario_id"]: m for m in data.get("mappings", [])}


def load_results(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _build_event_sequence(observables: list) -> list:
    sequence = []
    for obs in observables:
        if obs.get("type") != "cloudtrail_log":
            continue
        sequence.append(
            {
                "event_name": obs.get("event_name", ""),
                "principal": obs.get("principal"),
                "resource": obs.get("resource"),
                "event_time": obs.get("event_time"),
            }
        )
    sequence.sort(key=lambda event: event.get("event_time") or 0)
    return sequence


def _evaluate_composite(det: dict, detection_results: list, event_sequence: list) -> dict:
    requires = det.get("requires", [])
    passed_ids = {r["rule_id"] for r in detection_results if r.get("passed") is True}
    skipped_ids = {r["rule_id"] for r in detection_results if r.get("passed") is None}
    effective_requires = [rule_id for rule_id in requires if rule_id not in skipped_ids]
    base_pass = bool(effective_requires) and all(rule_id in passed_ids for rule_id in effective_requires)

    principal = None
    sequence_seconds = None
    if base_pass and event_sequence:
        matching_events = [event for event in event_sequence if event["event_name"] in {"CreateRole", "AttachRolePolicy", "CreateAccessKey"}]
        principal_groups = {}
        for event in matching_events:
            key = event.get("principal") or "unknown"
            principal_groups.setdefault(key, []).append(event)

        for candidate_principal, events in principal_groups.items():
            ordered_names = [event["event_name"] for event in events]
            if all(name in ordered_names for name in ("CreateRole", "AttachRolePolicy", "CreateAccessKey")):
                relevant = [event for event in events if event["event_name"] in ("CreateRole", "AttachRolePolicy", "CreateAccessKey")]
                relevant.sort(key=lambda event: event.get("event_time") or 0)
                first_time = relevant[0].get("event_time")
                last_time = relevant[-1].get("event_time")
                if first_time is None or last_time is None:
                    principal = candidate_principal
                    sequence_seconds = None
                    break
                window = det.get("window_seconds")
                duration = round(last_time - first_time, 3)
                if window is None or duration <= window:
                    principal = candidate_principal
                    sequence_seconds = duration
                    break

    passed = base_pass and principal is not None
    return {
        "rule_id": det["rule_id"],
        "description": det.get("description", ""),
        "composite": True,
        "requires": requires,
        "principal": principal,
        "sequence_window_seconds": sequence_seconds,
        "passed": passed,
    }


def evaluate_scenario(scenario_result: dict, mapping: dict) -> dict:
    observables = scenario_result.get("observables_generated", [])
    event_sequence = _build_event_sequence(observables)

    # Count occurrences of each (type, pattern) pair
    log_counts: Counter = Counter()
    event_counts: Counter = Counter()
    for obs in observables:
        obs_type = obs.get("type", "")
        if obs_type == "auth_log":
            log_counts[obs.get("pattern", "")] += 1
        elif obs_type == "cloudtrail_log":
            event_counts[obs.get("event_name", "")] += 1

    detection_results = []
    composite_deps: dict = {}

    for det in mapping.get("required_detections", []):
        rule_id = det["rule_id"]
        description = det.get("description", "")

        if det.get("composite"):
            composite_deps[rule_id] = det
            continue

        # SIEM alert checks require a live SIEM — skip in CI, mark as N/A
        if det.get("type") == "siem_alert" or "siem_alert" in rule_id.lower():
            detection_results.append({
                "rule_id": rule_id,
                "description": description,
                "status": "skipped",
                "reason": "Requires live SIEM (not available in CI)",
                "passed": None,  # excluded from coverage calculation
            })
            continue

        # Match against observables
        min_hits = det.get("min_hits", 1)
        hit_count = 0

        # auth_log checks
        if "auth_log" in det.get("index_pattern", "") or any(
            k in (det.get("query") or {}).get("bool", {}).get("must", [{}])[0].get("match", {})
            for k in ["message"]
        ):
            # Extract pattern from query
            must_clauses = (det.get("query") or {}).get("bool", {}).get("must", [])
            pattern = None
            for clause in must_clauses:
                if "match" in clause and "message" in clause["match"]:
                    pattern = clause["match"]["message"]
                    break
            if pattern:
                hit_count = log_counts.get(pattern, 0)

        # cloudtrail checks
        elif "cloudtrail" in det.get("index_pattern", ""):
            must_clauses = (det.get("query") or {}).get("bool", {}).get("must", [])
            event_name = None
            for clause in must_clauses:
                if "match" in clause and "eventName" in clause["match"]:
                    event_name = clause["match"]["eventName"]
                    break
            if event_name:
                hit_count = event_counts.get(event_name, 0)

        passed = hit_count >= min_hits
        detection_results.append({
            "rule_id": rule_id,
            "description": description,
            "hit_count": hit_count,
            "min_hits": min_hits,
            "passed": passed,
        })

    # Evaluate composite rules
    for rule_id, det in composite_deps.items():
        detection_results.append(_evaluate_composite(det, detection_results, event_sequence))

    # Coverage = passed / (total excluding skipped)
    countable = [r for r in detection_results if r.get("passed") is not None]
    total = len(countable)
    passed_count = sum(1 for r in countable if r["passed"])
    coverage_pct = round((passed_count / total) * 100, 1) if total > 0 else 0.0

    return {
        "scenario_id": scenario_result["scenario_id"],
        "mitre_ttp": mapping.get("mitre_ttp", ""),
        "status": scenario_result.get("status"),
        "detection_coverage_pct": coverage_pct,
        "passed": passed_count,
        "total": total,
        "detections": detection_results,
        "sim_start": scenario_result.get("started_at", ""),
        "sim_end": scenario_result.get("finished_at", ""),
        "details": scenario_result.get("details", {}),
        "event_sequence": event_sequence,
    }


def main():
    parser = argparse.ArgumentParser(description="auto-redteam detection evaluator")
    parser.add_argument("--results", default="artifacts/results.json")
    parser.add_argument("--mappings", default="evaluation/expected_mappings.yaml")
    parser.add_argument("--out", default="artifacts/evaluation.json")
    args = parser.parse_args()

    results = load_results(args.results)
    mappings = load_mappings(args.mappings)

    eval_results = []
    for scenario in results.get("scenarios", []):
        sid = scenario["scenario_id"]
        if scenario.get("status") == "dry-run":
            print(f"[EVAL] Skipping {sid} (dry-run)")
            continue
        mapping = mappings.get(sid)
        if not mapping:
            print(f"[EVAL] No mapping found for {sid}, skipping")
            continue
        print(f"\n[EVAL] Evaluating: {sid}")
        result = evaluate_scenario(scenario, mapping)
        eval_results.append(result)
        print(f"  Coverage: {result['detection_coverage_pct']}%  ({result['passed']}/{result['total']} checks passed)")
        for det in result["detections"]:
            status = "PASS" if det.get("passed") is True else ("SKIP" if det.get("passed") is None else "FAIL")
            hits = det.get("hit_count", "—")
            print(f"    [{status}] {det['rule_id']}  hits={hits}")

    total_detections = sum(e["total"] for e in eval_results)
    total_passed = sum(e["passed"] for e in eval_results)
    overall = round((total_passed / total_detections) * 100, 1) if total_detections > 0 else 0.0

    output = {
        "run_id": results.get("run_id"),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "scenarios_evaluated": len(eval_results),
            "total_detection_checks": total_detections,
            "passed": total_passed,
            "overall_coverage_pct": overall,
        },
        "scenarios": eval_results,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n[EVAL] Overall coverage: {overall}%")
    print(f"[EVAL] Written to {out_path}")

    if overall < 50:
        print("[EVAL] WARNING: Coverage below 50%")
        sys.exit(1)


if __name__ == "__main__":
    main()
