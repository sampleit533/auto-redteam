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


EVENT_LIKE_TYPES = ("cloudtrail_log", "s3_access_log", "audit_log")


def _build_event_sequence(observables: list) -> list:
    """Flatten event-like observables into a time-sorted sequence."""
    sequence = []
    for obs in observables:
        if obs.get("type") not in EVENT_LIKE_TYPES:
            continue
        sequence.append(
            {
                "event_name": obs.get("event_name", ""),
                "principal": obs.get("principal") or obs.get("actor"),
                "resource": obs.get("resource"),
                "event_time": obs.get("event_time"),
                "observable_type": obs.get("type"),
            }
        )
    sequence.sort(key=lambda event: event.get("event_time") or 0)
    return sequence


def _match_observable(det: dict, observables: list) -> dict:
    """Direct observable-style matching (used by T3-T6).

    Supported fields in mapping:
      observable_type   – required, e.g. "connection_log"
      match_field       – optional, e.g. "pattern" or "event_name"
      match_value       – optional, value to compare against
      min_hits          – optional, minimum count of matching observables
      unique_field      – optional, count distinct values of this field
      min_unique        – required when unique_field is set
    """
    obs_type = det["observable_type"]
    match_field = det.get("match_field")
    match_value = det.get("match_value")

    matching = []
    for obs in observables:
        if obs.get("type") != obs_type:
            continue
        if match_field is not None and obs.get(match_field) != match_value:
            continue
        matching.append(obs)

    unique_field = det.get("unique_field")
    if unique_field is not None:
        unique_values = {
            obs.get(unique_field) for obs in matching if obs.get(unique_field) is not None
        }
        min_unique = int(det.get("min_unique", 1))
        passed = len(unique_values) >= min_unique
        return {
            "rule_id": det["rule_id"],
            "description": det.get("description", ""),
            "hit_count": len(unique_values),
            "min_hits": min_unique,
            "unique_field": unique_field,
            "passed": passed,
        }

    min_hits = int(det.get("min_hits", 1))
    hit_count = len(matching)
    return {
        "rule_id": det["rule_id"],
        "description": det.get("description", ""),
        "hit_count": hit_count,
        "min_hits": min_hits,
        "passed": hit_count >= min_hits,
    }


def _evaluate_composite(det: dict, detection_results: list, observables: list) -> dict:
    """Composite rule: all required sub-rules pass + same actor within window.

    Configurable via YAML mapping:
      requires              – list of sub-rule_ids that must pass
      group_by              – field used to group events by actor (default: "principal")
      observable_types      – list of observable types to consider (default: ["cloudtrail_log"])
      required_event_names  – event_names that must appear in the same group
                              (default: T2's CreateRole+AttachRolePolicy+CreateAccessKey)
      window_seconds        – max span between first and last event in the group
    """
    requires = det.get("requires", [])
    passed_ids = {r["rule_id"] for r in detection_results if r.get("passed") is True}
    skipped_ids = {r["rule_id"] for r in detection_results if r.get("passed") is None}
    effective_requires = [rule_id for rule_id in requires if rule_id not in skipped_ids]
    base_pass = bool(effective_requires) and all(rule_id in passed_ids for rule_id in effective_requires)

    group_by = det.get("group_by", "principal")
    relevant_types = det.get("observable_types", ["cloudtrail_log"])
    required_event_names = det.get(
        "required_event_names",
        ["CreateRole", "AttachRolePolicy", "CreateAccessKey"],
    )
    window = det.get("window_seconds")

    # Filter observables down to the configured types & event names
    candidates = []
    for obs in observables:
        if obs.get("type") not in relevant_types:
            continue
        if obs.get("event_name") not in required_event_names:
            continue
        candidates.append(obs)

    # Group by configured field (fall back to "principal" if group_by missing)
    groups: dict = {}
    for ev in candidates:
        key = ev.get(group_by) or ev.get("principal") or "unknown"
        groups.setdefault(key, []).append(ev)

    matched_actor = None
    sequence_seconds = None
    if base_pass:
        for actor, events in groups.items():
            event_names = {ev.get("event_name") for ev in events}
            if not all(name in event_names for name in required_event_names):
                continue
            ordered = sorted(events, key=lambda e: e.get("event_time") or 0)
            first_t = ordered[0].get("event_time")
            last_t = ordered[-1].get("event_time")
            if first_t is None or last_t is None:
                matched_actor = actor
                break
            duration = round(last_t - first_t, 3)
            if window is None or duration <= window:
                matched_actor = actor
                sequence_seconds = duration
                break

    passed = base_pass and matched_actor is not None
    return {
        "rule_id": det["rule_id"],
        "description": det.get("description", ""),
        "composite": True,
        "requires": requires,
        "group_by": group_by,
        "principal": matched_actor,
        "sequence_window_seconds": sequence_seconds,
        "passed": passed,
    }


def evaluate_scenario(scenario_result: dict, mapping: dict) -> dict:
    observables = scenario_result.get("observables_generated", [])
    event_sequence = _build_event_sequence(observables)

    # Legacy counters (T1, T2 use the ES-query style with these)
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

        # SIEM alert checks require a live SIEM — skip in CI
        if det.get("type") == "siem_alert":
            detection_results.append({
                "rule_id": rule_id,
                "description": description,
                "status": "skipped",
                "reason": "Requires live SIEM (not available in CI)",
                "passed": None,
            })
            continue

        # New-style direct observable matching (T3-T6)
        if "observable_type" in det:
            detection_results.append(_match_observable(det, observables))
            continue

        # Legacy ES-query style (T1, T2)
        min_hits = det.get("min_hits", 1)
        hit_count = 0

        if "auth_log" in det.get("index_pattern", "") or any(
            k in (det.get("query") or {}).get("bool", {}).get("must", [{}])[0].get("match", {})
            for k in ["message"]
        ):
            must_clauses = (det.get("query") or {}).get("bool", {}).get("must", [])
            pattern = None
            for clause in must_clauses:
                if "match" in clause and "message" in clause["match"]:
                    pattern = clause["match"]["message"]
                    break
            if pattern:
                hit_count = log_counts.get(pattern, 0)
        elif "cloudtrail" in det.get("index_pattern", ""):
            must_clauses = (det.get("query") or {}).get("bool", {}).get("must", [])
            event_name = None
            for clause in must_clauses:
                if "match" in clause and "eventName" in clause["match"]:
                    event_name = clause["match"]["eventName"]
                    break
            if event_name:
                hit_count = event_counts.get(event_name, 0)

        # Legacy SIEM-alert heuristic (only when no observable_type configured)
        if "siem_alert" in rule_id.lower():
            detection_results.append({
                "rule_id": rule_id,
                "description": description,
                "status": "skipped",
                "reason": "Requires live SIEM (not available in CI)",
                "passed": None,
            })
            continue

        passed = hit_count >= min_hits
        detection_results.append({
            "rule_id": rule_id,
            "description": description,
            "hit_count": hit_count,
            "min_hits": min_hits,
            "passed": passed,
        })

    # Evaluate composite rules (pass full observables for configurable correlation)
    for rule_id, det in composite_deps.items():
        detection_results.append(_evaluate_composite(det, detection_results, observables))

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

    # Append to history for multi-run trend reporting
    history_dir = out_path.parent / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    history_id = output.get("run_id") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    history_path = history_dir / f"{history_id}.json"
    with open(history_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[EVAL] Appended to history: {history_path}")

    if overall < 50:
        print("[EVAL] WARNING: Coverage below 50%")
        sys.exit(1)


if __name__ == "__main__":
    main()
