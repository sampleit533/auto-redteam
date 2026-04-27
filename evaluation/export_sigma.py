#!/usr/bin/env python3
"""
Sigma rule exporter — reads `evaluation/expected_mappings.yaml` and
produces industry-standard Sigma detection rules under `sigma/`.

Bridges the academic auto-redteam evaluator with the broader
detection-engineering ecosystem (Sigma → Splunk / ES / Sentinel via
the official Sigma converter).

Usage:
    python evaluation/export_sigma.py
    python evaluation/export_sigma.py --out-dir sigma
"""

import argparse
import re
import uuid
from datetime import date
from pathlib import Path

import yaml


# Stable namespace so repeated exports produce deterministic Sigma IDs.
NAMESPACE = uuid.UUID("0c5e0e3c-7b1a-5d2f-90ab-cdef00000001")

MITRE_TAGS = {
    "T1110.001": ["attack.credential_access", "attack.t1110.001"],
    "T1078.004": ["attack.persistence", "attack.privilege_escalation",
                  "attack.t1078.004"],
    "T1021":     ["attack.lateral_movement", "attack.t1021"],
    "T1530":     ["attack.collection", "attack.t1530"],
    "T1195.001": ["attack.initial_access", "attack.t1195.001"],
    "T1046":     ["attack.discovery", "attack.t1046"],
}

# Map our internal observable types to Sigma logsource shapes
LOGSOURCES = {
    "auth_log":       {"product": "linux", "service": "auth"},
    "cloudtrail_log": {"product": "aws",   "service": "cloudtrail"},
    "s3_access_log":  {"product": "aws",   "service": "s3"},
    "audit_log":      {"product": "github", "service": "audit"},
    "connection_log": {"category": "network_connection"},
    "scan_log":       {"category": "network_connection"},
    "nids_alert":     {"category": "ids", "product": "auto-redteam-nids-lite"},
}


def _stable_uuid(scenario_id: str, rule_id: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{scenario_id}/{rule_id}"))


def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def _title_case(rule_id: str) -> str:
    return rule_id.replace("_", " ").title()


def _convert_legacy_query(det: dict) -> dict:
    """Extract field/value selection from ES-query-style mapping (T1/T2)."""
    must = (det.get("query") or {}).get("bool", {}).get("must", [])
    selection = {}
    for clause in must:
        if "match" in clause:
            for key, value in clause["match"].items():
                if key == "eventName":
                    # Sigma uses EventName for cloudtrail
                    selection["EventName"] = value
                elif key == "message":
                    selection["message|contains"] = value
                else:
                    selection[key] = value
    return selection


def _infer_observable_type(det: dict) -> str:
    if det.get("observable_type"):
        return det["observable_type"]
    idx = det.get("index_pattern", "")
    if "auth" in idx or "logs" in idx:
        return "auth_log"
    if "cloudtrail" in idx:
        return "cloudtrail_log"
    return "unknown"


def build_sigma(scenario_id: str, mitre_ttp: str, det: dict) -> dict | None:
    """Return a dict ready to be dumped as a Sigma rule, or None to skip."""
    rule_id = det["rule_id"]

    # Skip composite rules — Sigma's correlation extension is rule-of-rules
    # and not a clean 1-to-1 export from our composite definition.
    if det.get("composite"):
        return None

    # Skip pure live-SIEM placeholders that have no detection logic of their own
    if det.get("type") == "siem_alert":
        return None

    obs_type = _infer_observable_type(det)
    logsource = LOGSOURCES.get(obs_type, {"product": "unknown"})

    if "observable_type" in det:
        match_field = det.get("match_field")
        match_value = det.get("match_value")
        selection = {match_field: match_value} if match_field is not None else {}
    else:
        selection = _convert_legacy_query(det)

    # Sigma condition. Threshold rules use `count()` aggregation.
    if det.get("unique_field"):
        n = int(det.get("min_unique", 1))
        condition = f"selection | count(unique:{det['unique_field']}) > {n - 1}"
    else:
        n = int(det.get("min_hits", 1))
        condition = f"selection | count() > {n - 1}" if n > 1 else "selection"

    description = det.get("description", "").strip() or _title_case(rule_id)
    references = []
    if mitre_ttp:
        references.append(
            f"https://attack.mitre.org/techniques/{mitre_ttp.replace('.', '/')}/"
        )
    references.append(
        f"https://github.com/auto-redteam/scenarios/{scenario_id}"
    )

    return {
        "title": _title_case(rule_id),
        "id": _stable_uuid(scenario_id, rule_id),
        "status": "experimental",
        "description": description,
        "references": references,
        "author": "auto-redteam (capstone)",
        "date": date.today().isoformat(),
        "tags": MITRE_TAGS.get(mitre_ttp, [f"attack.{mitre_ttp.lower()}"] if mitre_ttp else []),
        "logsource": logsource,
        "detection": {
            "selection": selection,
            "condition": condition,
        },
        "falsepositives": [
            "Legitimate automation, scheduled jobs, or sanctioned red-team exercises.",
        ],
        "level": "medium",
    }


def main():
    parser = argparse.ArgumentParser(description="Export auto-redteam mappings as Sigma rules")
    parser.add_argument("--mappings", default="evaluation/expected_mappings.yaml")
    parser.add_argument("--out-dir", default="sigma")
    args = parser.parse_args()

    with open(args.mappings) as f:
        data = yaml.safe_load(f)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    skipped = 0
    for mapping in data.get("mappings", []):
        scenario_id = mapping["scenario_id"]
        mitre_ttp = mapping.get("mitre_ttp", "")
        for det in mapping.get("required_detections", []):
            sigma = build_sigma(scenario_id, mitre_ttp, det)
            if sigma is None:
                skipped += 1
                continue
            slug = _slugify(f"{scenario_id}__{det['rule_id']}")
            out_path = out_dir / f"{slug}.yml"
            with open(out_path, "w") as f:
                yaml.dump(sigma, f, sort_keys=False, default_flow_style=False, allow_unicode=True)
            written += 1

    print(f"[SIGMA] Exported {written} rule(s), skipped {skipped} composite/siem-alert → {out_dir}/")


if __name__ == "__main__":
    main()
