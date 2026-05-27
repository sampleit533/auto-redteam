#!/usr/bin/env python3
"""
auto-redteam simulation entry point.

Usage:
    python simulate.py --scenario t1_bruteforce_ssh --mode safe
    python simulate.py --scenario all --mode dry-run
    python simulate.py --list
"""

import argparse
import importlib
import json
import os
import sys
import time
import yaml
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment

SCENARIOS_DIR = Path(__file__).parent.parent / "scenarios"
RUNNERS_DIR = Path(__file__).parent / "scenarios"

SCENARIO_MODULE_MAP = {
    "t1_bruteforce_ssh": "t1_bruteforce",
    "t2_privilege_escalation": "t2_priv_escalation",
    "t3_lateral_movement": "t3_lateral_movement",
    "t4_data_exfiltration": "t4_data_exfiltration",
    "t5_ci_compromise": "t5_ci_compromise",
    "t6_network_recon": "t6_network_recon",
    "t7_log4shell_probe": "t7_log4shell_probe",
    "t8_cloud_recon": "t8_cloud_recon",
}

# Named scenario groups. `--scenario cloud` runs the AWS kill chain in order:
#   Discovery (t8) → Privilege Escalation (t2) → Exfiltration (t4)
# These three are the ones deployed to REAL AWS (see redteam-cloud-deploy.yml).
SCENARIO_GROUPS = {
    "cloud": [
        "t8_cloud_recon",
        "t2_privilege_escalation",
        "t4_data_exfiltration",
    ],
}


def load_scenario_def(scenario_id: str) -> dict:
    """Load scenario YAML definition."""
    # Map short IDs to file names
    yaml_name_map = {
        "t1_bruteforce_ssh": "T1_bruteforce_ssh.yaml",
        "t2_privilege_escalation": "T2_privilege_escalation.yaml",
        "t3_lateral_movement": "T3_lateral_movement.yaml",
        "t4_data_exfiltration": "T4_data_exfiltration.yaml",
        "t5_ci_compromise": "T5_ci_compromise.yaml",
        "t6_network_recon": "T6_network_recon.yaml",
        "t7_log4shell_probe": "T7_log4shell_probe.yaml",
        "t8_cloud_recon": "T8_cloud_recon.yaml",
    }
    yaml_file = SCENARIOS_DIR / yaml_name_map.get(scenario_id, f"{scenario_id}.yaml")
    if not yaml_file.exists():
        raise FileNotFoundError(f"Scenario definition not found: {yaml_file}")
    with open(yaml_file) as f:
        return yaml.safe_load(f)


def render_scenario_def(scenario_def: dict, run_id: str) -> dict:
    """Render simple Jinja placeholders in the scenario definition."""
    env = Environment(autoescape=False)
    context = {
        **os.environ,
        "run_id": run_id,
    }

    def render_value(value):
        if isinstance(value, dict):
            return {k: render_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [render_value(v) for v in value]
        if isinstance(value, str) and "{{" in value:
            return env.from_string(value).render(**context)
        return value

    return render_value(scenario_def)


def run_scenario(scenario_id: str, mode: str, run_id: str) -> dict:
    """Load and execute a scenario module."""
    if scenario_id not in SCENARIO_MODULE_MAP:
        print(f"[ERROR] Unknown scenario: {scenario_id}")
        print(f"  Known scenarios: {', '.join(SCENARIO_MODULE_MAP.keys())}")
        sys.exit(1)

    module_name = SCENARIO_MODULE_MAP[scenario_id]
    scenario_def = render_scenario_def(load_scenario_def(scenario_id), run_id)

    print(f"\n{'='*60}")
    print(f"  Scenario : {scenario_def['title']}")
    print(f"  MITRE    : {scenario_def['mitre_ttp']} — {scenario_def['mitre_name']}")
    print(f"  Mode     : {mode}")
    print(f"  Run ID   : {run_id}")
    print(f"{'='*60}\n")

    if mode == "dry-run":
        print("[DRY-RUN] Would execute scenario. No actions taken.")
        return {
            "scenario_id": scenario_id,
            "status": "dry-run",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "observables_generated": [],
        }

    # Dynamically import scenario module
    sys.path.insert(0, str(RUNNERS_DIR))
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        print(f"[ERROR] Could not import scenario module '{module_name}': {e}")
        sys.exit(1)

    started_at = datetime.now(timezone.utc).isoformat()
    result = module.run(scenario_def=scenario_def, run_id=run_id, mode=mode)
    finished_at = datetime.now(timezone.utc).isoformat()

    return {
        "scenario_id": scenario_id,
        "status": result.get("status", "unknown"),
        "started_at": started_at,
        "finished_at": finished_at,
        "observables_generated": result.get("observables_generated", []),
        "details": result.get("details", {}),
    }


def main():
    parser = argparse.ArgumentParser(description="auto-redteam simulation runner")
    parser.add_argument(
        "--scenario",
        required=False,
        default=None,
        help="Scenario ID to run, or 'all' to run every registered scenario",
    )
    parser.add_argument(
        "--mode",
        choices=["safe", "dry-run"],
        default="safe",
        help="Execution mode: 'safe' runs the scenario, 'dry-run' only logs actions",
    )
    parser.add_argument(
        "--run-id",
        default=os.environ.get("GITHUB_RUN_ID", f"local-{int(time.time())}"),
        help="Unique run identifier (defaults to GITHUB_RUN_ID or timestamp)",
    )
    parser.add_argument(
        "--output",
        default="artifacts/results.json",
        help="Path to write results JSON",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available scenarios and exit",
    )
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for sid in SCENARIO_MODULE_MAP:
            try:
                defn = load_scenario_def(sid)
                print(f"  {sid:35s} {defn['mitre_ttp']}  {defn['title']}")
            except Exception:
                print(f"  {sid:35s} (definition not found)")
        return

    if not args.scenario:
        parser.print_help()
        sys.exit(1)

    if args.scenario == "all":
        scenarios_to_run = list(SCENARIO_MODULE_MAP.keys())
    elif args.scenario in SCENARIO_GROUPS:
        scenarios_to_run = SCENARIO_GROUPS[args.scenario]
    else:
        scenarios_to_run = [args.scenario]

    all_results = []
    for sid in scenarios_to_run:
        result = run_scenario(sid, args.mode, args.run_id)
        all_results.append(result)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(
            {
                "run_id": args.run_id,
                "mode": args.mode,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scenarios": all_results,
            },
            f,
            indent=2,
        )
    print(f"\n[INFO] Results written to {output_path}")

    failed = [r for r in all_results if r["status"] not in ("success", "dry-run")]
    if failed:
        print(f"[WARN] {len(failed)} scenario(s) did not complete successfully.")
        sys.exit(1)


if __name__ == "__main__":
    main()
