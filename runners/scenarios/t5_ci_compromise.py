"""
T5 — Supply-chain / CI Compromise Pattern (T1195.001)

Generates synthetic audit-log events that mirror GitHub Actions audit
logs showing an unauthorized workflow execution combined with anomalous
repository secret access by the same actor. Pure observable generation:
no real CI workflow is triggered, no real secret is read.
"""

import os
import time


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]

    org = target.get("org_name", "redteam-sandbox-org")
    repo = target.get("repo_name", "redteam-sandbox-repo")
    actor = os.environ.get(
        target.get("test_principal_env", "REDTEAM_CI_ACTOR"),
        f"sandbox-actor-{run_id}",
    )

    approved = list(params.get("approved_workflows", []))
    unauth = params.get("unauthorized_workflow", ".github/workflows/exfil-test.yml")
    secret = params.get("secret_name", "REDTEAM_DEPLOY_KEY")
    context = params.get("unusual_context", "manual-trigger-from-fork")
    delay = float(params.get("delay_between_events_seconds", 2.0))

    observables: list = []

    print(f"[T5] Org/Repo : {org}/{repo}")
    print(f"[T5] Actor    : {actor}")
    print(f"[T5] Approved : {len(approved)} workflow(s)")
    print(f"[T5] Simulated unauthorized workflow: {unauth}")

    # Event 1 — Unauthorized workflow run
    print(f"\n[T5] Step 1/2: emit audit_log[workflow_run.unauthorized_job]")
    observables.append({
        "type": "audit_log",
        "event_name": "workflow_run.unauthorized_job",
        "actor": actor,
        "principal": actor,
        "org": org,
        "repo": repo,
        "workflow_path": unauth,
        "approved_workflows": approved,
        "trigger_context": context,
        "event_time": time.time(),
        "run_id": run_id,
    })
    print(f"[T5]   actor={actor} workflow={unauth}")

    if delay > 0:
        time.sleep(delay)

    # Event 2 — Anomalous secret read by the same actor
    print(f"[T5] Step 2/2: emit audit_log[secret.read]")
    observables.append({
        "type": "audit_log",
        "event_name": "secret.read",
        "actor": actor,
        "principal": actor,
        "org": org,
        "repo": repo,
        "secret_name": secret,
        "trigger_context": context,
        "event_time": time.time(),
        "run_id": run_id,
    })
    print(f"[T5]   actor={actor} secret={secret} context={context}")

    print(f"\n[T5] Done. Generated {len(observables)} audit_log event(s).")

    return {
        "status": "success",
        "observables_generated": observables,
        "details": {
            "org": org,
            "repo": repo,
            "actor": actor,
            "approved_workflows": approved,
            "unauthorized_workflow": unauth,
            "secret_name": secret,
            "trigger_context": context,
        },
    }
