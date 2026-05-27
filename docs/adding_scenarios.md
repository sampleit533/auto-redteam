# Adding New Scenarios

Every scenario in auto-redteam consists of three parts:

1. **YAML definition** — `scenarios/TX_name.yaml`
2. **Python module** — `runners/scenarios/tx_name.py`
3. **Mapping entry** — a block in `evaluation/expected_mappings.yaml`

Then register the scenario in one place: `runners/simulate.py`.

---

## Step 1 — Write the YAML definition

Copy `scenarios/T1_bruteforce_ssh.yaml` as a template. The required fields are:

```yaml
id: t3_my_scenario          # lowercase, underscores
version: "1.0"
title: "Human-readable title"
mitre_ttp: T1021            # MITRE ATT&CK technique ID
mitre_name: "Remote Services"
description: >
  One paragraph explaining what this simulates and why it's safe.

target:
  service: ssh              # or iam, s3, web, etc.
  host: "{{ TARGET_HOST | default('target-host') }}"

parameters:
  # Any parameters your runner module will read from scenario_def["parameters"]
  my_param: 42

expected_observables:
  - type: auth_log          # or cloudtrail_log, network_log, siem_alert
    pattern: "some log pattern"
    min_occurrences: 1

cleanup:
  - description: "What gets cleaned up"

notes: >
  Any safety notes or caveats.
```

---

## Step 2 — Write the Python module

Create `runners/scenarios/tx_name.py`. It must expose a single function:

```python
def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    """
    Execute the scenario.

    Returns:
        {
            "status": "success" | "partial" | "error",
            "observables_generated": [...],
            "details": {...}
        }
    """
    ...
```

- Read all parameters from `scenario_def["parameters"]` and `scenario_def["target"]`.
- Use environment variables for secrets (e.g., `os.environ.get("TARGET_HOST", ...)`).
- Always clean up any resources you create before returning.
- Never connect to external networks — stay within the sandbox Docker network.

---

## Step 3 — Register the scenario

In `runners/simulate.py`, add one entry to each dict:

```python
SCENARIO_MODULE_MAP = {
    "t1_bruteforce_ssh": "t1_bruteforce",
    "t2_privilege_escalation": "t2_priv_escalation",
    "t3_my_scenario": "t3_my_module",   # ← add here
}
```

And in `simulate.py`'s `load_scenario_def()`, add the filename mapping:

```python
yaml_name_map = {
    "t1_bruteforce_ssh": "T1_bruteforce_ssh.yaml",
    "t2_privilege_escalation": "T2_privilege_escalation.yaml",
    "t3_my_scenario": "T3_my_scenario.yaml",   # ← add here
}
```

---

## Step 4 — Add detection mappings

Add a block to `evaluation/expected_mappings.yaml`. The evaluator supports two styles:

**A. Legacy ES-query style** — mirrors Elasticsearch DSL, used by T1/T2:

```yaml
  - scenario_id: tx_my_scenario
    mitre_ttp: T1021
    required_detections:
      - rule_id: MY_DETECTION_RULE
        index_pattern: "redteam-logs-*"
        query:
          bool:
            must:
              - match: { "message": "some expected log line" }
        min_hits: 1
        description: "Expected log pattern must appear"
    max_ttd_seconds: 300
```

**B. Observable-type style** (preferred for new scenarios) — more concise, used by T3/T4/T6:

```yaml
  - scenario_id: tx_my_scenario
    mitre_ttp: T1021
    required_detections:
      - rule_id: MY_RULE_HITS
        observable_type: connection_log     # observable type emitted by your runner
        match_field: pattern                # field to filter on (e.g. pattern, event_name)
        match_value: "remote_service_connection"
        min_hits: 5
        description: "≥5 matching observables"
      - rule_id: MY_RULE_FANOUT
        observable_type: connection_log
        match_field: pattern
        match_value: "remote_service_connection"
        unique_field: destination_host      # count unique values of this field
        min_unique: 4
        description: "Source touches ≥4 distinct destinations"
      - rule_id: MY_RULE_SIEM
        type: siem_alert                    # always skipped in CI (no live SIEM)
        description: "SIEM alert (live SIEM only)"
        min_hits: 1
    max_ttd_seconds: 300
```

**Composite rule** (optional, used by T2/T5) — correlates multiple sub-rules + same actor + time window:

```yaml
      - rule_id: MY_COMPOSITE
        composite: true
        requires: [MY_RULE_A, MY_RULE_B]    # all must pass
        group_by: actor                     # field used to identify "same actor" (default: principal)
        observable_types: [audit_log]       # which observable types to consider (default: cloudtrail_log)
        required_event_names:               # event_names that must all appear in one group
          - workflow_run.unauthorized_job
          - secret.read
        window_seconds: 60                  # max time span between first and last event
        description: "Same actor performs both actions within 60s"
```

---

## Step 5 — Make the scenario runnable from CI

Scenarios run via `--scenario <id>` (the pipeline and `run-local.sh` pass this
through). A single ID, `all`, or a group name all work. To include the new
scenario in a chain, add its ID to a group in `SCENARIO_GROUPS` in
`runners/simulate.py`:

```python
SCENARIO_GROUPS = {
    "kill-chain": ["t1_bruteforce_ssh", "t2_privilege_escalation", "t4_data_exfiltration"],
    "cloud": ["t8_cloud_recon", "t2_privilege_escalation", "t4_data_exfiltration"],
    # "my-chain": ["tx_my_scenario", ...],   # ← add a group here if needed
}
```

The pipeline gate (`redteam-pipeline.yml`) and the real-AWS deploy
(`redteam-cloud-deploy.yml`) both run `--scenario kill-chain`; adjust the group
or the gate's `required` list there if the new scenario should be enforced.

---

## Checklist

- [ ] `scenarios/TX_name.yaml` created
- [ ] `runners/scenarios/tx_name.py` created with `run()` function
- [ ] Cleanup logic in `run()` removes all created resources
- [ ] `runners/simulate.py` updated (both `SCENARIO_MODULE_MAP` and `yaml_name_map`)
- [ ] `evaluation/expected_mappings.yaml` updated
- [ ] `runners/simulate.py` `SCENARIO_GROUPS` / pipeline gate updated (if part of a chain)
- [ ] Tested with `--mode dry-run` locally
