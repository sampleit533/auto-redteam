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

Add a block to `evaluation/expected_mappings.yaml`:

```yaml
  - scenario_id: t3_my_scenario
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

---

## Step 5 — Add the scenario to the workflow dropdown

In `.github/workflows/redteam-on-demand.yml`, add the new ID to the `options` list:

```yaml
      scenario:
        type: choice
        options:
          - t1_bruteforce_ssh
          - t2_privilege_escalation
          - t3_my_scenario      # ← add here
          - all
```

---

## Checklist

- [ ] `scenarios/TX_name.yaml` created
- [ ] `runners/scenarios/tx_name.py` created with `run()` function
- [ ] Cleanup logic in `run()` removes all created resources
- [ ] `runners/simulate.py` updated (both `SCENARIO_MODULE_MAP` and `yaml_name_map`)
- [ ] `evaluation/expected_mappings.yaml` updated
- [ ] `.github/workflows/redteam-on-demand.yml` dropdown updated
- [ ] Tested with `--mode dry-run` locally
