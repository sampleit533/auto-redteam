# auto-redteam

Academic prototype for red team automation in CI/CD. Runs non-destructive attack scenario simulations against isolated sandbox environments, records observables, evaluates detection coverage, and generates reports for coursework/demo purposes.

## Scope

This repository is intentionally limited to a university coursework scope.

- Implemented end-to-end scenarios: `T1` and `T2`
- Evaluation source of truth: simulation observables and expected mappings
- Primary outputs: workflow artifacts, JSON results, HTML reports
- Out of current implementation scope: production SIEM integrations, Slack/JIRA notifications, enterprise secrets management, and full T3-T6 scenario coverage

## Architecture

```
[Trigger] → [Provision Infra] → [Deploy Targets] → [Simulate]
         → [Collect Telemetry] → [Evaluate] → [Report] → [Teardown]
```

## Scenarios

| ID | Name | MITRE TTP | Status |
|----|------|-----------|--------|
| T1 | SSH Brute-force | T1110.001 | ✅ implemented |
| T2 | Privilege Escalation (IAM) | T1078.004 | ✅ implemented |
| T3 | Lateral Movement Pattern | T1021 | planned |
| T4 | Data Access / Exfiltration Pattern | T1530 | planned |
| T5 | Supply-chain / CI Compromise Pattern | T1195.001 | planned |
| T6 | Reconnaissance / Discovery | T1046 | planned |

More scenarios can be added by dropping a YAML file in `scenarios/` and a Python module in `runners/scenarios/`.

## Quick Start

### Run manually (on-demand)

1. Go to **Actions** → **RedTeam On-Demand**
2. Click **Run workflow**
3. Select a scenario (`t1_bruteforce_ssh` or `t2_privilege_escalation`)
4. Fill in the approval ticket ID
5. Click **Run workflow**

### Run all scenarios

```bash
# Local dry-run (no real infra needed)
python runners/simulate.py --scenario all --mode dry-run
```

## Repository Structure

```
auto-redteam/
├── .github/workflows/
│   ├── redteam-on-demand.yml       # Manual trigger with approval gate
│   └── redteam-scheduled.yml       # Nightly baseline run
├── scenarios/                       # Scenario definitions (YAML, versioned)
│   ├── T1_bruteforce_ssh.yaml
│   └── T2_privilege_escalation.yaml
├── runners/
│   ├── Dockerfile                   # Attack runner image (safe tools only)
│   ├── simulate.py                  # Main entry point
│   └── scenarios/
│       ├── t1_bruteforce.py         # T1 implementation
│       └── t2_priv_escalation.py    # T2 implementation
├── targets/
│   └── docker-compose.yml           # Sandbox target workloads
├── collection/
│   └── filebeat.yml                 # Log shipping config
├── evaluation/
│   ├── evaluate_results.py          # Detection evaluator
│   └── expected_mappings.yaml       # TTP → expected SIEM alert mapping
├── reporting/
│   ├── generate_report.py
│   └── templates/
│       └── report.html.j2
├── infra/
│   └── main.tf                      # Terraform sandbox (Docker provider)
└── docs/
    ├── approval_form.md
    ├── runbook.md
    ├── kill_switch.md
    └── adding_scenarios.md          # How to add new scenarios
```

## Safety

- All simulations are **non-destructive** — they generate observable telemetry patterns only.
- Every run requires an **approval ticket ID** (enforced by the workflow).
- Sandbox infra is **ephemeral**: created before each run, destroyed after (`terraform destroy` runs even on failure).
- No real credentials, no external network targets, no production systems.

## Adding New Scenarios

See [`docs/adding_scenarios.md`](docs/adding_scenarios.md) for a step-by-step guide.

## License

MIT
