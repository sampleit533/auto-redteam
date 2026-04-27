# auto-redteam

Academic prototype for red team automation in CI/CD. Runs non-destructive attack scenario simulations against isolated sandbox environments, records observables, evaluates detection coverage, and generates reports for coursework/demo purposes.

## Scope

- Implemented end-to-end scenarios: `T1`, `T2`, `T3`, `T4`, `T5`, `T6`
- Evaluation source of truth: simulation observables and expected mappings
- Primary outputs: workflow artifacts, JSON results, HTML reports, **PCAP files** (T3 / T6) for offline replay into Zeek/Suricata
- Out of current implementation scope: production SIEM integrations, Slack/JIRA notifications, enterprise secrets management

## Architecture

```
[Trigger] → [Provision Infra] → [Deploy Targets] → [Simulate]
         → [Collect Telemetry] → [Evaluate] → [Report] → [Teardown]
```

## Scenarios

| ID | Name | MITRE TTP | Status | Sandbox target |
|----|------|-----------|--------|----------------|
| T1 | SSH Brute-force | T1110.001 | implemented | target-ssh (Ubuntu/sshd) |
| T2 | Privilege Escalation (IAM) | T1078.004 | implemented | LocalStack IAM |
| T3 | Lateral Movement Pattern | T1021 | implemented | target-ssh / target-web / target-redis / localstack |
| T4 | Data Access / Bulk S3 Read | T1530 | implemented | LocalStack S3 |
| T5 | Supply-chain / CI Compromise | T1195.001 | implemented | observable-only (audit_log events) |
| T6 | Network Service Discovery | T1046 | implemented | target-ssh / target-web / target-redis / localstack |

More scenarios can be added by dropping a YAML file in `scenarios/` and a Python module in `runners/scenarios/`.

## Quick Start

### Run manually (on-demand)

1. Go to **Actions** → **RedTeam On-Demand**
2. Click **Run workflow**
3. Select a scenario (`t1_bruteforce_ssh` … `t6_network_recon`, or `all`)
4. Fill in the approval ticket ID
5. Click **Run workflow**

### Run all scenarios locally

```bash
# Bring up sandbox + run all 6 scenarios + tear down (single command)
./run-local.sh safe all

# Dry-run only (no infra needed)
python runners/simulate.py --scenario all --mode dry-run
```

### PCAP capture (T3 / T6)

The two network-sensor scenarios capture a `.pcap` per run by spawning an
ephemeral Docker container (`redteam/pcap-recorder`, alpine + tcpdump) with
`--cap-add=NET_RAW --cap-add=NET_ADMIN --network=host`. No host `setcap` or
`sudo` is required — the capability lives only inside the throwaway
container.

Activated by `ENABLE_PCAP=1` (default in `run-local.sh` and the GitHub
workflows). The recorder image is built once on first use.

Output: `artifacts/<scenario_id>-<run_id>.pcap`, replayable into Zeek /
Suricata for sensor-rule validation.

### NIDS-lite (T3 / T6)

After each network-detection scenario completes, the runner re-reads its
own pcap with `tcpdump -nr` (same recorder image), parses SYN packets, and
emits synthetic `nids_alert` observables on:

- `LATERAL_FANOUT` — single source touches ≥4 distinct destination services
- `PORT_SCAN` — single source touches ≥5 distinct destination ports

This closes the loop from captured pcap → detection: the
`NIDS_LATERAL_MOVEMENT` and `NIDS_PORT_SCAN` rules in
`expected_mappings.yaml` evaluate against these alerts instead of being
SKIP-ped (no live Zeek/Suricata required).

### Multi-run trend dashboard

Each evaluation is appended to `artifacts/history/<run_id>.json`.
`reporting/generate_trends.py` aggregates these into
`artifacts/trends.html` showing:

- Overall detection-coverage trend across runs
- Per-scenario coverage history with bar charts
- Auto-detected regressions (where coverage dropped between adjacent runs)

### Baseline regression gate

`evaluation/check_baseline.py` compares the latest evaluation against
`evaluation/baseline.json`. The CI workflows fail if any rule that was
PASS in the baseline is now FAIL or missing. Update the baseline after
intentional changes:

```bash
python evaluation/check_baseline.py --update
```

### Sigma rule export

`evaluation/export_sigma.py` translates the internal
`expected_mappings.yaml` into industry-standard Sigma YAML rules under
`sigma/`. Each rule has a stable UUID, MITRE ATT&CK tags, logsource
shape, and `count()` / `count(unique:…)` thresholds matching the
internal mapping. Compatible with the official Sigma converter for
Splunk / ES / Sentinel.

## Repository Structure

```
auto-redteam/
├── .github/workflows/
│   ├── redteam-on-demand.yml       # Manual trigger with approval gate
│   └── redteam-scheduled.yml       # Nightly baseline run
├── scenarios/                       # Scenario definitions (YAML, versioned)
│   ├── T1_bruteforce_ssh.yaml
│   ├── T2_privilege_escalation.yaml
│   ├── T3_lateral_movement.yaml
│   ├── T4_data_exfiltration.yaml
│   ├── T5_ci_compromise.yaml
│   └── T6_network_recon.yaml
├── runners/
│   ├── Dockerfile                   # Attack runner image (safe tools only)
│   ├── simulate.py                  # Main entry point
│   └── scenarios/
│       ├── t1_bruteforce.py         # T1 implementation
│       ├── t2_priv_escalation.py    # T2 implementation
│       ├── t3_lateral_movement.py   # T3 implementation
│       ├── t4_data_exfiltration.py  # T4 implementation
│       ├── t5_ci_compromise.py      # T5 implementation
│       └── t6_network_recon.py      # T6 implementation
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
