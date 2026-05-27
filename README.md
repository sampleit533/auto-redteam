# auto-redteam

Academic prototype for red team automation in CI/CD. Runs non-destructive attack scenario simulations against isolated sandbox environments, records observables, evaluates detection coverage, and generates reports for coursework/demo purposes.

## Scope

- Core scenarios (host→cloud kill chain): `T1` (Initial Access) → `T2` (Privilege Escalation) → `T4` (Exfiltration). The repo also ships `T3`/`T5`/`T6`/`T7`/`T8` as extension scenarios on the same framework.
- Runs against a **fake cloud (LocalStack) in CI** and is promoted to **real AWS** on merge to `main` via GitHub OIDC (zero static keys)
- Evaluation source of truth: simulation observables, **real CloudTrail** (management + S3 data events), and expected mappings
- Primary outputs: workflow artifacts, JSON results, HTML reports, trend dashboard, Sigma rules, **PCAP files** (T3 / T6 / T7) and **Snort 3 alert logs** (T7) for offline detection replay
- Out of current implementation scope: live SIEM (ELK/Splunk/Sentinel) ingest, EDR/WAF, Slack/JIRA notifications, enterprise secrets management (replaced by OIDC)

> Full architecture (with diagrams): [`docs/architecture.md`](docs/architecture.md).
> Proposal: [`proposal_v2_redteam.md`](proposal_v2_redteam.md).

## Architecture

```
[Trigger] → [Provision Infra] → [Deploy Targets] → [Simulate]
         → [Collect Telemetry] → [Evaluate] → [Report] → [Teardown]
```

## Scenarios

**Core scenarios** — the focus of the report/demo, forming a host→cloud kill chain:

| ID | Name | MITRE TTP | Status | Sandbox target |
|----|------|-----------|--------|----------------|
| T1 | SSH Brute-force (Initial Access) | T1110.001 | implemented | target-ssh (Ubuntu/sshd) |
| T2 | Privilege Escalation (IAM) | T1078.004 | implemented | LocalStack IAM / real AWS |
| T4 | Data Access / Bulk S3 Read (Exfiltration) | T1530 | implemented | LocalStack S3 / real AWS |

**Extension scenarios** — shipped on the same framework, available but outside the core scope:

| ID | Name | MITRE TTP | Status | Sandbox target |
|----|------|-----------|--------|----------------|
| T3 | Lateral Movement Pattern | T1021 | implemented | target-ssh / target-web / target-redis / localstack |
| T5 | Supply-chain / CI Compromise | T1195.001 | implemented | observable-only (audit_log events) |
| T6 | Network Service Discovery | T1046 | implemented | target-ssh / target-web / target-redis / localstack |
| T7 | Log4Shell N-day Probe (CVE-2021-44228) | T1190 | implemented | target-web (nginx) + offline Snort 3 replay |
| T8 | Cloud Recon / Discovery | T1580 | implemented | real AWS IAM/STS + CloudTrail |

The pipeline gate and the deploy workflow run **`--scenario kill-chain`** = **T1
(Initial Access — SSH brute-force against an `sshd` on the runner) → T2 (Privilege
Escalation) → T4 (Exfiltration)**; T2/T4 execute on real AWS, exercising CloudTrail
management events and S3 data events. The bundled **`--scenario cloud`** (**T8 → T2 →
T4**) remains available as the recon-led extension chain.

More scenarios can be added by dropping a YAML file in `scenarios/` and a Python module in `runners/scenarios/`.

## Quick Start

### Run in CI (pipeline)

The `redteam-pipeline.yml` workflow runs automatically on every `push`/`pull_request`
to `main`: lint + secret scan → run the kill chain on LocalStack → evaluate detection.
On merge to `main` it gates and promotes the kill chain to **real AWS** via the
reusable `redteam-cloud-deploy.yml` (OIDC, approval ticket). Download the HTML report
from the run's **Artifacts** section.

### Run all scenarios locally

```bash
# Bring up sandbox + run all scenarios (core + extensions) + tear down (single command)
./run-local.sh safe all

# Or run just the 3 core scenarios as a chain (T1 host → T2 → T4)
./run-local.sh safe kill-chain
# Extension: full cloud chain with the T8 recon lead-in
./run-local.sh safe cloud   # T8 → T2 → T4

# Dry-run only (no infra needed)
python runners/simulate.py --scenario all --mode dry-run
```

### PCAP capture (T3 / T6 / T7)

The three network-sensor scenarios capture a `.pcap` per run by spawning an
ephemeral Docker container (`redteam/pcap-recorder`, alpine + tcpdump) with
`--cap-add=NET_RAW --cap-add=NET_ADMIN --network=host`. No host `setcap` or
`sudo` is required — the capability lives only inside the throwaway
container.

Activated by `ENABLE_PCAP=1` (default in `run-local.sh` and the GitHub
workflows). The recorder image is built once on first use. T3 and T6
capture on `-i any` (LINUX_SLL2 link-type, fine for `nids-lite`); T7
captures on `-i lo` (EN10MB) so the offline Snort 3 engine can decode it.

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

### Snort 3 offline replay (T7)

T7 sends Log4Shell (CVE-2021-44228) JNDI probes against `target-web`,
captures pcap, then replays it through an ephemeral Snort 3 container
(`redteam/snort-runner`, alpine + snort 3.x) running the bundled
`log4shell.rules`:

- SID 1000001 — generic `${jndi:` lookup
- SID 1000002 — `${jndi:ldap://` outbound payload
- SID 1000003 — `${jndi:rmi://` outbound payload

Parsed Snort `alert_fast` lines are surfaced as `snort_alert` observables
and validated by the evaluator (`SNORT_LOG4SHELL_*` rules in
`expected_mappings.yaml`). Build is one-shot — alpine community repo,
no DAQ/NIC trickery — and runs entirely from the captured pcap, so the
runner stays non-destructive (no Java, no actual Log4Shell exploitation).

Output: `artifacts/<scenario_id>-<run_id>.snort.txt` next to the pcap.

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
│   ├── redteam-pipeline.yml        # Continuous CI/CD: push/PR → lint → LocalStack → deploy
│   └── redteam-cloud-deploy.yml    # Reusable: promote kill chain to real AWS (OIDC, approval gate)
├── scenarios/                       # Scenario definitions (YAML, versioned)
│   ├── T1_bruteforce_ssh.yaml
│   ├── T2_privilege_escalation.yaml
│   ├── T3_lateral_movement.yaml
│   ├── T4_data_exfiltration.yaml
│   ├── T5_ci_compromise.yaml
│   ├── T6_network_recon.yaml
│   └── T7_log4shell_probe.yaml
├── runners/
│   ├── Dockerfile                   # Attack runner image (safe tools only)
│   ├── simulate.py                  # Main entry point
│   └── scenarios/
│       ├── t1_bruteforce.py         # T1 implementation
│       ├── t2_priv_escalation.py    # T2 implementation
│       ├── t3_lateral_movement.py   # T3 implementation
│       ├── t4_data_exfiltration.py  # T4 implementation
│       ├── t5_ci_compromise.py      # T5 implementation
│       ├── t6_network_recon.py      # T6 implementation
│       ├── t7_log4shell_probe.py    # T7 implementation
│       └── t8_cloud_recon.py        # T8 implementation (real AWS recon)
├── targets/
│   ├── docker-compose.yml           # Sandbox target workloads
│   ├── pcap-recorder/               # tcpdump container image (T3/T6/T7)
│   └── snort-runner/                # Snort 3 offline replay image (T7)
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
│   ├── main.tf                      # Terraform sandbox (Docker provider)
│   └── aws-bootstrap/               # OIDC provider, redteam-deploy role, boundary, CloudTrail trail
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
