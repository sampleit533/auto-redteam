# Runbook — auto-redteam

## Running a scenario (on-demand)

1. Ensure you have an approval ticket from the lab owner.
2. Go to **Actions → RedTeam — On-Demand → Run workflow**.
3. Fill in the form:
   - **scenario**: choose the scenario ID
   - **approval_ticket**: paste your ticket ID
   - **mode**: use `safe` for a real sandbox simulation
4. Click **Run workflow**.
5. Monitor the run. Download the HTML report from the **Artifacts** section.

## Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `REDTEAM_SSH_TEST_PASSWORD` | Password for the `redteam-test` SSH account in the sandbox |

## Stopping a run (kill switch)

See `docs/kill_switch.md`.

## Environment variables (for local runs)

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_SSH_HOST` | `target-ssh` | Hostname of the SSH target container |
| `IAM_ENDPOINT` | `http://localstack:4566` | LocalStack IAM endpoint |
| `ELASTICSEARCH_HOST` | `http://elasticsearch:9200` | Elasticsearch for telemetry |
| `REDTEAM_SSH_TEST_PASSWORD` | `RedteamPass123!` | Test account password |
| `AWS_ACCESS_KEY_ID` | `test` | Synthetic AWS key (LocalStack) |
| `AWS_SECRET_ACCESS_KEY` | `test` | Synthetic AWS secret (LocalStack) |
| `REDTEAM_IAM_PRINCIPAL` | `redteam-sandbox-principal` | Synthetic principal label attached to T2 events |

## Local run

```bash
cd /path/to/auto-redteam
pip install -r runners/requirements.txt
python runners/simulate.py --scenario t2_privilege_escalation --mode safe
```

## Troubleshooting

**SSH connection refused** — Check that `target-ssh` container is running:
```bash
docker compose -f targets/docker-compose.yml ps
```

**LocalStack not ready** — Wait a few more seconds and retry. LocalStack can take 15–30s to initialize IAM.

**T2 does not reach LocalStack** — Verify `IAM_ENDPOINT` points at the running sandbox endpoint and that LocalStack started with `iam`, `sts`, and `cloudtrail` enabled.

**Elasticsearch query fails** — The evaluator will log a warning and mark the detection as failed. Verify Elasticsearch is running and the index exists.
