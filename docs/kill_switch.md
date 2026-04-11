# Kill Switch Procedure

If a simulation run needs to be stopped immediately:

## 1. Cancel the GitHub Actions run

Go to **Actions → [the running workflow] → Cancel workflow**.

## 2. Tear down sandbox containers (if running locally)

```bash
cd targets
docker compose down -v --remove-orphans
```

## 3. Destroy Terraform infra (if provisioned)

```bash
cd infra
terraform destroy -auto-approve -var="run_id=<your-run-id>"
```

## 4. Verify no leftover resources

```bash
docker ps | grep redteam
docker network ls | grep rt-sandbox
```

The nightly cleanup job and the `teardown` step in each workflow both run with `if: always()`, so they execute even when the workflow is cancelled. Manual intervention is only needed if the runner itself crashes.
