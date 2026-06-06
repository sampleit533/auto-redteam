# Foothold — running T2 / T4 on a real EC2 ("compromised cloud workload")

This adds **one cheap EC2** that stands in for a compromised cloud workload, and
runs the **unchanged** T2 (IAM privilege escalation) and T4 (S3 bulk read)
scenarios **on that box**. Because the EC2 carries an instance profile, `boto3`
picks those credentials up from IMDS automatically — so CloudTrail attributes
every `CreateRole` / `GetObject` to the **workload's role and the EC2's source
IP**, instead of to a CI runner. That is the realistic adversary-emulation
story for a DevSecOps detection demo.

> **The "real server" is the attacker's vantage point, not the data store.**
> T4 storage stays in **real S3** (`redteam-sandbox-*`) — that is what makes
> `GetObject` a CloudTrail **data event** the trail can detect. Copying data
> onto the EC2's local disk would turn it into an ordinary host file read with
> **no CloudTrail signal**, defeating the T4 detection. EC2 = compute/foothold,
> S3 = the real cloud storage target. Both are real cloud, each in its right role.

## What `foothold.tf` creates

| Resource | Purpose |
|---|---|
| `aws_instance.foothold` (t3.micro, AL2023, gp3 8GB, IMDSv2) | The foothold. Egress-only SG, **no inbound**. |
| `aws_iam_role.foothold` + instance profile | Scoped to exactly the T2/T4/t8 actions (reuses the deploy role's documents) + read/write the code bucket + `AmazonSSMManagedInstanceCore`. |
| `aws_s3_bucket.foothold_code` (`redteam-foothold-code-<acct>`) | Private bucket the runner code is synced to and pulled from. Name is **not** `redteam-sandbox-*`, so it never pollutes the T4 data-event trail. |
| EventBridge Scheduler `foothold_stop` / `foothold_start` + role | Auto stop (00:00 ICT) / start (08:00 ICT) for cost control. |
| `deploy_drive_foothold` policy on `redteam-deploy` | Lets the gated CI workflow wake the box, `ssm:SendCommand`, read results, and sync code up. |

The control plane is **SSM Session Manager** — no SSH, no open ports, no key.

## Cost (well under the $30 / 3-week budget)

- t3.micro on-demand `us-east-1` ≈ **$0.0104/hr**. 24×7 for 3 weeks ≈ **$5.2**;
  with the nightly auto-stop, roughly **half** that.
- gp3 8 GB ≈ **$0.64/month**. S3 + CloudWatch Logs for this workload: cents.
- EventBridge Scheduler: free at this volume.

**Total: a few dollars for the whole 3 weeks.** `terraform destroy` removes it all.

## One-time setup

1. **Apply** (admin credentials, same module as the rest of the bootstrap):

   ```bash
   cd infra/aws-bootstrap
   terraform init
   terraform apply        # reviews EC2 + code bucket + scheduler + IAM
   ```

   This **also tightens the OIDC trust** (`main.tf`): the `redteam-deploy` role
   can now be assumed **only** from a job bound to the `aws-sandbox`
   environment. The existing deploy job (`redteam-cloud-deploy.yml`) and the new
   foothold-run job both set `environment: aws-sandbox`, so nothing breaks — but
   any future job that wants AWS creds must use that environment.

2. **Record the outputs into repo variables**
   (Settings → Secrets and variables → Actions → Variables):

   ```bash
   terraform output foothold_instance_id   # -> FOOTHOLD_INSTANCE_ID
   terraform output foothold_code_bucket   # -> FOOTHOLD_CODE_BUCKET
   ```

   Also set **`FOOTHOLD_ALLOWED_ACTORS`** = comma-separated GitHub logins
   allowed to launch a run (e.g. `sampleit533`).

3. **Authorization gate (do this once):**
   - Repo → Settings → Environments → **`aws-sandbox`** → add **Required
     reviewers** (an approver). Every real-cloud run now needs a manual click.
   - Branch protection on `main`: require PR + **review from Code Owners**
     (see `.github/CODEOWNERS`).

   Gate layers, in order: actor allowlist → required-reviewer approval → OIDC
   trust scoped to the environment (no environment ⇒ no AWS credentials).

## Running a scenario

### A. Gated workflow (the auditable path)

Actions → **RedTeam — Foothold Run** → Run workflow → pick the scenario +
approval ticket. The workflow: syncs the code to S3 → wakes the EC2 → waits for
SSM → `SendCommand` to run the scenario on the box → polls and prints output →
pulls `results.json` back as an artifact. Requires allowlist + reviewer
approval first.

### B. Manual live demo (SSM Session Manager)

```bash
# 1. push the current code up (admin or deploy creds, from the repo root):
aws s3 sync . s3://$(terraform -chdir=infra/aws-bootstrap output -raw foothold_code_bucket)/repo \
  --delete --exclude '.git/*' --exclude 'artifacts/*'

# 2. start a shell on the foothold (no SSH, no inbound):
aws ssm start-session --target <FOOTHOLD_INSTANCE_ID>

# 3. on the box — run T2 (IAM privesc) or T4 (S3 bulk read):
sudo /opt/redteam/run-scenario.sh t2_privilege_escalation
sudo /opt/redteam/run-scenario.sh t4_data_exfiltration
```

`run-scenario.sh` pulls the latest code from the bucket, sets
`REDTEAM_CLOUD_MODE=aws` + the sandbox env, runs `simulate.py` for the one
scenario, and uploads `results.json` back to the code bucket. No access keys are
ever printed.

## Verifying attribution on CloudTrail

After a run, the events carry the **foothold's identity**, not a CI runner's:

```bash
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventName,AttributeValue=CreateRole \
  --query 'Events[0].CloudTrailEvent' --output text | \
  python3 -c 'import sys,json; e=json.load(sys.stdin); \
    print("principal:", e["userIdentity"]["arn"]); \
    print("sourceIP :", e["sourceIPAddress"])'
# principal: arn:aws:sts::406953137587:assumed-role/redteam-ec2-foothold/<instance-id>
# sourceIP : <the EC2's IP>
```

For T4, the `GetObject` data events land in the CloudWatch Logs group
`/aws/cloudtrail/redteam-sandbox` (read back automatically by the runner).

## Teardown

```bash
cd infra/aws-bootstrap
# remove only the foothold + its drive policy, keep the OIDC/role bootstrap:
terraform destroy \
  -target=aws_instance.foothold \
  -target=aws_scheduler_schedule.foothold_stop \
  -target=aws_scheduler_schedule.foothold_start \
  -target=aws_s3_bucket.foothold_code \
  -target=aws_iam_role_policy.deploy_drive_foothold
# ...or `terraform destroy` to tear the whole sandbox down at end of the project.
```

> Note: the OIDC `sub` stays scoped to `:environment:aws-sandbox` after teardown.
> If you ever want the pre-gate behaviour back, set
> `-var 'deploy_environment=*'` is **not** valid for `StringEquals`; instead
> revert that condition in `main.tf`.
