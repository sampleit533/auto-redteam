# aws-bootstrap — one-time AWS foundation

Run **once**, locally, with admin credentials. Creates the durable pieces that
let GitHub Actions run scenarios against real AWS **without any long-lived key**:

| Resource | Purpose |
|---|---|
| GitHub OIDC provider | CI authenticates to AWS with a short-lived web-identity token |
| `redteam-deploy` role | The only thing CI assumes; trust locked to `repo:sampleit533/auto-redteam:*` |
| `redteam-sandbox-boundary` | Permissions boundary (pure Deny) — neuters anything T2 creates |

The deploy role's permissions are scoped to exactly what the scenarios touch:
sandbox-pathed IAM principals (T2), `cloudtrail:LookupEvents` (T2 detection),
and `redteam-sandbox-*` S3 buckets (T4, Phase 2).

## Apply

```bash
# Requires huy.ngovinh to have AdministratorAccess TEMPORARILY (see project notes).
cd infra/aws-bootstrap
terraform init
terraform plan      # review
terraform apply
terraform output    # copy deploy_role_arn into the GitHub Actions workflow
```

## After apply

1. Put `deploy_role_arn` into the workflow's `role-to-assume`.
2. **Remove `AdministratorAccess` from `huy.ngovinh`** — CI now uses OIDC, the
   local user no longer needs elevated rights. Goal state: zero static keys.

State is local (`terraform.tfstate`) — this is a one-time bootstrap, not part of
the per-run ephemeral lifecycle. Keep the state file out of git (already covered
by `.gitignore` patterns for `*.tfstate`).
