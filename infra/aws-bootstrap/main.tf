# =============================================================================
# auto-redteam — AWS bootstrap (run ONCE, locally, with admin credentials)
#
# Creates the durable foundation for running scenarios against REAL AWS:
#   1. GitHub Actions OIDC identity provider   (CI authenticates with no keys)
#   2. redteam-deploy role                      (the only thing CI assumes)
#   3. redteam-sandbox-boundary                 (permissions boundary that
#                                                 neuters anything T2 creates)
#
# After `terraform apply` here, GitHub Actions assumes redteam-deploy via OIDC.
# No long-lived AWS access key is ever stored in the repo or in CI.
#
# IAM is a GLOBAL service, so this module is region-agnostic; we pin us-east-1
# because that is where CloudTrail records global-service (IAM/STS) events.
# =============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "Region for the AWS provider. IAM is global; us-east-1 is where CloudTrail logs global-service events (T2 looks them up here)."
  type        = string
  default     = "us-east-1"
}

variable "github_repo" {
  description = "owner/name of the repo allowed to assume the deploy role"
  type        = string
  default     = "sampleit533/auto-redteam"
}

variable "deploy_role_name" {
  description = "Name of the role GitHub Actions assumes via OIDC"
  type        = string
  default     = "redteam-deploy"
}

variable "sandbox_path" {
  description = "IAM path under which T2 may create principals. The deploy role can ONLY touch principals under this path."
  type        = string
  default     = "/redteam-sandbox/"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  oidc_host  = "token.actions.githubusercontent.com"
}

# -----------------------------------------------------------------------------
# 1. GitHub Actions OIDC provider
#    Thumbprint is fetched live from GitHub's OIDC discovery endpoint so we
#    never hardcode a fingerprint that GitHub may rotate.
# -----------------------------------------------------------------------------
data "tls_certificate" "github" {
  url = "https://${local.oidc_host}/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://${local.oidc_host}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]

  tags = { Project = "auto-redteam" }
}

# -----------------------------------------------------------------------------
# 2. Permissions boundary for T2's ephemeral principals
#    A pure Deny: any role/user T2 creates is born completely inert — even if
#    its access key leaked mid-run it could perform NOTHING. The "privilege
#    escalation" is therefore a faithful API-call sequence with zero blast radius.
# -----------------------------------------------------------------------------
resource "aws_iam_policy" "sandbox_boundary" {
  name        = "redteam-sandbox-boundary"
  description = "Neuters every action — applied as permissions boundary to T2-created principals."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DenyEverything"
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
  tags = { Project = "auto-redteam" }
}

# -----------------------------------------------------------------------------
# 3. The deploy role assumed by GitHub Actions
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    # Token must be minted for STS...
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    # ...and only for workflows in OUR repo (any branch/PR/tag).
    # Tighten later to e.g. "repo:${var.github_repo}:environment:aws-sandbox".
    condition {
      test     = "StringLike"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repo}:*"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = var.deploy_role_name
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust.json
  max_session_duration = 3600
  tags                 = { Project = "auto-redteam" }
}

# Scoped permissions for what the scenarios actually do on real AWS.
data "aws_iam_policy_document" "deploy_perms" {

  # --- T2: create the ephemeral principals, but ONLY under the sandbox path
  #         AND only if the caller pins our neutering boundary on them. ---
  statement {
    sid     = "T2CreateBoundedPrincipals"
    effect  = "Allow"
    actions = ["iam:CreateRole", "iam:CreateUser"]
    resources = [
      "arn:${local.partition}:iam::${local.account_id}:role${var.sandbox_path}*",
      "arn:${local.partition}:iam::${local.account_id}:user${var.sandbox_path}*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [aws_iam_policy.sandbox_boundary.arn]
    }
  }

  # --- T2: manage + tear down those same sandbox principals ---
  statement {
    sid    = "T2ManageSandboxPrincipals"
    effect = "Allow"
    actions = [
      "iam:DeleteRole", "iam:DeleteUser",
      "iam:TagRole", "iam:TagUser", "iam:UntagRole", "iam:UntagUser",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
      "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:ListAccessKeys",
      "iam:GetRole", "iam:GetUser",
    ]
    resources = [
      "arn:${local.partition}:iam::${local.account_id}:role${var.sandbox_path}*",
      "arn:${local.partition}:iam::${local.account_id}:user${var.sandbox_path}*",
    ]
  }

  # --- T2 detection: read REAL CloudTrail management events (free) ---
  statement {
    sid       = "T2ReadCloudTrail"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"] # LookupEvents does not support resource-level scoping
  }

  # --- T4 (Phase 2): ephemeral S3 buckets, sandbox-prefixed only ---
  statement {
    sid    = "T4SandboxBuckets"
    effect = "Allow"
    actions = [
      "s3:CreateBucket", "s3:DeleteBucket", "s3:ListBucket",
      "s3:PutObject", "s3:GetObject", "s3:DeleteObject",
      "s3:GetBucketLocation",
    ]
    resources = [
      "arn:${local.partition}:s3:::redteam-sandbox-*",
      "arn:${local.partition}:s3:::redteam-sandbox-*/*",
    ]
  }

  # --- Identify self (sts:GetCallerIdentity is always allowed, listed for clarity) ---
  statement {
    sid       = "WhoAmI"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deploy_perms" {
  name   = "redteam-deploy-permissions"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy_perms.json
}

# -----------------------------------------------------------------------------
# Outputs — feed these into the GitHub Actions workflow / runner env.
# -----------------------------------------------------------------------------
output "deploy_role_arn" {
  description = "Set as the role-to-assume in the GitHub Actions OIDC step."
  value       = aws_iam_role.deploy.arn
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}

output "sandbox_boundary_arn" {
  description = "T2 runner pins this as PermissionsBoundary on every principal it creates."
  value       = aws_iam_policy.sandbox_boundary.arn
}

output "sandbox_path" {
  value = var.sandbox_path
}
