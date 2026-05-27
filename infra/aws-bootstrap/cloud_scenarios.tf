# =============================================================================
# auto-redteam — extra cloud infrastructure for the recon + exfil scenarios
#
# This file extends the one-time bootstrap (see main.tf) with what the two
# additional cloud scenarios need on REAL AWS:
#
#   • Recon (t8, T1580)  — read-only Discovery permissions on the deploy role.
#                          Detection uses CloudTrail MANAGEMENT events, which
#                          Event history captures for free — no trail required.
#
#   • Exfil  (t4, T1530) — S3 GetObject/PutObject are DATA events: CloudTrail
#                          does NOT record them unless a trail with an S3 data
#                          event selector is configured. So we create a trail
#                          that ships data events for the sandbox buckets to a
#                          CloudWatch Logs group, which the runner reads back
#                          (the same "genuine, not self-reported" idea as T2).
#
# Everything here lives in the same root module/state as main.tf, so it reuses
# its locals (account_id, partition) and the aws_iam_role.deploy resource.
# =============================================================================

locals {
  trail_name      = "redteam-sandbox-trail"
  trail_log_group = "/aws/cloudtrail/redteam-sandbox"
  # Trail's own log bucket. Deliberately NOT prefixed "redteam-sandbox-" so the
  # S3 data-event selector below does not log the trail writing its own logs.
  trail_bucket = "redteam-trail-logs-${local.account_id}"
  # Prefix the data-event selector watches. T4 buckets are redteam-sandbox-t4-*.
  sandbox_s3_prefix = "arn:${local.partition}:s3:::redteam-sandbox-"
  # Constructed up-front to avoid a cycle between the trail and its bucket policy.
  trail_arn = "arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
}

# -----------------------------------------------------------------------------
# Extra permissions on the existing deploy role: Discovery (recon) + reading
# the data-event log group (exfil). Kept in a SEPARATE inline policy so the
# base T2 policy in main.tf stays focused.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_cloud_extra" {

  # --- t8 recon: read-only enumeration of the account (Cloud Discovery) ---
  statement {
    sid    = "ReconReadOnlyDiscovery"
    effect = "Allow"
    actions = [
      "iam:ListUsers",
      "iam:ListRoles",
      "iam:ListPolicies",
      "iam:GetAccountAuthorizationDetails",
      "iam:ListAccessKeys",
      "s3:ListAllMyBuckets",
    ]
    resources = ["*"] # List/Get discovery calls are account-wide, cannot be path-scoped
  }

  # --- t4 exfil detection: read S3 data events back from CloudWatch Logs ---
  statement {
    sid    = "T4ReadS3DataEvents"
    effect = "Allow"
    actions = [
      "logs:FilterLogEvents",
      "logs:GetLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = [
      aws_cloudwatch_log_group.trail.arn,
      "${aws_cloudwatch_log_group.trail.arn}:*",
    ]
  }

  statement {
    sid       = "T4DescribeLogGroups"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deploy_cloud_extra" {
  name   = "redteam-deploy-cloud-extra"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy_cloud_extra.json
}

# -----------------------------------------------------------------------------
# CloudWatch Logs destination for S3 data events (near real-time readback).
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "trail" {
  name              = local.trail_log_group
  retention_in_days = 7
  tags              = { Project = "auto-redteam" }
}

# Role CloudTrail assumes to deliver events into the log group above.
data "aws_iam_policy_document" "trail_cwl_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_cwl" {
  name               = "redteam-trail-cwl"
  assume_role_policy = data.aws_iam_policy_document.trail_cwl_trust.json
  tags               = { Project = "auto-redteam" }
}

data "aws_iam_policy_document" "trail_cwl_perms" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "trail_cwl" {
  name   = "deliver-to-cwl"
  role   = aws_iam_role.trail_cwl.id
  policy = data.aws_iam_policy_document.trail_cwl_perms.json
}

# -----------------------------------------------------------------------------
# S3 bucket the trail delivers to (required even when also shipping to CWL).
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket
  force_destroy = true # allow `terraform destroy` to remove it with logs inside
  tags          = { Project = "auto-redteam" }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

# -----------------------------------------------------------------------------
# The trail: data events only (management events already come free via Event
# history / LookupEvents, which T2 and recon use). Scoped to sandbox buckets.
# -----------------------------------------------------------------------------
resource "aws_cloudtrail" "redteam_sandbox" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_cwl.arn
  # Single-region (us-east-1): the T4 runner always creates its sandbox bucket
  # in us-east-1, so its S3 data events are recorded here. A multi-region trail
  # would be forced to also include global-service events, which we don't want.
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_logging                = true

  # Advanced (not basic) selector: basic selectors only accept a full bucket ARN
  # (arn:aws:s3:::bucket/) and reject a partial bucket-name prefix. We want ALL
  # buckets named redteam-sandbox-* and only their object data events, so we
  # match resources.ARN with starts_with. No readOnly field => both reads
  # (GetObject) and writes (PutObject) are captured. No management-event
  # selector => data events only (management events come free via Event history).
  advanced_event_selector {
    name = "Sandbox S3 object data events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = [local.sandbox_s3_prefix] # arn:aws:s3:::redteam-sandbox-
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
  tags       = { Project = "auto-redteam" }
}

# -----------------------------------------------------------------------------
# Outputs consumed by the runner / workflow for the exfil scenario.
# -----------------------------------------------------------------------------
output "cloudtrail_log_group_name" {
  description = "CloudWatch Logs group T4 reads S3 data events back from."
  value       = aws_cloudwatch_log_group.trail.name
}

output "trail_arn" {
  value = aws_cloudtrail.redteam_sandbox.arn
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.id
}
