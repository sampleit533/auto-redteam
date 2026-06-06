# =============================================================================
# auto-redteam — EC2 attacker foothold for running scenarios ON a real server
#
# Adversary-emulation model: a single cheap EC2 stands in for a COMPROMISED
# cloud workload. It carries an instance profile (redteam-ec2-foothold) scoped
# to exactly what T2 (IAM privesc) and T4 (S3 bulk read) need. Running the
# UNCHANGED runner code on this box means boto3 picks the instance-profile
# credentials up from IMDS, so CloudTrail attributes every CreateRole /
# GetObject to this workload's role and its source IP — the realistic story.
#
# Same root module/state as main.tf + cloud_scenarios.tf, so it reuses their
# locals (account_id, partition, trail_log_group), the sandbox boundary, the
# deploy role, and the scenario permission documents.
#
#   • Control plane : SSM Session Manager only — NO inbound ports, no SSH key.
#   • Storage (T4)  : stays in real S3 (redteam-sandbox-*). This box is the
#                     attacker's vantage point, NOT the data store.
#   • Code delivery : a private code bucket (NOT sandbox-prefixed, so it never
#                     pollutes the T4 S3 data-event trail); the EC2 pulls with
#                     its instance role — no git credentials ever land here.
#   • Cost          : t3.micro + 8GB gp3, auto stop/start nightly. << $30 / 3wk.
# =============================================================================

variable "foothold_instance_type" {
  description = "EC2 type for the foothold. t3.micro is plenty for the runner."
  type        = string
  default     = "t3.micro"
}

variable "foothold_stop_cron" {
  description = "EventBridge Scheduler cron (UTC) to STOP the box. Default 17:00 UTC = 00:00 ICT."
  type        = string
  default     = "cron(0 17 * * ? *)"
}

variable "foothold_start_cron" {
  description = "EventBridge Scheduler cron (UTC) to START the box. Default 01:00 UTC = 08:00 ICT."
  type        = string
  default     = "cron(0 1 * * ? *)"
}

locals {
  foothold_code_bucket = "redteam-foothold-code-${local.account_id}"
}

# -----------------------------------------------------------------------------
# Latest Amazon Linux 2023 AMI (x86_64) — SSM agent is preinstalled.
# -----------------------------------------------------------------------------
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Default VPC + a subnet (public, IGW-routed) so the SSM agent and AWS APIs are
# reachable over egress 443. No inbound is opened, so a public IP is harmless.
data "aws_vpc" "default" {
  default = true
}

# Only AZs that actually offer the chosen instance type (e.g. t3.micro is not
# available in us-east-1e), so the picked subnet is always launchable.
data "aws_ec2_instance_type_offerings" "foothold_azs" {
  filter {
    name   = "instance-type"
    values = [var.foothold_instance_type]
  }
  location_type = "availability-zone"
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "availability-zone"
    values = data.aws_ec2_instance_type_offerings.foothold_azs.locations
  }
}

# -----------------------------------------------------------------------------
# Security group: NO ingress, egress all. SSM needs no inbound at all.
# -----------------------------------------------------------------------------
resource "aws_security_group" "foothold" {
  name        = "redteam-foothold-sg"
  description = "auto-redteam foothold - egress only, no inbound (SSM control plane)."
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "All outbound (SSM endpoints + AWS APIs over 443)."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "auto-redteam", Name = "redteam-foothold-sg" }
}

# -----------------------------------------------------------------------------
# Private code bucket — the EC2 pulls runner code from here (no git creds).
# Name is deliberately NOT "redteam-sandbox-*", so its objects do NOT match the
# T4 S3 data-event selector in cloud_scenarios.tf (would otherwise be noise).
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "foothold_code" {
  bucket        = local.foothold_code_bucket
  force_destroy = true
  tags          = { Project = "auto-redteam" }
}

resource "aws_s3_bucket_public_access_block" "foothold_code" {
  bucket                  = aws_s3_bucket.foothold_code.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------------------------
# Instance role + profile. Trust = EC2. Permissions = SSM core + the SAME
# scenario documents the deploy role uses (reused, so scoping stays identical:
# IAM only under the sandbox path + with the boundary; S3 only redteam-sandbox-*)
# + read/write on the private code bucket.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "foothold_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "foothold" {
  name               = "redteam-ec2-foothold"
  assume_role_policy = data.aws_iam_policy_document.foothold_trust.json
  tags               = { Project = "auto-redteam" }
}

# SSM Session Manager / Run Command agent connectivity.
resource "aws_iam_role_policy_attachment" "foothold_ssm" {
  role       = aws_iam_role.foothold.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Scenario permissions — reuse the exact scoped documents from main.tf and
# cloud_scenarios.tf. The foothold can do precisely what T2/T4/t8 require and
# nothing more, so "compromising" this box still yields zero blast radius.
resource "aws_iam_role_policy" "foothold_scenarios" {
  name   = "redteam-foothold-scenarios"
  role   = aws_iam_role.foothold.id
  policy = data.aws_iam_policy_document.deploy_perms.json
}

resource "aws_iam_role_policy" "foothold_cloud_extra" {
  name   = "redteam-foothold-cloud-extra"
  role   = aws_iam_role.foothold.id
  policy = data.aws_iam_policy_document.deploy_cloud_extra.json
}

# Pull runner code + push results: the private code bucket only.
data "aws_iam_policy_document" "foothold_code_access" {
  statement {
    sid       = "ListCodeBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.foothold_code.arn]
  }
  statement {
    sid       = "ReadWriteCodeBucket"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.foothold_code.arn}/*"]
  }
}

resource "aws_iam_role_policy" "foothold_code_access" {
  name   = "redteam-foothold-code-access"
  role   = aws_iam_role.foothold.id
  policy = data.aws_iam_policy_document.foothold_code_access.json
}

resource "aws_iam_instance_profile" "foothold" {
  name = "redteam-ec2-foothold"
  role = aws_iam_role.foothold.name
  tags = { Project = "auto-redteam" }
}

# -----------------------------------------------------------------------------
# The foothold instance. user_data installs Python 3.11 + git and drops the
# run-scenario.sh helper (base64-embedded to avoid quoting issues).
# -----------------------------------------------------------------------------
locals {
  foothold_run_script = templatefile("${path.module}/run-scenario.sh.tftpl", {
    code_bucket     = local.foothold_code_bucket
    region          = var.region
    boundary_arn    = aws_iam_policy.sandbox_boundary.arn
    sandbox_path    = var.sandbox_path
    trail_log_group = local.trail_log_group
  })
}

resource "aws_instance" "foothold" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.foothold_instance_type
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [aws_security_group.foothold.id]
  iam_instance_profile        = aws_iam_instance_profile.foothold.name
  associate_public_ip_address = true

  # IMDSv2 required (token-based) — basic hardening of the metadata endpoint.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  user_data = <<-EOT
    #!/bin/bash
    set -eux
    dnf install -y python3.11 python3.11-pip git
    mkdir -p /opt/redteam
    echo "${base64encode(local.foothold_run_script)}" | base64 -d > /opt/redteam/run-scenario.sh
    chmod +x /opt/redteam/run-scenario.sh
  EOT

  tags = { Project = "auto-redteam", Name = "redteam-foothold" }
}

# -----------------------------------------------------------------------------
# Auto stop/start (cost control) via EventBridge Scheduler universal targets.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "scheduler_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "redteam-foothold-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_trust.json
  tags               = { Project = "auto-redteam" }
}

data "aws_iam_policy_document" "scheduler_perms" {
  statement {
    effect    = "Allow"
    actions   = ["ec2:StartInstances", "ec2:StopInstances"]
    resources = ["arn:${local.partition}:ec2:${var.region}:${local.account_id}:instance/${aws_instance.foothold.id}"]
  }
}

resource "aws_iam_role_policy" "scheduler_perms" {
  name   = "start-stop-foothold"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_perms.json
}

resource "aws_scheduler_schedule" "foothold_stop" {
  name = "redteam-foothold-stop"
  flexible_time_window {
    mode = "OFF"
  }
  schedule_expression          = var.foothold_stop_cron
  schedule_expression_timezone = "UTC"
  target {
    arn      = "arn:${local.partition}:scheduler:::aws-sdk:ec2:stopInstances"
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ InstanceIds = [aws_instance.foothold.id] })
  }
}

resource "aws_scheduler_schedule" "foothold_start" {
  name = "redteam-foothold-start"
  flexible_time_window {
    mode = "OFF"
  }
  schedule_expression          = var.foothold_start_cron
  schedule_expression_timezone = "UTC"
  target {
    arn      = "arn:${local.partition}:scheduler:::aws-sdk:ec2:startInstances"
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ InstanceIds = [aws_instance.foothold.id] })
  }
}

# -----------------------------------------------------------------------------
# Let the CI deploy role DRIVE the foothold over SSM (the gated automation path):
# wake the box, send the scenario command, read results, and sync code up.
# This is additive to the deploy role's existing direct-run permissions.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_drive_foothold" {
  statement {
    sid    = "WakeFoothold"
    effect = "Allow"
    actions = [
      "ec2:StartInstances",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceStatus",
    ]
    resources = ["*"] # Describe* cannot be resource-scoped; Start is gated by the run workflow target.
  }
  statement {
    sid    = "SendScenarioCommand"
    effect = "Allow"
    actions = [
      "ssm:SendCommand",
    ]
    resources = [
      "arn:${local.partition}:ec2:${var.region}:${local.account_id}:instance/${aws_instance.foothold.id}",
      "arn:${local.partition}:ssm:${var.region}::document/AWS-RunShellScript",
    ]
  }
  statement {
    sid    = "ReadCommandResults"
    effect = "Allow"
    actions = [
      "ssm:GetCommandInvocation",
      "ssm:ListCommandInvocations",
      "ssm:ListCommands",
      "ssm:DescribeInstanceInformation",
    ]
    resources = ["*"] # these SSM read APIs do not support resource-level scoping
  }
  statement {
    sid       = "SyncCodeUp"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:DeleteObject"]
    resources = [aws_s3_bucket.foothold_code.arn, "${aws_s3_bucket.foothold_code.arn}/*"]
  }
}

resource "aws_iam_role_policy" "deploy_drive_foothold" {
  name   = "redteam-deploy-drive-foothold"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy_drive_foothold.json
}

# -----------------------------------------------------------------------------
# Outputs — feed into repo variables / the foothold-run workflow.
# -----------------------------------------------------------------------------
output "foothold_instance_id" {
  description = "Set as repo variable FOOTHOLD_INSTANCE_ID for the run workflow; also the SSM Session Manager target."
  value       = aws_instance.foothold.id
}

output "foothold_code_bucket" {
  description = "Private bucket the runner code is synced to / pulled from."
  value       = aws_s3_bucket.foothold_code.id
}

output "foothold_role_arn" {
  description = "Instance-profile role CloudTrail will attribute the attack to."
  value       = aws_iam_role.foothold.arn
}
