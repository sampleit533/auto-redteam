"""
T2 — IAM Privilege Escalation Simulation (T1078.004)

Simulates the API call sequence characteristic of privilege escalation:
  CreateRole → AttachRolePolicy → CreateAccessKey

Two backends, selected by REDTEAM_CLOUD_MODE:
  • "aws"  → REAL AWS IAM. Principals are created under a locked-down path
             ("/redteam-sandbox/") with a Deny-all permissions boundary, so
             the escalation is a faithful API sequence with ZERO blast radius.
             Detection is genuine: the cloudtrail_log observables are read
             back from REAL CloudTrail (management events), not self-reported.
  • else   → LocalStack sandbox (default). Observables are self-reported,
             because LocalStack does not expose CloudTrail Event history.

All resources are cleaned up at the end of the run regardless of backend.
"""

import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import cloudtrail_util

EXPECTED_EVENTS = ["CreateRole", "AttachRolePolicy", "CreateAccessKey"]


def _real_aws() -> bool:
    return os.environ.get("REDTEAM_CLOUD_MODE", "").lower() == "aws"


def _iam_client(endpoint: str, region: str):
    """LocalStack client uses a fixed endpoint + dummy creds; the real-AWS
    client uses the default credential chain (env / OIDC / shared config)."""
    if _real_aws():
        return boto3.client(
            "iam",
            region_name=region,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return boto3.client(
        "iam",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        config=Config(retries={"max_attempts": 2}),
    )


def _record_event(observables: list, event_name: str, principal: str, resource: str, run_id: str):
    """Self-report a cloudtrail_log observable — LocalStack mode only."""
    observables.append(
        {
            "type": "cloudtrail_log",
            "event_name": event_name,
            "principal": principal,
            "resource": resource,
            "event_time": time.time(),
            "source": "self-reported",
            "run_id": run_id,
        }
    )


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]

    real_aws = _real_aws()
    # IAM is global; in real mode pin us-east-1 (where CloudTrail logs it).
    if real_aws:
        region = os.environ.get("AWS_REGION", "us-east-1")
        endpoint = None
    else:
        endpoint = os.environ.get("IAM_ENDPOINT", target.get("endpoint", "http://localstack:4566"))
        region = target.get("region", "us-east-1")

    role_name = params.get("role_name", f"redteam-test-role-{run_id}")
    policy_arn = params.get("policy_arn", "arn:aws:iam::aws:policy/ReadOnlyAccess")
    delay = float(params.get("delay_between_calls_seconds", 5))
    principal = os.environ.get(target.get("test_principal_env", "REDTEAM_IAM_PRINCIPAL"), "redteam-sandbox-principal")
    total_window = int(params.get("total_window_seconds", 300))

    # Cloud-mode guardrails: every created principal MUST carry the neutering
    # boundary and live under the sandbox path. Refuse to run unbounded.
    sandbox_path = os.environ.get("REDTEAM_SANDBOX_PATH", "/redteam-sandbox/")
    boundary_arn = os.environ.get("REDTEAM_SANDBOX_BOUNDARY_ARN")
    if real_aws and not boundary_arn:
        return {
            "status": "error",
            "observables_generated": [],
            "details": {
                "error": "REDTEAM_SANDBOX_BOUNDARY_ARN is required in cloud mode "
                "(refusing to create IAM principals without a permissions boundary)."
            },
        }

    iam = _iam_client(endpoint, region)
    observables: list = []
    created_resources: dict = {}
    # Buffer back a little so clock skew never excludes our own events.
    ct_start = datetime.now(timezone.utc) - timedelta(seconds=60)

    assume_role_policy = """{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }"""

    print(f"[T2] Backend: {'REAL AWS' if real_aws else 'LocalStack'} ({endpoint or region})")
    print(f"[T2] Simulating privilege escalation sequence for run: {run_id}")
    print(f"[T2] Delay between calls: {delay}s")
    print(f"[T2] Principal: {principal}")
    if real_aws:
        print(f"[T2] Sandbox path: {sandbox_path}  boundary: {boundary_arn}")

    # Step 1 — CreateRole
    print(f"\n[T2] Step 1/3: CreateRole ({role_name})")
    try:
        create_role_kwargs = dict(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy,
            Description=f"Ephemeral test role - auto-redteam run {run_id}",
            Tags=[{"Key": "auto-redteam", "Value": run_id}],
        )
        if real_aws:
            create_role_kwargs["Path"] = sandbox_path
            create_role_kwargs["PermissionsBoundary"] = boundary_arn
        resp = iam.create_role(**create_role_kwargs)
        created_resources["role_name"] = role_name
        print(f"[T2]   → Role ARN: {resp['Role']['Arn']}")
        if not real_aws:
            _record_event(observables, "CreateRole", principal, role_name, run_id)
    except ClientError as e:
        print(f"[T2]   ERROR: {e}")
        return {"status": "error", "observables_generated": observables, "details": {"error": str(e)}}

    time.sleep(delay)

    # Step 2 — AttachRolePolicy
    print(f"[T2] Step 2/3: AttachRolePolicy ({policy_arn})")
    try:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"[T2]   → Policy attached successfully")
        if not real_aws:
            _record_event(observables, "AttachRolePolicy", principal, policy_arn, run_id)
    except ClientError as e:
        print(f"[T2]   ERROR: {e}")

    time.sleep(delay)

    # Step 3 — CreateAccessKey (for a synthetic, boundaried sandbox user)
    synthetic_user = f"redteam-user-{run_id}"
    print(f"[T2] Step 3/3: CreateAccessKey for user {synthetic_user}")
    try:
        try:
            create_user_kwargs = dict(
                UserName=synthetic_user,
                Tags=[{"Key": "auto-redteam", "Value": run_id}],
            )
            if real_aws:
                create_user_kwargs["Path"] = sandbox_path
                create_user_kwargs["PermissionsBoundary"] = boundary_arn
            iam.create_user(**create_user_kwargs)
            created_resources["user_name"] = synthetic_user
        except ClientError:
            created_resources["user_name"] = synthetic_user  # may already exist

        key_resp = iam.create_access_key(UserName=synthetic_user)
        created_resources["access_key_id"] = key_resp["AccessKey"]["AccessKeyId"]
        # NB: never print/return the secret — the boundary makes it inert anyway.
        print(f"[T2]   → Access Key ID: {key_resp['AccessKey']['AccessKeyId']}")
        if not real_aws:
            _record_event(observables, "CreateAccessKey", principal, synthetic_user, run_id)
            observables[-1]["key_id"] = key_resp["AccessKey"]["AccessKeyId"]
    except ClientError as e:
        print(f"[T2]   ERROR: {e}")

    # Cleanup (CloudTrail has already recorded the Create* events, so tearing
    # down now does not affect detection — it just guarantees no residue).
    print("\n[T2] Cleaning up ephemeral resources...")
    _cleanup(iam, created_resources, policy_arn)

    # Detection: real CloudTrail (genuine) or self-reported (LocalStack).
    if real_aws:
        ct_region = os.environ.get("REDTEAM_CLOUDTRAIL_REGION", "us-east-1")
        timeout_s = int(os.environ.get("REDTEAM_CLOUDTRAIL_TIMEOUT", "900"))
        interval_s = int(os.environ.get("REDTEAM_CLOUDTRAIL_INTERVAL", "30"))
        print("\n[T2] Reading back REAL CloudTrail to confirm detection...")
        ct_obs = cloudtrail_util.poll_for_events(
            EXPECTED_EVENTS,
            run_id=run_id,
            start_time=ct_start,
            region=ct_region,
            timeout_s=timeout_s,
            interval_s=interval_s,
        )
        observables.extend(ct_obs)

    all_events = {o["event_name"] for o in observables if o["type"] == "cloudtrail_log"}
    expected = set(EXPECTED_EVENTS)
    status = "success" if expected.issubset(all_events) else "partial"

    print(f"\n[T2] Done. Events confirmed: {', '.join(sorted(all_events)) or '(none)'}")
    return {
        "status": status,
        "observables_generated": observables,
        "details": {
            "backend": "aws" if real_aws else "localstack",
            "events_generated": sorted(all_events),
            "endpoint": endpoint,
            "region": region,
            "run_id": run_id,
            "principal": principal,
            "role_name": role_name,
            "user_name": synthetic_user,
            "sandbox_path": sandbox_path if real_aws else None,
            "boundary_arn": boundary_arn if real_aws else None,
            "sequence_window_seconds": total_window,
        },
    }


def _cleanup(iam, resources: dict, policy_arn: str):
    """Remove all sandbox resources created during the simulation."""
    if "access_key_id" in resources and "user_name" in resources:
        try:
            iam.delete_access_key(
                UserName=resources["user_name"],
                AccessKeyId=resources["access_key_id"],
            )
            print(f"[T2]   Deleted access key {resources['access_key_id']}")
        except ClientError as e:
            print(f"[T2]   Cleanup warning (key): {e}")

    if "user_name" in resources:
        try:
            iam.delete_user(UserName=resources["user_name"])
            print(f"[T2]   Deleted user {resources['user_name']}")
        except ClientError as e:
            print(f"[T2]   Cleanup warning (user): {e}")

    if "role_name" in resources:
        try:
            iam.detach_role_policy(RoleName=resources["role_name"], PolicyArn=policy_arn)
        except ClientError:
            pass
        try:
            iam.delete_role(RoleName=resources["role_name"])
            print(f"[T2]   Deleted role {resources['role_name']}")
        except ClientError as e:
            print(f"[T2]   Cleanup warning (role): {e}")
