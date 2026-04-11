"""
T2 — IAM Privilege Escalation Simulation (T1078.004)

Simulates the API call sequence characteristic of privilege escalation:
  CreateRole → AttachRolePolicy → CreateAccessKey

Targets a sandbox IAM endpoint (LocalStack) using synthetic credentials.
No real AWS permissions are modified.
"""

import os
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def _iam_client(endpoint: str, region: str) -> object:
    return boto3.client(
        "iam",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        config=Config(retries={"max_attempts": 2}),
    )


def _record_event(observables: list, event_name: str, principal: str, resource: str, run_id: str):
    observables.append(
        {
            "type": "cloudtrail_log",
            "event_name": event_name,
            "principal": principal,
            "resource": resource,
            "event_time": time.time(),
            "run_id": run_id,
        }
    )


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]

    endpoint = os.environ.get("IAM_ENDPOINT", target.get("endpoint", "http://localstack:4566"))
    region = target.get("region", "us-east-1")
    role_name = params.get("role_name", f"redteam-test-role-{run_id}")
    policy_arn = params.get("policy_arn", "arn:aws:iam::aws:policy/ReadOnlyAccess")
    delay = float(params.get("delay_between_calls_seconds", 5))
    principal = os.environ.get(target.get("test_principal_env", "REDTEAM_IAM_PRINCIPAL"), "redteam-sandbox-principal")
    total_window = int(params.get("total_window_seconds", 300))

    iam = _iam_client(endpoint, region)
    observables = []
    created_resources = {}

    assume_role_policy = """{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }"""

    print(f"[T2] IAM endpoint: {endpoint}")
    print(f"[T2] Simulating privilege escalation sequence for run: {run_id}")
    print(f"[T2] Delay between calls: {delay}s")
    print(f"[T2] Principal: {principal}")

    # Step 1 — CreateRole
    print(f"\n[T2] Step 1/3: CreateRole ({role_name})")
    try:
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy,
            Description=f"Ephemeral test role — auto-redteam run {run_id}",
            Tags=[{"Key": "auto-redteam", "Value": run_id}],
        )
        created_resources["role_name"] = role_name
        print(f"[T2]   → Role ARN: {resp['Role']['Arn']}")
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
        _record_event(observables, "AttachRolePolicy", principal, policy_arn, run_id)
    except ClientError as e:
        print(f"[T2]   ERROR: {e}")

    time.sleep(delay)

    # Step 3 — CreateAccessKey (using a synthetic IAM user for the sandbox)
    synthetic_user = f"redteam-user-{run_id}"
    print(f"[T2] Step 3/3: CreateAccessKey for user {synthetic_user}")
    try:
        # Create the user first (sandbox only)
        try:
            iam.create_user(
                UserName=synthetic_user,
                Tags=[{"Key": "auto-redteam", "Value": run_id}],
            )
            created_resources["user_name"] = synthetic_user
        except ClientError:
            pass  # May already exist in LocalStack

        key_resp = iam.create_access_key(UserName=synthetic_user)
        created_resources["access_key_id"] = key_resp["AccessKey"]["AccessKeyId"]
        print(f"[T2]   → Access Key ID: {key_resp['AccessKey']['AccessKeyId']}")
        _record_event(observables, "CreateAccessKey", principal, synthetic_user, run_id)
        observables[-1]["key_id"] = key_resp["AccessKey"]["AccessKeyId"]
    except ClientError as e:
        print(f"[T2]   ERROR: {e}")

    # Cleanup
    print("\n[T2] Cleaning up ephemeral resources...")
    _cleanup(iam, created_resources, policy_arn)

    all_events = {o["event_name"] for o in observables if o["type"] == "cloudtrail_log"}
    expected = {"CreateRole", "AttachRolePolicy", "CreateAccessKey"}
    status = "success" if expected.issubset(all_events) else "partial"

    print(f"\n[T2] Done. Events generated: {', '.join(all_events)}")
    return {
        "status": status,
        "observables_generated": observables,
        "details": {
            "events_generated": list(all_events),
            "endpoint": endpoint,
            "run_id": run_id,
            "principal": principal,
            "role_name": role_name,
            "user_name": synthetic_user,
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
