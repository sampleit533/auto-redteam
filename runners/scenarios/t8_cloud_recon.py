"""
T8 — Cloud Infrastructure Discovery (T1580)

Simulates the read-only enumeration an attacker performs after gaining a
foothold and before escalating / exfiltrating: list IAM users, roles, managed
policies, the full account authorization detail, and S3 buckets. This is the
opening move of the cloud kill chain (Discovery → PrivEsc(T2) → Exfil(T4)).

Two backends, selected by REDTEAM_CLOUD_MODE (same pattern as T2):
  • "aws"  → REAL AWS. The calls are genuine read-only API calls; detection is
             genuine too — the cloudtrail_log observables are read back from
             REAL CloudTrail MANAGEMENT events (free, no trail required).
             Recon calls embed no run_id in any resource, so we scope the
             CloudTrail read-back by the CALLER'S SESSION identity instead
             (the assumed-role session name "redteam-<run_id>" in CI, or the
             IAM username locally), plus the start time.
  • else   → LocalStack sandbox (default). The same list calls are made, but
             observables are self-reported because LocalStack has no CloudTrail
             Event history.

Read-only: nothing is created or modified, so there is nothing to clean up.
"""

import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

import cloudtrail_util

# Discovery events we require for detection. All are IAM management events,
# which CloudTrail records in us-east-1 (IAM is global) and which an
# assumed-role caller can make without a username — so they are reliable in CI.
EXPECTED_EVENTS = [
    "ListUsers",
    "ListRoles",
    "ListPolicies",
    "GetAccountAuthorizationDetails",
]


def _real_aws() -> bool:
    return os.environ.get("REDTEAM_CLOUD_MODE", "").lower() == "aws"


def _client(service: str, endpoint: str, region: str):
    """Real-AWS client uses the default credential chain; LocalStack client
    uses a fixed endpoint + dummy creds (mirrors t2_priv_escalation)."""
    if _real_aws():
        return boto3.client(
            service,
            region_name=region,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return boto3.client(
        service,
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        config=Config(retries={"max_attempts": 2}),
    )


def _record_event(observables: list, event_name: str, principal: str, run_id: str):
    """Self-report a cloudtrail_log observable — LocalStack mode only."""
    observables.append(
        {
            "type": "cloudtrail_log",
            "event_name": event_name,
            "principal": principal,
            "resource": None,
            "event_time": time.time(),
            "source": "self-reported",
            "run_id": run_id,
        }
    )


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    target = scenario_def["target"]
    params = scenario_def.get("parameters", {})

    real_aws = _real_aws()
    # IAM/STS are global → CloudTrail logs them in us-east-1; pin it in real mode.
    if real_aws:
        region = os.environ.get("AWS_REGION", "us-east-1")
        endpoint = None
    else:
        endpoint = os.environ.get("IAM_ENDPOINT", target.get("endpoint", "http://localstack:4566"))
        region = target.get("region", "us-east-1")

    delay = float(params.get("delay_between_calls_seconds", 2))
    total_window = int(params.get("total_window_seconds", 300))
    principal = os.environ.get(
        target.get("test_principal_env", "REDTEAM_IAM_PRINCIPAL"),
        "redteam-sandbox-principal",
    )

    iam = _client("iam", endpoint, region)
    sts = _client("sts", endpoint, region)
    s3 = _client("s3", endpoint, region)

    observables: list = []
    counts: dict = {}
    # Buffer back so clock skew never excludes our own events.
    ct_start = datetime.now(timezone.utc) - timedelta(seconds=60)
    scope_token = None  # set from GetCallerIdentity below (real mode)

    print(f"[T8] Backend: {'REAL AWS' if real_aws else 'LocalStack'} ({endpoint or region})")
    print(f"[T8] Cloud Discovery (read-only enumeration) for run: {run_id}")

    # Each tuple: (label, callable, event_name). callable returns a count summary.
    def _whoami():
        ident = sts.get_caller_identity()
        return ident

    def _list_users():
        return iam.list_users(MaxItems=200).get("Users", [])

    def _list_roles():
        return iam.list_roles(MaxItems=200).get("Roles", [])

    def _list_policies():
        # Scope=Local → customer-managed policies (the interesting ones for recon).
        return iam.list_policies(Scope="Local", MaxItems=200).get("Policies", [])

    def _get_account_auth_details():
        # The big one: dumps users+roles+groups+policies in a single call.
        return iam.get_account_authorization_details(MaxItems=200)

    def _list_buckets():
        return s3.list_buckets().get("Buckets", [])

    steps = [
        ("GetCallerIdentity (whoami)", _whoami, "GetCallerIdentity"),
        ("ListUsers", _list_users, "ListUsers"),
        ("ListRoles", _list_roles, "ListRoles"),
        ("ListPolicies (customer-managed)", _list_policies, "ListPolicies"),
        ("GetAccountAuthorizationDetails", _get_account_auth_details, "GetAccountAuthorizationDetails"),
        ("ListBuckets", _list_buckets, "ListBuckets"),
    ]

    for i, (label, fn, event_name) in enumerate(steps, 1):
        print(f"[T8] Step {i}/{len(steps)}: {label}")
        try:
            result = fn()
            # Derive the CloudTrail scope token from the caller's own identity.
            if event_name == "GetCallerIdentity" and real_aws:
                arn = (result or {}).get("Arn", "")
                # assumed-role: .../redteam-deploy/redteam-<run_id> → session name
                # IAM user:     .../user/<name>                     → username
                scope_token = arn.rsplit("/", 1)[-1] if "/" in arn else (arn or None)
                print(f"[T8]   caller={arn}  scope_token={scope_token}")
            elif isinstance(result, list):
                counts[event_name] = len(result)
                print(f"[T8]   → {len(result)} item(s)")
            elif isinstance(result, dict):
                n = len(result.get("UserDetailList", [])) + len(result.get("RoleDetailList", []))
                counts[event_name] = n
                print(f"[T8]   → {n} principal detail(s)")
            # LocalStack has no CloudTrail Event history → self-report.
            if not real_aws:
                _record_event(observables, event_name, principal, run_id)
        except (ClientError, BotoCoreError) as e:
            print(f"[T8]   WARN {event_name}: {e}")
        time.sleep(delay)

    # Detection: real CloudTrail (genuine) or self-reported (LocalStack).
    if real_aws:
        ct_region = os.environ.get("REDTEAM_CLOUDTRAIL_REGION", "us-east-1")
        timeout_s = int(os.environ.get("REDTEAM_CLOUDTRAIL_TIMEOUT", "900"))
        interval_s = int(os.environ.get("REDTEAM_CLOUDTRAIL_INTERVAL", "30"))
        print("\n[T8] Reading back REAL CloudTrail to confirm Discovery events...")
        ct_obs = cloudtrail_util.poll_for_events(
            EXPECTED_EVENTS,
            run_id=run_id,
            start_time=ct_start,
            region=ct_region,
            timeout_s=timeout_s,
            interval_s=interval_s,
            scope_token=scope_token,  # session/username, NOT run_id (no run_id in recon calls)
        )
        observables.extend(ct_obs)

    all_events = {o["event_name"] for o in observables if o["type"] == "cloudtrail_log"}
    expected = set(EXPECTED_EVENTS)
    status = "success" if expected.issubset(all_events) else "partial"

    print(f"\n[T8] Done. Discovery events confirmed: {', '.join(sorted(all_events)) or '(none)'}")
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
            "scope_token": scope_token,
            "enumerated_counts": counts,
            "sequence_window_seconds": total_window,
        },
    }
