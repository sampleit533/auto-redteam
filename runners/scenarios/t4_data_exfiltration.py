"""
T4 — Data Access / Bulk S3 Read Pattern (T1530)

Simulates the bulk-read pattern characteristic of data staging before
exfiltration: create a sandbox S3 bucket, populate it with synthetic objects,
and read them rapidly from a single principal. Non-destructive — the bucket and
its objects are deleted at the end of the run.

Two backends, selected by REDTEAM_CLOUD_MODE (same pattern as T2):
  • "aws"  → REAL AWS S3. The bucket is named redteam-sandbox-t4-<run_id> (the
             "redteam-sandbox-" prefix is what the CloudTrail data-event
             selector watches) and created in us-east-1, where the single-region
             trail lives. Detection is genuine: GetObject is a CloudTrail DATA
             event, so the observables are read back from the CloudWatch Logs
             group the trail ships data events to — NOT self-reported.
  • else   → LocalStack sandbox (default). Observables are self-reported,
             because LocalStack does not expose CloudTrail data events.
"""

import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import s3log_util


def _real_aws() -> bool:
    return os.environ.get("REDTEAM_CLOUD_MODE", "").lower() == "aws"


def _s3_client(endpoint: str, region: str):
    """Real-AWS client uses the default credential chain; LocalStack client
    uses a fixed endpoint + dummy creds (mirrors t2_priv_escalation)."""
    if _real_aws():
        return boto3.client(
            "s3",
            region_name=region,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}, signature_version="s3v4"),
        )
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        config=Config(retries={"max_attempts": 2}, signature_version="s3v4"),
    )


def _record(observables: list, principal: str, bucket: str, key: str, run_id: str):
    """Self-report an s3_access_log observable — LocalStack mode only."""
    observables.append({
        "type": "s3_access_log",
        "event_name": "GetObject",
        "principal": principal,
        "bucket": bucket,
        "key": key,
        "event_time": time.time(),
        "source": "self-reported",
        "run_id": run_id,
    })


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]

    real_aws = _real_aws()
    if real_aws:
        # The single-region trail lives in us-east-1, so the bucket (and thus its
        # S3 data events) must be there too. The "redteam-sandbox-" prefix is
        # mandatory: it is what the trail's data-event selector matches.
        region = os.environ.get("AWS_REGION", "us-east-1")
        endpoint = None
        default_bucket = f"redteam-sandbox-t4-{run_id}"
    else:
        endpoint = os.environ.get("IAM_ENDPOINT", target.get("endpoint", "http://localstack:4566"))
        region = target.get("region", "us-east-1")
        default_bucket = f"redteam-test-bucket-{run_id}"

    bucket = (params.get("bucket_name") if not real_aws else None) or default_bucket
    bucket = bucket.lower().replace("_", "-")

    num_objects = int(params.get("num_objects", 100))
    object_size = int(params.get("object_size_bytes", 256))
    read_count = int(params.get("read_count", 100))
    delay = float(params.get("delay_between_reads_seconds", 0.05))

    principal = os.environ.get(
        target.get("test_principal_env", "REDTEAM_IAM_PRINCIPAL"),
        "redteam-sandbox-principal",
    )

    s3 = _s3_client(endpoint, region)
    observables: list = []
    # Buffer back so clock skew / delivery batching never excludes our events.
    ct_start = datetime.now(timezone.utc) - timedelta(seconds=60)

    print(f"[T4] Backend: {'REAL AWS' if real_aws else 'LocalStack'} ({endpoint or region})")
    print(f"[T4] Bucket: {bucket}")
    print(f"[T4] Plan: populate {num_objects} objects, then perform {read_count} GetObject calls")
    print(f"[T4] Principal: {principal}")

    # Step 1 — CreateBucket
    print(f"\n[T4] Step 1/3: CreateBucket")
    try:
        create_kwargs = {"Bucket": bucket}
        # us-east-1 must NOT pass a LocationConstraint; every other region must.
        if real_aws and region != "us-east-1":
            create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**create_kwargs)
        print(f"[T4]   Created bucket {bucket}")
    except ClientError as e:
        if "BucketAlreadyOwnedByYou" in str(e) or "BucketAlreadyExists" in str(e):
            print(f"[T4]   Bucket already exists, reusing")
        else:
            print(f"[T4]   ERROR: {e}")
            return {
                "status": "error",
                "observables_generated": observables,
                "details": {"error": str(e), "endpoint": endpoint, "bucket": bucket},
            }

    # Step 2 — Populate synthetic objects
    print(f"[T4] Step 2/3: PutObject ×{num_objects}")
    object_keys: list = []
    for i in range(num_objects):
        key = f"data/object_{i:04d}.bin"
        body = bytes((i * 7 + 13) % 256 for _ in range(object_size))
        try:
            s3.put_object(Bucket=bucket, Key=key, Body=body)
            object_keys.append(key)
        except ClientError as e:
            print(f"[T4]   put_object {key}: {e}")
    print(f"[T4]   Populated {len(object_keys)} objects")

    if not object_keys:
        return {
            "status": "error",
            "observables_generated": observables,
            "details": {"error": "no objects populated", "endpoint": endpoint, "bucket": bucket},
        }

    # Step 3 — Bulk read
    print(f"[T4] Step 3/3: GetObject ×{read_count} (bulk read)")
    successful_reads = 0
    failed_reads = 0
    for i in range(read_count):
        key = object_keys[i % len(object_keys)]
        try:
            resp = s3.get_object(Bucket=bucket, Key=key)
            resp["Body"].read()
            successful_reads += 1
            if not real_aws:
                _record(observables, principal, bucket, key, run_id)
            if (i + 1) % 25 == 0 or i == 0:
                print(f"[T4]   {i+1}/{read_count} reads completed")
        except ClientError as e:
            failed_reads += 1
            observables.append({
                "type": "error",
                "operation": "GetObject",
                "key": key,
                "error": str(e),
            })
        if delay > 0:
            time.sleep(delay)
    print(f"[T4]   Reads: {successful_reads} ok, {failed_reads} failed")

    # Detection (real mode): read S3 DATA events back from CloudWatch Logs BEFORE
    # tearing down — DeleteObject/DeleteBucket are also data events and would add
    # noise, but more importantly we want to confirm the reads were captured.
    min_get = max(1, int(read_count * 0.8))
    if real_aws:
        log_group = os.environ.get("REDTEAM_TRAIL_LOG_GROUP", "/aws/cloudtrail/redteam-sandbox")
        ct_region = os.environ.get("REDTEAM_CLOUDTRAIL_REGION", "us-east-1")
        timeout_s = int(os.environ.get("REDTEAM_CLOUDTRAIL_TIMEOUT", "900"))
        interval_s = int(os.environ.get("REDTEAM_CLOUDTRAIL_INTERVAL", "30"))
        print("\n[T4] Reading back REAL CloudTrail S3 data events from CloudWatch Logs...")
        data_obs = s3log_util.poll_for_s3_data_events(
            log_group,
            run_id=run_id,
            start_time=ct_start,
            region=ct_region,
            scope=bucket,  # data events carry no run_id; scope by the bucket name
            expected_event_names=("GetObject",),
            min_count=min_get,
            timeout_s=timeout_s,
            interval_s=interval_s,
        )
        observables.extend(data_obs)

    # Cleanup
    print(f"\n[T4] Cleaning up ephemeral resources...")
    deleted = 0
    for key in object_keys:
        try:
            s3.delete_object(Bucket=bucket, Key=key)
            deleted += 1
        except ClientError:
            pass
    print(f"[T4]   Deleted {deleted}/{len(object_keys)} objects")
    try:
        s3.delete_bucket(Bucket=bucket)
        print(f"[T4]   Deleted bucket {bucket}")
    except ClientError as e:
        print(f"[T4]   Cleanup warning (bucket): {e}")

    # Success criterion: in real mode, detection is confirmed by CloudTrail data
    # events; in LocalStack mode, by the reads the runner performed.
    get_obs = sum(1 for o in observables if o.get("type") == "s3_access_log" and o.get("event_name") == "GetObject")
    if real_aws:
        status = "success" if get_obs >= min_get else "partial"
    else:
        status = "success" if successful_reads >= min_get else "partial"
    print(f"\n[T4] Done. Successful reads: {successful_reads}/{read_count}; "
          f"GetObject observables: {get_obs}")

    return {
        "status": status,
        "observables_generated": observables,
        "details": {
            "backend": "aws" if real_aws else "localstack",
            "endpoint": endpoint,
            "region": region,
            "bucket": bucket,
            "principal": principal,
            "objects_populated": len(object_keys),
            "successful_reads": successful_reads,
            "failed_reads": failed_reads,
            "getobject_observables": get_obs,
            "run_id": run_id,
        },
    }
