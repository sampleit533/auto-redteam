"""
T4 — Data Access / Bulk S3 Read Pattern (T1530)

Simulates the bulk-read pattern characteristic of data staging before
exfiltration. Creates a sandbox S3 bucket on LocalStack, populates it
with synthetic objects, and reads them rapidly. Non-destructive: bucket
+ objects are deleted at the end of the run.
"""

import os
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def _s3_client(endpoint: str, region: str):
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        config=Config(retries={"max_attempts": 2}, signature_version="s3v4"),
    )


def _record(observables: list, principal: str, bucket: str, key: str, run_id: str):
    observables.append({
        "type": "s3_access_log",
        "event_name": "GetObject",
        "principal": principal,
        "bucket": bucket,
        "key": key,
        "event_time": time.time(),
        "run_id": run_id,
    })


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]

    endpoint = os.environ.get("IAM_ENDPOINT", target.get("endpoint", "http://localstack:4566"))
    region = target.get("region", "us-east-1")
    bucket = (params.get("bucket_name") or f"redteam-test-bucket-{run_id}").lower().replace("_", "-")

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

    print(f"[T4] S3 endpoint: {endpoint}")
    print(f"[T4] Bucket: {bucket}")
    print(f"[T4] Plan: populate {num_objects} objects, then perform {read_count} GetObject calls")
    print(f"[T4] Principal: {principal}")

    # Step 1 — CreateBucket
    print(f"\n[T4] Step 1/3: CreateBucket")
    try:
        s3.create_bucket(Bucket=bucket)
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

    status = "success" if successful_reads >= max(1, int(read_count * 0.8)) else "partial"
    print(f"\n[T4] Done. Successful reads: {successful_reads}/{read_count}")

    return {
        "status": status,
        "observables_generated": observables,
        "details": {
            "endpoint": endpoint,
            "bucket": bucket,
            "principal": principal,
            "objects_populated": len(object_keys),
            "successful_reads": successful_reads,
            "failed_reads": failed_reads,
        },
    }
