"""
Real S3 DATA-event reader for the exfil scenario (T4).

S3 GetObject/PutObject are CloudTrail *data events*: unlike the management
events T2/recon use, they are NOT recorded by default and do NOT appear in
`LookupEvents`. They are captured only when a trail has an S3 data-event
selector. Our Terraform (`infra/aws-bootstrap/cloud_scenarios.tf`) creates such
a trail scoped to `redteam-sandbox-*` buckets and ships the events to a
CloudWatch Logs group, which this module reads back with `FilterLogEvents`.

That makes T4's detection genuine in exactly the same way T2's is: the
evaluator counts S3 reads that AWS actually recorded, not ones the runner
self-reported. CloudWatch delivery is near real-time (usually under a couple of
minutes), but we still poll with a timeout to absorb latency.

Fails soft: on any error/timeout it returns whatever it found so the calling
scenario degrades to "partial" rather than crashing the run.
"""

import json
import time
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


def _client(region: str):
    return boto3.client(
        "logs",
        region_name=region,
        config=Config(retries={"max_attempts": 5, "mode": "standard"}),
    )


def _parse_event_time(detail: dict):
    """CloudTrail eventTime is ISO8601 'Z'; return epoch seconds (float)."""
    ts = detail.get("eventTime")
    if not ts:
        return time.time()
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        ).timestamp()
    except (ValueError, TypeError):
        return time.time()


def _to_observable(detail: dict, run_id: str) -> dict:
    rp = detail.get("requestParameters") or {}
    ui = detail.get("userIdentity") or {}
    # principal: assumed-role ARN is identical across this run's reads, so the
    # evaluator's unique-principal check collapses them to one actor.
    principal = ui.get("arn") or ui.get("principalId") or "unknown"
    return {
        "type": "s3_access_log",
        "event_name": detail.get("eventName"),
        "principal": principal,
        "bucket": rp.get("bucketName"),
        "key": rp.get("key"),
        "event_time": _parse_event_time(detail),
        "cloudtrail_event_id": detail.get("eventID"),
        "aws_region": detail.get("awsRegion"),
        "source": "real-cloudtrail-data",  # provenance: derived, not self-reported
        "run_id": run_id,
    }


def poll_for_s3_data_events(
    log_group_name: str,
    run_id: str,
    start_time,
    region: str = "us-east-1",
    scope: str = None,
    expected_event_names=("GetObject",),
    min_count: int = 1,
    timeout_s: int = 900,
    interval_s: int = 30,
) -> list:
    """Poll the CloudWatch Logs group the trail ships S3 data events to, until
    the primary expected event reaches `min_count` for THIS run, or we time out.

    An event counts as ours only if `scope` (e.g. the run's bucket name) appears
    in its raw record — data events carry no run_id of their own, so we scope by
    the bucket. Returns a list of `s3_access_log` observable dicts (deduped by
    CloudTrail eventID). Empty/partial on timeout.
    """
    expected = list(expected_event_names)
    primary = expected[0] if expected else "GetObject"
    logs = _client(region)
    start_ms = int(start_time.timestamp() * 1000)
    found: dict = {}  # eventID -> observable
    deadline = time.time() + timeout_s
    attempt = 0

    print(
        f"[S3LOG] Polling CloudWatch Logs '{log_group_name}' ({region}) for "
        f"{expected} scoped to '{scope or run_id}' "
        f"(need ≥{min_count} {primary}, timeout {timeout_s}s)"
    )

    while True:
        attempt += 1
        token = None
        try:
            while True:
                kwargs = {
                    "logGroupName": log_group_name,
                    "startTime": start_ms,
                    "limit": 10000,
                }
                if token:
                    kwargs["nextToken"] = token
                resp = logs.filter_log_events(**kwargs)
                for ev in resp.get("events", []):
                    msg = ev.get("message", "") or ""
                    if scope and scope not in msg:
                        continue
                    try:
                        detail = json.loads(msg)
                    except (ValueError, TypeError):
                        continue
                    if detail.get("eventName") not in expected:
                        continue
                    eid = detail.get("eventID") or f"{ev.get('eventId')}"
                    found[eid] = _to_observable(detail, run_id)
                token = resp.get("nextToken")
                if not token:
                    break
        except (ClientError, BotoCoreError) as e:
            # ResourceNotFound while the log stream is still being created, etc.
            print(f"[S3LOG]   filter error (attempt {attempt}): {e}")

        primary_count = sum(1 for o in found.values() if o["event_name"] == primary)
        if primary_count >= min_count:
            print(
                f"[S3LOG] Found {primary_count} {primary} event(s) "
                f"(+{len(found) - primary_count} other) after {attempt} poll(s)."
            )
            break
        if time.time() >= deadline:
            print(
                f"[S3LOG] Timeout after {attempt} poll(s); "
                f"have {primary_count} {primary} (need {min_count})."
            )
            break
        print(
            f"[S3LOG]   poll {attempt}: have {primary_count}/{min_count} {primary}; "
            f"waiting {interval_s}s"
        )
        time.sleep(interval_s)

    return list(found.values())
