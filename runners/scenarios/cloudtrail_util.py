"""
Real CloudTrail reader for cloud scenarios.

Polls CloudTrail `LookupEvents` (management events — free, no trail required)
for the API calls a scenario just made, and returns them as `cloudtrail_log`
observables DERIVED FROM AWS rather than self-reported. This is what makes
T2's detection genuine: the evaluator counts events that CloudTrail actually
recorded, with the same ~5–15 min latency a real defender faces.

IAM and STS are GLOBAL services — CloudTrail records their events in
us-east-1 regardless of the caller's region — so us-east-1 is the default
lookup region here.

Fails soft: on any error or timeout it returns whatever it found, so the
calling scenario degrades to "partial" instead of crashing the whole run.
"""

import json
import time

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


def _client(region: str):
    return boto3.client(
        "cloudtrail",
        region_name=region,
        config=Config(retries={"max_attempts": 5, "mode": "standard"}),
    )


def _lookup_by_event_name(ct, event_name: str, start_time) -> list:
    """All events with this EventName since start_time (paginated).

    LookupEvents accepts only ONE LookupAttribute per request, so we filter
    by EventName here and scope to our run client-side via `scope_token`.
    """
    events: list = []
    token = None
    while True:
        kwargs = {
            "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": event_name}
            ],
            "StartTime": start_time,
            "MaxResults": 50,
        }
        if token:
            kwargs["NextToken"] = token
        resp = ct.lookup_events(**kwargs)
        events.extend(resp.get("Events", []))
        token = resp.get("NextToken")
        if not token:
            break
    return events


def _first_resource(ev: dict):
    for r in ev.get("Resources", []) or []:
        if r.get("ResourceName"):
            return r["ResourceName"]
    return None


def _to_observable(event_name: str, ev: dict, detail: dict, run_id: str) -> dict:
    return {
        "type": "cloudtrail_log",
        "event_name": event_name,
        # Caller identity — identical across this run's calls, so the
        # evaluator's composite rule groups all three under one principal.
        "principal": ev.get("Username")
        or detail.get("userIdentity", {}).get("arn")
        or "unknown",
        "resource": _first_resource(ev),
        "event_time": ev["EventTime"].timestamp()
        if ev.get("EventTime")
        else time.time(),
        "cloudtrail_event_id": ev.get("EventId"),
        "aws_region": detail.get("awsRegion"),
        "source": "real-cloudtrail",  # provenance: derived, not self-reported
        "run_id": run_id,
    }


def poll_for_events(
    expected_event_names,
    run_id: str,
    start_time,
    region: str = "us-east-1",
    timeout_s: int = 900,
    interval_s: int = 30,
    scope_token: str = None,
) -> list:
    """Poll CloudTrail until every expected event for THIS run is found or we
    time out. An event counts as ours only if `scope_token` (default: run_id,
    which is embedded in every resource name) appears in its raw record.

    Returns a list of `cloudtrail_log` observable dicts (one per event name
    found). Empty/partial on timeout.
    """
    scope = scope_token or run_id
    ct = _client(region)
    expected = set(expected_event_names)
    found: dict = {}  # event_name -> observable
    deadline = time.time() + timeout_s
    attempt = 0

    print(
        f"[CT] Polling CloudTrail ({region}) for {sorted(expected)} "
        f"scoped to run_id={run_id} (latency ~5–15min, timeout {timeout_s}s)"
    )

    while True:
        attempt += 1
        for name in sorted(expected - set(found)):
            try:
                raw_events = _lookup_by_event_name(ct, name, start_time)
            except (ClientError, BotoCoreError) as e:
                print(f"[CT]   lookup {name} error: {e}")
                continue
            for ev in raw_events:
                detail_str = ev.get("CloudTrailEvent", "") or ""
                if scope and scope not in detail_str:
                    continue
                try:
                    detail = json.loads(detail_str)
                except (ValueError, TypeError):
                    detail = {}
                found[name] = _to_observable(name, ev, detail, run_id)
                break

        remaining = expected - set(found)
        if not remaining:
            print(f"[CT] All {len(expected)} events found after {attempt} poll(s).")
            break
        if time.time() >= deadline:
            print(f"[CT] Timeout after {attempt} poll(s); missing: {sorted(remaining)}")
            break
        print(
            f"[CT]   poll {attempt}: have {sorted(found)}; "
            f"waiting {interval_s}s for {sorted(remaining)}"
        )
        time.sleep(interval_s)

    return list(found.values())
