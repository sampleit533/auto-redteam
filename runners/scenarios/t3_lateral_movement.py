"""
T3 — Lateral Movement Pattern (T1021)

Simulates lateral movement by connecting from a single source to multiple
internal hosts in the sandbox Docker network. Non-destructive: TCP connect
only — the socket is closed immediately after a successful handshake.
Records every probe outcome as a connection_log observable.
"""

import os
import socket
import time

import nids_lite
import pcap_util


def _resolve(host_name: str) -> str:
    """Map sandbox container DNS name to an addressable host.

    When TARGET_USE_LOCALHOST=1 (run-local.sh / GitHub runner mode), all
    sandbox hosts resolve to "localhost" because Docker port mappings
    forward to host. Otherwise the container DNS name is used (in-network
    execution).
    """
    if os.environ.get("TARGET_USE_LOCALHOST") == "1":
        return "localhost"
    env_key = f"TARGET_{host_name.upper().replace('-', '_')}_HOST"
    return os.environ.get(env_key, host_name)


def _connect(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "established"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except socket.gaierror:
        return "dns_error"
    except OSError as e:
        return f"error:{type(e).__name__}"


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]
    hosts = target.get("hosts", [])

    interval = float(params.get("interval_seconds", 0.5))
    timeout = float(params.get("connect_timeout_seconds", 3.0))
    source_label = params.get("source_label", "redteam-runner")

    observables: list = []
    established = 0
    refused = 0
    other = 0
    pcap_artifact = None

    print(f"[T3] Source: {source_label}")
    print(f"[T3] Lateral targets: {len(hosts)} probes")

    probe_ports = sorted({int(h["port"]) for h in hosts})
    scenario_id = scenario_def.get("id", "t3_lateral_movement")

    with pcap_util.capture(scenario_id, run_id, probe_ports) as (pcap_path, pcap_active):
        if pcap_active:
            pcap_artifact = pcap_path

        for i, h in enumerate(hosts, 1):
            name = h["name"]
            port = int(h["port"])
            protocol = h.get("protocol", "tcp")
            host = _resolve(name)

            outcome = _connect(host, port, timeout)
            print(f"[T3] {i:2d}/{len(hosts)}: {name}:{port} ({protocol})  → {outcome}")

            observables.append({
                "type": "connection_log",
                "pattern": "remote_service_connection",
                "source": source_label,
                "destination_host": name,
                "destination_port": port,
                "protocol": protocol,
                "outcome": outcome,
                "event_time": time.time(),
                "run_id": run_id,
            })

            if outcome == "established":
                established += 1
            elif outcome == "refused":
                refused += 1
            else:
                other += 1

            if i < len(hosts) and interval > 0:
                time.sleep(interval)

    unique_destinations = len({o["destination_host"] for o in observables})
    status = "success" if unique_destinations >= 4 else "partial"

    print(f"\n[T3] Done. Established: {established}  Refused: {refused}  Other: {other}")
    print(f"[T3] Unique destination hosts: {unique_destinations}")

    nids_alert_count = 0
    if pcap_artifact:
        try:
            alerts = nids_lite.detect_lateral_fanout(pcap_artifact, run_id)
            for a in alerts:
                print(
                    f"[T3] [NIDS-lite] {a['signature']} src={a['source_ip']} "
                    f"unique_hosts={a['unique_dest_hosts']}"
                )
            observables.extend(alerts)
            nids_alert_count = len(alerts)
        except Exception as e:
            print(f"[T3] NIDS-lite analysis failed: {e}")

    details = {
        "source": source_label,
        "destinations_attempted": len(hosts),
        "unique_destination_hosts": unique_destinations,
        "established": established,
        "refused": refused,
        "other": other,
    }
    if pcap_artifact:
        details["pcap_artifact"] = pcap_artifact
    if nids_alert_count:
        details["nids_alerts_emitted"] = nids_alert_count

    return {
        "status": status,
        "observables_generated": observables,
        "details": details,
    }
