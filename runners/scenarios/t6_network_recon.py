"""
T6 — Network Reconnaissance / Service Discovery (T1046)

TCP connect probes against the sandbox Docker network. Iterates a host x
port matrix and records each probe outcome as a scan_log observable.
Non-destructive: connect-and-close only, no banner grab, no fingerprinting.
"""

import os
import socket
import time

import nids_lite
import pcap_util


def _resolve(host_name: str) -> str:
    """Map sandbox container DNS name to an addressable host. See t3 docs."""
    if os.environ.get("TARGET_USE_LOCALHOST") == "1":
        return "localhost"
    env_key = f"TARGET_{host_name.upper().replace('-', '_')}_HOST"
    return os.environ.get(env_key, host_name)


def _probe(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except socket.gaierror:
        return "dns_error"
    except OSError:
        return "closed"


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]

    hosts = list(target.get("hosts", []))
    ports = list(target.get("ports", []))
    source = params.get("source_label", "redteam-recon")
    timeout = float(params.get("connect_timeout_seconds", 1.5))
    delay = float(params.get("inter_probe_delay_seconds", 0.05))

    observables: list = []
    open_count = 0
    closed_count = 0
    other_count = 0
    pcap_artifact = None

    total = len(hosts) * len(ports)
    print(f"[T6] Source: {source}")
    print(f"[T6] Targets: {len(hosts)} hosts × {len(ports)} ports = {total} probes")

    scenario_id = scenario_def.get("id", "t6_network_recon")

    with pcap_util.capture(scenario_id, run_id, [int(p) for p in ports]) as (pcap_path, pcap_active):
        if pcap_active:
            pcap_artifact = pcap_path

        idx = 0
        for h in hosts:
            host = _resolve(h)
            for port in ports:
                idx += 1
                outcome = _probe(host, int(port), timeout)
                observables.append({
                    "type": "scan_log",
                    "pattern": "port_probe",
                    "source": source,
                    "destination_host": h,
                    "destination_port": int(port),
                    "outcome": outcome,
                    "event_time": time.time(),
                    "run_id": run_id,
                })
                if outcome == "open":
                    open_count += 1
                    print(f"[T6] {idx:3d}/{total}: {h}:{port}  OPEN")
                elif outcome == "closed":
                    closed_count += 1
                else:
                    other_count += 1
                if delay > 0 and idx < total:
                    time.sleep(delay)

    unique_ports = len({o["destination_port"] for o in observables})
    unique_hosts = len({o["destination_host"] for o in observables})
    status = "success" if total > 0 and len(observables) == total else "partial"

    print(f"\n[T6] Done. Open: {open_count}  Closed: {closed_count}  Other: {other_count}")
    print(f"[T6] Unique destination ports: {unique_ports}  unique hosts: {unique_hosts}")

    nids_alert_count = 0
    if pcap_artifact:
        try:
            alerts = nids_lite.detect_port_scan(pcap_artifact, run_id)
            for a in alerts:
                print(
                    f"[T6] [NIDS-lite] {a['signature']} src={a['source_ip']} "
                    f"unique_ports={a['unique_dest_ports']}"
                )
            observables.extend(alerts)
            nids_alert_count = len(alerts)
        except Exception as e:
            print(f"[T6] NIDS-lite analysis failed: {e}")

    details = {
        "source": source,
        "hosts_scanned": len(hosts),
        "ports_per_host": len(ports),
        "total_probes": total,
        "unique_destination_ports": unique_ports,
        "unique_destination_hosts": unique_hosts,
        "open_count": open_count,
        "closed_count": closed_count,
        "other_count": other_count,
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
