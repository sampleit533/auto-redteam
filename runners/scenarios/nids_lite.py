"""
Lightweight NIDS analyzer — reads a pcap and emits synthetic nids_alert
observables based on simple flow-pattern heuristics. Bridges captured
traffic into the evaluator without requiring a live Zeek/Suricata.

Implementation: spawns the same `redteam/pcap-recorder` container used
for capture, runs `tcpdump -nr` on the pcap, parses the output with
regex, applies fan-out heuristics. No new Python dependencies.
"""

import os
import re
import shutil
import subprocess
import time
from collections import defaultdict
from pathlib import Path


PCAP_IMAGE = os.environ.get("PCAP_IMAGE", "redteam/pcap-recorder:latest")

# tcpdump line example:
#   09:24:56.160562 lo    In  IP 127.0.0.1.52288 > 127.0.0.1.2222: Flags [S], seq ...
# Group 1 = src ip, 2 = sport, 3 = dst ip, 4 = dport, 5 = flags
_LINE_RE = re.compile(
    r"^\s*\d+:\d+:\d+\.\d+\s+\S+\s+\S+\s+IP\s+"
    r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+"
    r"(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+Flags\s+\[([^\]]+)\]"
)


def _read_pcap(pcap_path: str):
    """Yield (src, sport, dst, dport, flags) tuples from a pcap file."""
    if shutil.which("docker") is None:
        return
    pcap_abs = Path(pcap_path).resolve()
    if not pcap_abs.exists():
        return
    # Default tcpdump time format (HH:MM:SS.uuuuuu) — keeps regex simple.
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{pcap_abs.parent}:/in:ro",
        PCAP_IMAGE,
        "tcpdump", "-nr", f"/in/{pcap_abs.name}",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return
    for line in res.stdout.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        src, sport, dst, dport, flags = m.groups()
        yield src, int(sport), dst, int(dport), flags


def _is_initial_syn(flags: str) -> bool:
    """True for client-initiating SYN (excludes SYN-ACK and other combos)."""
    return "S" in flags and "." not in flags


def _exclude_self_src(src: str) -> bool:
    """Filter out source IPs that are clearly server-side or not relevant."""
    # When -i any captures both lo and docker bridge, we may see traffic from
    # multiple source IPs for the same logical scan. We keep all of them and
    # let the evaluator find at least one matching alert.
    return False


def detect_port_scan(pcap_path: str, run_id: str,
                     min_unique_ports: int = 5) -> list:
    """Emit nids_alert observables when a single source touches many distinct
    destination ports — characteristic of TCP port scanning."""
    by_src = defaultdict(lambda: {"ports": set(), "first_pkt": None, "last_pkt": None})
    pkt_count = 0
    for src, sport, dst, dport, flags in _read_pcap(pcap_path):
        if not _is_initial_syn(flags):
            continue
        if _exclude_self_src(src):
            continue
        rec = by_src[src]
        rec["ports"].add(dport)
        rec["last_pkt"] = (dst, dport)
        if rec["first_pkt"] is None:
            rec["first_pkt"] = (dst, dport)
        pkt_count += 1

    alerts = []
    for src, rec in sorted(by_src.items()):
        if len(rec["ports"]) >= min_unique_ports:
            alerts.append({
                "type": "nids_alert",
                "signature": "PORT_SCAN",
                "rule": "nids-lite/port-scan",
                "source_ip": src,
                "unique_dest_ports": len(rec["ports"]),
                "min_threshold": min_unique_ports,
                "event_time": time.time(),
                "run_id": run_id,
            })
    return alerts


def detect_lateral_fanout(pcap_path: str, run_id: str,
                          min_unique_hosts: int = 4) -> list:
    """Emit nids_alert observables when a single source reaches many distinct
    destination hosts — characteristic of lateral-movement spread."""
    by_src = defaultdict(lambda: {"hosts": set()})
    for src, sport, dst, dport, flags in _read_pcap(pcap_path):
        if not _is_initial_syn(flags):
            continue
        if _exclude_self_src(src):
            continue
        # Skip "self-connect" loopback patterns where dst == src (rare)
        if dst == src and src.startswith("127."):
            # Loopback fan-out across many ports counts as scan, not lateral.
            # We still record dst for fan-out so set logic stays consistent.
            pass
        by_src[src]["hosts"].add(dst)

    alerts = []
    for src, rec in sorted(by_src.items()):
        if len(rec["hosts"]) >= min_unique_hosts:
            alerts.append({
                "type": "nids_alert",
                "signature": "LATERAL_FANOUT",
                "rule": "nids-lite/lateral-fanout",
                "source_ip": src,
                "unique_dest_hosts": len(rec["hosts"]),
                "min_threshold": min_unique_hosts,
                "event_time": time.time(),
                "run_id": run_id,
            })
    return alerts
