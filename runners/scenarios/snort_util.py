"""
Offline Snort 3 replay — feeds a captured pcap into the Snort recorder
container shipped at `targets/snort-runner/`, parses alert_fast.txt, and
returns a list of snort_alert observables for the evaluator.

Bridges captured traffic into a real signature-based detection chain
without requiring a live sensor on the host. Uses the same docker
capability pattern as pcap_util — capability lives only inside the
ephemeral container, no host-side setcap or sudo.
"""

import os
import re
import shutil
import subprocess
import time
from pathlib import Path


SNORT_IMAGE = os.environ.get("SNORT_IMAGE", "redteam/snort-runner:latest")

# Snort 3 alert_fast format:
# 05/20-11:16:01.308866 [**] [1:1000002:4] "MSG" [**] [Priority: 0] \
# {TCP} 127.0.0.1:40102 -> 127.0.0.1:18080
_ALERT_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r'"(?P<msg>[^"]+)"\s+'
    r"\[\*\*\]\s+\[Priority:\s*(?P<prio>\d+)\]\s+"
    r"\{(?P<proto>\w+)\}\s+"
    r"(?P<src>\S+?):(?P<sport>\d+)\s+->\s+(?P<dst>\S+?):(?P<dport>\d+)\s*$"
)


def _image_present() -> bool:
    res = subprocess.run(
        ["docker", "image", "inspect", SNORT_IMAGE],
        capture_output=True, text=True,
    )
    return res.returncode == 0


def _ensure_image() -> bool:
    if _image_present():
        return True
    here = Path(__file__).resolve()
    repo_root = here.parent.parent.parent  # runners/scenarios → repo root
    ctx = repo_root / "targets" / "snort-runner"
    if not (ctx / "Dockerfile").exists():
        print(f"[SNORT] image {SNORT_IMAGE} missing and no Dockerfile at {ctx}")
        return False
    print(f"[SNORT] building {SNORT_IMAGE} from {ctx} ...")
    res = subprocess.run(
        ["docker", "build", "-q", "-t", SNORT_IMAGE, str(ctx)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        print(f"[SNORT] image build failed: {(res.stderr or res.stdout).strip()[:300]}")
        return False
    return True


def replay(pcap_path: str, run_id: str, scenario_id: str = "snort") -> list:
    """Replay a pcap through Snort 3 and return parsed alerts.

    Returns a list of `snort_alert` observable dicts. Empty list on any
    failure (image missing, docker unreachable, no alerts produced) so
    the calling scenario can fail soft and surface the issue via stdout.
    """
    if shutil.which("docker") is None:
        print("[SNORT] docker not on PATH — replay skipped")
        return []
    pcap_abs = Path(pcap_path).resolve()
    if not pcap_abs.exists():
        print(f"[SNORT] pcap not found: {pcap_abs}")
        return []
    if not _ensure_image():
        return []

    in_dir = pcap_abs.parent
    out_dir = Path(os.environ.get("ARTIFACTS_DIR", in_dir)).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    alert_file = out_dir / f"{scenario_id}-{run_id}.snort.txt"
    # Snort always writes "alert_fast.txt" inside its log dir; we mount a
    # private subdir per scenario so concurrent runs don't clobber each other.
    log_dir = out_dir / f"snort-log-{scenario_id}-{run_id}"
    log_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{in_dir}:/in:ro",
        "-v", f"{log_dir}:/out",
        SNORT_IMAGE,
        "snort",
        "-c", "/etc/snort/snort.lua",
        "-r", f"/in/{pcap_abs.name}",
        "-A", "alert_fast",
        "-l", "/out",
        "-q",
    ]
    print(f"[SNORT] replaying {pcap_abs.name} through {SNORT_IMAGE}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("[SNORT] replay timed out after 120s")
        return []
    if res.returncode != 0:
        # Snort returns non-zero on EOF for some pcaps even when it produced
        # alerts; only treat as fatal if no alert file appeared.
        msg = (res.stderr or res.stdout).strip().splitlines()[-1:] or [""]
        print(f"[SNORT] non-zero exit ({res.returncode}): {msg[0][:200]}")

    raw = log_dir / "alert_fast.txt"
    if not raw.exists():
        # Try to chown back so the host can read it (file written as root).
        return []
    # Same root-ownership story as pcap_util — chown via a one-off container.
    try:
        subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{log_dir}:/out",
                SNORT_IMAGE,
                "chown", f"{os.getuid()}:{os.getgid()}", "/out/alert_fast.txt",
            ],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        pass

    try:
        text = raw.read_text(errors="replace")
    except PermissionError:
        # Fall back to reading inside a container if chown failed.
        cat = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{log_dir}:/out:ro",
                SNORT_IMAGE,
                "cat", "/out/alert_fast.txt",
            ],
            capture_output=True, text=True, timeout=10,
        )
        text = cat.stdout if cat.returncode == 0 else ""

    # Persist a stable per-scenario copy alongside the pcap so the artifact
    # directory contains the human-readable alert log too.
    try:
        alert_file.write_text(text)
    except OSError:
        pass

    alerts = []
    seen = set()  # de-dupe by (sid, src, sport, dst, dport, ts) to keep one per logical hit
    for line in text.splitlines():
        m = _ALERT_RE.match(line.strip())
        if not m:
            continue
        d = m.groupdict()
        key = (d["sid"], d["src"], d["sport"], d["dst"], d["dport"], d["ts"])
        if key in seen:
            continue
        seen.add(key)
        alerts.append({
            "type": "snort_alert",
            "rule_id": int(d["sid"]),
            "rule_gid": int(d["gid"]),
            "rule_rev": int(d["rev"]),
            "signature": d["msg"],
            "priority": int(d["prio"]),
            "protocol": d["proto"],
            "source_ip": d["src"],
            "source_port": int(d["sport"]),
            "destination_ip": d["dst"],
            "destination_port": int(d["dport"]),
            "alert_time": d["ts"],
            "event_time": time.time(),
            "run_id": run_id,
        })
    print(f"[SNORT] parsed {len(alerts)} alert(s) from {raw.name}")
    return alerts
