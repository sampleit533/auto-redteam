"""
PCAP capture utility — spawns an ephemeral container with cap_net_raw
and cap_net_admin to run tcpdump while a network-touching scenario is
executing. Output is bind-mounted to artifacts/.

Activated by ENABLE_PCAP=1. Falls back gracefully (yields no-op) when:
  - ENABLE_PCAP is unset
  - docker is not on PATH or the daemon is unreachable
  - the recorder image is missing AND auto-build is disabled
  - the container fails to start

This avoids any host-side setcap/sudo dance: the capability is granted
only inside the ephemeral container and is destroyed with `--rm`.
"""

import os
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path


PCAP_IMAGE = os.environ.get("PCAP_IMAGE", "redteam/pcap-recorder:latest")


def _default_interface() -> str:
    iface = os.environ.get("PCAP_INTERFACE")
    if iface:
        return iface
    # When the recorder runs with --network=host on Linux, "any" sees both
    # lo (host-mode loopback) and the docker0/veth interfaces.
    return "any"


def _image_present() -> bool:
    res = subprocess.run(
        ["docker", "image", "inspect", PCAP_IMAGE],
        capture_output=True, text=True,
    )
    return res.returncode == 0


def _ensure_image() -> bool:
    if _image_present():
        return True
    # Auto-build from targets/pcap-recorder/ if available
    here = Path(__file__).resolve()
    repo_root = here.parent.parent.parent  # runners/scenarios → repo root
    ctx = repo_root / "targets" / "pcap-recorder"
    if not (ctx / "Dockerfile").exists():
        print(f"[PCAP] image {PCAP_IMAGE} missing and no Dockerfile at {ctx}")
        return False
    print(f"[PCAP] building {PCAP_IMAGE} from {ctx} ...")
    res = subprocess.run(
        ["docker", "build", "-q", "-t", PCAP_IMAGE, str(ctx)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        print(f"[PCAP] image build failed: {(res.stderr or res.stdout).strip()[:300]}")
        return False
    return True


@contextmanager
def capture(scenario_id: str, run_id: str, ports=None):
    """Capture pcap to artifacts/<scenario>-<run_id>.pcap inside a docker container.

    Yields (pcap_path: str | None, active: bool).
    """
    if os.environ.get("ENABLE_PCAP") != "1":
        yield (None, False)
        return

    if shutil.which("docker") is None:
        print("[PCAP] docker not on PATH — capture disabled")
        yield (None, False)
        return

    # Sanity check: docker daemon reachable
    ping = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if ping.returncode != 0:
        print(f"[PCAP] docker daemon unreachable: {ping.stderr.strip()[:200]} — capture disabled")
        yield (None, False)
        return

    if not _ensure_image():
        yield (None, False)
        return

    iface = _default_interface()
    out_dir = Path(os.environ.get("ARTIFACTS_DIR", "artifacts")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_name = f"{scenario_id}-{run_id}.pcap"
    pcap_path = out_dir / pcap_name
    container_name = f"pcap-{scenario_id}-{run_id}"[:63]  # docker name limit

    bpf = " or ".join(f"port {int(p)}" for p in (ports or []))

    cmd = [
        "docker", "run", "-d", "--rm",
        "--network=host",
        "--cap-add=NET_RAW",
        "--cap-add=NET_ADMIN",
        "-v", f"{out_dir}:/out",
        "--name", container_name,
        PCAP_IMAGE,
        "tcpdump",
        "-i", iface,
        "-w", f"/out/{pcap_name}",
        "-U",            # packet-buffered output
        "-n",            # no DNS resolution
        "-s", "256",     # snaplen — headers + small payload
        "-B", "16384",   # 16MB OS buffer to avoid drops on busy lo
    ]
    if bpf:
        cmd.append(bpf)

    print(f"[PCAP] starting recorder container: iface={iface} filter='{bpf or '(none)'}' → {pcap_path}")

    try:
        res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
        container_id = res.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[PCAP] failed to start container: {(e.stderr or e.stdout).strip()[:300]}")
        yield (None, False)
        return
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[PCAP] failed to start container: {e}")
        yield (None, False)
        return

    # Give tcpdump a moment to bind / fail
    time.sleep(0.5)
    check = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        capture_output=True, text=True,
    )
    if check.returncode != 0 or check.stdout.strip() != "true":
        logs = subprocess.run(
            ["docker", "logs", container_name],
            capture_output=True, text=True,
        )
        msg = (logs.stderr or logs.stdout or "(no logs)").strip()
        print(f"[PCAP] recorder exited early: {msg[:300]}")
        # cleanup just in case
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        yield (None, False)
        return

    try:
        yield (str(pcap_path), True)
    finally:
        # Stop tcpdump cleanly so the pcap is flushed
        subprocess.run(
            ["docker", "stop", "-t", "5", container_name],
            capture_output=True, text=True,
        )
        # --rm should clean up; force just in case
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True, text=True,
        )
        # File was written by root inside the container — chown to host user
        if pcap_path.exists():
            try:
                subprocess.run(
                    [
                        "docker", "run", "--rm",
                        "-v", f"{out_dir}:/out",
                        PCAP_IMAGE,
                        "chown", f"{os.getuid()}:{os.getgid()}", f"/out/{pcap_name}",
                    ],
                    capture_output=True, text=True, timeout=15,
                )
            except subprocess.TimeoutExpired:
                pass
        size = pcap_path.stat().st_size if pcap_path.exists() else 0
        print(f"[PCAP] stopped: {pcap_name} ({size:,} bytes)")
