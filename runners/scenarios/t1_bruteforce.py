"""
T1 — SSH Brute-force Simulation (T1110.001)

Sends N failed SSH authentication attempts followed by one successful
login using a pre-seeded test account. Non-destructive: targets only
the sandbox SSH server.
"""

import os
import socket
import time
import paramiko


def run(scenario_def: dict, run_id: str, mode: str) -> dict:
    params = scenario_def["parameters"]
    target = scenario_def["target"]

    host = os.environ.get("TARGET_SSH_HOST", target.get("host", "target-ssh"))
    port = int(target.get("port", 2222))
    test_account = target.get("test_account", "redteam-test")
    test_password = (
        os.environ.get(target.get("test_password_env", "REDTEAM_SSH_TEST_PASSWORD")) or "RedteamPass123!"
    )

    attempts = int(params.get("attempts", 50))
    interval = float(params.get("interval_seconds", 1.5))
    success_after = int(params.get("success_after_attempt", 45))
    wrong_password = params.get("wrong_password", "wrongpassword123")

    observables = []
    failed_count = 0
    success = False

    print(f"[T1] Target: {host}:{port}  Account: {test_account}")
    print(f"[T1] Plan: {attempts} attempts, success at attempt #{success_after}")

    for i in range(1, attempts + 1):
        use_correct = i == success_after
        password = test_password if use_correct else wrong_password

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=host,
                port=port,
                username=test_account,
                password=password,
                timeout=5,
                banner_timeout=5,
                auth_timeout=5,
                look_for_keys=False,
                allow_agent=False,
            )
            print(f"[T1] Attempt {i:3d}/{attempts}: SUCCESS (accepted)")
            observables.append({"type": "auth_log", "pattern": "Accepted password", "attempt": i})
            success = True
            client.close()
        except paramiko.AuthenticationException:
            failed_count += 1
            if i % 10 == 0 or i == 1:
                print(f"[T1] Attempt {i:3d}/{attempts}: FAILED (auth) — {failed_count} failures so far")
            observables.append({"type": "auth_log", "pattern": "Failed password", "attempt": i})
        except (socket.error, paramiko.SSHException) as e:
            print(f"[T1] Attempt {i:3d}/{attempts}: CONNECTION ERROR — {e}")
            observables.append({"type": "error", "message": str(e), "attempt": i})
        finally:
            try:
                client.close()
            except Exception:
                pass

        if i < attempts:
            time.sleep(interval)

    status = "success" if success and failed_count >= 40 else "partial"
    print(f"\n[T1] Done. Failed: {failed_count}, Successful login: {success}")
    return {
        "status": status,
        "observables_generated": observables,
        "details": {
            "failed_attempts": failed_count,
            "successful_login": success,
            "target_host": host,
            "target_port": port,
        },
    }
