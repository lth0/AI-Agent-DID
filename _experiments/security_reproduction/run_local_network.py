"""Run one local security scenario with tracked child processes and logs."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

import requests


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from _demo_2v2.start_network import start_network  # noqa: E402


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config_file")
    parser.add_argument("--startup-wait", type=int, default=45)
    parser.add_argument("--audit-wait", type=int, default=90)
    parser.add_argument("--issuer", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    return parser.parse_args()


def wait_for_ports(ports, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all(_port_ready(port) for port in ports):
            return True
        time.sleep(1)
    return False


def _port_ready(port):
    try:
        requests.get(f"http://127.0.0.1:{port}/status", timeout=1)
        return True
    except requests.RequestException:
        return False


def main() -> int:
    args = parse_args()
    config_path = os.path.abspath(args.config_file)
    with open(config_path, "r", encoding="utf-8") as handle:
        config = json.load(handle)

    log_dir = os.path.join(
        PROJECT_ROOT, ".codex", "security_runs", config.get("experiment_id", "run")
    )
    os.makedirs(log_dir, exist_ok=True)
    processes = []
    handles = []
    try:
        if args.issuer:
            issuer_out = open(os.path.join(log_dir, "issuer.out.log"), "w", encoding="utf-8")
            issuer_err = open(os.path.join(log_dir, "issuer.err.log"), "w", encoding="utf-8")
            handles.extend([issuer_out, issuer_err])
            processes.append(subprocess.Popen(
                [sys.executable, os.path.join(PROJECT_ROOT, "_ops_services", "issuer_server.py")],
                cwd=PROJECT_ROOT, stdout=issuer_out, stderr=issuer_err,
            ))
            time.sleep(5)

        processes.extend(start_network(config_path, keep_alive=False))
        ports = [item["port"] for item in config.get("holders", [])]
        ports += [item["port"] for item in config.get("verifiers", [])]
        if not wait_for_ports(ports, args.startup_wait):
            print(f"Network did not become ready; inspect {log_dir}")
            return 2

        trigger_out = open(os.path.join(log_dir, "trigger.log"), "w", encoding="utf-8")
        trigger_err = open(os.path.join(log_dir, "trigger.err.log"), "w", encoding="utf-8")
        handles.extend([trigger_out, trigger_err])
        for _ in range(max(1, args.repeat)):
            trigger = subprocess.Popen(
                [sys.executable, os.path.join(PROJECT_ROOT, "_demo_2v2", "trigger_audit.py"), config_path],
                cwd=PROJECT_ROOT, stdout=trigger_out, stderr=trigger_err,
            )
            processes.append(trigger)
            trigger.wait(timeout=args.audit_wait)
            # trigger_audit only submits background work; allow the verifier worker
            # to finish before the next run or cleanup.
            time.sleep(args.audit_wait)
        print(log_dir)
        return 0
    except subprocess.TimeoutExpired:
        print(f"Audit timed out; inspect {log_dir}")
        return 3
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for handle in handles:
            handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
