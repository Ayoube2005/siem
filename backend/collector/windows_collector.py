#!/usr/bin/env python3
"""Lightweight Windows Event Log collector for the AI-SIEM.

Forwards selected Windows Security/System events to the SIEM ingest API.
Uses PowerShell `Get-WinEvent` under the hood, so it needs no pywin32 — just a
standard Python 3 install on Windows. Run it in an elevated terminal to read the
Security log.

Example (PowerShell, as Administrator):
    python collector\\windows_collector.py --api http://localhost:8000 `
        --user admin --password admin --interval 15
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Windows Security event IDs we care about -> SIEM normalization.
EVENT_MAP = {
    4624: {"event_type": "login", "outcome": "success", "action": "logon"},
    4625: {"event_type": "login", "outcome": "failure", "action": "logon"},
    4634: {"event_type": "login", "outcome": "success", "action": "logoff"},
    4648: {"event_type": "login", "outcome": "success", "action": "explicit_logon"},
    4672: {"event_type": "privilege_escalation", "outcome": "success", "action": "special_privileges"},
    4688: {"event_type": "process", "outcome": "success", "action": "process_creation"},
    4720: {"event_type": "access", "outcome": "success", "action": "account_created"},
}
SECURITY_IDS = ",".join(str(k) for k in EVENT_MAP)


def login(api: str, username: str, password: str) -> str:
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"{api}/api/auth/login", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())["access_token"]


def post_batch(api: str, token: str, events: list[dict]) -> dict:
    if not events:
        return {"ingested": 0, "alerts_created": 0}
    body = json.dumps({"events": events}).encode()
    req = urllib.request.Request(f"{api}/api/events/batch", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def query_windows_events(seconds: int) -> list[dict]:
    """Return recent Security-log events via PowerShell as a list of dicts."""
    ps = (
        f"$start=(Get-Date).AddSeconds(-{seconds});"
        f"$ids=@({SECURITY_IDS});"
        "try {"
        "  Get-WinEvent -FilterHashtable @{LogName='Security';Id=$ids;StartTime=$start}"
        "    -ErrorAction Stop |"
        "  Select-Object Id,TimeCreated,MachineName,"
        "    @{N='Message';E={$_.Message -replace '\\s+',' '}} |"
        "  ConvertTo-Json -Compress -Depth 3"
        "} catch { '[]' }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=60,
        ).stdout.strip()
    except Exception as e:
        print(f"[collector] PowerShell query failed: {e}")
        return []
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return data


def normalize(win_event: dict) -> dict | None:
    eid = int(win_event.get("Id", 0))
    mapping = EVENT_MAP.get(eid)
    if not mapping:
        return None
    ts = win_event.get("TimeCreated")
    # PowerShell emits /Date(ms)/ — best-effort parse, else now().
    timestamp = datetime.now(timezone.utc).isoformat()
    if isinstance(ts, str) and "Date(" in ts:
        try:
            ms = int(ts.split("Date(")[1].split(")")[0].split("+")[0])
            timestamp = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
        except Exception:
            pass
    msg = win_event.get("Message", "") or ""
    return {
        "timestamp": timestamp,
        "source": "windows",
        "event_type": mapping["event_type"],
        "action": mapping["action"],
        "outcome": mapping["outcome"],
        "hostname": win_event.get("MachineName"),
        "severity": "Medium" if mapping["outcome"] == "failure" else "Informational",
        "message": msg[:2000],
        "raw": {"event_id": eid, "command_line": msg[:2000]},
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Windows -> AI-SIEM log collector")
    p.add_argument("--api", default="http://localhost:8000")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--interval", type=int, default=15, help="poll interval seconds")
    args = p.parse_args()

    print(f"[collector] Authenticating to {args.api} ...")
    token = login(args.api, args.user, args.password)
    print("[collector] Connected. Forwarding Windows Security events. Ctrl+C to stop.")

    # Poll slightly wider than the interval to avoid gaps; dedup is handled server-side.
    window = args.interval + 5
    while True:
        raw_events = query_windows_events(window)
        normalized = [n for n in (normalize(e) for e in raw_events) if n]
        if normalized:
            try:
                res = post_batch(args.api, token, normalized)
                print(f"[collector] forwarded {res['ingested']} events, "
                      f"{res['alerts_created']} alert(s)")
            except Exception as e:
                print(f"[collector] post failed: {e}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
