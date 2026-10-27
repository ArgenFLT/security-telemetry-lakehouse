"""Synthetic Wazuh-style alert generator (JSON Lines).

Produces deterministic, harmless telemetry so the pipeline runs anywhere without
real infrastructure. Three scenarios are injected on top of benign noise:

1. SSH brute force against a Linux host that ends in a successful login (T1110 -> T1078).
2. Windows logon brute force against a domain controller, no success (T1110).
3. PowerShell with an encoded command launched by an Office application (T1059.001).

All attacker IPs come from the RFC 5737 documentation ranges, and the encoded
payload only prints a string. A small share of events is deliberately corrupted
(``dirty_rate``) to exercise the data quality gate.
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

AGENTS = [
    {"id": "001", "name": "web-01", "ip": "10.0.1.10", "os": "linux"},
    {"id": "002", "name": "db-01", "ip": "10.0.1.20", "os": "linux"},
    {"id": "003", "name": "win-ws-01", "ip": "10.0.2.31", "os": "windows"},
    {"id": "004", "name": "win-ws-02", "ip": "10.0.2.32", "os": "windows"},
    {"id": "005", "name": "dc-01", "ip": "10.0.2.5", "os": "windows"},
]
LINUX_AGENTS = [a for a in AGENTS if a["os"] == "linux"]
WINDOWS_AGENTS = [a for a in AGENTS if a["os"] == "windows"]

USERS = ["alice", "bob", "carol", "dave", "erin", "svc_backup"]
INTERNAL_SOURCES = ["10.0.0.5", "10.0.2.31", "10.0.2.32", "10.0.2.40", "10.0.3.7", "10.0.3.8"]

SSH_ATTACKER_IP = "203.0.113.45"
WIN_ATTACKER_IP = "198.51.100.77"

MITRE_VALID_ACCOUNTS = ("T1078", "Valid Accounts", ["Initial Access", "Persistence"])
MITRE_BRUTE_FORCE = ("T1110", "Brute Force", ["Credential Access"])

RULES = {
    "ssh_success": ("5715", 3, "sshd: authentication success.", MITRE_VALID_ACCOUNTS),
    "ssh_failed": ("5760", 5, "sshd: authentication failed.", MITRE_BRUTE_FORCE),
    "win_success": ("60106", 3, "Windows logon success.", MITRE_VALID_ACCOUNTS),
    "win_failed": ("60122", 5, "Logon failure - Unknown user or bad password.", MITRE_BRUTE_FORCE),
    "process": ("61603", 3, "Sysmon - Event 1: Process creation", None),
}

BENIGN_PROCESSES = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe", r"explorer.exe"),
    (r"C:\Windows\explorer.exe", "explorer.exe", r"userinit.exe"),
    (r"C:\Windows\System32\notepad.exe", "notepad.exe", r"explorer.exe"),
    (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs", r"services.exe"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe -NoProfile -Command Get-Date", r"explorer.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE", r"explorer.exe"),
]
POWERSHELL_IMAGE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

_SEQ = {"n": 0}


def _wazuh_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+0000"


def _encoded(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


def _alert(ts: datetime, agent: dict, kind: str, data: dict, full_log: str, location: str) -> dict:
    rule_id, level, description, mitre = RULES[kind]
    rule = {"id": rule_id, "level": level, "description": description}
    if mitre:
        rule["mitre"] = {"id": [mitre[0]], "technique": [mitre[1]], "tactic": mitre[2]}
    _SEQ["n"] += 1
    return {
        "timestamp": _wazuh_ts(ts),
        "rule": rule,
        "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
        "manager": {"name": "wazuh-manager"},
        "id": f"{int(ts.timestamp())}.{_SEQ['n']}",
        "full_log": full_log,
        "data": data,
        "location": location,
    }


def _ssh_event(ts, agent, success, src_ip, user, rng):
    port = rng.randint(32768, 60999)
    syslog = ts.strftime("%b %d %H:%M:%S")
    if success:
        msg = f"{syslog} {agent['name']} sshd[{rng.randint(1000, 9999)}]: Accepted password for {user} from {src_ip} port {port} ssh2"
    else:
        msg = f"{syslog} {agent['name']} sshd[{rng.randint(1000, 9999)}]: Failed password for {user} from {src_ip} port {port} ssh2"
    data = {"srcip": src_ip, "srcuser": user, "srcport": str(port)}
    return _alert(ts, agent, "ssh_success" if success else "ssh_failed", data, msg, "/var/log/auth.log")


def _win_logon_event(ts, agent, success, src_ip, user, rng):
    event_id = "4624" if success else "4625"
    data = {
        "win": {
            "system": {"eventID": event_id, "computer": agent["name"]},
            "eventdata": {
                "targetUserName": user,
                "ipAddress": src_ip,
                "logonType": rng.choice(["3", "10"]),
                "workstationName": "-",
            },
        }
    }
    msg = f"Windows security event {event_id} for {user} from {src_ip}"
    return _alert(ts, agent, "win_success" if success else "win_failed", data, msg, "EventChannel")


def _process_event(ts, agent, image, command_line, parent_image, user):
    data = {
        "win": {
            "system": {"eventID": "1", "computer": agent["name"]},
            "eventdata": {
                "image": image,
                "commandLine": command_line,
                "parentImage": parent_image,
                "user": f"CORP\\{user}",
            },
        }
    }
    return _alert(ts, agent, "process", data, f"Sysmon Event 1: {command_line}", "EventChannel")


def _benign_event(ts: datetime, rng: random.Random) -> dict:
    roll = rng.random()
    if roll < 0.08:
        return _ssh_event(ts, rng.choice(LINUX_AGENTS), True, rng.choice(INTERNAL_SOURCES), rng.choice(USERS), rng)
    if roll < 0.12:
        return _ssh_event(ts, rng.choice(LINUX_AGENTS), False, rng.choice(INTERNAL_SOURCES), rng.choice(USERS), rng)
    if roll < 0.37:
        return _win_logon_event(ts, rng.choice(WINDOWS_AGENTS), True, rng.choice(INTERNAL_SOURCES), rng.choice(USERS), rng)
    if roll < 0.40:
        return _win_logon_event(ts, rng.choice(WINDOWS_AGENTS), False, rng.choice(INTERNAL_SOURCES), rng.choice(USERS), rng)
    agent = rng.choice(WINDOWS_AGENTS)
    user = rng.choice(USERS)
    if rng.random() < 0.004:
        # Admin automation using -EncodedCommand from cmd.exe: noisy but low risk.
        cmd = f"powershell.exe -NoProfile -EncodedCommand {_encoded('Get-Service | Out-Null')}"
        return _process_event(ts, agent, POWERSHELL_IMAGE, cmd, r"C:\Windows\System32\cmd.exe", "svc_backup")
    image, cmd, parent = rng.choice(BENIGN_PROCESSES)
    return _process_event(ts, agent, image, cmd, rf"C:\Windows\{parent}", user)


def _attack_events(start: datetime, hours: int, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    span = hours * 3600

    def at(offset_seconds: int):
        return start + timedelta(seconds=offset_seconds) if offset_seconds < span else None

    # 1) SSH brute force then success against web-01 (02:03 into the run).
    t0 = at(2 * 3600 + 180)
    if t0:
        web = LINUX_AGENTS[0]
        guesses = ["admin", "root", "oracle", "test", "ubuntu", "bob"]
        for i in range(40):
            ts = t0 + timedelta(seconds=i * 4 + rng.random())
            events.append(_ssh_event(ts, web, False, SSH_ATTACKER_IP, rng.choice(guesses), rng))
        events.append(_ssh_event(t0 + timedelta(seconds=170), web, True, SSH_ATTACKER_IP, "bob", rng))

    # 2) Windows logon brute force against the domain controller (04:17), no success.
    t1 = at(4 * 3600 + 17 * 60)
    if t1:
        dc = WINDOWS_AGENTS[-1]
        for i in range(25):
            ts = t1 + timedelta(seconds=i * 4 + rng.random())
            events.append(_win_logon_event(ts, dc, False, WIN_ATTACKER_IP, rng.choice(USERS + ["administrator"]), rng))

    # 3) Encoded PowerShell spawned by Word (05:42).
    t2 = at(5 * 3600 + 42 * 60)
    if t2:
        ws = WINDOWS_AGENTS[1]
        payload = _encoded("Write-Output 'stl-synthetic-payload'")
        cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {payload}"
        events.append(_process_event(t2, ws, POWERSHELL_IMAGE, cmd,
                                     r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "dave"))
    return events


def _corrupt(event: dict, rng: random.Random) -> str:
    """Return a corrupted JSON line (one of four failure modes)."""
    mode = rng.choice(["truncated", "bad_timestamp", "missing_agent", "bad_ip"])
    if mode == "truncated":
        return json.dumps(event)[: rng.randint(20, 80)]
    if mode == "bad_timestamp":
        event["timestamp"] = "not-a-timestamp"
    elif mode == "missing_agent":
        event["agent"].pop("name", None)
    else:
        data = event.get("data", {})
        if "srcip" in data:
            data["srcip"] = "999.999.1.1"
        else:
            event["timestamp"] = "not-a-timestamp"
    return json.dumps(event)


def generate_lines(
    start: datetime,
    hours: int = 24,
    events_per_hour: int = 500,
    seed: int = 42,
    dirty_rate: float = 0.01,
    attacks: bool = True,
) -> list[str]:
    """Generate JSON lines sorted by event time."""
    rng = random.Random(seed)
    _SEQ["n"] = 0
    start = start.astimezone(timezone.utc)
    events: list[dict] = []
    for h in range(hours):
        base = start + timedelta(hours=h)
        for _ in range(events_per_hour):
            ts = base + timedelta(seconds=rng.random() * 3600)
            events.append(_benign_event(ts, rng))
    if attacks:
        events.extend(_attack_events(start, hours, rng))
    events.sort(key=lambda e: e["timestamp"])

    lines = []
    for event in events:
        if rng.random() < dirty_rate:
            lines.append(_corrupt(event, rng))
        else:
            lines.append(json.dumps(event))
    return lines


def write_jsonl(path: Path, lines: list[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)
