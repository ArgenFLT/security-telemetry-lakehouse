"""Map Wazuh-style alerts to a flat, OCSF-inspired schema.

The target is not a full OCSF implementation: it keeps the OCSF class/category/activity
vocabulary (Authentication 3002, Process Activity 1007) and field semantics, flattened
into columns that are friendly to columnar storage and SQL.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import pyarrow as pa


class NormalizationError(ValueError):
    """Raised when a raw event cannot be mapped; the message is the reject reason."""


# class name -> (class_uid, category_uid)
CLASSES = {
    "Authentication": (3002, 3),
    "Process Activity": (1007, 1),
    "Base Event": (0, 0),
}

# Wazuh rule id -> (class name, activity name, status)
RULE_MAP = {
    "5715": ("Authentication", "Logon", "Success"),
    "5760": ("Authentication", "Logon", "Failure"),
    "60106": ("Authentication", "Logon", "Success"),
    "60122": ("Authentication", "Logon", "Failure"),
    "61603": ("Process Activity", "Launch", "Unknown"),
}
ACTIVITY_ID = {"Logon": 1, "Launch": 1, "Unknown": 0}
STATUS_ID = {"Unknown": 0, "Success": 1, "Failure": 2}

SCHEMA = pa.schema(
    [
        ("event_uid", pa.string()),
        ("time", pa.timestamp("us", tz="UTC")),
        ("event_date", pa.date32()),
        ("class_uid", pa.int32()),
        ("class_name", pa.string()),
        ("category_uid", pa.int32()),
        ("activity_id", pa.int32()),
        ("activity_name", pa.string()),
        ("status_id", pa.int32()),
        ("status", pa.string()),
        ("severity_id", pa.int32()),
        ("device_name", pa.string()),
        ("device_ip", pa.string()),
        ("device_agent_id", pa.string()),
        ("src_ip", pa.string()),
        ("actor_user_name", pa.string()),
        ("target_user_name", pa.string()),
        ("auth_protocol", pa.string()),
        ("process_name", pa.string()),
        ("process_cmd_line", pa.string()),
        ("process_parent_name", pa.string()),
        ("rule_id", pa.string()),
        ("rule_description", pa.string()),
        ("rule_level", pa.int32()),
        ("attack_technique_ids", pa.list_(pa.string())),
        ("raw", pa.string()),
    ]
)


def _get(obj: Any, *path: str, default=None):
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").split("\\")[-1] or None


def severity_from_level(level: int) -> int:
    """Wazuh level (0-15) -> OCSF severity_id (0-6)."""
    if level <= 3:
        return 1
    if level <= 6:
        return 2
    if level <= 9:
        return 3
    if level <= 12:
        return 4
    if level <= 14:
        return 5
    return 6


def _clean_ip(value: str | None) -> str | None:
    if value in (None, "", "-", "::1", "127.0.0.1"):
        return None
    return value


def parse_timestamp(value: Any) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(timezone.utc)
    except (TypeError, ValueError):
        raise NormalizationError("invalid_timestamp") from None


def normalize_event(raw: dict) -> dict:
    """Return one flat normalized record or raise NormalizationError."""
    if not isinstance(raw, dict):
        raise NormalizationError("not_an_object")

    ts = parse_timestamp(raw.get("timestamp"))
    rule = raw.get("rule") or {}
    rule_id = str(rule.get("id", ""))
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        raise NormalizationError("invalid_rule_level") from None

    class_name, activity_name, status = RULE_MAP.get(rule_id, ("Base Event", "Unknown", "Unknown"))
    class_uid, category_uid = CLASSES[class_name]

    data = raw.get("data") or {}
    src_ip = target_user = actor_user = protocol = None
    process_name = cmd_line = parent_name = None

    if class_name == "Authentication":
        if "srcip" in data or "srcuser" in data:
            protocol = "ssh"
            src_ip = _clean_ip(data.get("srcip"))
            target_user = data.get("srcuser")
        else:
            protocol = "windows"
            src_ip = _clean_ip(_get(data, "win", "eventdata", "ipAddress"))
            target_user = _get(data, "win", "eventdata", "targetUserName")
    elif class_name == "Process Activity":
        eventdata = _get(data, "win", "eventdata", default={})
        process_name = _basename(eventdata.get("image"))
        cmd_line = eventdata.get("commandLine")
        parent_name = _basename(eventdata.get("parentImage"))
        actor_user = (eventdata.get("user") or "").split("\\")[-1] or None

    uid = raw.get("id") or hashlib.sha1(json.dumps(raw, sort_keys=True).encode()).hexdigest()
    mitre_ids = _get(rule, "mitre", "id", default=[]) or []

    return {
        "event_uid": str(uid),
        "time": ts,
        "event_date": ts.date(),
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "activity_id": ACTIVITY_ID[activity_name],
        "activity_name": activity_name,
        "status_id": STATUS_ID[status],
        "status": status,
        "severity_id": severity_from_level(level),
        "device_name": _get(raw, "agent", "name", default=""),
        "device_ip": _get(raw, "agent", "ip"),
        "device_agent_id": _get(raw, "agent", "id"),
        "src_ip": src_ip,
        "actor_user_name": actor_user,
        "target_user_name": target_user,
        "auth_protocol": protocol,
        "process_name": process_name,
        "process_cmd_line": cmd_line,
        "process_parent_name": parent_name,
        "rule_id": rule_id,
        "rule_description": rule.get("description"),
        "rule_level": level,
        "attack_technique_ids": list(mitre_ids),
        "raw": raw.get("full_log"),
    }
