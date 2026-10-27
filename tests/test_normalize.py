import pytest

from stl.normalize import NormalizationError, normalize_event, severity_from_level

BASE = {
    "timestamp": "2026-10-01T02:03:04.567+0000",
    "id": "1.1",
    "agent": {"id": "001", "name": "web-01", "ip": "10.0.1.10"},
    "full_log": "raw",
}


def event(rule, data):
    return {**BASE, "rule": rule, "data": data}


def test_ssh_failed_logon_maps_to_authentication_failure():
    rec = normalize_event(
        event(
            {"id": "5760", "level": 5, "description": "d",
             "mitre": {"id": ["T1110"], "technique": ["Brute Force"], "tactic": ["Credential Access"]}},
            {"srcip": "203.0.113.45", "srcuser": "root"},
        )
    )
    assert rec["class_name"] == "Authentication"
    assert rec["class_uid"] == 3002
    assert rec["status"] == "Failure" and rec["status_id"] == 2
    assert rec["src_ip"] == "203.0.113.45"
    assert rec["target_user_name"] == "root"
    assert rec["auth_protocol"] == "ssh"
    assert rec["attack_technique_ids"] == ["T1110"]
    assert rec["event_date"].isoformat() == "2026-10-01"


def test_windows_logon_dash_ip_becomes_null():
    rec = normalize_event(
        event({"id": "60106", "level": 3, "description": "d"},
              {"win": {"eventdata": {"targetUserName": "alice", "ipAddress": "-"}}})
    )
    assert rec["src_ip"] is None
    assert rec["auth_protocol"] == "windows"


def test_process_event_extracts_names_and_user():
    rec = normalize_event(
        event(
            {"id": "61603", "level": 3, "description": "d"},
            {"win": {"eventdata": {
                "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "commandLine": "powershell.exe -enc AAAA",
                "parentImage": r"C:\Office\WINWORD.EXE",
                "user": r"CORP\dave"}}},
        )
    )
    assert rec["class_name"] == "Process Activity"
    assert rec["process_name"] == "powershell.exe"
    assert rec["process_parent_name"] == "WINWORD.EXE"
    assert rec["actor_user_name"] == "dave"


def test_unknown_rule_becomes_base_event():
    rec = normalize_event(event({"id": "99999", "level": 1, "description": "d"}, {}))
    assert rec["class_name"] == "Base Event" and rec["class_uid"] == 0


def test_invalid_timestamp_raises():
    bad = {**BASE, "timestamp": "nope", "rule": {"id": "5760", "level": 5}, "data": {}}
    with pytest.raises(NormalizationError, match="invalid_timestamp"):
        normalize_event(bad)


@pytest.mark.parametrize("level,expected", [(0, 1), (3, 1), (5, 2), (8, 3), (12, 4), (14, 5), (15, 6)])
def test_severity_mapping(level, expected):
    assert severity_from_level(level) == expected
