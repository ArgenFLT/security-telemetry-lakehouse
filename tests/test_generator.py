import json
from datetime import datetime, timezone

from stl.generator import SSH_ATTACKER_IP, WIN_ATTACKER_IP, generate_lines

START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_generation_is_deterministic():
    a = generate_lines(START, hours=6, events_per_hour=50, seed=7)
    b = generate_lines(START, hours=6, events_per_hour=50, seed=7)
    assert a == b


def test_different_seed_changes_output():
    a = generate_lines(START, hours=6, events_per_hour=50, seed=1)
    b = generate_lines(START, hours=6, events_per_hour=50, seed=2)
    assert a != b


def test_attack_scenarios_are_injected():
    lines = generate_lines(START, hours=6, events_per_hour=20, seed=3, dirty_rate=0.0)
    text = "\n".join(lines)
    assert SSH_ATTACKER_IP in text
    assert WIN_ATTACKER_IP in text
    assert "EncodedCommand" in text


def test_no_attacks_flag():
    lines = generate_lines(START, hours=6, events_per_hour=20, seed=3, dirty_rate=0.0, attacks=False)
    assert SSH_ATTACKER_IP not in "\n".join(lines)


def test_clean_output_is_valid_json_and_sorted():
    lines = generate_lines(START, hours=3, events_per_hour=30, seed=5, dirty_rate=0.0)
    events = [json.loads(line) for line in lines]
    stamps = [e["timestamp"] for e in events]
    assert stamps == sorted(stamps)


def test_dirty_rate_produces_corrupted_lines():
    lines = generate_lines(START, hours=3, events_per_hour=200, seed=5, dirty_rate=0.2)
    bad = 0
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if event.get("timestamp") == "not-a-timestamp" or "name" not in event.get("agent", {}):
            bad += 1
    assert bad > 0
