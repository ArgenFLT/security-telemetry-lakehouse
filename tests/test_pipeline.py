import json
from datetime import datetime, timezone

import duckdb
import pytest

from stl.generator import generate_lines, write_jsonl
from stl.pipeline import normalize_to_parquet
from stl.quality import QualityError

START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _count_rows(lake_dir) -> int:
    con = duckdb.connect()
    return con.execute(
        f"select count(*) from read_parquet('{lake_dir}/**/*.parquet', hive_partitioning=true)"
    ).fetchone()[0]


def _run(tmp_path, dirty_rate, max_ratio=0.05, hours=6):
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, generate_lines(START, hours=hours, events_per_hour=100, seed=11, dirty_rate=dirty_rate))
    return normalize_to_parquet(
        raw, tmp_path / "lake", tmp_path / "quarantine.jsonl", tmp_path / "report.json", max_ratio
    )


def test_pipeline_writes_partitioned_parquet_and_report(tmp_path):
    report = _run(tmp_path, dirty_rate=0.01)
    assert report["total"] > 0
    assert report["accepted"] + report["rejected"] == report["total"]
    assert (tmp_path / "lake" / "event_date=2026-10-01").exists()

    assert _count_rows(tmp_path / "lake") == report["accepted"]
    assert json.loads((tmp_path / "report.json").read_text())["total"] == report["total"]


def test_quarantine_matches_rejected_count(tmp_path):
    report = _run(tmp_path, dirty_rate=0.02)
    quarantined = (tmp_path / "quarantine.jsonl").read_text().splitlines()
    assert len(quarantined) == report["rejected"]
    assert all("reasons" in json.loads(line) for line in quarantined)


def test_quality_gate_blocks_load_when_threshold_exceeded(tmp_path):
    with pytest.raises(QualityError):
        _run(tmp_path, dirty_rate=0.5, max_ratio=0.05)
    assert not (tmp_path / "lake").exists()
    assert (tmp_path / "report.json").exists()  # report is still written for diagnosis


def test_rerun_is_idempotent(tmp_path):
    first = _run(tmp_path, dirty_rate=0.0)
    second = _run(tmp_path, dirty_rate=0.0)
    assert first == second
    assert _count_rows(tmp_path / "lake") == second["accepted"]
