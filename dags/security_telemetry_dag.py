"""Daily security telemetry pipeline.

generate_raw -> normalize_to_parquet (quality gate) -> dbt_build

`generate_raw` stands in for real ingestion (Wazuh archives, Kafka consumer, S3 landing
zone). Replace it with your source and keep the rest unchanged.

Configuration via environment variables:
  STL_PROJECT_DIR  repository root (default: parent of this dags/ folder)
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:  # Airflow 3
    from airflow.sdk import dag, task
except ImportError:  # Airflow 2.x
    from airflow.decorators import dag, task

PROJECT_DIR = Path(os.environ.get("STL_PROJECT_DIR", Path(__file__).resolve().parents[1]))

default_args = {
    "owner": "data-engineering",
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
}


@dag(
    dag_id="security_telemetry_daily",
    description="Raw security events -> validated Parquet lakehouse -> dbt detections",
    schedule="@daily",
    start_date=datetime(2026, 10, 1, tzinfo=timezone.utc),
    catchup=False,
    max_active_runs=1,
    default_args=default_args,
    tags=["security", "lakehouse", "dbt"],
)
def security_telemetry_daily():
    @task
    def generate_raw(logical_date=None) -> str:
        from stl.generator import generate_lines, write_jsonl

        day = logical_date.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        raw_path = PROJECT_DIR / "data" / "raw" / f"events_{day:%Y%m%d}.jsonl"
        lines = generate_lines(start=day, hours=24, seed=int(day.timestamp()))
        write_jsonl(raw_path, lines)
        return str(raw_path)

    @task
    def normalize_to_parquet(raw_path: str) -> dict:
        from stl.pipeline import normalize_to_parquet as run_normalize

        # A QualityError here fails the task and stops dbt from reading bad data.
        return run_normalize(
            Path(raw_path),
            PROJECT_DIR / "data" / "lakehouse" / "events",
            PROJECT_DIR / "data" / "quarantine" / f"{Path(raw_path).stem}_rejected.jsonl",
            PROJECT_DIR / "data" / "quality_report.json",
            max_reject_ratio=0.05,
        )

    @task
    def dbt_build(report: dict) -> None:
        subprocess.run(
            ["dbt", "build", "--project-dir", "dbt_project", "--profiles-dir", "dbt_project"],
            cwd=PROJECT_DIR,
            check=True,
        )

    dbt_build(normalize_to_parquet(generate_raw()))


security_telemetry_daily()
