"""Raw JSONL -> validated, partitioned Parquet lakehouse."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pyarrow as pa
import pyarrow.dataset as ds

from .normalize import SCHEMA, NormalizationError, normalize_event
from .quality import enforce, summarize, validate


def normalize_to_parquet(
    raw_path: Path,
    lakehouse_dir: Path,
    quarantine_path: Path,
    report_path: Path,
    max_reject_ratio: float = 0.05,
) -> dict:
    """Normalize a raw JSONL file and write Parquet partitioned by event_date.

    Rejected lines are always written to the quarantine file and the report is always
    written. The lakehouse is only updated if the reject ratio is within the threshold,
    so a bad batch never contaminates downstream models.
    """
    accepted: list[dict] = []
    rejected: list[dict] = []
    reasons: Counter = Counter()
    total = 0

    with raw_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                reasons["invalid_json"] += 1
                rejected.append({"reasons": ["invalid_json"], "line": line[:2000]})
                continue
            try:
                record = normalize_event(raw)
            except NormalizationError as exc:
                reasons[str(exc)] += 1
                rejected.append({"reasons": [str(exc)], "line": line[:2000]})
                continue
            issues = validate(record)
            if issues:
                for issue in issues:
                    reasons[issue] += 1
                rejected.append({"reasons": issues, "line": line[:2000]})
                continue
            accepted.append(record)

    quarantine_path.parent.mkdir(parents=True, exist_ok=True)
    with quarantine_path.open("w", encoding="utf-8") as fh:
        for item in rejected:
            fh.write(json.dumps(item) + "\n")

    report = summarize(total, len(accepted), reasons)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    enforce(report, max_reject_ratio)

    if accepted:
        table = pa.Table.from_pylist(accepted, schema=SCHEMA)
        lakehouse_dir.mkdir(parents=True, exist_ok=True)
        ds.write_dataset(
            table,
            base_dir=str(lakehouse_dir),
            format="parquet",
            partitioning=ds.partitioning(pa.schema([("event_date", pa.date32())]), flavor="hive"),
            existing_data_behavior="delete_matching",
            basename_template="part-{i}.parquet",
        )
    return report
