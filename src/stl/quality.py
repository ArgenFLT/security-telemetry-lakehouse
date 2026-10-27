"""Data quality gate: record-level validation, quarantine and a fail threshold."""

from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import datetime, timedelta, timezone


class QualityError(RuntimeError):
    """Raised when the share of rejected records exceeds the allowed threshold."""


def validate(record: dict, now: datetime | None = None) -> list[str]:
    """Return a list of issue codes; an empty list means the record is valid."""
    now = now or datetime.now(timezone.utc)
    issues: list[str] = []

    if not record.get("device_name"):
        issues.append("missing_device_name")
    if not record.get("event_uid"):
        issues.append("missing_event_uid")

    ts = record["time"]
    if ts < datetime(2000, 1, 1, tzinfo=timezone.utc) or ts > now + timedelta(days=1):
        issues.append("time_out_of_range")

    if not 0 <= record["severity_id"] <= 6:
        issues.append("invalid_severity")

    for field in ("src_ip", "device_ip"):
        value = record.get(field)
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                issues.append(f"invalid_{field}")

    if record["class_name"] == "Authentication" and not record.get("target_user_name"):
        issues.append("auth_without_user")

    return issues


def summarize(total: int, accepted: int, reasons: Counter) -> dict:
    rejected = total - accepted
    return {
        "total": total,
        "accepted": accepted,
        "rejected": rejected,
        "reject_ratio": round(rejected / total, 6) if total else 0.0,
        "reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
    }


def enforce(report: dict, max_reject_ratio: float) -> None:
    if report["reject_ratio"] > max_reject_ratio:
        raise QualityError(
            f"Reject ratio {report['reject_ratio']:.2%} exceeds allowed {max_reject_ratio:.2%}; "
            "lakehouse not updated. Inspect the quarantine file."
        )
