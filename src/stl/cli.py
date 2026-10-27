"""Command line entry point: ``stl generate | normalize | run``."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .generator import generate_lines, write_jsonl
from .pipeline import normalize_to_parquet
from .quality import QualityError

DEFAULT_RAW = "data/raw/events.jsonl"
DEFAULT_LAKEHOUSE = "data/lakehouse/events"
DEFAULT_QUARANTINE = "data/quarantine/rejected.jsonl"
DEFAULT_REPORT = "data/quality_report.json"


def _parse_start(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _generate(args: argparse.Namespace, out: str) -> None:
    lines = generate_lines(
        start=_parse_start(args.start),
        hours=args.hours,
        events_per_hour=args.events_per_hour,
        seed=args.seed,
        dirty_rate=args.dirty_rate,
    )
    n = write_jsonl(Path(out), lines)
    print(f"generated {n} raw lines -> {out}")


def _normalize(args: argparse.Namespace, raw: str) -> int:
    try:
        report = normalize_to_parquet(
            Path(raw),
            Path(args.lakehouse),
            Path(args.quarantine),
            Path(args.report),
            max_reject_ratio=args.max_reject_ratio,
        )
    except QualityError as exc:
        print(f"QUALITY GATE FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    _generate(args, args.raw)
    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    return _normalize(args, args.raw)


def cmd_run(args: argparse.Namespace) -> int:
    _generate(args, args.raw)
    return _normalize(args, args.raw)


def _add_generation_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--start", default="2026-10-01T00:00:00Z", help="ISO start time (UTC)")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--events-per-hour", type=int, default=500)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--dirty-rate", type=float, default=0.01, help="share of corrupted lines")


def _add_normalize_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--lakehouse", default=DEFAULT_LAKEHOUSE)
    p.add_argument("--quarantine", default=DEFAULT_QUARANTINE)
    p.add_argument("--report", default=DEFAULT_REPORT)
    p.add_argument("--max-reject-ratio", type=float, default=0.05)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="stl", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="create synthetic raw Wazuh-style events")
    gen.add_argument("--raw", default=DEFAULT_RAW, help="output JSONL path")
    _add_generation_options(gen)
    gen.set_defaults(func=cmd_generate)

    norm = sub.add_parser("normalize", help="raw JSONL -> validated Parquet lakehouse")
    norm.add_argument("--raw", default=DEFAULT_RAW, help="input JSONL path")
    _add_normalize_options(norm)
    norm.set_defaults(func=cmd_normalize)

    run = sub.add_parser("run", help="generate + normalize")
    run.add_argument("--raw", default=DEFAULT_RAW)
    _add_generation_options(run)
    _add_normalize_options(run)
    run.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
