"""Build deterministic CSV metric tables from offline experiment inputs."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    from .compute_metrics import compute_all_metrics
    from .load_events import (
        AnalysisInputError,
        load_classifications,
        load_events,
        load_evasion_records,
        load_resource_csv,
    )
except ImportError:  # pragma: no cover - direct script fallback
    from compute_metrics import compute_all_metrics
    from load_events import (
        AnalysisInputError,
        load_classifications,
        load_events,
        load_evasion_records,
        load_resource_csv,
    )


TABLE_FIELDS: dict[str, tuple[str, ...]] = {
    "detection_rate": (
        "experiment_id",
        "detector",
        "technique",
        "total_plants",
        "detected_plants",
        "detection_rate",
        "data_status",
    ),
    "latency": (
        "experiment_id",
        "detector",
        "technique",
        "matched_alerts",
        "valid_latency_count",
        "invalid_latency_count",
        "mean_latency_ms",
        "median_latency_ms",
        "min_latency_ms",
        "max_latency_ms",
        "data_status",
    ),
    "false_positives": (
        "experiment_id",
        "detector",
        "technique",
        "alert_count",
        "classified_alert_count",
        "unclassified_alert_count",
        "false_positive_count",
        "data_status",
    ),
    "resource_summary": (
        "experiment_id",
        "detector",
        "phase",
        "sample_count",
        "process_count",
        "valid_cpu_samples",
        "mean_cpu_percent",
        "max_cpu_percent",
        "valid_memory_samples",
        "mean_resident_memory_kb",
        "max_resident_memory_kb",
        "valid_read_delta_samples",
        "mean_read_bytes_delta",
        "total_read_bytes_delta",
        "valid_write_delta_samples",
        "mean_write_bytes_delta",
        "total_write_bytes_delta",
        "missing_measurement_fields",
        "data_status",
    ),
    "evasion": (
        "experiment_id",
        "detector",
        "technique",
        "evasion_label",
        "total_trials",
        "detected_trials",
        "evasion_detection_rate",
        "data_status",
    ),
}


def write_table(
    path: str | Path,
    rows: Iterable[Mapping[str, Any]],
    *,
    fieldnames: Sequence[str],
) -> Path:
    """Write sorted, stable CSV output with blank cells for ``None``."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(
        (dict(row) for row in rows),
        key=lambda row: tuple(str(row.get(field, "")) for field in fieldnames),
    )
    with destination.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=list(fieldnames),
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(ordered)
    return destination


def write_metric_tables(
    metrics: Mapping[str, Sequence[Mapping[str, Any]]],
    output_dir: str | Path,
) -> list[Path]:
    destination = Path(output_dir)
    paths: list[Path] = []
    for name in TABLE_FIELDS:
        paths.append(
            write_table(
                destination / f"{name}.csv",
                metrics.get(name, []),
                fieldnames=TABLE_FIELDS[name],
            )
        )
    return paths


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plants", required=True, help="plant JSONL input")
    parser.add_argument("--alerts", required=True, help="alert JSONL input")
    parser.add_argument("--resources", required=True, help="resource CSV input")
    parser.add_argument("--classifications", help="analysis alert-classification JSONL")
    parser.add_argument("--evasion", help="explicit evasion-result JSONL")
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plants, alerts = load_events(args.plants, args.alerts)
        resources = load_resource_csv(args.resources)
        classifications = (
            load_classifications(args.classifications) if args.classifications else None
        )
        evasion = load_evasion_records(args.evasion) if args.evasion else None
        metrics = compute_all_metrics(
            plants,
            alerts,
            resources,
            classifications=classifications,
            evasion=evasion,
        )
        paths = write_metric_tables(metrics, args.output_dir)
    except (AnalysisInputError, OSError) as exc:
        print(f"[analysis] error: {exc}", file=sys.stderr)
        return 2

    for path in paths:
        print(path)
    if not args.classifications:
        print(
            "[analysis] false-positive counts are unavailable: no classification sidecar supplied",
            file=sys.stderr,
        )
    if not args.evasion:
        print(
            "[analysis] evasion table is empty: no explicit evasion-result input supplied",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
