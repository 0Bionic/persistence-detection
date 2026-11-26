"""Compute reproducible offline metrics from validated analysis inputs.

Detection matching uses a runner-supplied ``plant_event_id`` when an alert
contains one. Otherwise it uses the contract's shared ``run_id`` plus
experiment, technique, and compatible trial. A plant's optional
``metadata.detectors`` or ``metadata.detector`` scope is honored; when absent,
the caller's detector list is treated as the explicit experiment grid. This is
an assumption to confirm with Student 1 because plant records themselves do
not currently contain a detector field.

Raw alerts are never modified with classifications. False-positive metrics use
the separate analysis-owned classification mapping loaded from
``alert_classification`` records. Missing classifications and missing resource
measurements remain explicit missing values rather than zeroes.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Any, Iterable, Mapping, Sequence

try:
    from .load_events import AnalysisInputError, DETECTORS
except ImportError:  # pragma: no cover - direct script fallback
    from load_events import AnalysisInputError, DETECTORS


def _group_key(record: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(record["experiment_id"]),
        str(record["detector"]),
        str(record["technique"]),
    )


def _plant_group_key(record: Mapping[str, Any]) -> tuple[str, str]:
    return str(record["experiment_id"]), str(record["technique"])


def _detector_scope(plant: Mapping[str, Any], detectors: Sequence[str]) -> tuple[str, ...]:
    metadata = plant.get("metadata")
    if not isinstance(metadata, Mapping):
        return tuple(detectors)
    scoped = metadata.get("detectors")
    if isinstance(scoped, list) and all(isinstance(value, str) for value in scoped):
        return tuple(scoped)
    single = metadata.get("detector")
    if isinstance(single, str):
        return (single,)
    return tuple(detectors)


def _compatible_trial(alert: Mapping[str, Any], plant: Mapping[str, Any]) -> bool:
    alert_trial = alert.get("trial")
    return alert_trial is None or alert_trial == plant.get("trial")


def _match_alert(
    alert: Mapping[str, Any],
    plants: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    """Match one alert to one plant without inventing ground truth."""

    plant_event_id = alert.get("plant_event_id")
    if plant_event_id is not None:
        candidates = [
            plant
            for plant in plants
            if plant.get("plant_event_id") == plant_event_id
            and alert.get("experiment_id") == plant.get("experiment_id")
            and alert.get("technique") == plant.get("technique")
            and _compatible_trial(alert, plant)
        ]
    else:
        candidates = [
            plant
            for plant in plants
            if alert.get("experiment_id") == plant.get("experiment_id")
            and alert.get("run_id") == plant.get("run_id")
            and alert.get("technique") == plant.get("technique")
            and _compatible_trial(alert, plant)
        ]
    if len(candidates) > 1:
        raise AnalysisInputError(
            f"alert {alert.get('alert_id')} matches multiple plant records; "
            "run_id/plant_event_id is not unique"
        )
    return candidates[0] if candidates else None


def _plant_groups(
    plants: Sequence[Mapping[str, Any]],
    detectors: Sequence[str],
) -> dict[tuple[str, str, str], list[Mapping[str, Any]]]:
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for plant in plants:
        for detector in _detector_scope(plant, detectors):
            if detector not in detectors:
                raise AnalysisInputError(
                    f"plant {plant.get('plant_event_id')} names unknown detector {detector!r}"
                )
            groups[(str(plant["experiment_id"]), detector, str(plant["technique"]))].append(plant)
    return groups


def compute_detection_metrics(
    plants: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
    *,
    detectors: Sequence[str] = DETECTORS,
) -> list[dict[str, Any]]:
    """Return one detection-rate row per experiment/detector/technique."""

    detector_list = tuple(detectors)
    groups = _plant_groups(plants, detector_list)
    detected: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for alert in alerts:
        matched = _match_alert(alert, plants)
        if matched is None or alert.get("detector") not in detector_list:
            continue
        key = (
            str(matched["experiment_id"]),
            str(alert["detector"]),
            str(matched["technique"]),
        )
        detected[key].add(str(matched["plant_event_id"]))

    rows: list[dict[str, Any]] = []
    for key in sorted(groups):
        experiment_id, detector, technique = key
        scoped_plants = groups[key]
        plant_ids = {str(plant["plant_event_id"]) for plant in scoped_plants}
        detected_count = len(detected[key].intersection(plant_ids))
        total = len(plant_ids)
        rows.append(
            {
                "experiment_id": experiment_id,
                "detector": detector,
                "technique": technique,
                "total_plants": total,
                "detected_plants": detected_count,
                "detection_rate": detected_count / total if total else None,
                "data_status": "ok" if total else "missing_denominator",
            }
        )
    return rows


def _matched_latency_records(
    plants: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        plant = _match_alert(alert, plants)
        if plant is None:
            continue
        latency_ns = (
            int(alert["observation_time_epoch_ns"])
            - int(plant["plant_time_epoch_ns"])
        )
        rows.append(
            {
                "experiment_id": alert["experiment_id"],
                "detector": alert["detector"],
                "technique": alert["technique"],
                "alert_id": alert["alert_id"],
                "plant_event_id": plant["plant_event_id"],
                "latency_ms": latency_ns / 1_000_000 if latency_ns >= 0 else None,
                "latency_status": "ok" if latency_ns >= 0 else "negative_timestamp_delta",
            }
        )
    return rows


def compute_latency_metrics(
    plants: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Summarize matched alert latency using epoch nanoseconds only."""

    matched = _matched_latency_records(plants, alerts)
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in matched:
        grouped[(row["experiment_id"], row["detector"], row["technique"])].append(row)

    rows: list[dict[str, Any]] = []
    for key in sorted(grouped):
        records = grouped[key]
        valid = [float(row["latency_ms"]) for row in records if row["latency_ms"] is not None]
        invalid_count = len(records) - len(valid)
        rows.append(
            {
                "experiment_id": key[0],
                "detector": key[1],
                "technique": key[2],
                "matched_alerts": len(records),
                "valid_latency_count": len(valid),
                "invalid_latency_count": invalid_count,
                "mean_latency_ms": statistics.fmean(valid) if valid else None,
                "median_latency_ms": statistics.median(valid) if valid else None,
                "min_latency_ms": min(valid) if valid else None,
                "max_latency_ms": max(valid) if valid else None,
                "data_status": "partial" if invalid_count else "ok",
            }
        )
    return rows


def compute_false_positive_metrics(
    alerts: Sequence[Mapping[str, Any]],
    classifications: Mapping[str, Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Count explicit false-positive classifications without treating missing as zero."""

    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for alert in alerts:
        grouped[_group_key(alert)].append(alert)
    if classifications is not None:
        alert_ids = {str(alert["alert_id"]) for alert in alerts}
        unknown = sorted(set(classifications).difference(alert_ids))
        if unknown:
            raise AnalysisInputError(
                "classification references unknown alert IDs: " + ", ".join(unknown)
            )

    rows: list[dict[str, Any]] = []
    for key in sorted(grouped):
        records = grouped[key]
        if classifications is None:
            classified = []
            unclassified = len(records)
            false_positive_count = None
            status = "classification_missing"
        else:
            values = [classifications.get(str(alert["alert_id"])) for alert in records]
            classified = [
                value for value in values if value and value.get("classification") != "unclassified"
            ]
            unclassified = len(values) - len(classified)
            false_positive_count = (
                sum(value.get("classification") == "false_positive" for value in classified)
                if classified
                else None
            )
            status = "ok" if unclassified == 0 else "partial"
        rows.append(
            {
                "experiment_id": key[0],
                "detector": key[1],
                "technique": key[2],
                "alert_count": len(records),
                "classified_alert_count": len(classified),
                "unclassified_alert_count": unclassified,
                "false_positive_count": false_positive_count,
                "data_status": status,
            }
        )
    return rows


def _mean_or_none(values: Iterable[float | int | None]) -> float | None:
    present = [float(value) for value in values if value is not None]
    return statistics.fmean(present) if present else None


def _max_or_none(values: Iterable[float | int | None]) -> float | None:
    present = [float(value) for value in values if value is not None]
    return max(present) if present else None


def _sum_or_none(values: Iterable[int | None]) -> int | None:
    present = [int(value) for value in values if value is not None]
    return sum(present) if present else None


def compute_resource_metrics(resources: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Summarize resource rows by experiment, detector, and phase."""

    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in resources:
        grouped[(str(row["experiment_id"]), str(row["detector"]), str(row["phase"]))].append(row)

    rows: list[dict[str, Any]] = []
    for key in sorted(grouped):
        records = grouped[key]
        cpu = [row.get("cpu_percent") for row in records]
        memory = [row.get("resident_memory_kb") for row in records]
        read = [row.get("read_bytes_delta") for row in records]
        write = [row.get("write_bytes_delta") for row in records]
        missing_fields = sum(value is None for value in cpu + memory + read + write)
        rows.append(
            {
                "experiment_id": key[0],
                "detector": key[1],
                "phase": key[2],
                "sample_count": len(records),
                "process_count": len({row["pid"] for row in records}),
                "valid_cpu_samples": sum(value is not None for value in cpu),
                "mean_cpu_percent": _mean_or_none(cpu),
                "max_cpu_percent": _max_or_none(cpu),
                "valid_memory_samples": sum(value is not None for value in memory),
                "mean_resident_memory_kb": _mean_or_none(memory),
                "max_resident_memory_kb": _max_or_none(memory),
                "valid_read_delta_samples": sum(value is not None for value in read),
                "mean_read_bytes_delta": _mean_or_none(read),
                "total_read_bytes_delta": _sum_or_none(read),
                "valid_write_delta_samples": sum(value is not None for value in write),
                "mean_write_bytes_delta": _mean_or_none(write),
                "total_write_bytes_delta": _sum_or_none(write),
                "missing_measurement_fields": missing_fields,
                "data_status": "partial" if missing_fields else "ok",
            }
        )
    return rows


def compute_evasion_metrics(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Summarize explicit evasion outcomes; an empty input stays empty."""

    grouped: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for record in records:
        key = (
            str(record["experiment_id"]),
            str(record["detector"]),
            str(record["technique"]),
            str(record["evasion_label"]),
        )
        grouped[key].append(record)
    rows: list[dict[str, Any]] = []
    for key in sorted(grouped):
        values = grouped[key]
        detected = sum(bool(value["detected"]) for value in values)
        rows.append(
            {
                "experiment_id": key[0],
                "detector": key[1],
                "technique": key[2],
                "evasion_label": key[3],
                "total_trials": len(values),
                "detected_trials": detected,
                "evasion_detection_rate": detected / len(values) if values else None,
                "data_status": "ok" if values else "missing",
            }
        )
    return rows


def compute_all_metrics(
    plants: Sequence[Mapping[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
    resources: Sequence[Mapping[str, Any]],
    *,
    classifications: Mapping[str, Mapping[str, Any]] | None = None,
    evasion: Sequence[Mapping[str, Any]] | None = None,
    detectors: Sequence[str] = DETECTORS,
) -> dict[str, list[dict[str, Any]]]:
    """Compute every offline table without creating values for absent inputs."""

    return {
        "detection_rate": compute_detection_metrics(plants, alerts, detectors=detectors),
        "latency": compute_latency_metrics(plants, alerts),
        "false_positives": compute_false_positive_metrics(alerts, classifications),
        "resource_summary": compute_resource_metrics(resources),
        "evasion": compute_evasion_metrics(evasion or []),
    }
