"""Validated offline input loaders for plants, alerts, classifications, and resources."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

try:  # Works from the repository root and from ``analysis/``.
    from detectors.alert_schema import ContractError, from_json_line
    from measure_resources import CSV_FIELDS, DETECTORS, PHASES
except ImportError:  # pragma: no cover - direct module fallback
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from detectors.alert_schema import ContractError, from_json_line
    from analysis.measure_resources import CSV_FIELDS, DETECTORS, PHASES


class AnalysisInputError(ValueError):
    """Raised when an offline input is missing or malformed."""


CLASSIFICATIONS = ("true_positive", "false_positive", "unclassified")
REQUIRED_RESOURCE_COLUMNS = frozenset(CSV_FIELDS)


def _require_file(path: str | Path, *, label: str) -> Path:
    candidate = Path(path)
    if not candidate.exists():
        raise AnalysisInputError(f"{label} input does not exist: {candidate}")
    if not candidate.is_file():
        raise AnalysisInputError(f"{label} input is not a file: {candidate}")
    return candidate


def _read_json_object(line: str, *, path: Path, line_number: int) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise AnalysisInputError(
            f"{path}:{line_number}: malformed JSON: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise AnalysisInputError(f"{path}:{line_number}: JSON record must be an object")
    return value


def load_jsonl_records(
    path: str | Path,
    *,
    expected_record_type: str,
    label: str,
    validate_contract: bool = True,
) -> list[dict[str, Any]]:
    """Load nonblank JSONL records with line-numbered errors."""

    source = _require_file(path, label=label)
    records: list[dict[str, Any]] = []
    try:
        lines = source.open("r", encoding="utf-8")
    except OSError as exc:
        raise AnalysisInputError(f"could not open {label} input {source}: {exc}") from exc
    with lines:
        for line_number, raw_line in enumerate(lines, start=1):
            if not raw_line.strip():
                continue
            record = _read_json_object(raw_line, path=source, line_number=line_number)
            if validate_contract:
                try:
                    validated = from_json_line(raw_line)
                except (ContractError, json.JSONDecodeError) as exc:
                    raise AnalysisInputError(
                        f"{source}:{line_number}: invalid {expected_record_type} record: {exc}"
                    ) from exc
            else:
                validated = record
            if validated.get("record_type") != expected_record_type:
                raise AnalysisInputError(
                    f"{source}:{line_number}: expected record_type={expected_record_type!r}, "
                    f"got {record.get('record_type')!r}"
                )
            records.append(validated)
    return records


def load_events(
    plant_path: str | Path,
    alert_path: str | Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load and validate the runner plant JSONL and detector alert JSONL."""

    return (
        load_jsonl_records(plant_path, expected_record_type="plant", label="plant"),
        load_jsonl_records(alert_path, expected_record_type="alert", label="alert"),
    )


def _required_string(record: Mapping[str, Any], field: str, *, context: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise AnalysisInputError(f"{context}: {field} must be a non-empty string")
    return value


def _parse_int(value: str, *, field: str, context: str, minimum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise AnalysisInputError(f"{context}: {field} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise AnalysisInputError(f"{context}: {field} must be >= {minimum}")
    return parsed


def _parse_optional_int(value: str, *, field: str, context: str) -> int | None:
    if value == "":
        return None
    return _parse_int(value, field=field, context=context)


def _parse_optional_float(value: str, *, field: str, context: str) -> float | None:
    if value == "":
        return None
    try:
        return float(value)
    except ValueError as exc:
        raise AnalysisInputError(f"{context}: {field} must be numeric or blank") from exc


def load_resource_csv(path: str | Path) -> list[dict[str, Any]]:
    """Load the CSV format emitted by ``analysis/measure_resources.py``."""

    source = _require_file(path, label="resource CSV")
    try:
        stream = source.open("r", newline="", encoding="utf-8")
    except OSError as exc:
        raise AnalysisInputError(f"could not open resource CSV {source}: {exc}") from exc
    with stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None:
            raise AnalysisInputError(f"{source}: resource CSV has no header")
        missing = sorted(REQUIRED_RESOURCE_COLUMNS.difference(reader.fieldnames))
        if missing:
            raise AnalysisInputError(
                f"{source}: resource CSV is missing columns: {', '.join(missing)}"
            )
        rows: list[dict[str, Any]] = []
        for line_number, raw in enumerate(reader, start=2):
            context = f"{source}:{line_number}"
            if None in raw:
                raise AnalysisInputError(f"{context}: too many CSV fields")
            for field in CSV_FIELDS:
                if raw.get(field) is None:
                    raise AnalysisInputError(f"{context}: missing field {field}")
            detector = _required_string(raw, "detector", context=context)
            if detector not in DETECTORS:
                raise AnalysisInputError(f"{context}: unknown detector {detector!r}")
            phase = _required_string(raw, "phase", context=context)
            if phase not in PHASES:
                raise AnalysisInputError(f"{context}: phase must be idle or active")
            status = _required_string(raw, "sample_status", context=context)
            parsed: dict[str, Any] = dict(raw)
            parsed["trial"] = _parse_int(raw["trial"], field="trial", context=context, minimum=0)
            parsed["pid"] = _parse_int(raw["pid"], field="pid", context=context, minimum=1)
            parsed["sample_time_epoch_ns"] = _parse_int(
                raw["sample_time_epoch_ns"],
                field="sample_time_epoch_ns",
                context=context,
                minimum=0,
            )
            parsed["cpu_percent"] = _parse_optional_float(
                raw["cpu_percent"], field="cpu_percent", context=context
            )
            parsed["cpu_time_jiffies"] = _parse_optional_int(
                raw["cpu_time_jiffies"], field="cpu_time_jiffies", context=context
            )
            parsed["resident_memory_kb"] = _parse_optional_int(
                raw["resident_memory_kb"], field="resident_memory_kb", context=context
            )
            parsed["read_bytes_delta"] = _parse_optional_int(
                raw["read_bytes_delta"], field="read_bytes_delta", context=context
            )
            parsed["write_bytes_delta"] = _parse_optional_int(
                raw["write_bytes_delta"], field="write_bytes_delta", context=context
            )
            parsed["error"] = raw["error"] or None
            rows.append(parsed)
    return rows


def load_classifications(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load analysis-owned alert classifications keyed by alert ID.

    Classification is intentionally a separate JSONL input because the shared
    raw-alert contract forbids classification fields on detector records.
    """

    source = _require_file(path, label="classification")
    result: dict[str, dict[str, Any]] = {}
    try:
        stream = source.open("r", encoding="utf-8")
    except OSError as exc:
        raise AnalysisInputError(f"could not open classification input {source}: {exc}") from exc
    with stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if not raw_line.strip():
                continue
            context = f"{source}:{line_number}"
            record = _read_json_object(raw_line, path=source, line_number=line_number)
            if record.get("record_type") != "alert_classification":
                raise AnalysisInputError(f"{context}: record_type must be 'alert_classification'")
            alert_id = _required_string(record, "alert_id", context=context)
            classification = _required_string(record, "classification", context=context)
            if classification not in CLASSIFICATIONS:
                raise AnalysisInputError(
                    f"{context}: classification must be one of {CLASSIFICATIONS}"
                )
            if alert_id in result:
                raise AnalysisInputError(f"{context}: duplicate classification for {alert_id}")
            result[alert_id] = record
    return result


def load_evasion_records(path: str | Path) -> list[dict[str, Any]]:
    """Load explicit evasion outcomes; no evasion data is inferred."""

    source = _require_file(path, label="evasion")
    records = load_jsonl_records(
        source,
        expected_record_type="evasion_result",
        label="evasion",
        validate_contract=False,
    )
    for index, record in enumerate(records, start=1):
        context = f"{source}:record {index}"
        for field in ("experiment_id", "run_id", "detector", "technique", "evasion_label"):
            _required_string(record, field, context=context)
        if record["detector"] not in DETECTORS:
            raise AnalysisInputError(f"{context}: unknown detector {record['detector']!r}")
        if not isinstance(record.get("detected"), bool):
            raise AnalysisInputError(f"{context}: detected must be boolean")
    return records
