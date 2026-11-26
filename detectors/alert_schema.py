"""Shared JSONL event contract for the persistence-detection project."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


SCHEMA_VERSION = "1.0"

TECHNIQUE_SLUGS = (
    "cron",
    "systemd_user",
    "shell_rc",
    "ssh_authorized_keys",
    "xdg_autostart",
    "ld_preload",
)

DETECTOR_NAMES = (
    "baseline_diff",
    "inotify",
    "auditd",
)

RECORD_TYPES = ("plant", "alert")
TRIAL_SOURCES = ("runner", "detector_cli", "unassigned")
OPERATIONS = (
    "create",
    "modify",
    "delete",
    "write",
    "move",
    "metadata",
    "unknown",
)

FORBIDDEN_CLASSIFICATION_FIELDS = {
    "false_positive",
    "is_false_positive",
    "classification",
}

REQUIRED_COMMON_FIELDS = {
    "schema_version",
    "record_type",
    "experiment_id",
    "run_id",
    "trial",
    "trial_source",
    "technique",
    "detector",
    "paths",
    "operation",
}


class ContractError(ValueError):
    """Raised when a record does not satisfy the shared event contract."""


def _require_string(record: Mapping[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be a non-empty string")
    return value


def _require_non_negative_int(record: Mapping[str, Any], field: str) -> int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be a non-negative integer")
    return value


def validate_record(record: Mapping[str, Any]) -> None:
    """Validate one runner plant record or raw detector alert."""

    if not isinstance(record, Mapping):
        raise ContractError("record must be a mapping")

    forbidden = FORBIDDEN_CLASSIFICATION_FIELDS.intersection(record)
    if forbidden:
        raise ContractError(
            "classification fields are analysis-only: " + ", ".join(sorted(forbidden))
        )

    missing = REQUIRED_COMMON_FIELDS.difference(record)
    if missing:
        raise ContractError("missing fields: " + ", ".join(sorted(missing)))

    if record["schema_version"] != SCHEMA_VERSION:
        raise ContractError(f"schema_version must be {SCHEMA_VERSION!r}")

    record_type = _require_string(record, "record_type")
    if record_type not in RECORD_TYPES:
        raise ContractError(f"record_type must be one of {RECORD_TYPES}")

    _require_string(record, "experiment_id")
    _require_string(record, "run_id")

    trial = record["trial"]
    trial_source = record["trial_source"]
    if trial_source not in TRIAL_SOURCES:
        raise ContractError(f"trial_source must be one of {TRIAL_SOURCES}")
    if trial is not None and (
        isinstance(trial, bool) or not isinstance(trial, int) or trial < 0
    ):
        raise ContractError("trial must be null or a non-negative integer")
    if record_type == "plant":
        if trial is None or trial_source != "runner":
            raise ContractError("plant records require a runner-supplied trial")
    elif trial is None and trial_source != "unassigned":
        raise ContractError("unassigned alerts must have trial=null")
    elif trial is not None and trial_source == "unassigned":
        raise ContractError("a numbered trial requires runner or detector_cli provenance")

    technique = record["technique"]
    if not isinstance(technique, str) or technique not in TECHNIQUE_SLUGS:
        raise ContractError(f"technique must be one of {TECHNIQUE_SLUGS}")

    detector = record["detector"]
    if record_type == "plant":
        if detector is not None:
            raise ContractError("plant records must have detector=null")
        if "plant_event_id" not in record:
            raise ContractError("plant records require plant_event_id")
        _require_string(record, "plant_event_id")
        if "plant_time_epoch_ns" not in record or "plant_time_utc" not in record:
            raise ContractError("plant records require plant_time_epoch_ns and plant_time_utc")
        _require_non_negative_int(record, "plant_time_epoch_ns")
        _require_string(record, "plant_time_utc")
    else:
        if not isinstance(detector, str) or detector not in DETECTOR_NAMES:
            raise ContractError(f"alert detector must be one of {DETECTOR_NAMES}")
        if "alert_id" not in record:
            raise ContractError("alert records require alert_id")
        _require_string(record, "alert_id")
        if "observation_time_epoch_ns" not in record:
            raise ContractError("alert records require observation_time_epoch_ns")
        if "observation_time_utc" not in record:
            raise ContractError("alert records require observation_time_utc")
        _require_non_negative_int(record, "observation_time_epoch_ns")
        _require_string(record, "observation_time_utc")

        plant_event_id = record.get("plant_event_id")
        if plant_event_id is not None:
            _require_string({"plant_event_id": plant_event_id}, "plant_event_id")
            if record.get("plant_event_id_source") != "runner":
                raise ContractError(
                    "plant_event_id is allowed only when plant_event_id_source='runner'"
                )
        elif "plant_event_id_source" in record:
            raise ContractError("plant_event_id_source requires plant_event_id")

        if "alert_group_id" not in record:
            raise ContractError("alert records require alert_group_id")
        _require_string(record, "alert_group_id")

    paths = record["paths"]
    if not isinstance(paths, list) or not paths or any(
        not isinstance(path, str) or not path.strip() for path in paths
    ):
        raise ContractError("paths must be a non-empty list of strings")

    operation = record["operation"]
    if operation not in OPERATIONS:
        raise ContractError(f"operation must be one of {OPERATIONS}")

    for optional_object in ("metadata", "evidence"):
        if optional_object in record and not isinstance(record[optional_object], Mapping):
            raise ContractError(f"{optional_object} must be an object when present")


def to_json_line(record: Mapping[str, Any]) -> str:
    """Validate and serialize one record as deterministic JSONL."""

    validate_record(record)
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def from_json_line(line: str) -> dict[str, Any]:
    """Parse and validate one JSONL record."""

    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise ContractError("JSONL record must be a JSON object")
    validate_record(record)
    return record
