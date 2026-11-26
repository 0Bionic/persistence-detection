"""Dependency-free helpers shared by the persistence detectors."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

try:  # Works both as ``detectors.common`` and from a detector script directory.
    from .alert_schema import SCHEMA_VERSION, to_json_line
except ImportError:  # pragma: no cover - direct script execution fallback
    from alert_schema import SCHEMA_VERSION, to_json_line


DUPLICATE_WINDOW_NS = 250_000_000


def now_epoch_ns() -> int:
    """Return the wall-clock observation time used by event records."""

    return time.time_ns()


def epoch_ns_to_utc(epoch_ns: int) -> str:
    """Format epoch nanoseconds as an ISO-8601 UTC timestamp."""

    seconds, nanoseconds = divmod(epoch_ns, 1_000_000_000)
    timestamp = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return timestamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{nanoseconds:09d}Z"


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def normalize_path(path: str, *, home: str | None = None, user: str | None = None) -> str:
    """Expand configured placeholders and return an absolute lexical path."""

    expanded = path.replace("{home}", home or os.path.expanduser("~"))
    expanded = expanded.replace("{user}", user or os.environ.get("USER", "unknown"))
    expanded = os.path.expandvars(os.path.expanduser(expanded))
    return os.path.abspath(os.path.normpath(expanded))


def operation_group(operation: str) -> str:
    """Map raw operations to the grouping classes used for deduplication."""

    if operation in {"create", "modify", "write", "move"}:
        return "write"
    if operation == "delete":
        return "delete"
    if operation == "metadata":
        return "metadata"
    return "unknown"


def duplicate_key(
    *,
    detector: str,
    experiment_id: str,
    run_id: str,
    trial: int | None,
    trial_source: str,
    technique: str,
    paths: Iterable[str],
    operation: str,
) -> tuple[Any, ...]:
    """Return the stable key used by all detectors for duplicate grouping."""

    normalized_paths = tuple(sorted(normalize_path(path) for path in paths))
    return (
        detector,
        experiment_id,
        run_id,
        trial,
        trial_source,
        technique,
        normalized_paths,
        operation_group(operation),
    )


@dataclass
class GroupedRawEvent:
    """A logical alert group retaining every raw event that formed it."""

    alert_group_id: str
    detector: str
    experiment_id: str
    run_id: str
    trial: int | None
    trial_source: str
    technique: str
    paths: tuple[str, ...]
    operation: str
    operation_group: str
    first_observation_time_epoch_ns: int
    last_observation_time_epoch_ns: int
    raw_events: list[dict[str, Any]] = field(default_factory=list)


class DuplicateEventGrouper:
    """Group duplicate observations using the shared 250 ms rule.

    The comparison is against the first observation in the current group, not
    the most recent one. ``add`` returns groups closed by the new event;
    ``flush`` returns groups whose first observation is outside the window.
    Every raw event is copied into ``GroupedRawEvent.raw_events``.
    """

    def __init__(self, *, window_ns: int = DUPLICATE_WINDOW_NS) -> None:
        if window_ns < 0:
            raise ValueError("window_ns must be non-negative")
        self.window_ns = window_ns
        self._active: dict[tuple[Any, ...], GroupedRawEvent] = {}

    def add(
        self,
        *,
        detector: str,
        experiment_id: str,
        run_id: str,
        trial: int | None,
        trial_source: str,
        technique: str,
        paths: Iterable[str],
        operation: str,
        observation_time_epoch_ns: int,
        raw_event: Mapping[str, Any],
    ) -> list[GroupedRawEvent]:
        """Add one raw event and return groups closed by this event."""

        normalized_paths = tuple(sorted(normalize_path(path) for path in paths))
        key = duplicate_key(
            detector=detector,
            experiment_id=experiment_id,
            run_id=run_id,
            trial=trial,
            trial_source=trial_source,
            technique=technique,
            paths=normalized_paths,
            operation=operation,
        )
        closed: list[GroupedRawEvent] = []
        current = self._active.get(key)
        if current is None or (
            observation_time_epoch_ns - current.first_observation_time_epoch_ns
            > self.window_ns
        ):
            if current is not None:
                closed.append(self._active.pop(key))
            current = GroupedRawEvent(
                alert_group_id=new_id("group"),
                detector=detector,
                experiment_id=experiment_id,
                run_id=run_id,
                trial=trial,
                trial_source=trial_source,
                technique=technique,
                paths=normalized_paths,
                operation=operation,
                operation_group=operation_group(operation),
                first_observation_time_epoch_ns=observation_time_epoch_ns,
                last_observation_time_epoch_ns=observation_time_epoch_ns,
            )
            self._active[key] = current
        else:
            current.last_observation_time_epoch_ns = observation_time_epoch_ns

        current.raw_events.append(dict(raw_event))
        return closed

    def flush(self, *, observation_time_epoch_ns: int | None = None) -> list[GroupedRawEvent]:
        """Close groups whose first observation is outside the grouping window."""

        now = now_epoch_ns() if observation_time_epoch_ns is None else observation_time_epoch_ns
        closed: list[GroupedRawEvent] = []
        for key, group in list(self._active.items()):
            if now - group.first_observation_time_epoch_ns > self.window_ns:
                closed.append(self._active.pop(key))
        return closed

    def flush_all(self) -> list[GroupedRawEvent]:
        """Close and return every currently active group."""

        closed = list(self._active.values())
        self._active.clear()
        return closed


def make_plant_record(
    *,
    experiment_id: str,
    run_id: str,
    trial: int,
    technique: str,
    paths: Iterable[str],
    operation: str = "unknown",
    plant_time_epoch_ns: int | None = None,
    plant_event_id: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a runner-owned plant record.

    The runner creates ``run_id`` once per plant attempt and passes the same
    value to every record associated with that attempt.
    """

    observed = now_epoch_ns() if plant_time_epoch_ns is None else plant_time_epoch_ns
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "plant",
        "experiment_id": experiment_id,
        "run_id": run_id,
        "trial": trial,
        "trial_source": "runner",
        "technique": technique,
        "detector": None,
        "plant_event_id": plant_event_id or new_id("plant"),
        "plant_time_epoch_ns": observed,
        "plant_time_utc": epoch_ns_to_utc(observed),
        "paths": [normalize_path(path) for path in paths],
        "operation": operation,
    }
    if metadata is not None:
        record["metadata"] = dict(metadata)
    return record


def make_alert_record(
    *,
    detector: str,
    experiment_id: str,
    run_id: str,
    trial: int | None,
    technique: str,
    paths: Iterable[str],
    operation: str,
    raw_events: Iterable[Mapping[str, Any]],
    alert_group_id: str,
    trial_source: str = "unassigned",
    observation_time_epoch_ns: int | None = None,
    plant_event_id: str | None = None,
    runner_provided_plant_event_id: bool = False,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a raw detector alert with no analysis classification.

    ``run_id`` must be the runner-created ID for the plant attempt observed by
    this detector. Multiple detectors may use the same run ID; ``detector``
    distinguishes their alerts.
    """

    if plant_event_id is not None and not runner_provided_plant_event_id:
        raise ValueError("plant_event_id requires an ID explicitly supplied by the runner")
    if runner_provided_plant_event_id and not plant_event_id:
        raise ValueError("runner_provided_plant_event_id requires plant_event_id")

    observed = now_epoch_ns() if observation_time_epoch_ns is None else observation_time_epoch_ns
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "alert",
        "experiment_id": experiment_id,
        "run_id": run_id,
        "trial": trial,
        "trial_source": trial_source,
        "technique": technique,
        "detector": detector,
        "alert_id": new_id("alert"),
        "alert_group_id": alert_group_id,
        "observation_time_epoch_ns": observed,
        "observation_time_utc": epoch_ns_to_utc(observed),
        "paths": [normalize_path(path) for path in paths],
        "operation": operation,
        "evidence": {"raw_events": [dict(event) for event in raw_events]},
    }
    if plant_event_id is not None:
        record["plant_event_id"] = plant_event_id
        record["plant_event_id_source"] = "runner"
    if metadata is not None:
        record["metadata"] = dict(metadata)
    return record


def write_jsonl_record(stream: Any, record: Mapping[str, Any]) -> None:
    """Write one validated record to a text stream."""

    stream.write(to_json_line(record) + "\n")


def resolve_config_path(template: str, *, home: str | None = None, user: str | None = None) -> Path:
    return Path(normalize_path(template, home=home, user=user))
