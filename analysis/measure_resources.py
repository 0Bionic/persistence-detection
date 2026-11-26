"""Measure detector resource use from a supplied set of process IDs.

Experiment C in the proposal measures each detector during idle and active
phases.  This module records structured ``/proc`` measurements only.  Capture
raw ``pidstat`` output separately when running in the Ubuntu VM; see
``analysis/RESOURCE_MEASUREMENTS.md`` for the cross-check procedure.

The sampler keeps one row per requested PID per sample.  CPU is calculated
from the change in ``utime + stime`` jiffies, resident memory comes from
``VmRSS``, and read/write I/O are deltas of ``read_bytes`` and ``write_bytes``
from ``/proc/<pid>/io``.  Missing or inaccessible values remain blank in CSV
and are explained in the error column; they are never converted to zero.
"""

from __future__ import annotations

import argparse
import csv
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, TextIO


DETECTORS = ("baseline_diff", "inotify", "auditd")
PHASES = ("idle", "active")
CSV_FIELDS = (
    "experiment_id",
    "run_id",
    "trial",
    "detector",
    "phase",
    "pid",
    "sample_source",
    "sample_time_epoch_ns",
    "sample_time_utc",
    "sample_status",
    "cpu_percent",
    "cpu_time_jiffies",
    "resident_memory_kb",
    "read_bytes_delta",
    "write_bytes_delta",
    "error",
)


class ResourceMeasurementError(RuntimeError):
    """Raised for invalid measurement configuration or output failures."""


def epoch_ns_to_utc(epoch_ns: int) -> str:
    """Format epoch nanoseconds as an ISO-8601 UTC value."""

    seconds, nanoseconds = divmod(epoch_ns, 1_000_000_000)
    timestamp = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return timestamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{nanoseconds:09d}Z"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except PermissionError as exc:
        raise ResourceMeasurementError(f"permission denied reading {path}") from exc
    except FileNotFoundError as exc:
        raise ResourceMeasurementError(f"{path} disappeared while sampling") from exc
    except OSError as exc:
        raise ResourceMeasurementError(f"could not read {path}: {exc}") from exc


def _parse_stat_cpu_and_start_time(stat_text: str, *, pid: int) -> tuple[int, int]:
    closing_paren = stat_text.rfind(")")
    if closing_paren < 0:
        raise ResourceMeasurementError(f"malformed /proc/{pid}/stat: missing comm terminator")
    fields_after_comm = stat_text[closing_paren + 2 :].split()
    # The first item is field 3 (state). Fields 14 and 15 are indexes 11 and
    # 12; field 22 (starttime) is index 19 after the process name.
    if len(fields_after_comm) <= 19:
        raise ResourceMeasurementError(
            f"malformed /proc/{pid}/stat: missing CPU or start-time fields"
        )
    try:
        cpu_time_jiffies = int(fields_after_comm[11]) + int(fields_after_comm[12])
        start_time_ticks = int(fields_after_comm[19])
        return cpu_time_jiffies, start_time_ticks
    except ValueError as exc:
        raise ResourceMeasurementError(
            f"malformed /proc/{pid}/stat: non-numeric CPU or start-time fields"
        ) from exc


def _parse_rss_kb(status_text: str, *, pid: int) -> int:
    for line in status_text.splitlines():
        name, separator, value = line.partition(":")
        if name == "VmRSS":
            parts = value.split()
            if len(parts) >= 2 and parts[1] == "kB":
                try:
                    return int(parts[0])
                except ValueError as exc:
                    break
    raise ResourceMeasurementError(f"malformed /proc/{pid}/status: VmRSS unavailable")


def _parse_io_counters(io_text: str, *, pid: int) -> tuple[int, int]:
    counters: dict[str, int] = {}
    for line in io_text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in {"read_bytes", "write_bytes"}:
            try:
                counters[name] = int(value.strip())
            except ValueError as exc:
                raise ResourceMeasurementError(
                    f"malformed /proc/{pid}/io: non-numeric {name}"
                ) from exc
    missing = {"read_bytes", "write_bytes"}.difference(counters)
    if missing:
        raise ResourceMeasurementError(
            f"/proc/{pid}/io missing counters: {', '.join(sorted(missing))}"
        )
    return counters["read_bytes"], counters["write_bytes"]


@dataclass(frozen=True)
class ProcSnapshot:
    pid: int
    start_time_ticks: int | None
    cpu_time_jiffies: int | None
    resident_memory_kb: int | None
    read_bytes: int | None
    write_bytes: int | None
    status: str
    error: str | None = None


def read_proc_snapshot(pid: int, *, proc_root: str | os.PathLike[str] = "/proc") -> ProcSnapshot:
    """Read one PID without turning unavailable values into zeroes."""

    pid_dir = Path(proc_root) / str(pid)
    stat_path = pid_dir / "stat"
    if not pid_dir.exists():
        return ProcSnapshot(
            pid=pid,
            start_time_ticks=None,
            cpu_time_jiffies=None,
            resident_memory_kb=None,
            read_bytes=None,
            write_bytes=None,
            status="exited",
            error=f"process {pid} is no longer present",
        )

    errors: list[str] = []
    try:
        cpu_time_jiffies, start_time_ticks = _parse_stat_cpu_and_start_time(
            _read_text(stat_path), pid=pid
        )
    except ResourceMeasurementError as exc:
        start_time_ticks = None
        cpu_time_jiffies = None
        errors.append(str(exc))

    try:
        resident_memory_kb = _parse_rss_kb(_read_text(pid_dir / "status"), pid=pid)
    except ResourceMeasurementError as exc:
        resident_memory_kb = None
        errors.append(str(exc))

    try:
        read_bytes, write_bytes = _parse_io_counters(_read_text(pid_dir / "io"), pid=pid)
    except ResourceMeasurementError as exc:
        read_bytes = None
        write_bytes = None
        errors.append(str(exc))

    if not errors:
        status = "ok"
        error = None
    elif any("permission denied" in error for error in errors):
        status = "permission_error"
        error = "; ".join(errors)
    else:
        status = "inaccessible"
        error = "; ".join(errors)
    return ProcSnapshot(
        pid=pid,
        start_time_ticks=start_time_ticks,
        cpu_time_jiffies=cpu_time_jiffies,
        resident_memory_kb=resident_memory_kb,
        read_bytes=read_bytes,
        write_bytes=write_bytes,
        status=status,
        error=error,
    )


class ProcResourceSampler:
    """Sample a fixed PID set, retaining state for interval deltas."""

    def __init__(
        self,
        pids: Iterable[int],
        *,
        proc_root: str | os.PathLike[str] = "/proc",
        ticks_per_second: int | None = None,
        epoch_clock: Callable[[], int] = time.time_ns,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        normalized = tuple(dict.fromkeys(int(pid) for pid in pids))
        if not normalized or any(pid <= 0 for pid in normalized):
            raise ResourceMeasurementError("at least one positive PID is required")
        self.pids = normalized
        self.proc_root = proc_root
        self.ticks_per_second = ticks_per_second or int(os.sysconf(os.sysconf_names["SC_CLK_TCK"]))
        if self.ticks_per_second <= 0:
            raise ResourceMeasurementError("system clock tick rate must be positive")
        self.epoch_clock = epoch_clock
        self.monotonic_clock = monotonic_clock
        self._previous: dict[int, ProcSnapshot] = {}
        self._previous_monotonic: float | None = None

    def sample_once(
        self,
        *,
        sample_time_epoch_ns: int | None = None,
        monotonic_time: float | None = None,
    ) -> list[dict[str, object]]:
        """Return one row for every requested PID."""

        sample_time = self.epoch_clock() if sample_time_epoch_ns is None else sample_time_epoch_ns
        current_monotonic = (
            self.monotonic_clock() if monotonic_time is None else monotonic_time
        )
        elapsed = None
        if self._previous_monotonic is not None:
            elapsed = current_monotonic - self._previous_monotonic
        self._previous_monotonic = current_monotonic

        rows: list[dict[str, object]] = []
        for pid in self.pids:
            snapshot = read_proc_snapshot(pid, proc_root=self.proc_root)
            previous = self._previous.get(pid)
            row: dict[str, object] = {
                "pid": pid,
                "sample_source": "proc",
                "sample_time_epoch_ns": sample_time,
                "sample_time_utc": epoch_ns_to_utc(sample_time),
                "sample_status": snapshot.status,
                "cpu_percent": None,
                "cpu_time_jiffies": snapshot.cpu_time_jiffies,
                "resident_memory_kb": snapshot.resident_memory_kb,
                "read_bytes_delta": None,
                "write_bytes_delta": None,
                "error": snapshot.error,
            }

            errors = [snapshot.error] if snapshot.error else []
            same_process = (
                previous is not None
                and previous.start_time_ticks is not None
                and snapshot.start_time_ticks is not None
                and previous.start_time_ticks == snapshot.start_time_ticks
            )
            process_replaced = (
                previous is not None
                and previous.start_time_ticks is not None
                and snapshot.start_time_ticks is not None
                and previous.start_time_ticks != snapshot.start_time_ticks
            )
            if process_replaced:
                row["sample_status"] = "new_process_baseline"
                errors.append(
                    f"PID {pid} start time changed from "
                    f"{previous.start_time_ticks} to {snapshot.start_time_ticks}; "
                    "new process baseline, CPU and I/O deltas omitted"
                )
            elif previous is not None and not same_process:
                errors.append(
                    "process start time unavailable; CPU and I/O deltas omitted"
                )
            elif (
                same_process
                and elapsed is not None
                and elapsed > 0
                and snapshot.cpu_time_jiffies is not None
                and previous.cpu_time_jiffies is not None
            ):
                cpu_delta = snapshot.cpu_time_jiffies - previous.cpu_time_jiffies
                if cpu_delta >= 0:
                    row["cpu_percent"] = (
                        cpu_delta / self.ticks_per_second / elapsed * 100.0
                    )
                else:
                    errors.append("CPU counter decreased; CPU percentage omitted")
            elif same_process and elapsed is not None and elapsed <= 0:
                errors.append("non-positive sample interval; CPU percentage omitted")

            if same_process:
                for field_name, output_name in (
                    ("read_bytes", "read_bytes_delta"),
                    ("write_bytes", "write_bytes_delta"),
                ):
                    current_value = getattr(snapshot, field_name)
                    previous_value = getattr(previous, field_name)
                    if current_value is None or previous_value is None:
                        errors.append(f"{field_name} unavailable; delta omitted")
                    elif current_value >= previous_value:
                        row[output_name] = current_value - previous_value
                    else:
                        errors.append(f"{field_name} counter decreased; delta omitted")
            elif previous is None:
                errors.append("baseline sample; interval deltas unavailable")

            if errors:
                row["error"] = "; ".join(dict.fromkeys(error for error in errors if error))
            self._previous[pid] = snapshot
            rows.append(row)
        return rows

    def run(self, *, interval_seconds: float, duration_seconds: float) -> Iterable[dict[str, object]]:
        """Yield samples until the requested duration has elapsed."""

        if interval_seconds <= 0:
            raise ResourceMeasurementError("sampling interval must be positive")
        if duration_seconds < 0:
            raise ResourceMeasurementError("duration must be non-negative")
        started = self.monotonic_clock()
        while True:
            yield from self.sample_once()
            elapsed = self.monotonic_clock() - started
            if elapsed >= duration_seconds:
                break
            time.sleep(min(interval_seconds, duration_seconds - elapsed))


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _write_rows(
    output: TextIO,
    rows: Iterable[dict[str, object]],
    *,
    experiment_id: str,
    run_id: str,
    trial: int,
    detector: str,
    phase: str,
) -> None:
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        record = {
            "experiment_id": experiment_id,
            "run_id": run_id,
            "trial": trial,
            "detector": detector,
            "phase": phase,
            **row,
        }
        writer.writerow(record)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--trial", type=_non_negative_int, required=True)
    parser.add_argument("--detector", choices=DETECTORS, required=True)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument(
        "--pid",
        "--pids",
        dest="pid_groups",
        action="append",
        nargs="+",
        type=_positive_int,
        required=True,
        help="one or more detector/child PIDs; repeat --pid for another group",
    )
    parser.add_argument("--interval", type=float, required=True, help="seconds between samples")
    parser.add_argument("--duration", type=float, required=True, help="total sampling duration")
    parser.add_argument("--output", required=True, help="CSV output path")
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    pids = [pid for group in args.pid_groups for pid in group]
    try:
        sampler = ProcResourceSampler(pids, proc_root=args.proc_root)
        rows = sampler.run(
            interval_seconds=args.interval,
            duration_seconds=args.duration,
        )
        with open(args.output, "w", newline="", encoding="utf-8") as output:
            _write_rows(
                output,
                rows,
                experiment_id=args.experiment_id,
                run_id=args.run_id,
                trial=args.trial,
                detector=args.detector,
                phase=args.phase,
            )
    except (OSError, ResourceMeasurementError) as exc:
        print(f"[resources] error: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
