"""auditd rule management and audit-log persistence detection.

Audit timestamps come from ``msg=audit(SECONDS.FRACTION:SERIAL)``.  The
fraction is preserved as epoch nanoseconds in raw evidence and metadata, but
the alert's contract observation timestamp is the detector wall-clock time
when processing completes.  The fractional digit count determines the real
audit-log precision; a timestamp with no fraction has only one-second
precision.

Rule management is deliberately separate from monitoring.  The install,
status, and remove actions operate only on the project-owned audit key and
never clear the global audit rule set.
"""

from __future__ import annotations

import argparse
import os
import re
import selectors
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, TextIO

try:  # Works as ``detectors.auditd_watch`` and as a direct script.
    from .alert_schema import TECHNIQUE_SLUGS
    from .common import (
        DuplicateEventGrouper,
        GroupedRawEvent,
        make_alert_record,
        now_epoch_ns,
        normalize_path,
        write_jsonl_record,
    )
    from .config_loader import DetectorConfig, load_config, resolve_paths
except ImportError:  # pragma: no cover - direct script execution fallback
    from alert_schema import TECHNIQUE_SLUGS
    from common import DuplicateEventGrouper, GroupedRawEvent, make_alert_record, now_epoch_ns, normalize_path, write_jsonl_record
    from config_loader import DetectorConfig, load_config, resolve_paths


PROJECT_RULE_PREFIX = "persistence_detection_"
DEFAULT_AUDIT_LOG = "/var/log/audit/audit.log"
FOLLOWER_STARTUP_TIMEOUT_SECONDS = 10.0
SERIAL_FALLBACK_TIMEOUT_NS = 1_000_000_000
AUDIT_ID_RE = re.compile(
    r"msg=audit\((?P<seconds>\d+)(?:\.(?P<fraction>\d+))?:(?P<serial>\d+)\)"
)
FIELD_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?:\"(?P<quoted>(?:\\.|[^\"])*)\"|(?P<bare>[^\s]+))"
)


class AuditParseError(ValueError):
    """Raised when an audit-log line lacks the required audit identity."""


class AuditCommandError(RuntimeError):
    """Raised when an audit rule command fails."""


class AuditMonitorError(RuntimeError):
    """Raised when the audit-log follower stops unexpectedly."""


@dataclass(frozen=True)
class AuditRule:
    path: str
    permissions: str
    key: str
    raw_line: str


@dataclass(frozen=True)
class AuditLogRecord:
    record_type: str
    seconds: int
    fraction: str
    serial: int
    epoch_ns: int
    precision_ns: int
    fields: dict[str, str]
    raw_line: str


@dataclass
class AuditSerialGroup:
    seconds: int
    serial: int
    first_record: AuditLogRecord
    records: list[AuditLogRecord] = field(default_factory=list)


@dataclass
class AuditLogProcess:
    process: subprocess.Popen[bytes]
    log_path: str


CommandRunner = Callable[..., Any]


def project_rule_key(technique: str) -> str:
    return f"{PROJECT_RULE_PREFIX}{technique}"


def parse_audit_rule(line: str) -> AuditRule | None:
    """Parse an auditctl list line, ignoring non-watch rules."""

    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    values: dict[str, str] = {}
    for flag, value in zip(tokens, tokens[1:]):
        if flag in {"-w", "-p", "-k"}:
            values[flag] = value
    if not {"-w", "-p", "-k"}.issubset(values):
        return None
    return AuditRule(
        path=normalize_path(values["-w"]),
        permissions=values["-p"],
        key=values["-k"],
        raw_line=line,
    )


def _run_audit_command(command: list[str], runner: CommandRunner = subprocess.run) -> Any:
    try:
        result = runner(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        raise AuditCommandError(f"command failed: {' '.join(command)}: {detail}") from exc
    return result


def list_audit_rules(runner: CommandRunner = subprocess.run) -> list[AuditRule]:
    """List all watch rules returned by auditctl without modifying them."""

    result = _run_audit_command(["auditctl", "-l"], runner)
    rules: list[AuditRule] = []
    for line in (result.stdout or "").splitlines():
        rule = parse_audit_rule(line)
        if rule is not None:
            rules.append(rule)
    return rules


def status_rules(technique: str, runner: CommandRunner = subprocess.run) -> list[AuditRule]:
    """Return only this project's rules for the selected technique."""

    key = project_rule_key(technique)
    return [rule for rule in list_audit_rules(runner) if rule.key == key]


def install_rules(
    config: DetectorConfig,
    technique: str,
    *,
    home: str | os.PathLike[str] | None = None,
    user: str | None = None,
    runner: CommandRunner = subprocess.run,
) -> list[AuditRule]:
    """Install missing project rules without clearing or replacing others."""

    key = project_rule_key(technique)
    entry = config.techniques[technique]
    desired_paths = [normalize_path(str(path)) for path in resolve_paths(config, technique, home=home, user=user)]
    existing = {
        (rule.path, rule.permissions, rule.key)
        for rule in list_audit_rules(runner)
        if rule.key == key
    }
    installed: list[AuditRule] = []
    for path in desired_paths:
        identity = (path, "wa", key)
        if identity in existing:
            continue
        command = ["auditctl", "-w", path, "-p", "wa", "-k", key]
        _run_audit_command(command, runner)
        installed.append(AuditRule(path=path, permissions="wa", key=key, raw_line=""))
    if entry.path_kind not in {"file", "directory"}:  # Defensive config check.
        raise AuditCommandError(f"unsupported configured path kind: {entry.path_kind}")
    return installed


def remove_rules(technique: str, runner: CommandRunner = subprocess.run) -> list[AuditRule]:
    """Remove only existing rules carrying this project's exact key."""

    key = project_rule_key(technique)
    removed: list[AuditRule] = []
    for rule in list_audit_rules(runner):
        if rule.key != key:
            continue
        command = [
            "auditctl",
            "-d",
            "-w",
            rule.path,
            "-p",
            rule.permissions,
            "-k",
            rule.key,
        ]
        _run_audit_command(command, runner)
        removed.append(rule)
    return removed


def _unescape_audit_value(value: str) -> str:
    return value.replace(r'\"', '"').replace(r"\\", "\\")


def _timestamp_parts(seconds: int, fraction: str) -> tuple[int, int]:
    if not fraction:
        return seconds * 1_000_000_000, 1_000_000_000
    precision_ns = 10 ** max(0, 9 - len(fraction))
    fraction_ns = int((fraction + "000000000")[:9])
    return seconds * 1_000_000_000 + fraction_ns, precision_ns


def parse_audit_line(line: str) -> AuditLogRecord:
    raw_line = line.rstrip("\r\n")
    identity = AUDIT_ID_RE.search(raw_line)
    if identity is None:
        raise AuditParseError(f"missing audit timestamp/serial: {raw_line!r}")
    record_type_match = re.search(r"(?:^|\s)type=([^\s]+)", raw_line)
    record_type = record_type_match.group(1) if record_type_match else "UNKNOWN"
    fields: dict[str, str] = {}
    for match in FIELD_RE.finditer(raw_line):
        value = match.group("quoted")
        if value is None:
            value = match.group("bare") or ""
        fields[match.group("key")] = _unescape_audit_value(value)

    seconds = int(identity.group("seconds"))
    fraction = identity.group("fraction") or ""
    epoch_ns, precision_ns = _timestamp_parts(seconds, fraction)
    return AuditLogRecord(
        record_type=record_type,
        seconds=seconds,
        fraction=fraction,
        serial=int(identity.group("serial")),
        epoch_ns=epoch_ns,
        precision_ns=precision_ns,
        fields=fields,
        raw_line=raw_line,
    )


class AuditSerialGrouper:
    """Group consecutive audit records sharing the same seconds and serial."""

    def __init__(self) -> None:
        self._groups: dict[tuple[int, int], AuditSerialGroup] = {}
        self._last_key: tuple[int, int] | None = None

    def add(self, record: AuditLogRecord) -> list[AuditSerialGroup]:
        key = (record.seconds, record.serial)
        closed: list[AuditSerialGroup] = []
        if self._last_key is not None and key != self._last_key:
            previous = self._groups.pop(self._last_key, None)
            if previous is not None:
                closed.append(previous)
        group = self._groups.setdefault(
            key,
            AuditSerialGroup(
                seconds=record.seconds,
                serial=record.serial,
                first_record=record,
            ),
        )
        group.records.append(record)
        if record.record_type.upper() == "EOE":
            closed.append(self._groups.pop(key))
            if self._last_key == key:
                self._last_key = None
        else:
            self._last_key = key
        return closed

    def flush_stale(
        self,
        observation_time_epoch_ns: int,
        *,
        timeout_ns: int = SERIAL_FALLBACK_TIMEOUT_NS,
    ) -> list[AuditSerialGroup]:
        """Close incomplete groups after the bounded no-EOE fallback window."""

        if timeout_ns < 0:
            raise ValueError("timeout_ns must be non-negative")
        closed: list[AuditSerialGroup] = []
        for key, group in list(self._groups.items()):
            last_time = group.records[-1].epoch_ns
            if observation_time_epoch_ns - last_time >= timeout_ns:
                closed.append(self._groups.pop(key))
                if self._last_key == key:
                    self._last_key = None
        return closed

    def flush_all(self) -> list[AuditSerialGroup]:
        groups = list(self._groups.values())
        self._groups.clear()
        self._last_key = None
        return groups


def _first_field(group: AuditSerialGroup, *names: str) -> str | None:
    for record in group.records:
        for name in names:
            value = record.fields.get(name)
            if value and value not in {"?", "(null)"}:
                return value
    return None


def _int_or_string(value: str | None) -> int | str | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return value


def _path_matches(path: str, configured_paths: Iterable[str], path_kind: str) -> bool:
    normalized = normalize_path(path)
    for configured in configured_paths:
        root = normalize_path(configured)
        if path_kind == "file" and normalized == root:
            return True
        if path_kind == "directory":
            try:
                if os.path.commonpath((normalized, root)) == root:
                    return True
            except ValueError:
                pass
    return False


def _group_paths(group: AuditSerialGroup, configured_paths: Iterable[str], path_kind: str) -> list[str]:
    paths: set[str] = set()
    for record in group.records:
        candidate = record.fields.get("name")
        if candidate and candidate not in {"?", "(null)"}:
            normalized = normalize_path(candidate)
            if _path_matches(normalized, configured_paths, path_kind):
                paths.add(normalized)
    return sorted(paths)


def _operation_for_group(group: AuditSerialGroup) -> str:
    nametypes = {record.fields.get("nametype", "").upper() for record in group.records}
    if "CREATE" in nametypes:
        return "create"
    if "DELETE" in nametypes:
        return "delete"
    if "ATTR" in nametypes or "ATTRIBUTE" in nametypes:
        return "metadata"
    permissions = {record.fields.get("perm", "").lower() for record in group.records}
    if any("w" in permission for permission in permissions):
        return "modify"
    if any("a" in permission for permission in permissions):
        return "metadata"
    return "modify"


def _raw_group_event(group: AuditSerialGroup) -> dict[str, Any]:
    return {
        "source": "auditd",
        "audit_seconds": group.seconds,
        "audit_serial": group.serial,
        "audit_fraction": group.first_record.fraction,
        "record_count": len(group.records),
        "records": [
            {
                "type": record.record_type,
                "raw_line": record.raw_line,
                "fields": dict(record.fields),
            }
            for record in group.records
        ],
    }


class AuditAlertEmitter:
    """Group audit serials, apply duplicate grouping, and build alerts."""

    def __init__(
        self,
        *,
        configured_paths: Iterable[str],
        path_kind: str,
        experiment_id: str,
        run_id: str,
        trial: int | None,
        trial_source: str,
        technique: str,
        observation_clock: Callable[[], int] = now_epoch_ns,
    ) -> None:
        self.configured_paths = tuple(normalize_path(path) for path in configured_paths)
        self.path_kind = path_kind
        self.experiment_id = experiment_id
        self.run_id = run_id
        self.trial = trial
        self.trial_source = trial_source
        self.technique = technique
        self.audit_key = project_rule_key(technique)
        self.observation_clock = observation_clock
        self.serial_grouper = AuditSerialGrouper()
        self.duplicate_grouper = DuplicateEventGrouper()

    def _records_from_duplicate_groups(self, groups: Iterable[GroupedRawEvent]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for group in groups:
            audit_events = group.raw_events
            serials = [event.get("audit_serial") for event in audit_events]
            first_event = audit_events[0]
            detector_observation_time_epoch_ns = self.observation_clock()
            timestamp_precisions = [
                event.get("audit_timestamp_precision_ns") for event in audit_events
            ]
            audit_timestamps = [event.get("audit_time_epoch_ns") for event in audit_events]
            records.append(
                make_alert_record(
                    detector="auditd",
                    experiment_id=group.experiment_id,
                    run_id=group.run_id,
                    trial=group.trial,
                    trial_source=group.trial_source,
                    technique=group.technique,
                    paths=group.paths,
                    operation=group.operation,
                    raw_events=audit_events,
                    alert_group_id=group.alert_group_id,
                    observation_time_epoch_ns=detector_observation_time_epoch_ns,
                    metadata={
                        "audit_serials": serials,
                        "audit_timestamp_source": "audit_log_msg_audit",
                        "audit_timestamp_epoch_ns": first_event.get("audit_time_epoch_ns"),
                        "audit_timestamps_epoch_ns": audit_timestamps,
                        "audit_timestamp_precision_ns": first_event.get(
                            "audit_timestamp_precision_ns"
                        ),
                        "audit_timestamp_precisions_ns": timestamp_precisions,
                        "pid": first_event.get("pid"),
                        "uid": first_event.get("uid"),
                        "executable": first_event.get("executable"),
                        "operation_details": first_event.get("operation_details", {}),
                        "last_observation_time_epoch_ns": group.last_observation_time_epoch_ns,
                        "operation_group": group.operation_group,
                    },
                )
            )
        return records

    def _consume_serial_group(
        self,
        group: AuditSerialGroup,
        *,
        observation_time_epoch_ns: int | None = None,
    ) -> list[dict[str, Any]]:
        if not any(record.fields.get("key") == self.audit_key for record in group.records):
            return []
        paths = _group_paths(group, self.configured_paths, self.path_kind)
        if not paths:
            return []
        if observation_time_epoch_ns is None:
            observation_time_epoch_ns = self.observation_clock()
        raw_event = _raw_group_event(group)
        raw_event.update(
            {
                "paths": paths,
                "operation": _operation_for_group(group),
                "audit_time_epoch_ns": group.first_record.epoch_ns,
                "audit_timestamp_precision_ns": group.first_record.precision_ns,
                "pid": _int_or_string(_first_field(group, "pid")),
                "uid": _int_or_string(_first_field(group, "uid", "auid")),
                "executable": _first_field(group, "exe", "comm"),
                "operation_details": {
                    field: value
                    for field in (
                        "syscall",
                        "success",
                        "exit",
                        "perm",
                        "nametype",
                        "key",
                    )
                    if (value := _first_field(group, field)) is not None
                },
            }
        )
        closed = self.duplicate_grouper.add(
            detector="auditd",
            experiment_id=self.experiment_id,
            run_id=self.run_id,
            trial=self.trial,
            trial_source=self.trial_source,
            technique=self.technique,
            paths=paths,
            operation=raw_event["operation"],
            observation_time_epoch_ns=observation_time_epoch_ns,
            raw_event=raw_event,
        )
        return self._records_from_duplicate_groups(closed)

    def flush_expired(self, observation_time_epoch_ns: int) -> list[dict[str, Any]]:
        """Flush no-EOE serial groups and 250 ms duplicate groups by time."""

        records: list[dict[str, Any]] = []
        for group in self.serial_grouper.flush_stale(observation_time_epoch_ns):
            records.extend(
                self._consume_serial_group(
                    group,
                    observation_time_epoch_ns=observation_time_epoch_ns,
                )
            )
        records.extend(
            self._records_from_duplicate_groups(
                self.duplicate_grouper.flush(
                    observation_time_epoch_ns=observation_time_epoch_ns
                )
            )
        )
        return records

    def consume_line(self, line: str) -> list[dict[str, Any]]:
        record = parse_audit_line(line)
        detector_observation_time_epoch_ns = self.observation_clock()
        records = [
            alert
            for group in self.serial_grouper.add(record)
            for alert in self._consume_serial_group(
                group,
                observation_time_epoch_ns=detector_observation_time_epoch_ns,
            )
        ]
        records.extend(self.flush_expired(detector_observation_time_epoch_ns))
        return records

    def flush_all(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for group in self.serial_grouper.flush_all():
            records.extend(self._consume_serial_group(group))
        records.extend(self._records_from_duplicate_groups(self.duplicate_grouper.flush_all()))
        return records


class AuditByteLineBuffer:
    """Explicit byte buffer for the tail subprocess stream."""

    def __init__(self) -> None:
        self.buffers: dict[Any, bytearray] = {}

    def read_available(self, stream: Any) -> tuple[list[str], bool]:
        buffer = self.buffers.setdefault(stream, bytearray())
        chunk = os.read(stream.fileno(), 64 * 1024)
        eof = not chunk
        if chunk:
            buffer.extend(chunk)
        lines: list[str] = []
        while b"\n" in buffer:
            raw, _, remainder = buffer.partition(b"\n")
            buffer = bytearray(remainder)
            lines.append(raw.rstrip(b"\r").decode("utf-8", "replace"))
        if eof:
            if buffer:
                lines.append(bytes(buffer).rstrip(b"\r").decode("utf-8", "replace"))
            self.buffers.pop(stream, None)
        else:
            self.buffers[stream] = buffer
        return lines, eof


def _start_log_follower(log_path: str) -> AuditLogProcess:
    try:
        process = subprocess.Popen(
            ["tail", "-F", "-n", "0", "--", log_path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
        )
    except OSError as exc:
        raise AuditMonitorError(f"could not follow audit log {log_path}: {exc}") from exc
    return AuditLogProcess(process=process, log_path=log_path)


def _stop_log_follower(follower: AuditLogProcess) -> None:
    if follower.process.poll() is None:
        follower.process.terminate()
    try:
        follower.process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        follower.process.kill()
        follower.process.wait(timeout=1.0)
    for stream in (follower.process.stdout, follower.process.stderr):
        if stream is not None:
            stream.close()


def _follower_has_opened_log(follower: AuditLogProcess) -> bool:
    """Check that the live follower has an open descriptor for the log."""

    if follower.process.poll() is not None:
        return False
    try:
        if not os.path.isfile(follower.log_path) or not os.access(follower.log_path, os.R_OK):
            return False
    except OSError:
        return False

    proc_fds = Path(f"/proc/{follower.process.pid}/fd")
    if not proc_fds.is_dir():
        # Non-Linux development hosts do not expose /proc.  The live process
        # plus a readable log is the strongest portable readiness check.
        return True
    try:
        for fd_path in proc_fds.iterdir():
            try:
                if os.path.samefile(fd_path, follower.log_path):
                    return True
            except (FileNotFoundError, OSError):
                continue
    except OSError:
        return False
    return False


def wait_for_log_follower_ready(
    follower: AuditLogProcess,
    *,
    timeout_seconds: float = FOLLOWER_STARTUP_TIMEOUT_SECONDS,
    ready_probe: Callable[[AuditLogProcess], bool] = _follower_has_opened_log,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Wait until tail is live and has opened the requested log file."""

    if timeout_seconds <= 0:
        raise AuditMonitorError("audit-log follower readiness timeout must be positive")
    deadline = clock() + timeout_seconds
    while True:
        return_code = follower.process.poll()
        if return_code is not None:
            raise AuditMonitorError(
                "audit-log follower exited before readiness "
                f"with status {return_code}"
            )
        if ready_probe(follower):
            return
        remaining = deadline - clock()
        if remaining <= 0:
            raise AuditMonitorError(
                "audit-log follower readiness timed out after "
                f"{timeout_seconds:g} seconds"
            )
        sleep(min(0.05, remaining))


def monitor_log(
    *,
    config: DetectorConfig,
    technique: str,
    experiment_id: str,
    run_id: str,
    trial: int | None,
    home: str | os.PathLike[str] | None,
    user: str | None,
    output: TextIO,
    log_path: str = DEFAULT_AUDIT_LOG,
    diagnostics: TextIO = sys.stderr,
) -> None:
    entry = config.techniques[technique]
    paths = resolve_paths(config, technique, home=home, user=user)
    emitter = AuditAlertEmitter(
        configured_paths=[str(path) for path in paths],
        path_kind=entry.path_kind,
        experiment_id=experiment_id,
        run_id=run_id,
        trial=trial,
        trial_source="detector_cli" if trial is not None else "unassigned",
        technique=technique,
    )
    follower = _start_log_follower(log_path)
    selector = selectors.DefaultSelector()
    line_buffer = AuditByteLineBuffer()

    def write_records(records: Iterable[Mapping[str, Any]]) -> None:
        for record in records:
            write_jsonl_record(output, record)
        output.flush()

    try:
        if follower.process.stdout is None or follower.process.stderr is None:
            raise AuditMonitorError("audit-log follower did not provide pipes")
        wait_for_log_follower_ready(follower)
        selector.register(follower.process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(follower.process.stderr, selectors.EVENT_READ, "stderr")
        print(f"[auditd] ready: monitoring {log_path} for run_id={run_id}", file=diagnostics)
        while True:
            for key, _ in selector.select(timeout=0.1):
                lines, eof = line_buffer.read_available(key.fileobj)
                for line in lines:
                    if key.data == "stderr":
                        print(f"[tail] {line}", file=diagnostics)
                        continue
                    try:
                        write_records(emitter.consume_line(line))
                    except AuditParseError as exc:
                        print(f"[auditd] ignored malformed line: {exc}", file=diagnostics)
                if eof:
                    selector.unregister(key.fileobj)
            write_records(emitter.flush_expired(now_epoch_ns()))
            return_code = follower.process.poll()
            if return_code is not None:
                raise AuditMonitorError(
                    f"audit log follower exited with status {return_code}"
                )
    except KeyboardInterrupt:
        print("[auditd] stopping", file=diagnostics)
    finally:
        write_records(emitter.flush_all())
        selector.close()
        _stop_log_follower(follower)


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--technique", required=True, choices=TECHNIQUE_SLUGS)
    parser.add_argument("--config", default=str(Path(__file__).with_name("config.json")))
    parser.add_argument("--home", default=None)
    parser.add_argument("--user", default=None)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    for action in ("install", "status", "remove"):
        command = subparsers.add_parser(action)
        _add_config_args(command)

    monitor = subparsers.add_parser("monitor")
    monitor.add_argument("--experiment-id", required=True)
    monitor.add_argument("--run-id", required=True)
    monitor.add_argument("--trial", type=_non_negative_int, default=None)
    _add_config_args(monitor)
    monitor.add_argument("--output", required=True, help="JSONL output path, or - for stdout")
    monitor.add_argument("--log-file", default=DEFAULT_AUDIT_LOG)
    return parser


def _open_output(path: str) -> tuple[TextIO, bool]:
    if path == "-":
        return sys.stdout, False
    return open(path, "a", encoding="utf-8"), True


def main(argv: list[str] | None = None, *, runner: CommandRunner = subprocess.run) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.action == "install":
            installed = install_rules(
                config, args.technique, home=args.home, user=args.user, runner=runner
            )
            print(f"installed {len(installed)} project audit rule(s)")
            return 0
        if args.action == "status":
            for rule in status_rules(args.technique, runner):
                print(rule.raw_line)
            return 0
        if args.action == "remove":
            removed = remove_rules(args.technique, runner)
            print(f"removed {len(removed)} project audit rule(s)")
            return 0

        if args.trial is not None and args.trial < 0:
            raise AuditMonitorError("--trial must be non-negative")
        output, should_close = _open_output(args.output)
        try:
            monitor_log(
                config=config,
                technique=args.technique,
                experiment_id=args.experiment_id,
                run_id=args.run_id,
                trial=args.trial,
                home=args.home,
                user=args.user,
                output=output,
                log_path=args.log_file,
            )
        finally:
            if should_close:
                output.close()
    except (AuditCommandError, AuditMonitorError) as exc:
        print(f"[auditd] error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
