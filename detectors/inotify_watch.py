"""inotify-based persistence detector using the shared JSONL contract."""

from __future__ import annotations

import argparse
import os
import selectors
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, TextIO

try:  # Works as ``detectors.inotify_watch`` and as a direct script.
    from .alert_schema import TECHNIQUE_SLUGS
    from .common import (
        DuplicateEventGrouper,
        GroupedRawEvent,
        make_alert_record,
        normalize_path,
        now_epoch_ns,
        write_jsonl_record,
    )
    from .config_loader import DetectorConfig, load_config, resolve_paths
except ImportError:  # pragma: no cover - direct script execution fallback
    from alert_schema import TECHNIQUE_SLUGS
    from common import DuplicateEventGrouper, GroupedRawEvent, make_alert_record, normalize_path, now_epoch_ns, write_jsonl_record
    from config_loader import DetectorConfig, load_config, resolve_paths


class InotifyParseError(ValueError):
    """Raised when an inotifywait line cannot be parsed."""


class WatchSetupError(RuntimeError):
    """Raised when a configured watch cannot be prepared."""


class WatchRuntimeError(RuntimeError):
    """Raised when an inotifywait subprocess exits unexpectedly."""


class WatchStartupError(WatchRuntimeError):
    """Raised when watcher readiness cannot be established."""


STARTUP_TIMEOUT_SECONDS = 10.0
WATCH_READY_MARKER = "watches established."


@dataclass(frozen=True)
class WatchSpec:
    configured_path: str
    watch_root: str
    path_kind: str
    recursive: bool


@dataclass(frozen=True)
class InotifyEvent:
    path: str
    event_names: tuple[str, ...]
    raw_line: str


@dataclass
class WatchProcess:
    spec: WatchSpec
    process: subprocess.Popen[str]


class SelectorLineBuffer:
    """Decode complete newline-delimited lines without hidden text buffering."""

    def __init__(self) -> None:
        self._buffers: dict[Any, bytearray] = {}

    def read_available(self, stream: Any) -> tuple[list[str], bool]:
        """Read one selector-ready byte chunk and return lines plus EOF state."""

        buffer = self._buffers.setdefault(stream, bytearray())
        try:
            chunk = os.read(stream.fileno(), 64 * 1024)
        except BlockingIOError:
            return [], False

        eof = not chunk
        if chunk:
            buffer.extend(chunk)

        lines: list[str] = []
        while b"\n" in buffer:
            raw_line, _, remainder = buffer.partition(b"\n")
            buffer = bytearray(remainder)
            lines.append(raw_line.rstrip(b"\r").decode("utf-8", "replace"))

        if eof:
            if buffer:
                lines.append(bytes(buffer).rstrip(b"\r").decode("utf-8", "replace"))
            self._buffers.pop(stream, None)
        else:
            self._buffers[stream] = buffer
        return lines, eof


def parse_inotify_line(line: str) -> InotifyEvent:
    """Parse the configured ``path<TAB>events`` inotifywait format."""

    raw_line = line.rstrip("\r\n")
    if not raw_line:
        raise InotifyParseError("empty inotify event line")
    if "\t" not in raw_line:
        raise InotifyParseError(f"missing event delimiter in line: {raw_line!r}")
    raw_path, raw_events = raw_line.split("\t", 1)
    if not raw_path.strip() or not raw_events.strip():
        raise InotifyParseError(f"missing path or event names in line: {raw_line!r}")
    path = normalize_path(raw_path)
    event_names = tuple(
        name.strip().upper() for name in raw_events.split(",") if name.strip()
    )
    if not event_names:
        raise InotifyParseError(f"missing path or event names in line: {raw_line!r}")
    return InotifyEvent(path=path, event_names=event_names, raw_line=raw_line)


def operation_for_events(event_names: Iterable[str]) -> str | None:
    """Map inotify names to the contract's four filesystem operations."""

    names = {name.upper() for name in event_names}
    if names.intersection({"DELETE", "MOVED_FROM", "DELETE_SELF"}):
        return "delete"
    if names.intersection({"CREATE", "MOVED_TO"}):
        return "create"
    if names.intersection({"MODIFY", "CLOSE_WRITE"}):
        return "modify"
    if "ATTRIB" in names:
        return "metadata"
    # OPEN, ACCESS, CLOSE_NOWRITE, and similar read-only events are ignored.
    return None


def prepare_watch_specs(
    config: DetectorConfig,
    technique: str,
    *,
    home: str | os.PathLike[str] | None = None,
    user: str | None = None,
) -> tuple[WatchSpec, ...]:
    """Resolve and validate only the selected technique's watch paths."""

    entry = config.techniques[technique]
    specs: list[WatchSpec] = []
    for configured in resolve_paths(config, technique, home=home, user=user):
        configured_path = normalize_path(str(configured))
        if entry.path_kind == "file":
            parent = os.path.dirname(configured_path)
            if not os.path.isdir(parent):
                raise WatchSetupError(
                    f"cannot watch file {configured_path}: parent directory is missing or unavailable: {parent}"
                )
            if os.path.lexists(configured_path) and not os.path.isfile(configured_path):
                raise WatchSetupError(f"configured file path is not a file: {configured_path}")
            specs.append(
                WatchSpec(
                    configured_path=configured_path,
                    watch_root=parent,
                    path_kind="file",
                    recursive=False,
                )
            )
        elif entry.path_kind == "directory":
            if not os.path.isdir(configured_path):
                raise WatchSetupError(
                    f"cannot watch directory {configured_path}: directory is missing or unavailable"
                )
            specs.append(
                WatchSpec(
                    configured_path=configured_path,
                    watch_root=configured_path,
                    path_kind="directory",
                    recursive=True,
                )
            )
        else:  # Defensive check; config_loader already validates this.
            raise WatchSetupError(f"unsupported configured path kind: {entry.path_kind}")
    return tuple(specs)


def matching_watch_specs(path: str, specs: Iterable[WatchSpec]) -> tuple[WatchSpec, ...]:
    """Return specs whose configured file or directory contains ``path``."""

    normalized = normalize_path(path)
    matches: list[WatchSpec] = []
    for spec in specs:
        if spec.path_kind == "file":
            if normalized == spec.configured_path:
                matches.append(spec)
        else:
            try:
                if os.path.commonpath((normalized, spec.configured_path)) == spec.configured_path:
                    matches.append(spec)
            except ValueError:
                continue
    return tuple(matches)


def _records_from_groups(groups: Iterable[GroupedRawEvent]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for group in groups:
        records.append(
            make_alert_record(
                detector="inotify",
                experiment_id=group.experiment_id,
                run_id=group.run_id,
                trial=group.trial,
                trial_source=group.trial_source,
                technique=group.technique,
                paths=group.paths,
                operation=group.operation,
                raw_events=group.raw_events,
                alert_group_id=group.alert_group_id,
                # The contract timestamp is when the first grouped event was read.
                observation_time_epoch_ns=group.first_observation_time_epoch_ns,
                metadata={
                    "raw_event_count": len(group.raw_events),
                    "last_observation_time_epoch_ns": group.last_observation_time_epoch_ns,
                    "operation_group": group.operation_group,
                },
            )
        )
    return records


class InotifyAlertEmitter:
    """Parse, filter, group, and build contract alerts from inotify events."""

    def __init__(
        self,
        *,
        specs: Iterable[WatchSpec],
        experiment_id: str,
        run_id: str,
        trial: int | None,
        trial_source: str,
        technique: str,
    ) -> None:
        self.specs = tuple(specs)
        self.experiment_id = experiment_id
        self.run_id = run_id
        self.trial = trial
        self.trial_source = trial_source
        self.technique = technique
        self.grouper = DuplicateEventGrouper()

    def consume_line(
        self, line: str, *, observation_time_epoch_ns: int
    ) -> list[dict[str, Any]]:
        event = parse_inotify_line(line)
        return self.consume_event(event, observation_time_epoch_ns=observation_time_epoch_ns)

    def consume_event(
        self, event: InotifyEvent, *, observation_time_epoch_ns: int
    ) -> list[dict[str, Any]]:
        matches = matching_watch_specs(event.path, self.specs)
        operation = operation_for_events(event.event_names)
        if not matches or operation is None:
            return []

        closed = self.grouper.add(
            detector="inotify",
            experiment_id=self.experiment_id,
            run_id=self.run_id,
            trial=self.trial,
            trial_source=self.trial_source,
            technique=self.technique,
            paths=[event.path],
            operation=operation,
            observation_time_epoch_ns=observation_time_epoch_ns,
            raw_event={
                "source": "inotifywait",
                "raw_line": event.raw_line,
                "path": event.path,
                "event_names": list(event.event_names),
                "operation": operation,
                "matched_watch_roots": [spec.watch_root for spec in matches],
            },
        )
        return _records_from_groups(closed)

    def flush(self, *, observation_time_epoch_ns: int | None = None) -> list[dict[str, Any]]:
        return _records_from_groups(
            self.grouper.flush(observation_time_epoch_ns=observation_time_epoch_ns)
        )

    def flush_all(self) -> list[dict[str, Any]]:
        return _records_from_groups(self.grouper.flush_all())


def _command_for_spec(spec: WatchSpec) -> list[str]:
    command = [
        "inotifywait",
        "--monitor",
        "--format",
        "%w%f\t%e",
    ]
    if spec.recursive:
        command.append("--recursive")
    command.append(spec.watch_root)
    return command


def _is_ready_line(line: str) -> bool:
    return WATCH_READY_MARKER in line.strip().casefold()


def wait_for_watchers_ready(
    watchers: Iterable[WatchProcess],
    *,
    timeout_seconds: float = STARTUP_TIMEOUT_SECONDS,
    diagnostics: TextIO = sys.stderr,
    selector_factory: Any = selectors.DefaultSelector,
    clock: Any = time.monotonic,
    line_reader: SelectorLineBuffer | None = None,
) -> list[tuple[WatchProcess, str, int]]:
    """Wait until every subprocess confirms that its watches are established.

    Any stdout event lines read before readiness are buffered with their read
    timestamps so the main loop cannot lose an early event.
    """

    watchers = list(watchers)
    if timeout_seconds <= 0:
        raise WatchStartupError("inotify readiness timeout must be positive")
    if not watchers:
        raise WatchStartupError("no inotifywait subprocesses were started")

    selector = selector_factory()
    line_reader = line_reader or SelectorLineBuffer()
    ready: set[int] = set()
    buffered: list[tuple[WatchProcess, str, int]] = []
    deadline = clock() + timeout_seconds
    try:
        for watcher in watchers:
            if watcher.process.stdout is not None:
                selector.register(watcher.process.stdout, selectors.EVENT_READ, ("stdout", watcher))
            if watcher.process.stderr is not None:
                selector.register(watcher.process.stderr, selectors.EVENT_READ, ("stderr", watcher))

        while len(ready) < len(watchers):
            for watcher in watchers:
                return_code = watcher.process.poll()
                if return_code is not None:
                    raise WatchStartupError(
                        f"inotifywait for {watcher.spec.watch_root} exited before readiness "
                        f"with status {return_code}"
                    )

            remaining = deadline - clock()
            if remaining <= 0:
                pending = [
                    watcher.spec.watch_root
                    for watcher in watchers
                    if id(watcher) not in ready
                ]
                raise WatchStartupError(
                    f"inotify readiness timed out after {timeout_seconds:.1f}s; "
                    f"pending watches: {', '.join(pending)}"
                )

            selected = selector.select(remaining)
            if not selected:
                continue
            for key, _ in selected:
                stream_kind, watcher = key.data
                lines, eof = line_reader.read_available(key.fileobj)
                for line in lines:
                    if _is_ready_line(line):
                        ready.add(id(watcher))
                        continue
                    if stream_kind == "stderr":
                        print(f"[inotifywait] {line.rstrip()}", file=diagnostics)
                    else:
                        buffered.append((watcher, line, now_epoch_ns()))
                if eof:
                    try:
                        selector.unregister(key.fileobj)
                    except (KeyError, ValueError):
                        pass

        for watcher in watchers:
            return_code = watcher.process.poll()
            if return_code is not None:
                raise WatchStartupError(
                    f"inotifywait for {watcher.spec.watch_root} exited during readiness "
                    f"with status {return_code}"
                )
        return buffered
    finally:
        selector.close()


def _start_watchers(specs: Iterable[WatchSpec]) -> list[WatchProcess]:
    watchers: list[WatchProcess] = []
    try:
        for spec in specs:
            process = subprocess.Popen(
                _command_for_spec(spec),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,
            )
            watchers.append(WatchProcess(spec=spec, process=process))
    except OSError as exc:
        _stop_watchers(watchers)
        raise WatchSetupError(f"could not start inotifywait: {exc}") from exc
    return watchers


def _stop_watchers(watchers: Iterable[WatchProcess]) -> None:
    watchers = list(watchers)
    for watcher in watchers:
        if watcher.process.poll() is None:
            watcher.process.terminate()
    for watcher in watchers:
        try:
            watcher.process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            watcher.process.kill()
            watcher.process.wait(timeout=1.0)
        for stream in (watcher.process.stdout, watcher.process.stderr):
            if stream is not None:
                stream.close()


def _parser() -> argparse.ArgumentParser:
    def non_negative_int(value: str) -> int:
        parsed = int(value)
        if parsed < 0:
            raise argparse.ArgumentTypeError("must be non-negative")
        return parsed

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--trial", type=non_negative_int, default=None)
    parser.add_argument("--technique", required=True, choices=TECHNIQUE_SLUGS)
    parser.add_argument("--config", default=str(Path(__file__).with_name("config.json")))
    parser.add_argument("--home", default=None)
    parser.add_argument("--user", default=None)
    parser.add_argument("--output", required=True, help="JSONL output path, or - for stdout")
    return parser


def _open_output(path: str) -> tuple[TextIO, bool]:
    if path == "-":
        return sys.stdout, False
    return open(path, "a", encoding="utf-8"), True


def run_detector(args: argparse.Namespace, *, diagnostics: TextIO = sys.stderr) -> None:
    if args.trial is not None and args.trial < 0:
        raise WatchStartupError("--trial must be non-negative")

    config: DetectorConfig = load_config(args.config)
    specs = prepare_watch_specs(config, args.technique, home=args.home, user=args.user)
    trial_source = "detector_cli" if args.trial is not None else "unassigned"
    output, should_close = _open_output(args.output)
    watchers: list[WatchProcess] = []
    selector = selectors.DefaultSelector()
    line_reader = SelectorLineBuffer()
    emitter = InotifyAlertEmitter(
        specs=specs,
        experiment_id=args.experiment_id,
        run_id=args.run_id,
        trial=args.trial,
        trial_source=trial_source,
        technique=args.technique,
    )

    def write_records(records: Iterable[Mapping[str, Any]]) -> None:
        for record in records:
            write_jsonl_record(output, record)
        output.flush()

    try:
        watchers = _start_watchers(specs)
        buffered_events = wait_for_watchers_ready(
            watchers, diagnostics=diagnostics, line_reader=line_reader
        )
        print(
            f"[inotify] ready: all {len(watchers)} watcher subprocesses established "
            f"their watches for run_id={args.run_id}",
            file=diagnostics,
        )

        def consume_line(line: str, observation_time_epoch_ns: int) -> None:
            try:
                write_records(
                    emitter.consume_line(
                        line, observation_time_epoch_ns=observation_time_epoch_ns
                    )
                )
            except InotifyParseError as exc:
                print(f"[inotify] ignored malformed event: {exc}", file=diagnostics)

        for _, line, observation_time in buffered_events:
            consume_line(line, observation_time)

        for watcher in watchers:
            if watcher.process.stdout is not None:
                selector.register(watcher.process.stdout, selectors.EVENT_READ, ("stdout", watcher))
            if watcher.process.stderr is not None:
                selector.register(watcher.process.stderr, selectors.EVENT_READ, ("stderr", watcher))

        while True:
            for key, _ in selector.select(timeout=0.05):
                stream_kind, watcher = key.data
                lines, eof = line_reader.read_available(key.fileobj)
                for line in lines:
                    if stream_kind == "stderr":
                        print(f"[inotifywait] {line.rstrip()}", file=diagnostics)
                        continue

                    # Capture the observation timestamp immediately after reading
                    # the event line, before parsing or alert construction.
                    observation_time = now_epoch_ns()
                    consume_line(line, observation_time)
                if eof:
                    selector.unregister(key.fileobj)

            write_records(emitter.flush(observation_time_epoch_ns=now_epoch_ns()))
            for watcher in watchers:
                return_code = watcher.process.poll()
                if return_code is not None:
                    raise WatchRuntimeError(
                        f"inotifywait for {watcher.spec.watch_root} exited with status {return_code}"
                    )
    except KeyboardInterrupt:
        print("[inotify] stopping", file=diagnostics)
    finally:
        write_records(emitter.flush_all())
        selector.close()
        _stop_watchers(watchers)
        if should_close:
            output.close()


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        run_detector(args)
    except (WatchSetupError, WatchRuntimeError) as exc:
        print(f"[inotify] error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
