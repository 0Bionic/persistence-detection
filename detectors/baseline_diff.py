"""Periodic baseline file-diff detector.

The detector is intentionally usable as a library so local checks can exercise
temporary paths without starting a long-running detector process.  The command
line entry point captures one baseline and then scans every configured interval.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, TextIO

try:  # Works as ``detectors.baseline_diff`` and as a direct script.
    from .alert_schema import TECHNIQUE_SLUGS
    from .common import (
        DuplicateEventGrouper,
        make_alert_record,
        now_epoch_ns,
        write_jsonl_record,
    )
    from .config_loader import DetectorConfig, load_config, resolve_paths
except ImportError:  # pragma: no cover - direct script execution fallback
    from alert_schema import TECHNIQUE_SLUGS
    from common import DuplicateEventGrouper, make_alert_record, now_epoch_ns, write_jsonl_record
    from config_loader import DetectorConfig, load_config, resolve_paths


ALLOWED_INTERVALS = (5, 30, 60)
CHUNK_SIZE = 1024 * 1024


def _path_is_under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _fingerprint_file(path: str) -> dict[str, Any]:
    """Return a content and metadata fingerprint for one readable file."""

    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    stat_result = os.stat(path, follow_symlinks=False)
    return {
        "sha256": digest.hexdigest(),
        "size": stat_result.st_size,
        "mtime_ns": stat_result.st_mtime_ns,
        "mode": stat_result.st_mode,
    }


def _issue(kind: str, path: str, error: BaseException | None = None) -> dict[str, str]:
    result = {"kind": kind, "path": path}
    if error is not None:
        result["error"] = f"{type(error).__name__}: {error}"
    return result


def scan_paths(paths: Iterable[Path], *, path_kind: str) -> dict[str, Any]:
    """Scan configured paths and return fingerprints plus explicit scan issues.

    ``unavailable_files`` and ``unavailable_roots`` prevent a transient
    permission/read failure from being silently interpreted as a deletion.
    Directly missing file paths remain eligible for deletion detection when a
    previous readable fingerprint exists.
    """

    files: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, str]] = []
    unavailable_files: set[str] = set()
    unavailable_roots: set[str] = set()

    def record_file(path: str) -> None:
        normalized = os.path.abspath(os.path.normpath(path))
        try:
            files[normalized] = _fingerprint_file(normalized)
        except FileNotFoundError as exc:
            issues.append(_issue("missing", normalized, exc))
        except (OSError, PermissionError) as exc:
            issues.append(_issue("unreadable", normalized, exc))
            unavailable_files.add(normalized)

    for configured_path in paths:
        root = os.path.abspath(os.path.normpath(str(configured_path)))
        if path_kind == "file":
            if not os.path.lexists(root):
                issues.append(_issue("missing", root))
            elif not os.path.isfile(root):
                issues.append(_issue("not_a_file", root))
                unavailable_files.add(root)
            else:
                record_file(root)
            continue

        if not os.path.lexists(root):
            issues.append(_issue("missing_directory", root))
            unavailable_roots.add(root)
            continue
        if not os.path.isdir(root):
            issues.append(_issue("not_a_directory", root))
            unavailable_roots.add(root)
            continue

        def on_walk_error(error: OSError) -> None:
            error_path = os.path.abspath(getattr(error, "filename", root) or root)
            issues.append(_issue("unreadable_directory", error_path, error))
            unavailable_roots.add(error_path)

        for directory, directory_names, file_names in os.walk(
            root, topdown=True, onerror=on_walk_error, followlinks=False
        ):
            directory_names.sort()
            file_names.sort()
            for file_name in file_names:
                record_file(os.path.join(directory, file_name))

    return {
        "files": files,
        "issues": issues,
        "unavailable_files": unavailable_files,
        "unavailable_roots": unavailable_roots,
    }


def diff_snapshots(previous: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return creation, deletion, content, and metadata changes."""

    previous_files = previous["files"]
    current_files = current["files"]
    unavailable_files = current["unavailable_files"]
    unavailable_roots = current["unavailable_roots"]

    def suppressed(path: str) -> bool:
        return path in unavailable_files or any(
            _path_is_under(path, root) for root in unavailable_roots
        )

    changes: list[dict[str, Any]] = []
    for path in sorted(set(current_files).difference(previous_files)):
        changes.append(
            {
                "path": path,
                "operation": "create",
                "previous_fingerprint": None,
                "current_fingerprint": current_files[path],
            }
        )
    for path in sorted(set(previous_files).difference(current_files)):
        if not suppressed(path):
            changes.append(
                {
                    "path": path,
                    "operation": "delete",
                    "previous_fingerprint": previous_files[path],
                    "current_fingerprint": None,
                }
            )
    for path in sorted(set(previous_files).intersection(current_files)):
        old = previous_files[path]
        new = current_files[path]
        if old == new:
            continue
        operation = "modify" if old["sha256"] != new["sha256"] else "metadata"
        changes.append(
            {
                "path": path,
                "operation": operation,
                "previous_fingerprint": old,
                "current_fingerprint": new,
            }
        )
    return changes


def _issue_key(issue: Mapping[str, str]) -> tuple[str, str]:
    return issue["kind"], issue["path"]


def report_scan_issues(
    issues: Iterable[Mapping[str, str]],
    previous_issue_keys: set[tuple[str, str]],
    *,
    scan_number: int,
    stream: TextIO,
) -> set[tuple[str, str]]:
    """Report issue state transitions and return the current issue set."""

    current_issue_keys = {_issue_key(issue) for issue in issues}
    for issue in issues:
        key = _issue_key(issue)
        if key not in previous_issue_keys:
            detail = f" ({issue['error']})" if "error" in issue else ""
            print(
                f"[baseline_diff] scan={scan_number} {issue['kind']}: {issue['path']}{detail}",
                file=stream,
            )
    for kind, path in sorted(previous_issue_keys.difference(current_issue_keys)):
        print(f"[baseline_diff] scan={scan_number} resolved: {kind}: {path}", file=stream)
    return current_issue_keys


def build_alert_records(
    changes: Iterable[Mapping[str, Any]],
    *,
    experiment_id: str,
    run_id: str,
    trial: int | None,
    trial_source: str,
    technique: str,
    observation_time_epoch_ns: int,
    scan_number: int,
    interval: int,
) -> list[dict[str, Any]]:
    """Convert one scan's changes into contract-valid grouped alert records."""

    grouper = DuplicateEventGrouper()
    for change in changes:
        grouper.add(
            detector="baseline_diff",
            experiment_id=experiment_id,
            run_id=run_id,
            trial=trial,
            trial_source=trial_source,
            technique=technique,
            paths=[change["path"]],
            operation=change["operation"],
            observation_time_epoch_ns=observation_time_epoch_ns,
            raw_event={
                "source": "baseline_diff",
                "path": change["path"],
                "operation": change["operation"],
                "previous_fingerprint": change["previous_fingerprint"],
                "current_fingerprint": change["current_fingerprint"],
                "scan_number": scan_number,
            },
        )

    records: list[dict[str, Any]] = []
    for group in grouper.flush_all():
        records.append(
            make_alert_record(
                detector="baseline_diff",
                experiment_id=group.experiment_id,
                run_id=group.run_id,
                trial=group.trial,
                trial_source=group.trial_source,
                technique=group.technique,
                paths=group.paths,
                operation=group.operation,
                raw_events=group.raw_events,
                alert_group_id=group.alert_group_id,
                observation_time_epoch_ns=observation_time_epoch_ns,
                metadata={
                    "scan_number": scan_number,
                    "interval_seconds": interval,
                    "group_operation": group.operation_group,
                },
            )
        )
    return records


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
    parser.add_argument("--interval", type=int, choices=ALLOWED_INTERVALS, default=30)
    return parser


def _open_output(path: str) -> tuple[TextIO, bool]:
    if path == "-":
        return sys.stdout, False
    return open(path, "a", encoding="utf-8"), True


def run_detector(args: argparse.Namespace, *, diagnostics: TextIO = sys.stderr) -> None:
    config: DetectorConfig = load_config(args.config)
    entry = config.techniques[args.technique]
    paths = resolve_paths(config, args.technique, home=args.home, user=args.user)
    trial_source = "detector_cli" if args.trial is not None else "unassigned"

    baseline = scan_paths(paths, path_kind=entry.path_kind)
    issue_keys = report_scan_issues(
        baseline["issues"], set(), scan_number=0, stream=diagnostics
    )
    print(
        f"[baseline_diff] baseline captured run_id={args.run_id} technique={args.technique} "
        f"files={len(baseline['files'])} interval={args.interval}s",
        file=diagnostics,
    )

    output, should_close = _open_output(args.output)
    try:
        scan_number = 0
        while True:
            time.sleep(args.interval)
            scan_number += 1
            current = scan_paths(paths, path_kind=entry.path_kind)
            issue_keys = report_scan_issues(
                current["issues"], issue_keys, scan_number=scan_number, stream=diagnostics
            )
            changes = diff_snapshots(baseline, current)
            # This is when the completed scan/diff is observed by the detector.
            # It is intentionally later than filesystem scanning and comparison.
            observation_time = now_epoch_ns()
            for record in build_alert_records(
                changes,
                experiment_id=args.experiment_id,
                run_id=args.run_id,
                trial=args.trial,
                trial_source=trial_source,
                technique=args.technique,
                observation_time_epoch_ns=observation_time,
                scan_number=scan_number,
                interval=args.interval,
            ):
                write_jsonl_record(output, record)
            output.flush()
            baseline = current
    except KeyboardInterrupt:
        print("[baseline_diff] stopped", file=diagnostics)
    finally:
        if should_close:
            output.close()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    run_detector(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
