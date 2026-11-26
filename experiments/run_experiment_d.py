#!/usr/bin/env python3
"""Experiment D — evasion (proposal section 4.2).

Tests an attacker who knows the detector, in the two ways the proposal gives
as examples:

  timing  plant the implant, hold it briefly, then remove it again before the
          detector's next check has a chance to run — "plant and remove
          between two diff scans". Mainly bites ``baseline_diff``, but every
          available detector is exercised the same way; the hold time is
          approximate since the runner doesn't know the exact phase of
          ``baseline_diff``'s scan cycle.
  path    use the implant's ``evade`` verb, which writes to a location
          outside the canonical path in ``paths`` (e.g. ``~/.profile``
          instead of ``~/.bashrc``, the system-wide autostart dir instead of
          the per-user one). Implemented for shell_rc, ssh_authorized_keys,
          xdg_autostart, ld_preload; cron and systemd_user have no
          alternate location to hide in and are skipped (logged, not
          silently dropped).

Unlike Experiment A, this does not write ``plant``/``alert`` records at all:
the ``evasion_result`` record type is self-contained (explicit
``detected: bool``, no plant to match against), so mixing it into A's
detection-rate dataset would only confuse that comparison. Every detector
still starts the same way, under ``experiment_id="D"``; its raw alert output
is inspected directly (did the run_id show up at all?) rather than matched to
anything.

Usage:
    python3 experiments/run_experiment_d.py [options]
      --techniques cron systemd_user ...     (default: all six)
      --detectors baseline_diff inotify auditd   (default: all available)
      --iterations N                          repeats per cell (default: 10)
      --diff-intervals 5 30 60                scan intervals for baseline_diff
      --results-dir results                   where evasion_results.jsonl goes
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runner_common import (  # noqa: E402
    ALL_DETECTORS,
    DIFF_INTERVALS,
    DetectorSession,
    RESULTS_DIR,
    TECHNIQUE_SLUGS,
    append_jsonl,
    implant_cleanup,
    implant_evade,
    implant_has_evade,
    implant_plant,
    log,
    new_run_id,
    now_epoch_ns,
)

NO_ALTERNATE_LOCATION = {"cron", "systemd_user"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--techniques", nargs="+", default=list(TECHNIQUE_SLUGS), choices=TECHNIQUE_SLUGS)
    parser.add_argument("--detectors", nargs="+", default=list(ALL_DETECTORS), choices=ALL_DETECTORS)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--diff-intervals", nargs="+", type=int, default=list(DIFF_INTERVALS), choices=DIFF_INTERVALS)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    return parser.parse_args(argv)


def _any_alert_for_run(alerts_path: Path, run_id: str) -> bool:
    if not alerts_path.exists():
        return False
    needle = f'"run_id":"{run_id}"'
    with open(alerts_path, "r", encoding="utf-8") as stream:
        return any(needle in line for line in stream)


def run_timing_cell(
    *, technique: str, interval: int, trial: int, detectors: list[str],
    evasion_path: Path, alerts_scratch: Path, run_dir: Path,
) -> None:
    implant_cleanup(technique)
    run_id = new_run_id(f"D-timing-{technique}-i{interval}-t{trial}")
    hold_seconds = max(1, interval // 3)

    with DetectorSession(
        technique, experiment_id="D", run_id=run_id, trial=trial,
        run_dir=run_dir / run_id, master_alerts_path=alerts_scratch,
        detectors=detectors, interval=interval,
    ) as session:
        if not session.started:
            log(f"[D timing i={interval}] {technique} trial {trial}: no detector started, skipping")
            implant_cleanup(technique)
            return

        event_ts = now_epoch_ns()
        if not implant_plant(technique):
            implant_cleanup(technique)
            return
        time.sleep(hold_seconds)
        implant_cleanup(technique)

        remaining = (interval + 15 if "baseline_diff" in session.started else 20) - hold_seconds
        time.sleep(max(1, remaining))

    detected = _any_alert_for_run(alerts_scratch, run_id)
    for detector in session.started:
        append_jsonl(evasion_path, {
            "record_type": "evasion_result",
            "experiment_id": "D",
            "run_id": run_id,
            "trial": trial,
            "detector": detector,
            "technique": technique,
            "evasion_label": "timing",
            "detected": detected,
            "metadata": {"hold_seconds": hold_seconds, "scan_interval_seconds": interval},
            "event_time_epoch_ns": event_ts,
        })
    log(f"[D timing i={interval}] {technique} trial {trial}: held {hold_seconds}s, "
        f"still_detected={detected} ({session.started})")


def run_path_cell(
    *, technique: str, trial: int, detectors: list[str],
    evasion_path: Path, alerts_scratch: Path, run_dir: Path,
) -> None:
    if not implant_has_evade(technique):
        if technique not in NO_ALTERNATE_LOCATION:
            log(f"[D path] {technique}: no evade verb implemented, skipping")
        return

    implant_cleanup(technique)
    run_id = new_run_id(f"D-path-{technique}-t{trial}")
    event_ts = None

    # As in Experiment A: cleanup must happen only after the detector session
    # is fully stopped. implant cleanup rewrites files unconditionally (even
    # ones it never touched this trial) via `sed -i`, which still emits a
    # create/rename filesystem event with zero matching lines — doing that
    # while the detector is still watching the *canonical* path would make
    # path evasion look "detected" from cleanup noise on the real file, not
    # from the evasion path a narrowly-scoped detector was supposed to miss.
    with DetectorSession(
        technique, experiment_id="D", run_id=run_id, trial=trial,
        run_dir=run_dir / run_id, master_alerts_path=alerts_scratch,
        detectors=detectors,
    ) as session:
        if not session.started:
            log(f"[D path] {technique} trial {trial}: no detector started, skipping")
        else:
            event_ts = now_epoch_ns()
            if implant_evade(technique):
                time.sleep(20)
            else:
                event_ts = None

    implant_cleanup(technique)
    if event_ts is None:
        return

    detected = _any_alert_for_run(alerts_scratch, run_id)
    for detector in session.started:
        append_jsonl(evasion_path, {
            "record_type": "evasion_result",
            "experiment_id": "D",
            "run_id": run_id,
            "trial": trial,
            "detector": detector,
            "technique": technique,
            "evasion_label": "path",
            "detected": detected,
            "event_time_epoch_ns": event_ts,
        })
    log(f"[D path] {technique} trial {trial}: still_detected={detected} ({session.started})")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    evasion_path = args.results_dir / "evasion_results.jsonl"
    alerts_scratch = args.results_dir / ".exp_d_scratch_alerts.jsonl"
    run_dir = args.results_dir / ".exp_d_run"
    shutil.rmtree(run_dir, ignore_errors=True)
    alerts_scratch.unlink(missing_ok=True)

    for interval in args.diff_intervals:
        for technique in args.techniques:
            for trial in range(args.iterations):
                run_timing_cell(
                    technique=technique, interval=interval, trial=trial,
                    detectors=args.detectors, evasion_path=evasion_path,
                    alerts_scratch=alerts_scratch, run_dir=run_dir,
                )

    # Path evasion doesn't depend on the diff interval, so it's only run once
    # per technique/trial rather than once per interval value.
    for technique in args.techniques:
        for trial in range(args.iterations):
            run_path_cell(
                technique=technique, trial=trial, detectors=args.detectors,
                evasion_path=evasion_path, alerts_scratch=alerts_scratch, run_dir=run_dir,
            )

    shutil.rmtree(run_dir, ignore_errors=True)
    alerts_scratch.unlink(missing_ok=True)
    log(f"done. evasion results: {evasion_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
