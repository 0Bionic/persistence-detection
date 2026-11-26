#!/usr/bin/env python3
"""Experiment A — coverage and detection latency (proposal section 4.2).

For each technique, scan-interval cell, and trial: start every available
detector concurrently against that technique's configured path(s), write one
runner-owned ``plant`` record, wait for alerts, then stop the detectors and
clean the implant up. One shared ``run_id`` ties the plant to every alert any
detector produces for it; ``metadata.detectors`` on the plant records exactly
which detectors were actually running, so analysis doesn't have to guess.

The scan-interval sweep only changes ``baseline_diff``'s behavior; `inotify`
and `auditd` are re-run once per interval value anyway (same technique, same
trial count) rather than special-cased out, so every detector ends up with an
equal, directly comparable number of trials per technique. That costs extra
wall-clock time for a full run — see ``--iterations``/``--diff-intervals`` to
scale it down for a smoke test.

Usage:
    python3 experiments/run_experiment_a.py [options]
      --techniques cron systemd_user ...   (default: all six)
      --detectors baseline_diff inotify auditd   (default: all available)
      --iterations N                        repeats per cell (default: 10)
      --diff-intervals 5 30 60              scan intervals for baseline_diff
      --results-dir results                 where plants.jsonl/alerts.jsonl go
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
    PLANT_OPERATION,
    DetectorSession,
    RESULTS_DIR,
    TECHNIQUE_SLUGS,
    implant_cleanup,
    implant_plant,
    log,
    new_run_id,
    now_epoch_ns,
    technique_paths,
    write_plant,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--techniques", nargs="+", default=list(TECHNIQUE_SLUGS), choices=TECHNIQUE_SLUGS)
    parser.add_argument("--detectors", nargs="+", default=list(ALL_DETECTORS), choices=ALL_DETECTORS)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--diff-intervals", nargs="+", type=int, default=list(DIFF_INTERVALS), choices=DIFF_INTERVALS)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    return parser.parse_args(argv)


def run_cell(
    *, technique: str, interval: int, trial: int, detectors: list[str],
    plants_path: Path, alerts_path: Path, run_dir: Path,
) -> None:
    implant_cleanup(technique)
    run_id = new_run_id(f"A-{technique}-i{interval}-t{trial}")
    paths = technique_paths(technique)
    record = None

    # Cleanup must happen only *after* the detector session has been fully
    # stopped (end of the `with` block) — doing it while detectors are still
    # watching would have them observe the cleanup's own file write/rename
    # and misreport it as another alert for this same run_id/plant.
    with DetectorSession(
        technique, experiment_id="A", run_id=run_id, trial=trial,
        run_dir=run_dir / run_id, master_alerts_path=alerts_path,
        detectors=detectors, interval=interval,
    ) as session:
        if not session.started:
            log(f"[A interval={interval}] {technique} trial {trial}: no detector started, skipping")
        else:
            # Timestamp bracketed tightly around the plant call: captured
            # immediately before it, so it's a conservative upper bound on
            # the real write time rather than an underestimate (which would
            # let a fast detector's alert appear to precede its own plant).
            plant_ts = now_epoch_ns()
            if implant_plant(technique):
                record = write_plant(
                    plants_path, experiment_id="A", run_id=run_id, trial=trial,
                    technique=technique, paths=paths,
                    operation=PLANT_OPERATION.get(technique, "unknown"),
                    detectors=session.started,
                    plant_time_epoch_ns=plant_ts,
                )
                wait_seconds = interval + 15 if "baseline_diff" in session.started else 20
                log(f"[A interval={interval}] {technique} trial {trial}: planted, "
                    f"waiting up to {wait_seconds}s for {session.started}")
                time.sleep(wait_seconds)

    implant_cleanup(technique)
    if record is None:
        return

    alert_count = sum(
        1 for line in alerts_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and f'"run_id":"{run_id}"' in line
    ) if alerts_path.exists() else 0
    log(f"[A interval={interval}] {technique} trial {trial}: {alert_count} alert(s) "
        f"for plant_event_id={record['plant_event_id']}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    plants_path = args.results_dir / "plants.jsonl"
    alerts_path = args.results_dir / "alerts.jsonl"
    run_dir = args.results_dir / ".exp_a_run"
    shutil.rmtree(run_dir, ignore_errors=True)

    for interval in args.diff_intervals:
        for technique in args.techniques:
            for trial in range(args.iterations):
                run_cell(
                    technique=technique, interval=interval, trial=trial,
                    detectors=args.detectors, plants_path=plants_path,
                    alerts_path=alerts_path, run_dir=run_dir,
                )

    shutil.rmtree(run_dir, ignore_errors=True)
    log(f"done. plants: {plants_path}  alerts: {alerts_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
