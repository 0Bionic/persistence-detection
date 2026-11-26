#!/usr/bin/env python3
"""Experiment C — resource cost (proposal section 4.2).

Measures each detector's CPU, memory, and disk I/O via /proc, once idle
(just watching, nothing happening) and once active (the same implant being
planted and cleaned up in a tight loop for the whole sampling window).
Delegates the actual sampling to analysis/measure_resources.py; this script
only launches the detector (reusing runner_common.DetectorSession, same as
Experiments A/B/D), finds its PID (and any child process PIDs, e.g.
inotify_watch.py's inotifywait subprocess), drives the activity loop, and
glues the per-call CSVs together into one results/resources.csv —
measure_resources.py's ``--output`` overwrites rather than appends, so each
(detector, phase) gets its own temp file that this script concatenates.

Usage:
    python3 experiments/run_experiment_c.py [options]
      --technique shell_rc                  which implant's path to watch (default: shell_rc)
      --detectors baseline_diff inotify auditd   (default: all available)
      --interval 1                          seconds between /proc samples
      --duration 60                         seconds per idle/active phase
      --results-dir results
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runner_common import (  # noqa: E402
    ALL_DETECTORS,
    DetectorSession,
    REPO_ROOT,
    RESULTS_DIR,
    TECHNIQUE_SLUGS,
    implant_cleanup,
    implant_plant,
    log,
    new_run_id,
)

MEASURE_RESOURCES = REPO_ROOT / "analysis" / "measure_resources.py"


def child_pids(pid: int) -> list[int]:
    """Immediate child PIDs of ``pid``, read straight from /proc (no deps)."""
    pids: list[int] = []
    task_dir = Path(f"/proc/{pid}/task")
    try:
        tids = list(task_dir.iterdir())
    except OSError:
        return pids
    for tid_dir in tids:
        try:
            text = (tid_dir / "children").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        pids.extend(int(p) for p in text.split())
    return pids


def sample(
    *, experiment_id: str, run_id: str, trial: int, detector: str, phase: str,
    pids: list[int], interval: float, duration: float, output: Path,
) -> bool:
    cmd = [
        sys.executable, str(MEASURE_RESOURCES),
        "--experiment-id", experiment_id, "--run-id", run_id, "--trial", str(trial),
        "--detector", detector, "--phase", phase,
        "--interval", str(interval), "--duration", str(duration),
        "--output", str(output),
    ]
    for pid in pids:
        cmd += ["--pid", str(pid)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log(f"WARN: measure_resources failed for {detector}/{phase}: {result.stderr.strip()[-300:]}")
        return False
    return True


def activity_loop(technique: str, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        implant_plant(technique)
        time.sleep(0.5)
        implant_cleanup(technique)
        time.sleep(0.5)


def run_detector_phase(
    *, detector: str, technique: str, phase: str, interval: float, duration: float,
    run_dir: Path, csv_parts: list[Path],
) -> None:
    run_id = new_run_id(f"C-{detector}-{phase}")
    with DetectorSession(
        technique, experiment_id="C", run_id=run_id, trial=0,
        run_dir=run_dir / run_id, master_alerts_path=run_dir / "discarded_alerts.jsonl",
        detectors=[detector],
    ) as session:
        if not session.started:
            log(f"[C] {detector} {phase}: could not start, skipping")
            return

        handle = session.handles[0]
        pids = [handle.proc.pid] + child_pids(handle.proc.pid)
        stop_event = threading.Event()
        thread = None
        if phase == "active":
            implant_cleanup(technique)  # start from a clean state for the loop
            thread = threading.Thread(target=activity_loop, args=(technique, stop_event), daemon=True)
            thread.start()

        out = run_dir / f"{detector}_{phase}.csv"
        log(f"[C] {detector} {phase}: sampling pid(s)={pids} for {duration:.0f}s")
        ok = sample(
            experiment_id="C", run_id=run_id, trial=0, detector=detector, phase=phase,
            pids=pids, interval=interval, duration=duration, output=out,
        )
        if thread is not None:
            stop_event.set()
            thread.join(timeout=5)
            implant_cleanup(technique)

    if ok:
        csv_parts.append(out)


def merge_csvs(parts: list[Path], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrote_header = output_path.exists() and output_path.stat().st_size > 0
    with open(output_path, "a", encoding="utf-8") as out:
        for part in parts:
            try:
                lines = part.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            if not lines:
                continue
            if not wrote_header:
                out.write(lines[0] + "\n")
                wrote_header = True
            for line in lines[1:]:
                out.write(line + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--technique", default="shell_rc", choices=TECHNIQUE_SLUGS)
    parser.add_argument("--detectors", nargs="+", default=list(ALL_DETECTORS), choices=ALL_DETECTORS)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    run_dir = args.results_dir / ".exp_c_run"
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    csv_parts: list[Path] = []

    for detector in args.detectors:
        for phase in ("idle", "active"):
            run_detector_phase(
                detector=detector, technique=args.technique, phase=phase,
                interval=args.interval, duration=args.duration,
                run_dir=run_dir, csv_parts=csv_parts,
            )

    resources_csv = args.results_dir / "resources.csv"
    merge_csvs(csv_parts, resources_csv)
    shutil.rmtree(run_dir, ignore_errors=True)
    log(f"done. resources: {resources_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
