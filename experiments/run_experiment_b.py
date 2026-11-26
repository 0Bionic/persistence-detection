#!/usr/bin/env python3
"""Experiment B — false positives (proposal section 4.2).

No implants are planted here. Instead, every available detector watches all
six technique paths at once while a sequence of ordinary admin activities
happens: installing a small package, editing ``~/.bashrc`` directly (a real
alias, not an implant), adding a real personal cron job, and logging in over
SSH. Since nothing in this session is an implant, every alert the detectors
raise is — by construction — a false positive.

Raw alerts stay unmodified (the contract forbids classification fields on
them); instead this writes a separate ``classifications.jsonl`` sidecar of
``alert_classification`` records, one per alert this session produced, each
marked ``false_positive``. Nobody else has the ground truth to do that
labeling — the runner is the only component that knows no implant ran.

Usage:
    python3 experiments/run_experiment_b.py [options]
      --techniques cron systemd_user ...   (default: all six)
      --detectors baseline_diff inotify auditd   (default: all available)
      --iterations N                        repeats of the whole sequence (default: 3)
      --diff-interval N                      scan interval for baseline_diff (default: 30)
      --skip-pkg-install                     skip the package-install activity
      --results-dir results                  where alerts/classifications go
"""

from __future__ import annotations

import argparse
import contextlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runner_common import (  # noqa: E402
    ALL_DETECTORS,
    DetectorSession,
    RESULTS_DIR,
    TECHNIQUE_SLUGS,
    append_jsonl,
    file_size,
    log,
    new_run_id,
    now_epoch_ns,
    read_alert_ids_since,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--techniques", nargs="+", default=list(TECHNIQUE_SLUGS), choices=TECHNIQUE_SLUGS)
    parser.add_argument("--detectors", nargs="+", default=list(ALL_DETECTORS), choices=ALL_DETECTORS)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--diff-interval", type=int, default=30)
    parser.add_argument("--skip-pkg-install", action="store_true")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    return parser.parse_args(argv)


def settle_seconds(session_map: dict[str, DetectorSession], interval: int) -> int:
    any_diff = any("baseline_diff" in s.started for s in session_map.values())
    return interval + 10 if any_diff else 8


def act_install_package(*, skip: bool) -> None:
    if skip:
        log("skipping package install (--skip-pkg-install)")
        return
    result = subprocess.run(
        ["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "sl"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log(f"WARN: package install failed (no cached sudo / no network?): {result.stderr.strip()[:200]}")


def act_edit_bashrc() -> None:
    marker = "# pd-exp-b-real-edit"
    path = Path.home() / ".bashrc"
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(f"\n{marker}\nalias pd_exp_b_real='echo hi'\n")


def undo_edit_bashrc() -> None:
    marker = "# pd-exp-b-real-edit"
    path = Path.home() / ".bashrc"
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError:
        return
    kept = []
    skip_next = False
    for line in lines:
        if skip_next:
            skip_next = False
            continue
        if line.strip() == marker:
            skip_next = True  # also drop the alias line right after it
            continue
        kept.append(line)
    path.write_text("".join(kept), encoding="utf-8")


def act_add_real_cron() -> str:
    tag = f"pd-exp-b-real-cron-{__import__('os').getpid()}"
    line = f"17 3 * * * /bin/true # {tag}\n"
    existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    current = existing.stdout if existing.returncode == 0 else ""
    subprocess.run(["crontab", "-"], input=current + line, text=True, capture_output=True)
    return tag


def undo_add_real_cron(tag: str) -> None:
    existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if existing.returncode != 0:
        return
    kept = "\n".join(l for l in existing.stdout.splitlines() if tag not in l)
    subprocess.run(["crontab", "-"], input=kept + ("\n" if kept else ""), text=True, capture_output=True)


def act_ssh_login() -> None:
    import getpass
    user = getpass.getuser()
    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
         f"{user}@localhost", "true"],
        capture_output=True,
    )
    if result.returncode != 0:
        log("note: ssh login did not complete (no passwordless key set up) — window still counted")


def run_iteration(
    *, iteration: int, techniques: list[str], detectors: list[str], interval: int,
    skip_pkg_install: bool, alerts_path: Path, classifications_path: Path, run_dir: Path,
) -> None:
    run_id = new_run_id(f"B-iter{iteration}")
    windows: list[tuple[str, int, int]] = []
    start_offset = file_size(alerts_path)

    with contextlib.ExitStack() as stack:
        sessions: dict[str, DetectorSession] = {}
        for technique in techniques:
            session = stack.enter_context(DetectorSession(
                technique, experiment_id="B", run_id=run_id, trial=None,
                run_dir=run_dir / run_id / technique, master_alerts_path=alerts_path,
                detectors=detectors, interval=interval,
            ))
            sessions[technique] = session
        started_any = any(s.started for s in sessions.values())
        if not started_any:
            log(f"[B] iteration {iteration}: no detector started, skipping")
            return

        settle = settle_seconds(sessions, interval)
        log(f"[B] iteration {iteration}: watching {list(sessions)} "
            f"({sum(len(s.started) for s in sessions.values())} detector process(es)), settle={settle}s")

        def window(name: str, action) -> None:
            start = now_epoch_ns()
            action()
            time.sleep(settle)
            end = now_epoch_ns()
            windows.append((name, start, end))
            log(f"[B] iteration {iteration}: {name} window closed")

        window("install_package", lambda: act_install_package(skip=skip_pkg_install))
        window("edit_bashrc", act_edit_bashrc)
        cron_tag = {}

        def do_cron():
            cron_tag["tag"] = act_add_real_cron()

        window("add_real_cron", do_cron)
        window("ssh_login", act_ssh_login)

        # Undo the real edits now, still inside the session on purpose: an
        # alert from reverting your own benign edit is just as much a false
        # positive as the edit itself, and this experiment's whole point is
        # to count every alert a no-implant session produces.
        undo_edit_bashrc()
        if "tag" in cron_tag:
            undo_add_real_cron(cron_tag["tag"])
        time.sleep(settle)

    # Classify every alert this iteration produced as a false positive.
    new_alerts = read_alert_ids_since(alerts_path, after_byte_offset=start_offset)
    for alert in new_alerts:
        ts = alert.get("observation_time_epoch_ns", 0)
        activity = next((name for name, s, e in windows if s <= ts <= e), "outside_any_activity_window")
        append_jsonl(classifications_path, {
            "record_type": "alert_classification",
            "alert_id": alert["alert_id"],
            "classification": "false_positive",
            "reason": f"Experiment B iteration {iteration}: no implant planted; nearest activity={activity}",
        })
    log(f"[B] iteration {iteration}: {len(new_alerts)} alert(s), all classified false_positive")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    alerts_path = args.results_dir / "alerts.jsonl"
    classifications_path = args.results_dir / "classifications.jsonl"
    run_dir = args.results_dir / ".exp_b_run"
    shutil.rmtree(run_dir, ignore_errors=True)

    for iteration in range(args.iterations):
        run_iteration(
            iteration=iteration, techniques=args.techniques, detectors=args.detectors,
            interval=args.diff_interval, skip_pkg_install=args.skip_pkg_install,
            alerts_path=alerts_path, classifications_path=classifications_path, run_dir=run_dir,
        )

    shutil.rmtree(run_dir, ignore_errors=True)
    log(f"done. alerts: {alerts_path}  classifications: {classifications_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
