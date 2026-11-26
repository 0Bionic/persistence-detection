"""Shared orchestration helpers for the Experiment A/B/D runners.

Spawns the detectors in ``detectors/`` as subprocesses against the shared
JSONL event contract (``detectors/alert_schema.py``,
``detectors/ALERT_CONTRACT.md``), drives the implants in ``implants/`` via
their ``plant``/``cleanup``/``evade`` verbs, and appends validated
``plant``/``alert`` records (plus the ``alert_classification`` and
``evasion_result`` sidecar records the contract calls out as analysis-owned
but that only the runner has the ground truth to write) to ``results/``.

Each trial gets its own detector subprocesses, started fresh and torn down
afterwards — matching ALERT_CONTRACT.md's "detectors are restarted for every
trial" rule, so no baseline or watch state leaks between trials.
"""

from __future__ import annotations

import getpass
import json
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
IMPLANTS_DIR = REPO_ROOT / "implants"
DETECTORS_DIR = REPO_ROOT / "detectors"
RESULTS_DIR = REPO_ROOT / "results"

# Captured here, in this unprivileged process, before any sudo invocation.
# `sudo` commonly resets $USER (and sometimes $HOME) for the command it
# execs, which would otherwise silently break cron's path resolution (its
# configured path is the only one built from {user} rather than {home} —
# see detectors/config.json). Every detector invocation gets these passed
# explicitly via --home/--user instead of letting it fall back to
# os.environ, so path resolution can't depend on what sudo does to the
# subprocess's environment.
REAL_HOME = str(Path.home())
REAL_USER = getpass.getuser()

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detectors.alert_schema import DETECTOR_NAMES, TECHNIQUE_SLUGS  # noqa: E402
from detectors.common import (  # noqa: E402
    epoch_ns_to_utc,
    make_plant_record,
    new_id,
    now_epoch_ns,
    write_jsonl_record,
)
from detectors.config_loader import load_config, resolve_paths  # noqa: E402

ALL_DETECTORS: tuple[str, ...] = DETECTOR_NAMES  # ("baseline_diff", "inotify", "auditd")
DIFF_INTERVALS: tuple[int, ...] = (5, 30, 60)
CONFIG_PATH = DETECTORS_DIR / "config.json"

# Whether an implant's plant appends to an already-existing file (modify) or
# drops a brand-new file into an existing directory (create). Only cosmetic
# for the alert schema's duplicate-grouping (both map to the same "write"
# group), but worth getting right for the report.
PLANT_OPERATION: dict[str, str] = {
    "cron": "modify",
    "systemd_user": "create",
    "shell_rc": "modify",
    "ssh_authorized_keys": "modify",
    "xdg_autostart": "create",
    "ld_preload": "modify",
}


def log(message: str) -> None:
    print(f"[exp] {message}", file=sys.stderr, flush=True)


# --- implants ---------------------------------------------------------------

def implant_path(technique: str) -> Path:
    return IMPLANTS_DIR / f"{technique}.sh"


def implant_has_evade(technique: str) -> bool:
    try:
        text = implant_path(technique).read_text(encoding="utf-8")
    except OSError:
        return False
    return "do_evade()" in text


def run_implant(technique: str, verb: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(implant_path(technique)), verb],
        capture_output=True,
        text=True,
    )


def implant_cleanup(technique: str) -> None:
    run_implant(technique, "cleanup")


def implant_plant(technique: str) -> bool:
    result = run_implant(technique, "plant")
    if result.returncode != 0:
        log(f"WARN: planting {technique} failed: {result.stderr.strip()[-300:]}")
        return False
    return True


def implant_evade(technique: str) -> bool:
    result = run_implant(technique, "evade")
    if result.returncode != 0:
        log(f"WARN: evade for {technique} failed: {result.stderr.strip()[-300:]}")
        return False
    return True


def technique_paths(technique: str) -> tuple[str, ...]:
    config = load_config(str(CONFIG_PATH))
    return tuple(str(p) for p in resolve_paths(config, technique, home=REAL_HOME, user=REAL_USER))


# --- sudo / detector availability -------------------------------------------

# cron's configured path (/var/spool/cron/crontabs/{user}) is root:crontab-
# owned and not readable or even listable by a plain user on stock Ubuntu —
# unlike every other technique's path, which the owning user can always
# read. So baseline_diff/inotify, normally unprivileged, need sudo too, but
# only for this one technique; everything else stays unprivileged to avoid
# needlessly widening what runs as root (and because Experiment C's PID
# introspection and /proc sampling assume an unprivileged detector process).
SUDO_ONLY_TECHNIQUE = "cron"

_sudo_viable_cache: bool | None = None


def sudo_viable() -> bool:
    """Whether passwordless-cached sudo is available.

    Checked once per process and cached, so a missing cached credential
    produces one warning instead of one per trial. Run ``sudo -v`` before a
    long experiment so this stays true for the whole run.
    """

    global _sudo_viable_cache
    if _sudo_viable_cache is None:
        result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
        _sudo_viable_cache = result.returncode == 0
        if not _sudo_viable_cache:
            log("sudo unavailable: no cached credential (run `sudo -v` first) — "
                "auditd and cron's baseline_diff/inotify coverage will be skipped")
    return _sudo_viable_cache


def detector_needs_sudo(name: str, technique: str) -> bool:
    return name == "auditd" or technique == SUDO_ONLY_TECHNIQUE


def detector_available(name: str, technique: str = SUDO_ONLY_TECHNIQUE) -> bool:
    """Whether ``name`` can run right now, watching ``technique``.

    Defaults ``technique`` to the one that needs sudo, so a caller that
    doesn't have a specific technique in mind (e.g. a plain availability
    check) gets the more conservative answer rather than silently assuming
    the unprivileged case.
    """

    script = {
        "baseline_diff": "baseline_diff.py",
        "inotify": "inotify_watch.py",
        "auditd": "auditd_watch.py",
    }.get(name)
    if script is None or not (DETECTORS_DIR / script).exists():
        return False
    if detector_needs_sudo(name, technique):
        return sudo_viable()
    return True


def available_detectors(requested: Sequence[str] = ALL_DETECTORS, *, technique: str = SUDO_ONLY_TECHNIQUE) -> list[str]:
    available = [name for name in requested if detector_available(name, technique)]
    for name in requested:
        if name not in available:
            log(f"skipping detector '{name}': not available in this environment")
    return available


# --- detector subprocess management -----------------------------------------

_READY_MARKERS = {
    "baseline_diff": "baseline captured",
    "inotify": "[inotify] ready:",
    "auditd": "[auditd] ready:",
}


@dataclass
class DetectorHandle:
    name: str
    proc: subprocess.Popen
    output_path: Path
    diag_path: Path
    diag_file: IO[str]
    sudo: bool

    def wait_ready(self, timeout: float = 15.0) -> bool:
        deadline = time.monotonic() + timeout
        marker = _READY_MARKERS[self.name]
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                log(f"WARN: detector '{self.name}' exited before becoming ready "
                    f"(rc={self.proc.returncode}); see {self.diag_path}")
                return False
            try:
                text = self.diag_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if marker in text:
                return True
            time.sleep(0.2)
        log(f"WARN: detector '{self.name}' did not report ready within {timeout}s")
        return False

    def stop(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
        self.diag_file.close()


def _sudo_prefix() -> list[str]:
    # -n: fail fast if the cached credential is gone, instead of hanging on
    # a password prompt nobody is there to answer in an unattended run.
    return ["sudo", "-n"]


def _detector_command(
    name: str,
    *,
    experiment_id: str,
    run_id: str,
    trial: int | None,
    technique: str,
    output_path: Path,
    interval: int | None,
) -> list[str]:
    prefix = _sudo_prefix() if detector_needs_sudo(name, technique) else []
    # --home/--user always explicit (never left to default to os.environ /
    # Path.home() inside the subprocess) — see the REAL_HOME/REAL_USER
    # comment up top for why: sudo commonly rewrites $USER for the command
    # it execs, which would otherwise silently break cron's path resolution.
    identity = ["--home", REAL_HOME, "--user", REAL_USER]

    if name == "baseline_diff":
        cmd = [
            *prefix, sys.executable, str(DETECTORS_DIR / "baseline_diff.py"),
            "--experiment-id", experiment_id, "--run-id", run_id,
            "--technique", technique, *identity, "--output", str(output_path),
            "--interval", str(interval if interval is not None else 30),
        ]
    elif name == "inotify":
        cmd = [
            *prefix, sys.executable, str(DETECTORS_DIR / "inotify_watch.py"),
            "--experiment-id", experiment_id, "--run-id", run_id,
            "--technique", technique, *identity, "--output", str(output_path),
        ]
    elif name == "auditd":
        cmd = [
            *prefix, sys.executable, str(DETECTORS_DIR / "auditd_watch.py"), "monitor",
            "--experiment-id", experiment_id, "--run-id", run_id,
            "--technique", technique, *identity, "--output", str(output_path),
        ]
    else:
        raise ValueError(f"unknown detector: {name}")
    if trial is not None:
        cmd += ["--trial", str(trial)]
    return cmd


def auditd_install(technique: str) -> bool:
    result = subprocess.run(
        [*_sudo_prefix(), sys.executable, str(DETECTORS_DIR / "auditd_watch.py"),
         "install", "--technique", technique, "--home", REAL_HOME, "--user", REAL_USER],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log(f"WARN: auditd install for {technique} failed: {result.stderr.strip()}")
        return False
    return True


def auditd_remove(technique: str) -> None:
    subprocess.run(
        [*_sudo_prefix(), sys.executable, str(DETECTORS_DIR / "auditd_watch.py"),
         "remove", "--technique", technique, "--home", REAL_HOME, "--user", REAL_USER],
        capture_output=True, text=True,
    )


def start_detector(
    name: str,
    *,
    experiment_id: str,
    run_id: str,
    trial: int | None,
    technique: str,
    run_dir: Path,
    interval: int | None = None,
) -> DetectorHandle:
    run_dir.mkdir(parents=True, exist_ok=True)
    output_path = run_dir / f"{name}_{technique}_alerts.jsonl"
    diag_path = run_dir / f"{name}_{technique}_diag.log"
    cmd = _detector_command(
        name, experiment_id=experiment_id, run_id=run_id, trial=trial,
        technique=technique, output_path=output_path, interval=interval,
    )
    diag_file = open(diag_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        cmd, stdout=diag_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True,
    )
    return DetectorHandle(
        name=name, proc=proc, output_path=output_path, diag_path=diag_path,
        diag_file=diag_file, sudo=detector_needs_sudo(name, technique),
    )


class DetectorSession:
    """Starts a set of detectors against one technique, for one trial.

    Use as a context manager: handles auditd's install/remove rule lifecycle,
    waits for every detector to report readiness before the caller plants
    anything, and on exit stops every detector and appends their alert output
    into ``master_alerts_path``. ``self.started`` names which detectors
    actually came up — belongs in the plant record's ``metadata.detectors``.
    """

    def __init__(
        self,
        technique: str,
        *,
        experiment_id: str,
        run_id: str,
        trial: int | None,
        run_dir: Path,
        master_alerts_path: Path,
        detectors: Sequence[str] = ALL_DETECTORS,
        interval: int | None = None,
    ) -> None:
        self.technique = technique
        self.experiment_id = experiment_id
        self.run_id = run_id
        self.trial = trial
        self.run_dir = run_dir
        self.master_alerts_path = master_alerts_path
        self.requested = [d for d in detectors if detector_available(d, technique)]
        self.interval = interval
        self.handles: list[DetectorHandle] = []
        self.started: list[str] = []
        self._installed_auditd = False

    def __enter__(self) -> "DetectorSession":
        if "auditd" in self.requested:
            if auditd_install(self.technique):
                self._installed_auditd = True
            else:
                self.requested = [d for d in self.requested if d != "auditd"]

        for name in self.requested:
            handle = start_detector(
                name, experiment_id=self.experiment_id, run_id=self.run_id,
                trial=self.trial, technique=self.technique, run_dir=self.run_dir,
                interval=self.interval,
            )
            if handle.wait_ready():
                self.handles.append(handle)
                self.started.append(name)
            else:
                handle.stop()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        for handle in self.handles:
            handle.stop()
        if self._installed_auditd:
            auditd_remove(self.technique)
        self._merge_outputs()

    def _merge_outputs(self) -> None:
        self.master_alerts_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.master_alerts_path, "a", encoding="utf-8") as master:
            for handle in self.handles:
                try:
                    text = handle.output_path.read_text(encoding="utf-8")
                except OSError:
                    continue
                if text and not text.endswith("\n"):
                    text += "\n"
                master.write(text)

    def new_alert_count(self) -> int:
        """Alerts produced by any detector in this session, read fresh from disk."""
        total = 0
        for handle in self.handles:
            try:
                total += sum(1 for line in handle.output_path.read_text(encoding="utf-8").splitlines() if line.strip())
            except OSError:
                continue
        return total


# --- plant / classification / evasion record helpers ------------------------

def write_plant(
    path: Path,
    *,
    experiment_id: str,
    run_id: str,
    trial: int,
    technique: str,
    paths: Sequence[str],
    operation: str,
    detectors: Sequence[str],
    plant_time_epoch_ns: int | None = None,
) -> dict[str, Any]:
    record = make_plant_record(
        experiment_id=experiment_id,
        run_id=run_id,
        trial=trial,
        technique=technique,
        paths=paths,
        operation=operation,
        plant_time_epoch_ns=plant_time_epoch_ns,
        metadata={"detectors": list(detectors)},
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as stream:
        write_jsonl_record(stream, record)
    return record


def append_jsonl(path: Path, record: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")


def new_run_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def read_alert_ids_since(path: Path, *, after_byte_offset: int) -> list[dict[str, Any]]:
    """Alert records appended to ``path`` after a previously recorded byte offset."""
    if not path.exists():
        return []
    with open(path, "rb") as stream:
        stream.seek(after_byte_offset)
        chunk = stream.read()
    records = []
    for line in chunk.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0
