# experiments/

Runners for Experiments A, B, and D (proposal section 4.2). They drive the
implants in `implants/` and the detectors in `detectors/` together, against
the shared JSONL event contract (`detectors/alert_schema.py`,
`detectors/ALERT_CONTRACT.md`). Experiment C has no separate runner — see
[Experiment C](#experiment-c-resource-cost) below.

## How a trial works

Each runner's innermost loop, for one (technique, trial):

1. `implants/<technique>.sh cleanup` — guarantee a clean starting state.
2. Start every requested, available detector fresh (`detectors are restarted
   for every trial`, per `ALERT_CONTRACT.md`) against that technique's
   configured path(s), all sharing one `run_id`. For `auditd` this means
   `auditd_watch.py install` (needs cached sudo), then `monitor`.
3. Wait for each detector to report ready (reading its diagnostics for the
   marker line its script prints, e.g. `[inotify] ready: ...`), skipping any
   that doesn't come up (e.g. `auditd` with no cached sudo credential, or
   `inotify`/`auditd` on a path the sandbox user can't read — logged once,
   not fatal to the run).
4. Plant the implant (or, for Experiment D, hold it briefly then remove it,
   or use its `evade` verb instead).
5. Wait long enough for the slowest requested detector to have a chance —
   `scan_interval + 15s` when `baseline_diff` is running, else a flat ~20s.
6. Stop every detector (`SIGINT`, so each one's own cleanup/flush code runs —
   **not** `SIGTERM`, which none of them catch) and merge their JSONL output
   into the shared `results/alerts.jsonl`.
7. **Only now** run `implants/<technique>.sh cleanup`. This order matters:
   `pd_remove_block`'s `sed -i` rewrites a file even when nothing in it
   matched, which still emits a create/rename filesystem event — cleaning up
   while a detector is still watching that path would misreport the
   cleanup's own noise as a detection.

## Experiment A — coverage and latency

```bash
python3 experiments/run_experiment_a.py \
  --techniques cron systemd_user shell_rc ssh_authorized_keys xdg_autostart ld_preload \
  --detectors baseline_diff inotify auditd \
  --iterations 10 --diff-intervals 5 30 60
```

Writes one `plant` record per trial to `results/plants.jsonl` (with
`metadata.detectors` listing exactly which detectors were actually running —
the detection-matching assumption `analysis/compute_metrics.py` calls out as
needing confirmation from Student 1; this is that confirmation) and every
detector's raw `alert` records to `results/alerts.jsonl`.

The scan-interval sweep is only meaningful to `baseline_diff`; `inotify` and
`auditd` are re-run once per interval value anyway rather than special-cased
out of the loop, so every detector ends up with an equal, directly
comparable trial count per technique. That costs wall-clock time for a full
10-iteration × 3-interval × 6-technique run (hours, not minutes) — scale
`--iterations`/`--diff-intervals` down for a smoke test.

## Experiment B — false positives

```bash
python3 experiments/run_experiment_b.py \
  --iterations 3 --diff-interval 30
```

No implant runs here. Every available detector watches all six technique
paths at once while a sequence of ordinary admin activities happens:
installing a small package (`--skip-pkg-install` to skip; needs network +
cached sudo), a real `.bashrc` edit (and its own revert), a real personal
cron job (added, then removed), and an SSH login attempt. Writes alerts to
the same `results/alerts.jsonl` (`experiment_id: "B"`) plus
`results/classifications.jsonl`: one `alert_classification` record per alert,
all `false_positive`, since nothing planted anything. Raw alerts are never
edited in place — classification is a separate sidecar, as the contract
requires — and the runner is the only component with the ground truth to
write it (an alert can't self-report that it's spurious).

## Experiment D — evasion

```bash
python3 experiments/run_experiment_d.py \
  --iterations 10 --diff-intervals 5 30 60
```

Covers both evasion examples the proposal gives:

- **timing** — plant, hold briefly (`scan_interval / 3`, or 1s for
  event-driven detectors), remove again, then keep watching for the rest of
  the normal wait window. Approximate for `baseline_diff` since the runner
  doesn't know the exact phase of its scan cycle.
- **path** — use the implant's `evade` verb, which writes to a location
  outside the canonical path (e.g. `~/.profile` instead of `~/.bashrc`, the
  system-wide autostart dir instead of the per-user one). Implemented for
  `shell_rc`, `ssh_authorized_keys`, `xdg_autostart`, `ld_preload`; `cron`
  and `systemd_user` have no alternate location to hide in and are skipped
  (logged, not silently dropped). Only run once per technique/trial, not
  once per scan interval, since it doesn't depend on one.

Writes `results/evasion_results.jsonl`: one `evasion_result` record per
(detector, technique, evasion_label, trial), with an explicit `detected`
boolean the runner determines by checking whether that detector's own alert
stream shows anything at all for the run_id — not by matching against a
`plant` record. This experiment deliberately writes no `plant`/`alert`
records of its own distinguishable from noise in the shared dataset;
mixing evasion attempts into Experiment A's detection-rate numbers would
misrepresent both.

## Experiment C — resource cost

No separate runner. Measure it by hand around any of the runners above:
start the detector(s) you want to measure the same way `runner_common.py`
does (see `detectors/ALERT_CONTRACT.md` and the commands in the root
README's "Running the detectors" section), grab their PIDs, then:

```bash
python3 analysis/measure_resources.py \
  --experiment-id C --run-id <id> --trial 0 \
  --detector baseline_diff --phase idle \
  --pid <detector_pid> --interval 1 --duration 60 \
  --output results/resources.csv
```

Repeat with `--phase active` while an implant is being planted/removed in a
loop, and for each detector. See `analysis/RESOURCE_MEASUREMENTS.md` for the
CSV contract and the `pidstat` cross-check.

## Shared code

`runner_common.py` holds everything the three runners share: implant
plant/cleanup/evade wrappers, the detector subprocess lifecycle
(`DetectorSession`, a context manager — handles `auditd`'s install/remove
rule lifecycle, readiness detection, clean `SIGINT` shutdown, and merging
each detector's output into the shared alerts file), and the plant/
classification/evasion record writers (thin wrappers around
`detectors/common.py` so records always validate against the real schema).

## Troubleshooting

- **`auditd` never starts**: run `sudo -v` before a long experiment so the
  cached credential doesn't expire mid-run (checked once per process and
  cached; a stale credential produces one warning, not one per trial).
- **A run was killed mid-way**: implants clean up idempotently —
  `for t in cron systemd_user shell_rc ssh_authorized_keys xdg_autostart ld_preload; do bash implants/$t.sh cleanup; done`
  — and any audit rules left installed can be removed the same way:
  `for t in ...; do sudo python3 detectors/auditd_watch.py remove --technique $t; done`.
- **`cron`'s detectors can't start**: `/var/spool/cron/crontabs/` isn't
  readable by a non-root user on stock Ubuntu; this is expected outside a
  root-run detector session, not a bug in the implant or runner.
