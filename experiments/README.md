# experiments/

Runners for the four experiments in the proposal (section 4.2). These drive
the implants in `implants/` against whatever detectors exist in
`detectors/`.

## Detector interface

A detector is `detectors/<name>.sh`, invoked as `detectors/<name>.sh start`
and `detectors/<name>.sh stop`, with this environment set on both calls:

| Variable | Meaning |
|---|---|
| `PD_WATCH_PATHS_FILE` | file with one watched path per line |
| `PD_ALERT_LOG` | file the detector **appends** alerts to |
| `PD_DETECTOR_PID_FILE` | where `start` must write the PID of its background process, so a later `stop` can find and kill it |
| `PD_SCAN_INTERVAL` | seconds between scans — only meaningful to `diff`, other detectors ignore it |

`start` must background itself and return promptly once monitoring is live.
`stop` must be idempotent (safe to call even if already stopped).

Alert lines appended to `PD_ALERT_LOG`, tab-separated:

```
<epoch.ns>\t<detector-name>\t<path>\t<note>
```

`<path>` must be one of the watched paths (exactly as it appears in
`PD_WATCH_PATHS_FILE`) so the runner can match an alert back to the
technique that produced it. `<note>` is free text (e.g. `changed`,
`created`, the user/process from an audit record) and isn't parsed.

Expected detector names (matching the proposal): `diff`, `inotify`,
`auditd`. A runner skips any name whose script doesn't exist yet, so this
still runs end to end while `detectors/` is being built out.

## Running

```bash
# Experiment A: coverage + detection latency
experiments/exp_a_coverage_latency.sh \
  --detectors "diff inotify auditd" \
  --iterations 10 \
  --diff-intervals "5 30 60"

# Experiment B: false positives on normal admin activity
experiments/exp_b_false_positives.sh \
  --detectors "diff inotify auditd" \
  --iterations 10 \
  --diff-interval 30
```

Both write a timestamped CSV to `results/`. `--help` on either script prints
the full option list.

Experiments C (resource cost) and D (evasion) are not separate runner
scripts: C is Student 2's resource-measurement work layered on top of the
sessions these runners start (same `start`/`stop` detector calls, measured
with `pidstat`/`/proc` in between); D reuses these same implants' `evade`
verb (`implants/<tech>.sh evade`) in place of `plant` — every implant that
has a meaningful evasion variant (all but `cron` and `systemd_user`, whose
proposal-listed paths have no alternate location to hide in) implements one.

## Notes

- Every run calls each implant's `cleanup` before and after planting it, so
  a failed run shouldn't leave persistence lying around. If a run is killed
  mid-way, cleaning up by hand is one line per technique:
  `for t in cron systemd_user bashrc ssh_key xdg_autostart ld_preload; do bash implants/$t.sh cleanup; done`
- `ld_preload` and the `xdg_autostart`/`ssh_key` evasion variants need
  `sudo`. Run `sudo -v` once before a long experiment so the cached
  credential doesn't expire mid-run and silently fail a `plant`.
- Results are plain CSV on purpose (see `PD_ALL_DETECTORS` / the per-cell
  rows) — Student 2's analysis scripts in `analysis/` read these directly
  with pandas.
