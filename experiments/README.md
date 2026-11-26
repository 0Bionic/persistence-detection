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

# Experiment D: evasion (timing + alternate persistence paths)
experiments/exp_d_evasion.sh \
  --detectors "diff inotify auditd" \
  --iterations 10 \
  --diff-intervals "5 30 60"
```

All three write a timestamped CSV to `results/`. `--help` on any script
prints its full option list.

`exp_d_evasion.sh` covers both evasion examples from the proposal:
- **timing** — plant, hold briefly, remove again before the detector's next
  check, for every technique (this is the "remove between two diff scans"
  case; it's approximate for `diff` since the runner doesn't know the exact
  phase of its scan cycle, and is a short fixed hold for the event-driven
  detectors).
- **path** — use the implant's `evade` verb, which writes to a path outside
  the canonical one in `paths` (e.g. `~/.profile` instead of `~/.bashrc`,
  the system-wide autostart dir instead of the per-user one). Implemented
  for `bashrc`, `ssh_key`, `xdg_autostart`, `ld_preload`; `cron` and
  `systemd_user` have no alternate location to hide in and are recorded as
  `no_evasion_variant`.

"Still detected" counts any new alert in the window, not just one naming the
exact path touched — a detector that happens to also watch the path an
evasion lands on (e.g. `ld_preload`'s evasion rewrites `~/.bashrc`) should
get credit.

Experiment C (resource cost) is not a separate runner script: it's Student
2's resource-measurement work layered on top of the sessions these runners
already start (same `start`/`stop` detector calls, measured with
`pidstat`/`/proc` in between).

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
