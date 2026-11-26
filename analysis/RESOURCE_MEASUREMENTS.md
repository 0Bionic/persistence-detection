# Resource measurement contract

`measure_resources.py` implements the proposal's Experiment C measurement
using `/proc`. Run it once for each detector, trial, and phase (`idle` or
`active`), passing the detector PID and any child detector PIDs with repeated
`--pid` options. The output is one CSV row per PID per sample and includes the
experiment ID, shared run ID, trial, phase, detector, epoch-nanosecond sample
time, CPU percentage, resident memory in KiB, and per-interval read/write byte
deltas.

The first row for a PID is a baseline, so interval deltas are blank. If a
process exits, or `/proc` denies or loses access to a field, the affected
values remain blank and `sample_status`/`error` explain why. They are not
represented as zero.

## pidstat cross-check

On the Ubuntu VM, capture raw `pidstat` output separately from the structured
CSV, for example:

```text
pidstat -p PID1,PID2 -u -r -d INTERVAL COUNT > results/<run_id>_<phase>.pidstat.txt
```

Use the same detector PID set, phase, interval, duration, trial, and run ID in
the surrounding experiment notes. Keep the `.pidstat.txt` file unchanged as
the source record. Cross-check rows by PID and nearest sample time, converting
units explicitly where needed (`pidstat` reports rates/percentages while this
CSV reports `/proc` counter deltas and KiB RSS). Do not parse `pidstat` values
into the `/proc` CSV or replace inaccessible `/proc` values with them; report
the two sources separately and explain any differences caused by sampling
time, rounding, or tool semantics.
