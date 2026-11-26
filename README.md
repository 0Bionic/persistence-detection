# persistence-detection

## Offline Student 2 analysis

The offline analysis consumes validated plant and raw detector alert JSONL,
the resource CSV emitted by `analysis/measure_resources.py`, and an optional
analysis-owned classification sidecar. Raw alerts remain unchanged; false
positive labels belong in `alert_classification` records keyed by `alert_id`.
The pipeline matches alerts to plants by a runner-supplied `plant_event_id`
when present, otherwise by the shared `run_id`, technique, experiment, and a
compatible trial. If a plant has no detector scope in `metadata`, the analysis
uses the requested three-detector experiment grid; Student 1 should confirm
this assumption in the runner output.

Run the synthetic, side-effect-free checks from the repository root:

```bash
python3 -B analysis/check_measure_resources.py
python3 -B analysis/check_analysis.py
```

Build reproducible CSV tables from the synthetic fixtures:

```bash
python3 -B analysis/make_tables.py \
  --plants analysis/fixtures/plants.jsonl \
  --alerts analysis/fixtures/alerts.jsonl \
  --resources analysis/fixtures/resources.csv \
  --classifications analysis/fixtures/classifications.jsonl \
  --output-dir /tmp/persistence-analysis-tables
```

Generate dependency-free SVG plots from those tables:

```bash
python3 -B analysis/make_plots.py \
  --tables-dir /tmp/persistence-analysis-tables \
  --output-dir /tmp/persistence-analysis-plots
```

The fixture set intentionally has no evasion outcomes. The plot command
reports that the evasion plot cannot be generated and does not create
misleading values. Real evasion plotting requires explicit
`evasion_result` records containing an `evasion_label` and boolean `detected`.

The analysis reports latency in milliseconds from authoritative epoch
nanoseconds. Missing resource measurements and missing classifications remain
blank/explicitly unavailable rather than being treated as zero. See
`analysis/RESOURCE_MEASUREMENTS.md` for keeping raw `pidstat` output separate
from `/proc` resource fields.
