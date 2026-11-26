# persistence-detection

**Detecting Linux Persistence Techniques** — Applied OS, Cyber Defense and AI
Agents (Section L4). Full writeup: [`proposal/Project Proposal Detecting Linux Persistence Techniques.pdf`](proposal/Project%20Proposal%20Detecting%20Linux%20Persistence%20Techniques.pdf).

We simulate six common Linux persistence techniques, each a harmless script
that only proves it ran, and measure how well three defenders — periodic
baseline file diffing, inotify watches, and auditd rules — detect them: on
coverage, detection latency, false positives, resource cost, and under
evasion.

## Folder layout

| Folder | Contents |
|---|---|
| `implants/` | The six persistence techniques (cron, systemd user unit, shell rc, SSH `authorized_keys`, XDG autostart, `LD_PRELOAD`), plus each one's evasion variant. |
| `detectors/` | The three defenders: `baseline_diff.py`, `inotify_watch.py`, `auditd_watch.py`, and the shared JSONL event contract (`alert_schema.py`, `ALERT_CONTRACT.md`, `config.json`) they're built on. |
| `experiments/` | Runners for Experiments A, B, D (coverage/latency, false positives, evasion); Experiment C (resource cost) is driven by `analysis/measure_resources.py` against the PIDs these runners start. |
| `analysis/` | Turns the runner's `plants.jsonl`/`alerts.jsonl` (plus resource CSVs and classification/evasion sidecars) into the report's tables and plots. |
| `results/` | JSONL/CSV output from experiment runs, plus `system_info_<hostname>.txt` from `setup.sh`. |
| `docs/` | `VM_SETUP.md` — how to build the test VM. |
| `proposal/` | The submitted project proposal. |

## Setup

Target: Ubuntu 24.04 (see [`docs/VM_SETUP.md`](docs/VM_SETUP.md) for full VM
specs — use a VM, not your main machine, since the `LD_PRELOAD` implant, the
evasion variants, and the auditd detector touch root-owned system state).

```bash
git clone <this repo>
cd persistence-detection
bash setup.sh          # run as your normal user, NOT with sudo — it calls sudo itself
```

`setup.sh` installs everything the project needs (auditd, inotify-tools,
sysstat, cron, openssh-server, Python + pandas/matplotlib, a compiler for the
`LD_PRELOAD` implant), enables the relevant services, raises the inotify
watch limit, and records the machine's specs to
`results/system_info_<hostname>.txt`. It's safe to re-run. After it finishes,
**log out and back in once** (for the `adm` group membership) and take a VM
snapshot named `clean` — every experiment run should start from that
snapshot.

## Running an implant by hand

Every implant in `implants/` shares the same verbs:

```bash
bash implants/<technique>.sh plant     # install the persistence
bash implants/<technique>.sh trigger   # make it fire now (smoke test)
bash implants/<technique>.sh verify    # did it run? (checks the markers log)
bash implants/<technique>.sh status    # watched path(s) + whether a marker exists
bash implants/<technique>.sh evade     # install the evasion variant, where one exists
bash implants/<technique>.sh cleanup   # remove it, restore any files it changed
```

`<technique>` is one of: `cron`, `systemd_user`, `shell_rc`, `ssh_authorized_keys`,
`xdg_autostart`, `ld_preload` — the same technique slugs `detectors/config.json`
and the experiment runners use. Every marker line — proof an implant actually
ran — lands in `~/.local/share/pd-markers/markers.log`.

```bash
bash implants/cron.sh plant
bash implants/cron.sh status
bash implants/cron.sh cleanup
```

## Running the detectors

Each detector in `detectors/` is a standalone Python script, invoked directly
(not wrapped in a daemon) and driven by the experiment runners:

```bash
python3 detectors/baseline_diff.py --experiment-id A --run-id R1 --trial 0 \
  --technique shell_rc --output results/alerts.jsonl --interval 30
python3 detectors/inotify_watch.py --experiment-id A --run-id R1 --trial 0 \
  --technique shell_rc --output results/alerts.jsonl
sudo python3 detectors/auditd_watch.py install --technique shell_rc
sudo python3 detectors/auditd_watch.py monitor --experiment-id A --run-id R1 \
  --trial 0 --technique shell_rc --output results/alerts.jsonl
sudo python3 detectors/auditd_watch.py remove --technique shell_rc
```

They run until killed — with `SIGINT` specifically; none of them trap
`SIGTERM`, so stop them with Ctrl-C or `kill -INT`, not plain `kill`, or
their cleanup/flush-on-exit code won't run — appending JSONL `alert`
records as they go.
See [`detectors/ALERT_CONTRACT.md`](detectors/ALERT_CONTRACT.md) for the full
event schema and [`experiments/README.md`](experiments/README.md) for how the
runners orchestrate all three detectors at once against one plant event.

## Running the experiments

The easiest way, on the VM (needs a real terminal — see the note below):

```bash
bash run_experiments.sh --quick   # fast sanity pass first
bash run_experiments.sh           # the real run, full proposal scale
```

This caches a sudo credential up front (`auditd` and `ld_preload` both need
root), keeps it alive for the whole run, runs Experiments A, B, C, D in
sequence, and then the analysis step below. **Must be run on a real
machine/VM with a real terminal** — a Claude Code sandbox session can't
authenticate `sudo` interactively, by design, so this won't work inside one.

Or run each experiment on its own:

```bash
# Experiment A — coverage + detection latency
python3 experiments/run_experiment_a.py --iterations 10 --diff-intervals 5 30 60

# Experiment B — false positives on normal admin activity
python3 experiments/run_experiment_b.py --iterations 3 --diff-interval 30

# Experiment C — resource cost (CPU/memory/disk I/O per detector)
python3 experiments/run_experiment_c.py --technique shell_rc --duration 60

# Experiment D — evasion (timing + alternate persistence paths)
python3 experiments/run_experiment_d.py --iterations 10 --diff-intervals 5 30 60
```

A/B/D write `plants.jsonl` / `alerts.jsonl` (append-only, shared across runs)
into `results/`, plus `classifications.jsonl` (B) and `evasion_results.jsonl`
(D); C writes `resources.csv`. See [`experiments/README.md`](experiments/README.md)
for exactly what each one does and why.

## Analysis

```bash
python3 -B analysis/make_tables.py \
  --plants results/plants.jsonl --alerts results/alerts.jsonl \
  --resources results/resources.csv \
  --classifications results/classifications.jsonl \
  --evasion results/evasion_results.jsonl \
  --output-dir results/tables

python3 -B analysis/make_plots.py \
  --tables-dir results/tables --output-dir results/plots
```

See `analysis/RESOURCE_MEASUREMENTS.md` for the resource-CSV contract, and
`analysis/check_analysis.py` / `analysis/check_measure_resources.py` for the
project's synthetic, side-effect-free self-checks.

## Work split

| Member | Main tasks |
|---|---|
| Student 1 (Muhammad Hamza Bin Tariq) | The six implants, the experiment runner, the false-positive scenarios. |
| Student 2 (Raghib Ahmed) | The three detectors, the resource measurements, the analysis and plots. |
| Both | README, report, presentation, viva prep. |

See the proposal for the full research question, methodology, metrics, and
timeline.
