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
| `detectors/` | The three defenders: baseline diffing, inotify, auditd. |
| `experiments/` | Runners for Experiments A–D (coverage/latency, false positives, resource cost, evasion). |
| `analysis/` | Scripts that turn `results/*.csv` into the tables and plots for the report. |
| `results/` | CSV output from experiment runs, plus `system_info_<hostname>.txt` from `setup.sh`. |
| `docs/` | `VM_SETUP.md` — how to build the test VM. |
| `proposal/` | The submitted project proposal. |

## Setup

Target: Ubuntu 24.04 (see [`docs/VM_SETUP.md`](docs/VM_SETUP.md) for full VM
specs — use a VM, not your main machine, since the `LD_PRELOAD` implant and
the evasion variants touch root-owned system files).

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

`<technique>` is one of: `cron`, `systemd_user`, `bashrc`, `ssh_key`,
`xdg_autostart`, `ld_preload`. Every marker line — proof an implant actually
ran — lands in `~/.local/share/pd-markers/markers.log`.

```bash
bash implants/cron.sh plant
bash implants/cron.sh status
bash implants/cron.sh cleanup
```

## Running the detectors

Each detector in `detectors/` takes `start` / `stop`, watching the paths
listed in a file and appending alerts to a log (see
[`experiments/README.md`](experiments/README.md) for the exact interface —
this is what the experiment runners drive automatically).

## Running the experiments

```bash
# Experiment A — coverage + detection latency
experiments/exp_a_coverage_latency.sh --iterations 10 --diff-intervals "5 30 60"

# Experiment B — false positives on normal admin activity
experiments/exp_b_false_positives.sh --iterations 10 --diff-interval 30
```

Both write a timestamped CSV to `results/`. Experiment C (resource cost) and
Experiment D (evasion) are documented in
[`experiments/README.md`](experiments/README.md) — D reuses each implant's
`evade` verb in place of `plant`.

`analysis/` then turns those CSVs into the report's tables and plots (in
progress — see that folder once Student 2's analysis scripts land).

## Work split

| Member | Main tasks |
|---|---|
| Student 1 (Muhammad Hamza Bin Tariq) | The six implants, the experiment runner, the false-positive scenarios. |
| Student 2 (Raghib Ahmed) | The three detectors, the resource measurements, the analysis and plots. |
| Both | README, report, presentation, viva prep. |

See the proposal for the full research question, methodology, metrics, and
timeline.
