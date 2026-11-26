# Handoff notes

Written so a fresh Claude Code session (or you) can pick this up without
re-deriving context from commit messages. If you're that fresh session:
read this once, then treat the repo (READMEs, commit history) as the
source of truth for anything this file doesn't cover.

> **⚠️ The proposal's stated submission deadline was November 26, 2026.**
> Today, per this file's last edit, is November 27, 2026 — the deadline as
> written has already passed. Confirm the real deadline (an extension,
> or the proposal date being stale) before treating the timeline below as
> safe.

## Where things stand

All work is on the `integration` branch (pushed to `origin/integration`),
**not yet merged to `main`, no pull request opened yet** — deliberately
held per an earlier instruction to wait until real experiment data exists.
`main` still only has `setup.sh` and the proposal; `student1-implants` and
`student-2-work` are each team member's individual branches, now folded
into `integration`.

What's built and working, end to end, verified against the real detectors:

- **`implants/`** — all six persistence techniques (`cron`, `systemd_user`,
  `shell_rc`, `ssh_authorized_keys`, `xdg_autostart`, `ld_preload`), each
  with `plant`/`trigger`/`verify`/`status`/`cleanup`, and `evade` variants
  for four of them (not `cron`/`systemd_user` — no alternate location to
  hide in).
- **`detectors/`** — Student 2's three detectors (`baseline_diff.py`,
  `inotify_watch.py`, `auditd_watch.py`) and the shared JSONL event
  contract they're built on (`alert_schema.py`, `ALERT_CONTRACT.md`,
  `config.json`).
- **`experiments/`** — four Python runners (`run_experiment_a.py` through
  `_d.py`) plus shared orchestration (`runner_common.py`), driving the
  implants and detectors together against that contract.
- **`run_experiments.sh`** — one-shot script sequencing all four
  experiments plus the analysis step, for a real run on a real VM.
- **`analysis/`** — Student 2's `make_tables.py`/`make_plots.py`, already
  confirmed to correctly consume this project's runner output.

## Bugs found and fixed (all already pushed)

A "quick pass" (`run_experiments.sh --quick`) surfaced three real bugs,
all fixed in commit `202c370`:

1. **`sudo` mangles `$USER`** for the command it execs, which silently
   broke `cron`'s path resolution — it's the only technique whose
   configured path is built from `{user}` rather than `{home}` (see
   `detectors/config.json`). `auditd`/`baseline_diff` both "started" for
   `cron` but were watching the wrong path, producing a false `0 alert(s)`
   instead of a real miss. Fixed: every detector invocation now gets
   `--home`/`--user` passed explicitly (`runner_common.REAL_HOME`/
   `REAL_USER`, captured before any `sudo` wrapping).
2. **`cron`'s storage path needs root to even read**, not just to audit —
   unlike every other technique's path. `baseline_diff`/`inotify` are now
   `sudo`-elevated specifically for `cron` (`detector_needs_sudo()`), and
   Experiment C's resource sampler is elevated too when measuring a
   root-owned detector (its `/proc/<pid>/io` reads were permission-denied
   otherwise).
3. **`implants/ld_preload.sh`'s `cleanup` never undid its own `evade`'s
   `~/.bashrc` write** (every other implant's cleanup already handles both
   its canonical and evade files). Found via a real leftover block in a
   shared `~/.bashrc`. Fixed and verified.

Also fixed: `run_experiments.sh --quick` was passing an invalid
`--diff-interval 10` to Experiment B (`baseline_diff` only accepts
5/30/60) — that's what was actually behind the `rc=2` crashes in the
quick-pass B log. All three runners now validate interval arguments via
`choices=`, so this class of mistake fails immediately and clearly instead
of three layers down in a subprocess.

## Known environment caveat

The machine this was developed and tested on is **not** the proposal's
target environment: `/etc/os-release` here is Ubuntu 26.04, not the
24.04 `docs/VM_SETUP.md` specifies. `sudo` also cannot authenticate
interactively from inside a Claude Code sandbox session on this machine
(confirmed: even the person's own attempt via the `!` prefix hit the same
"terminal required" error, since it runs through the same session) — but
apparently works fine from a real terminal into the same filesystem,
since a real `sudo`-enabled quick pass did complete here (that's the run
that surfaced the three bugs above).

**`results/`'s current committed contents are from that quick pass, run
*before* the bug fixes** — kept for reference/comparison, explicitly not
meant to be the report's data (see commit `e35970b`'s message for exactly
which known issues are baked into it).

## Next steps

1. Fresh Ubuntu 24.04 VM per `docs/VM_SETUP.md` (not this machine).
2. `git clone` the repo, `git checkout integration`, `bash setup.sh`, log
   out/in once, snapshot it as `clean`.
3. `bash run_experiments.sh --quick` there — confirm `cron` now shows real
   coverage (not a clean skip, and not a false `0 alert(s)`) now that the
   sudo/`$USER` fixes are in.
4. If that looks right: revert to the `clean` snapshot, then
   `bash run_experiments.sh` (full scale, `--iterations 10`) for the real
   data. Expect several hours; see `experiments/README.md` for per-
   experiment runtime estimates and troubleshooting.
5. Bring the resulting `results/` back (push the branch, or just make it
   available) — then build tables/plots and write the report.

## The report

Structure it after `docs/Project - Part IV - Sample (B. Wajid).pdf`
(IEEE two-column format: Abstract, Keywords, Introduction, Methods,
Results — one lettered subsection per experiment with a figure each,
Discussion, Conclusion and Future Work, numbered References). That file
is **not** committed (it's someone else's authored work — see
`.gitignore`); it's local-only on whichever machine it was placed on. If
a fresh session needs it again, it has to be re-added locally, not
pulled from git.

Map the proposal's four experiments onto Results subsections directly:
A → coverage/latency, B → false positives, C → resource cost,
D → evasion. The hypotheses in proposal section 5 are natural candidates
for what the Discussion section should explicitly confirm or refute.
