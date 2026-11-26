#!/usr/bin/env bash
# Runs the whole experiment suite (A, D, B, C) and the analysis pipeline,
# unattended, on a real machine with a real terminal — NOT inside a Claude
# Code sandbox session, which cannot authenticate sudo interactively.
#
# Run this on the Ubuntu VM from docs/VM_SETUP.md, as your normal user (not
# root — it calls sudo itself, same convention as setup.sh), after setup.sh
# and a "clean" snapshot. It will prompt you once for your sudo password up
# front, then run unattended for a while (see --quick below for a fast
# sanity check first).
#
# Usage: bash run_experiments.sh [--quick] [--iterations N] [--skip-pkg-install]
#   --quick              fast sanity-check pass (iterations=1, fewer
#                         techniques/intervals) — run this FIRST to confirm
#                         everything works before committing to the full run
#   --iterations N        trials per cell for Experiments A/B/D (default: 10,
#                         matching the proposal's "about 10 times")
#   --skip-pkg-install    skip Experiment B's package-install activity
#                         (e.g. no network on the VM)
#
# Output: results/plants.jsonl, alerts.jsonl, classifications.jsonl,
# evasion_results.jsonl, resources.csv, and results/tables/*.csv +
# results/plots/*.svg once analysis runs.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

[[ $EUID -eq 0 ]] && { echo "Run as your normal user, not root/sudo. This script calls sudo itself." >&2; exit 1; }

ITERATIONS=10
SKIP_PKG_INSTALL=()
QUICK=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) QUICK=1; shift ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --skip-pkg-install) SKIP_PKG_INSTALL=(--skip-pkg-install); shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ $QUICK -eq 1 ]]; then
  ITERATIONS=1
  A_D_ARGS=(--techniques cron shell_rc ld_preload --diff-intervals 5 30)
  B_ARGS=(--techniques cron shell_rc ld_preload --diff-interval 10)
else
  A_D_ARGS=(--diff-intervals 5 30 60)
  B_ARGS=(--diff-interval 30)
fi

say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }

mkdir -p results
STAMP="$(date +%Y%m%d_%H%M%S)"

say "Caching sudo credential (needed for auditd and ld_preload)"
sudo -v || { echo "sudo authentication failed; aborting." >&2; exit 1; }

# Keep the cached credential alive for the whole run — a single scan-interval
# cell can run close to a minute, and sudo's default timestamp timeout is 15
# minutes, so a long unattended run could otherwise stall partway through on
# a fresh password prompt nobody is there to answer.
( while true; do sudo -n true 2>/dev/null; sleep 240; done ) &
KEEPALIVE_PID=$!
trap 'kill "$KEEPALIVE_PID" 2>/dev/null' EXIT

run_step() {
  local name="$1"; shift
  say "Running $name"
  local log="results/${name}_${STAMP}.log"
  if "$@" 2>&1 | tee "$log"; then
    say "$name finished — log: $log"
  else
    warn "$name exited non-zero — see $log. Continuing with the rest of the suite."
  fi
}

run_step exp_a python3 -B experiments/run_experiment_a.py \
  --iterations "$ITERATIONS" "${A_D_ARGS[@]}" --results-dir results

run_step exp_d python3 -B experiments/run_experiment_d.py \
  --iterations "$ITERATIONS" "${A_D_ARGS[@]}" --results-dir results

run_step exp_b python3 -B experiments/run_experiment_b.py \
  --iterations "$ITERATIONS" "${B_ARGS[@]}" "${SKIP_PKG_INSTALL[@]}" --results-dir results

run_step exp_c python3 -B experiments/run_experiment_c.py \
  --duration "$([[ $QUICK -eq 1 ]] && echo 20 || echo 60)" --results-dir results

kill "$KEEPALIVE_PID" 2>/dev/null
trap - EXIT

say "Running analysis (tables + plots)"
mkdir -p results/tables results/plots
python3 -B analysis/make_tables.py \
  --plants results/plants.jsonl --alerts results/alerts.jsonl \
  --resources results/resources.csv \
  --classifications results/classifications.jsonl \
  --evasion results/evasion_results.jsonl \
  --output-dir results/tables \
  || warn "make_tables.py failed — check the inputs above by hand"

python3 -B analysis/make_plots.py \
  --tables-dir results/tables --output-dir results/plots \
  || warn "make_plots.py failed — check results/tables/ by hand"

say "Done. Tables: results/tables/*.csv   Plots: results/plots/*.svg"
if [[ $QUICK -eq 1 ]]; then
  echo "This was a --quick sanity pass (iterations=1, a few techniques)."
  echo "Revert the VM to its 'clean' snapshot, then re-run without --quick for the real data."
fi
