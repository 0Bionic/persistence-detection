# shellcheck shell=bash
# Shared helpers for the experiment runners (Experiment A: coverage/latency,
# Experiment B: false positives). Source this, then use the exp_* functions.
#
# --- Detector interface (what detectors/<name>.sh must implement) ---------
#
# A detector script is invoked as:
#   detectors/<name>.sh start   (env below set)
#   detectors/<name>.sh stop    (same PID file)
#
# Environment passed to both verbs:
#   PD_WATCH_PATHS_FILE   file with one watched path per line
#   PD_ALERT_LOG          file the detector APPENDS alerts to (TSV, see below)
#   PD_DETECTOR_PID_FILE  where `start` must write the PID of its background
#                         process, so `stop` (run as a fresh invocation) knows
#                         what to kill
#   PD_SCAN_INTERVAL      seconds between scans — only meaningful to the
#                         polling/diffing detector, other detectors ignore it
#
# `start` must return promptly (fork/background itself) once monitoring is
# live; it must not block the caller. `stop` must be idempotent.
#
# Alert line format appended to PD_ALERT_LOG, tab-separated:
#   <epoch.ns>\t<detector>\t<path>\t<note>
# One line per detected change. `<path>` must be one of the watched paths
# (or the closest one it can name) so the runner can match an alert back to
# the technique that touched it.

set -uo pipefail

PD_EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PD_REPO_ROOT="$(cd "$PD_EXP_DIR/.." && pwd)"
PD_IMPLANTS_DIR="$PD_REPO_ROOT/implants"
PD_DETECTORS_DIR="$PD_REPO_ROOT/detectors"
PD_RESULTS_DIR="$PD_REPO_ROOT/results"
mkdir -p "$PD_RESULTS_DIR"

# shellcheck source=/dev/null
source "$PD_IMPLANTS_DIR/lib.sh"   # for PD_TECHNIQUES, PD_MARKER_FILE, pd_now

exp_log() { printf '[exp] %s\n' "$*" >&2; }
exp_die() { printf '[exp] ERROR: %s\n' "$*" >&2; exit 1; }

# All known detector names. A name is "available" if detectors/<name>.sh
# exists; the runners skip (with a warning) any that don't, so this project
# runs end to end before Student 2's detectors all land.
PD_ALL_DETECTORS="diff inotify auditd"

exp_detector_available() { [ -x "$PD_DETECTORS_DIR/$1.sh" ] || [ -f "$PD_DETECTORS_DIR/$1.sh" ]; }

# Path each implant's `paths` verb reports, one per technique.
exp_technique_path() { bash "$PD_IMPLANTS_DIR/$1.sh" paths | head -n1; }

# Build a file listing the watched paths for every technique in PD_TECHNIQUES.
exp_build_watch_paths_file() {
  local out="$1" tech
  : > "$out"
  for tech in $PD_TECHNIQUES; do
    exp_technique_path "$tech" >> "$out"
  done
}

# exp_detector_start <name> <run_dir> [scan_interval]
# Sets PD_ALERT_LOG / PD_DETECTOR_PID_FILE / PD_WATCH_PATHS_FILE as a side
# effect (exported, so the rest of the run's helpers can see them) and
# launches the detector's `start` verb.
exp_detector_start() {
  local name="$1" run_dir="$2" interval="${3:-}"
  mkdir -p "$run_dir"
  export PD_WATCH_PATHS_FILE="$run_dir/watch_paths.txt"
  export PD_ALERT_LOG="$run_dir/alerts.log"
  export PD_DETECTOR_PID_FILE="$run_dir/detector.pid"
  export PD_SCAN_INTERVAL="$interval"
  : > "$PD_ALERT_LOG"
  exp_build_watch_paths_file "$PD_WATCH_PATHS_FILE"
  exp_log "starting detector '$name' (interval=${interval:-n/a})"
  bash "$PD_DETECTORS_DIR/$name.sh" start \
    || exp_die "detector '$name' failed to start"
  sleep 1   # give it a moment to actually be watching before we plant anything
}

exp_detector_stop() {
  local name="$1"
  bash "$PD_DETECTORS_DIR/$name.sh" stop 2>/dev/null || true
}

# Number of lines currently in the alert log (a cheap "high-water mark" so we
# only look at alerts that arrive after this point).
exp_alert_log_lines() { wc -l < "$PD_ALERT_LOG" 2>/dev/null || echo 0; }

# exp_wait_for_alert <path> <since_line> <timeout_s>
# Polls PD_ALERT_LOG for a line (after line number <since_line>) mentioning
# <path>. Prints the alert's timestamp field on a match and returns 0;
# returns 1 on timeout with nothing printed.
exp_wait_for_alert() {
  local path="$1" since="$2" timeout="$3" waited=0 hit
  while (( waited < timeout )); do
    hit="$(tail -n +"$((since + 1))" "$PD_ALERT_LOG" 2>/dev/null | awk -F'\t' -v p="$path" '$3==p{print $1; exit}')"
    if [ -n "$hit" ]; then printf '%s' "$hit"; return 0; fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

# How long to wait for an alert before giving up on this (detector, cell).
# The diffing detector can only notice a change at its next scan, so give it
# two full intervals of slack; event-driven detectors get a flat ceiling.
exp_timeout_for() {
  local name="$1" interval="$2"
  if [ "$name" = "diff" ] && [ -n "$interval" ]; then
    echo $(( interval * 2 + 10 ))
  else
    echo 20
  fi
}

exp_csv_header_if_new() {
  local file="$1" header="$2"
  [ -s "$file" ] || echo "$header" > "$file"
}
